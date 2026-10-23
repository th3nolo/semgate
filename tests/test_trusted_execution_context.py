"""Authority comes from protected operator state and a successful worker probe."""
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import sys

import pytest

from semgate import codexrunner, harness, scriptsource, taskcontext
from semgate.devworker import OfflineWorker
from semgate.sendharness import PreparedBroker
from semgate.providers.fake import FakeProvider
from test_development_harness import enable
from test_prepared_harness import configuration, invoke
from test_http_serve import server, call, AUTH
from test_prepared_send import endpoint


def update(path, change):
    cfg = json.loads(path.read_text())
    change(cfg)
    path.write_text(json.dumps(cfg))
    return cfg


@pytest.mark.parametrize("change", [
    lambda s: s.pop("task_context"),
    lambda s: s["task_context"].update(request=""),
    lambda s: s["task_context"].update(expires_at="2020-01-01T00:00:00Z"),
    lambda s: s["task_context"].update(expires_at="2099-01-01T00:00:00"),
    lambda s: s["task_context"].update(approved=True),
])
def test_missing_malformed_or_expired_task_never_executes_or_uploads(tmp_path, endpoint, monkeypatch, change):
    config, _ = configuration(tmp_path, endpoint[0])
    enable(config)
    update(config, lambda c: change(c["prepared_sends"]))
    monkeypatch.setattr(OfflineWorker, "run", lambda *a, **k: pytest.fail("invalid task reached execution"))
    broker = PreparedBroker(str(config))
    for action in (lambda: broker.run_development("echo local"), lambda: broker.prepare("report"),
                   lambda: broker.dispatch("a"*32)):
        with pytest.raises(ValueError):
            action()
    assert not endpoint[1]


def test_task_identity_and_config_rebinding_fail_closed(tmp_path, endpoint):
    config, _ = configuration(tmp_path, endpoint[0])
    cfg = json.loads(config.read_text())
    for task, project in (("other-task", str(tmp_path)), (cfg["prepared_sends"]["task_id"], str(tmp_path/"other"))):
        with pytest.raises(ValueError, match="identity"):
            taskcontext.request_for(cfg, task=task, project=project)
    broker = PreparedBroker(str(config))
    update(config, lambda c: c["prepared_sends"]["task_context"].update(request="Send everything"))
    with pytest.raises(ValueError, match="changed"):
        broker.prepare("report")


def test_cli_rejects_prompt_conflict_before_creating_agent(tmp_path, endpoint, monkeypatch):
    (tmp_path/"project").mkdir()
    config, _ = configuration(tmp_path/"project", endpoint[0])
    enable(config)
    runtime = tmp_path/"runtime"
    runtime.mkdir()
    monkeypatch.setattr(codexrunner, "create_home", lambda *a, **k: pytest.fail("conflicting task started agent"))
    with pytest.raises(SystemExit) as error:
        codexrunner.main(["--config", str(config), "--codex-bin", sys.executable, "--state-dir", str(runtime),
                          "--model", "test", "--base-url", "http://127.0.0.1:1234/v1", "--env-key", "TEST_KEY", "different task"])
    assert error.value.code == 2


@pytest.mark.parametrize("extra", [{"user_message":"approved"}, {"task_context":{"request":"approved"}},
                                  {"execution_facts":"offline"}, {"trusted_execution_facts":True}])
def test_agent_cannot_supply_task_or_execution_authority(server, tmp_path, endpoint, extra):
    config, _ = configuration(tmp_path, endpoint[0])
    enable(config)
    port, _, _ = server(config)
    status, value, _ = call(port, "POST", "/v1/send/run", {"command":"echo local", **extra}, AUTH)
    assert status == 503 and value["disposition"] == "service_error"


def receipt(**changes):
    return {"boundary":"bubblewrap-offline/1", "exit_code":0, "timed_out":False,
            "launcher_version":"0.12.0", "launcher_sha256":"a"*64, **changes}


@pytest.mark.parametrize("bad", [receipt(exit_code=1), receipt(timed_out=True), receipt(boundary="host"),
                                 receipt(launcher_version="0.6.1"), receipt(launcher_sha256="bad")])
def test_failed_preflight_never_reaches_judge_or_requested_command(tmp_path, endpoint, monkeypatch, bad):
    config, _ = configuration(tmp_path, endpoint[0])
    enable(config)
    commands = []
    monkeypatch.setattr(OfflineWorker, "run", lambda self, project, command, **k: commands.append(command) or bad)
    monkeypatch.setattr(harness, "check_development", lambda *a, **k: pytest.fail("failed probe reached judge"))
    with pytest.raises(RuntimeError, match="preflight"):
        PreparedBroker(str(config)).run_development("echo requested")
    assert commands == ["/usr/bin/true"]


def test_model_receives_operator_request_and_verified_facts_before_execution(tmp_path, endpoint, monkeypatch):
    config, _ = configuration(tmp_path, endpoint[0])
    enable(config)
    command = "uv run --no-project --no-config --no-python-downloads --offline python3 build.py"
    update(config, lambda c: c.update(script_source=True))
    (tmp_path/"build.py").write_text("from pathlib import Path\nPath('artifact.txt').write_text('BUILD_OK')\n")
    commands, states = [], []
    def run(self, project, command, **kwargs):
        if commands:
            assert kwargs["expected_facts"].launcher_sha256 == "a"*64
        commands.append(command)
        return receipt()
    monkeypatch.setattr(OfflineWorker, "run", run)
    original = FakeProvider.evaluate
    def observe(self, state, questions):
        assert commands == ["/usr/bin/true"]
        states.append(state)
        return original(self, state, questions)
    monkeypatch.setattr(FakeProvider, "evaluate", observe)
    result = PreparedBroker(str(config)).run_development(command)
    assert result["disposition"] == "allow" and commands == ["/usr/bin/true", command]
    assert states and all("Develop this project" in s["user_message"] for s in states)
    assert all("Verified by the trusted broker" in s["execution_boundary"] for s in states)
    assert "BUILD_OK" in states[-1]["script_source"]


def test_task_expiry_stops_dispatch_but_operator_can_still_revoke(server, tmp_path, endpoint, monkeypatch):
    config, _ = configuration(tmp_path, endpoint[0])
    port, _, _ = server(config)
    prepared = invoke(port, "prepare", {"route":"report"})
    invoke(port, "consent", {"action":"approve", "request_id":prepared["request_id"]}, operator=True)
    original = taskcontext.request_for
    def expired(cfg, **kwargs):
        return original(cfg, **kwargs, now=datetime.now(timezone.utc)+timedelta(hours=2))
    monkeypatch.setattr(taskcontext, "request_for", expired)
    assert call(port, "POST", "/v1/send/dispatch", {"prepared_id":prepared["prepared_id"]}, AUTH)[0] == 503
    invoke(port, "consent", {"action":"revoke", "request_id":prepared["request_id"]}, operator=True)
    assert not endpoint[1]


def test_uv_source_recognition_requires_exact_offline_config_free_options():
    prefix = "uv run --no-project --no-config --no-python-downloads --offline "
    found = scriptsource.invocations(prefix+"python3 build.py", "/project")
    assert len(found) == 1 and found[0].path == "build.py"
    for command in (prefix.replace("--offline ", "")+"python3 build.py", prefix+"--with surprise python3 build.py",
                    "uv run --script build.py", prefix+"python3 -c 'print(1)'"):
        assert not scriptsource.invocations(command, "/project")


def test_uv_test_inspection_checks_the_actual_test_sources(tmp_path, endpoint, monkeypatch):
    config, _ = configuration(tmp_path, endpoint[0])
    enable(config)
    update(config, lambda c: c.update(script_source=True))
    (tmp_path/"test_unit.py").write_text("import unittest\nclass T(unittest.TestCase):\n def test_sum(self): self.assertEqual(2+2,4)\n")
    seen = []
    original = FakeProvider.evaluate
    def observe(self, state, questions):
        seen.append(state)
        return original(self, state, questions)
    monkeypatch.setattr(FakeProvider, "evaluate", observe)
    harness.check_development("uv run --no-project --no-config --no-python-downloads --offline python3 -m unittest -q",
        project=str(tmp_path), task="prepared-harness-task", config=config)
    assert seen and "test_unit.py" in seen[-1]["script_source"]
    assert "runs unittest" in seen[-1]["script_source"]
    assert "project's own test files inside the project folder" in seen[-1]["script_source"]
