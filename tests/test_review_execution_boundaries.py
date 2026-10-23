"""Preserve authority and provider input semantics at translated boundaries."""
from copy import deepcopy
from datetime import datetime, timedelta
import json
from pathlib import Path
import re
import subprocess
import sys

import pytest

from semgate import codexrunner, harness, privacy, router
from semgate.devworker import OfflineWorker, VerifiedOfflineFacts
from semgate.policy import Policy
from semgate.providers.fake import FakeProvider
from semgate.sendharness import PreparedBroker
from semgate.taskcontext import request_for
from test_development_harness import enable
from test_prepared_harness import ROOT, configuration
from test_privacy import CapturingProvider


@pytest.mark.parametrize("namespace", ["host", "worker"])
def test_literal_write_preserves_both_host_and_worker_forbidden_patterns(tmp_path, monkeypatch, namespace):
    config, state = configuration(tmp_path, "http://127.0.0.1:12345/report")
    enable(config)
    cfg = json.loads(config.read_text())
    cfg["trust"] = {"file": str(state / "trust.jsonl")}
    cfg["enforcement"]["auto_allow_tools"].append("write")
    config.write_text(json.dumps(cfg))
    target = tmp_path / "restricted.txt"
    forbidden = str(target) if namespace == "host" else "/workspace/restricted.txt"
    grant = json.loads((state / "grant.json").read_text())
    grant["forbidden_patterns"] = [re.escape(forbidden)]
    (state / "grant.json").write_text(json.dumps(grant))
    monkeypatch.setattr(OfflineWorker, "verify", lambda *a, **kw: VerifiedOfflineFacts("0.12.0", "a" * 64))
    calls = []
    monkeypatch.setattr(OfflineWorker, "write", lambda *a, **kw: calls.append(a) or {"returncode": 0})
    broker = PreparedBroker(str(config))
    try:
        result = broker.write_development({"path": target.name, "content": "literal data"})
    finally:
        broker.close()
    assert result["disposition"] == "deny", result
    assert result["reason_code"] == "grant_scope"
    assert calls == [] and not target.exists()


@pytest.mark.parametrize("alias", [False, True])
def test_runner_rejects_project_executable_before_creating_runtime_or_executing(tmp_path, monkeypatch, alias):
    project = tmp_path / "project"
    project.mkdir()
    config, _ = configuration(project, "http://127.0.0.1:12345/report")
    enable(config)
    binary = project / "codex-wrapper"
    binary.write_bytes(b"synthetic candidate, never execute")
    if alias:
        external = tmp_path / "external-alias"
        try:
            external.symlink_to(binary)
        except OSError:
            pytest.skip("symlink privilege unavailable")
        binary = external
    state = tmp_path / "runtime"
    state.mkdir()
    def forbidden(*args, **kwargs):
        pytest.fail("project executable reached runtime creation or execution")
    monkeypatch.setattr(codexrunner, "create_home", forbidden)
    monkeypatch.setattr(codexrunner.proc, "run", forbidden)
    monkeypatch.setattr(codexrunner.proc, "popen", forbidden)
    prompt = json.loads(config.read_text())["prepared_sends"]["task_context"]["request"]
    with pytest.raises(SystemExit) as stopped:
        codexrunner.main(["--config", str(config), "--state-dir", str(state), "--codex-bin", str(binary),
                          "--model", "test", "--base-url", "http://127.0.0.1:12345/v1", "--env-key", "MODEL_KEY", prompt])
    assert stopped.value.code == 2
    assert list(state.iterdir()) == []


def test_version_probe_uses_same_filtered_environment_and_runtime_as_app_server(tmp_path, monkeypatch):
    home = codexrunner.create_home(tmp_path, model="test", base_url="http://127.0.0.1:12345/v1", env_key="MODEL_KEY")
    client = codexrunner.CodexRunner(Path(sys.executable), home, tmp_path / "client.json", project=tmp_path / "project",
        env={"MODEL_KEY": "synthetic-model", "UNRELATED_SECRET": "synthetic-private"})
    seen = []
    def version(*args, **kwargs):
        seen.append(kwargs)
        return subprocess.CompletedProcess(args, 0, "unexpected version", "")
    monkeypatch.setattr(codexrunner.proc, "run", version)
    with pytest.raises(ValueError, match="validated app-server version"):
        client.run("synthetic request")
    assert seen[0].get("env") == client.env
    assert seen[0].get("cwd") == home
    assert "UNRELATED_SECRET" not in client.env


def test_direct_runner_requires_an_external_executable(tmp_path):
    project = tmp_path / "project"
    project.mkdir()
    binary = project / "codex-wrapper"
    binary.write_bytes(b"synthetic candidate, never execute")
    with pytest.raises(ValueError, match="outside the project"):
        codexrunner.CodexRunner(binary, tmp_path / "runtime", tmp_path / "client.json", project=project)


def test_privacy_metadata_does_not_poison_authorization_or_permission_levels(tmp_path, monkeypatch):
    config, state = configuration(tmp_path, "http://127.0.0.1:12345/report")
    enable(config)
    cfg = json.loads(config.read_text())
    cfg["trust"] = {"file": str(state / "trust.jsonl")}
    cfg["privacy_gate"].update(allow_remote=True, require_prepared=False)
    config.write_text(json.dumps(cfg))
    grant = json.loads((state / "grant.json").read_text())
    purpose = "Send the 2021 report"
    grant["purpose"] = purpose
    (state / "grant.json").write_text(json.dumps(grant))
    pair = [CapturingProvider(), CapturingProvider()]
    monkeypatch.setattr(privacy.PrivacyGate, "_providers", lambda self: pair)
    ordinary = []
    original = FakeProvider.evaluate
    def capture(self, model_state, questions):
        ordinary.append(deepcopy({"state": model_state, "questions": questions}))
        return original(self, model_state, questions)
    monkeypatch.setattr(FakeProvider, "evaluate", capture)
    raw = "synthetic.person@example.test"
    harness.check({"tool": "custom_tool", "arguments": {"url": "https://example.test/report", "json": {"email": raw}},
                   "session_id": "metadata", "cwd": str(tmp_path), "project_root": str(tmp_path),
                   "user_messages": [purpose]}, config=config)
    assert pair[0].inputs and pair[0].inputs == pair[1].inputs
    private_state = pair[0].inputs[0]["state"]
    assert private_state["operator_purpose"] == purpose
    assert private_state["user_requests"] == [purpose]
    assert private_state["proposed_disclosure"]["categories"] == [{"category": "email", "count": 1}]
    assert len(ordinary) == 1
    expected_questions = router.questions(Policy.load(str(ROOT / "policies/router_policy_dev.json")))
    assert ordinary[0]["state"]["operator_purpose"] == purpose
    assert ordinary[0]["state"]["user_message"] == purpose
    assert ordinary[0]["questions"]["effect"] == expected_questions["effect"]
    assert raw not in json.dumps([p.inputs for p in pair] + ordinary)


def test_documented_http_profile_has_required_operator_task_binding():
    guide = (ROOT / "docs" / "guide.md").read_text(encoding="utf-8")
    section = guide.split("### Prepared execution in the HTTP harness", 1)[1]
    config = json.loads(section.split("```json\n", 1)[1].split("```", 1)[0])
    settings = config["prepared_sends"]
    context = settings["task_context"]
    expiry = datetime.fromisoformat(context["expires_at"].replace("Z", "+00:00"))
    assert expiry.tzinfo is not None
    assert request_for(config, task=settings["task_id"], project=settings["project_root"],
                       now=expiry - timedelta(seconds=1)) == context["request"]
    with pytest.raises(ValueError, match="expired"):
        request_for(config, task=settings["task_id"], project=settings["project_root"], now=expiry + timedelta(seconds=1))
