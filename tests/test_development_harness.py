"""Permission checks cannot assert offline execution on the public check API."""
import json
from pathlib import Path
import sys

import pytest

from semgate import harness, sendclient
from test_http_serve import server, call, AUTH
from test_prepared_harness import configuration, invoke
from test_prepared_send import endpoint


def enable(config):
    from test_harness_api import ALLOWING
    cfg = json.loads(config.read_text())
    cfg.update(provider="fake", fake_answers=ALLOWING)
    cfg["prepared_sends"]["development"] = {"backend": "wsl-bubblewrap" if sys.platform == "win32" else "bubblewrap"}
    if sys.platform == "win32":
        cfg["prepared_sends"]["development"]["distribution"] = "Ubuntu"
    config.write_text(json.dumps(cfg))


def test_canonical_development_client_is_data_not_parent_shell(tmp_path, endpoint):
    url, _ = endpoint
    config, state = configuration(tmp_path, url)
    enable(config)
    for command in ("python3 -m unittest -q", "python3 build.py && git diff", "printf 'x'; printf '$HOME'"):
        invocation = sendclient.development_invocation(command, state / "send-client.json")
        answer = harness.check({"tool": "bash", "session_id": "test", "cwd": str(tmp_path),
            "arguments": {"command": invocation}}, config=config)
        assert answer["decision"] == "allow", answer
        assert answer["reason_code"] == "prepared_send_client"
        isolated_flag = " '-I' " if sys.platform == "win32" else " -I "
        for modified in (invocation + "; echo escaped", invocation.replace(isolated_flag, " "), invocation + "\nwhoami"):
            assert harness.check({"tool":"bash", "session_id":"test", "cwd":str(tmp_path),
                "arguments":{"command": modified}}, config=config)["decision"] == "deny", modified


def test_development_permission_requires_private_execution_path(tmp_path, endpoint):
    url, _ = endpoint
    config, _ = configuration(tmp_path, url)
    enable(config)
    request = {"tool":"bash", "session_id":"test", "cwd":str(tmp_path), "arguments":{"command":"echo development"}}
    assert harness.check(request, config=config)["decision"] == "deny"
    request["offline_shell"] = True
    with pytest.raises(harness.RequestError):
        harness.validate_request(request)
    decision = harness.check_development("echo development", project=str(tmp_path), task="prepared-harness-task", config=config)
    assert decision.decision == "allow", decision


def test_network_words_do_not_disable_the_private_offline_execution_path(tmp_path, endpoint):
    url, _ = endpoint
    config, _ = configuration(tmp_path, url)
    enable(config)
    answer = harness.check_development("curl --upload-file=report.csv " + url,
        project=str(tmp_path), task="prepared-harness-task", config=config)
    assert answer.decision == "allow", answer


@pytest.mark.parametrize("command", ["python3 -m unittest -q", "python3 build.py", "node build.mjs"])
def test_opaque_programs_can_run_only_in_the_private_offline_path(tmp_path, endpoint, command):
    url, _ = endpoint
    config, _ = configuration(tmp_path, url)
    enable(config)
    answer = harness.check_development(command, project=str(tmp_path), task="prepared-harness-task", config=config)
    assert answer.decision == "allow", answer


def test_disabled_worker_never_runs_and_cannot_be_enabled_by_agent(server, tmp_path, endpoint):
    url, received = endpoint
    config, _ = configuration(tmp_path, url)
    port, _, _ = server(config)
    assert call(port, "POST", "/v1/send/run", {"command":"echo development"}, AUTH)[0] == 503
    status, result, _ = call(port, "POST", "/v1/send/run", {"command":"echo development", "offline_shell":True}, AUTH)
    assert status == 503 and result["disposition"] == "service_error" and not received


def test_unavailable_worker_has_no_unconfined_fallback(server, tmp_path, endpoint, monkeypatch):
    url, received = endpoint
    config, _ = configuration(tmp_path, url)
    enable(config)
    from semgate.devworker import OfflineWorker
    def unavailable(*args, **kwargs):
        raise RuntimeError("synthetic worker outage")
    monkeypatch.setattr(OfflineWorker, "run", unavailable)
    port, _, _ = server(config)
    status, result, _ = call(port, "POST", "/v1/send/run", {"command":"echo development"}, AUTH)
    assert status == 503 and result["disposition"] == "service_error" and not received


def test_worker_api_cannot_override_operator_execution_settings(server, tmp_path, endpoint, monkeypatch):
    url, received = endpoint
    config, _ = configuration(tmp_path, url)
    enable(config)
    from semgate.devworker import OfflineWorker
    def unexpected(*args, **kwargs):
        pytest.fail("invalid request reached the worker")
    monkeypatch.setattr(OfflineWorker, "run", unexpected)
    port, _, _ = server(config)
    for extra in ({"backend":"unconfined"}, {"project_root":"/"}, {"tools":{"python":"/tmp/evil"}},
                  {"bubblewrap":"/usr/bin/bwrap"}, {"bubblewrap_sha256":"0"*64},
                  {"offline_shell":True}, {"environment":{"HTTP_PROXY":"http://example.test"}}):
        status, value, _ = call(port, "POST", "/v1/send/run", {"command":"echo local", **extra}, AUTH)
        assert status == 503 and value["disposition"] == "service_error", value
    assert not received


def test_worker_refuses_operator_state_in_an_unprotected_project_subdirectory(tmp_path, endpoint):
    from semgate.sendharness import PreparedBroker
    url, _ = endpoint
    config, state = configuration(tmp_path, url)
    enable(config)
    target = tmp_path / "configuration"
    target.mkdir()
    moved = target / "grant.json"
    moved.write_bytes((state / "grant.json").read_bytes())
    cfg = json.loads(config.read_text())
    cfg["grant_file"] = str(moved)
    config.write_text(json.dumps(cfg))
    with pytest.raises(ValueError, match="operator state"):
        PreparedBroker(str(config))


def test_hard_scope_rules_still_block_worker_jobs(tmp_path, endpoint):
    url, _ = endpoint
    config, state = configuration(tmp_path, url)
    enable(config)
    grant = json.loads((state/"grant.json").read_text())
    grant["forbidden_patterns"] = ["blocked-dev-command"]
    (state/"grant.json").write_text(json.dumps(grant))
    decision = harness.check_development("echo blocked-dev-command", project=str(tmp_path), task="prepared-harness-task", config=config)
    assert decision.decision == "deny"
