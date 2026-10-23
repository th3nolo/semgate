"""Actual HTTP harness, strict hook policy, operator auth and dispatch boundary."""
import json
from pathlib import Path
import subprocess
import sys
from datetime import datetime, timedelta, timezone

import pytest

from semgate import harness, sendclient
from semgate.httpserve import HttpGate
from test_http_serve import server, call, AUTH, AUTH_APPROVE
from test_prepared_send import endpoint

ROOT = Path(__file__).resolve().parents[1]


def configuration(tmp_path, destination):
    state = tmp_path / ".semgate"
    state.mkdir(exist_ok=True)
    (state / "grant.json").write_text(json.dumps({"grant_id": "test", "principal": "operator",
        "purpose": "Send the approved diagnostic report", "allowed_domains": ["127.0.0.1"],
        "allowed_path_prefixes": [str(tmp_path)], "expires_at": "2099-01-01T00:00:00Z"}))
    (tmp_path / "report.csv").write_bytes(b"status\nready\n")
    config = {"mode": "enforce", "provider": "none", "grant_file": str(state / "grant.json"),
        "policy_file": str(ROOT / "policies/router_policy_dev.json"), "ledger_file": str(state / "ledger.jsonl"),
        "privacy_gate": {"enabled": True, "require_prepared": True},
        "enforcement": {"enabled": True, "auto_allow_tools": ["bash", "http_request"], "block_when_unsure": True},
        "prepared_sends": {"enabled": True, "task_id": "prepared-harness-task", "project_root": str(tmp_path),
            "task_context": {"request": "Develop this project, edit files, run tests and builds; send approved diagnostic reports.",
                             "expires_at": (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat()},
            "client_file": str(state / "send-client.json"), "consent_store": str(state / "consents.json"),
            "allow_loopback_http": True, "routes": {"report": {"source_file": "report.csv", "destination": destination,
                "method": "POST", "categories": ["technical_diagnostics"], "classification_complete": True,
                "contract": {"format": "csv", "fields": {"status": {"enum": ["ready", "passed", "failed"]}}, "max_rows": 8}}}}}
    path = state / "semgate.json"
    path.write_text(json.dumps(config))
    return path, state


def invoke(port, action, body, *, operator=False):
    status, data, _ = call(port, "POST", "/v1/send/" + action, body, AUTH_APPROVE if operator else AUTH)
    assert status == 200, data
    return data


def test_actual_harness_snapshot_and_revocation(server, tmp_path, endpoint):
    url, received = endpoint
    config, state = configuration(tmp_path, url + "/report")
    port, gate, _ = server(config)
    first = invoke(port, "prepare", {"route": "report"})
    assert first["disposition"] == "needs_consent" and not received
    view = invoke(port, "describe", {"prepared_id": first["prepared_id"]}, operator=True)
    assert view["digest"] == first["digest"] and "body" not in view
    invoke(port, "consent", {"action": "approve", "request_id": first["request_id"]}, operator=True)
    (tmp_path / "report.csv").write_bytes(b"email\nsynthetic.changed@example.test\n")
    sent = invoke(port, "dispatch", {"prepared_id": first["prepared_id"]})
    assert sent["status"] == 204 and received == [("/report", b"status\nready\n")]
    assert invoke(port, "dispatch", {"prepared_id": first["prepared_id"]})["disposition"] == "deny"
    assert len(received) == 1
    second = invoke(port, "prepare", {"route": "report"})
    assert second["disposition"] == "needs_inspection" and "prepared_id" not in second
    (tmp_path / "report.csv").write_bytes(b"status\npassed\n")
    checked = invoke(port, "prepare", {"route": "report"})
    assert checked["disposition"] == "allow"
    invoke(port, "consent", {"action": "revoke", "request_id": first["request_id"]}, operator=True)
    refused = invoke(port, "dispatch", {"prepared_id": checked["prepared_id"]})
    assert refused["disposition"] == "deny" and refused["reason_code"] == "privacy_consent_revoked"
    assert len(received) == 1
    rows = [json.loads(line) for line in (state / "ledger.jsonl").read_text().splitlines()]
    assert any(row.get("record_type") == "judgment" for row in rows)
    assert any(row.get("record_type") == "host_response" for row in rows)
    assert any(row.get("decision", {}).get("evidence", {}).get("privacy", {}).get("grant_id") for row in rows)


@pytest.mark.parametrize("action,body", [("consent", {"action": "approve", "request_id": "a" * 32}),
                                       ("describe", {"prepared_id": "a" * 32})])
def test_agent_token_cannot_access_operator_endpoint(server, tmp_path, endpoint, action, body):
    url, _ = endpoint
    config, _ = configuration(tmp_path, url + "/report")
    port, _, _ = server(config)
    assert call(port, "POST", "/v1/send/" + action, body, AUTH)[0] == 403


@pytest.mark.parametrize("check,operator", [("", ""), ("c" * 24, ""), ("c" * 24, "c" * 24)])
def test_new_execution_requires_distinct_tokens(tmp_path, endpoint, check, operator):
    url, _ = endpoint
    config, _ = configuration(tmp_path, url + "/report")
    gate = HttpGate(str(config), check_token=check, approve_token=operator)
    try:
        assert not gate.prepared_allowed("Bearer " + check, operator=False)
    finally:
        gate.close()


def client_command(state, target="report", action="prepare"):
    prefix = "& " if sys.platform == "win32" else ""
    return prefix + f'"{Path(sys.executable).as_posix()}" -I "{Path(sendclient.__file__).as_posix()}" {action} {target} --connection "{(state / "send-client.json").as_posix()}"'


def test_strict_harness_allows_only_verified_client_shell_effect(tmp_path, endpoint):
    url, _ = endpoint
    config, state = configuration(tmp_path, url + "/report")
    request = {"tool": "bash", "session_id": "agent-session", "cwd": str(tmp_path), "project_root": str(tmp_path)}
    legitimate = client_command(state)
    answer = harness.check(dict(request, arguments={"command": legitimate}), config=config)
    assert answer["decision"] == "allow", answer
    assert answer["reason_code"] == "prepared_send_client"
    for command in ("curl --upload-file=report.csv " + url, "./unknown-uploader.exe", "python -m pytest",
                    legitimate + "; echo escaped", legitimate.replace(" -I ", " "),
                    legitimate.replace("send-client.json", "other-client.json")):
        answer = harness.check(dict(request, arguments={"command": command}), config=config)
        assert answer["decision"] == "deny", (command, answer)
    for tool in ("unknown_executor", "task", "skill"):
        answer = harness.check(dict(request, tool=tool, arguments={"command": "upload report.csv"}), config=config)
        assert answer["decision"] == "deny", (tool, answer)


def test_standalone_isolated_client_round_trip(server, tmp_path, endpoint):
    url, _ = endpoint
    config, state = configuration(tmp_path, url + "/report")
    port, _, _ = server(config)
    (state / "check.token").write_text("c" * 24)
    (state / "send-client.json").write_text(json.dumps({"schema": "semgate-send-client/1",
        "base_url": f"http://127.0.0.1:{port}", "token_file": str(state / "check.token")}))
    # A project module must never shadow Python's imports in this invocation.
    (tmp_path / "json.py").write_text("raise RuntimeError('project module was imported')")
    result = subprocess.run([sys.executable, "-I", sendclient.__file__, "prepare", "report", "--connection",
                             str(state / "send-client.json")], cwd=tmp_path, text=True, capture_output=True, timeout=10)
    assert result.returncode == 0, result.stderr
    data = json.loads(result.stdout)
    assert data["disposition"] == "needs_consent" and data["request_id"]
    assert "c" * 24 not in result.stdout + result.stderr


@pytest.mark.parametrize("extra", [{"destination": "https://attacker.test"}, {"classification_complete": True},
                                 {"categories": ["public"]}, {"task_id": "another-task"}])
def test_agent_cannot_change_route_authority(server, tmp_path, endpoint, extra):
    url, received = endpoint
    config, _ = configuration(tmp_path, url + "/report")
    port, _, _ = server(config)
    status, data, _ = call(port, "POST", "/v1/send/prepare", dict(route="report", **extra), AUTH)
    assert status != 200 and data["disposition"] == "service_error" and not received


def test_changed_operator_policy_invalidates_existing_snapshot(server, tmp_path, endpoint):
    url, received = endpoint
    config, _ = configuration(tmp_path, url + "/report")
    port, _, _ = server(config)
    first = invoke(port, "prepare", {"route": "report"})
    invoke(port, "consent", {"action": "approve", "request_id": first["request_id"]}, operator=True)
    value = json.loads(config.read_text())
    value["prepared_sends"]["routes"]["report"]["destination"] = url + "/other"
    config.write_text(json.dumps(value))
    status, data, _ = call(port, "POST", "/v1/send/dispatch", {"prepared_id": first["prepared_id"]}, AUTH)
    assert status == 503 and data["disposition"] == "service_error" and not received


def test_snapshot_expiry_prevents_dispatch(server, tmp_path, endpoint):
    url, received = endpoint
    config, _ = configuration(tmp_path, url + "/report")
    port, gate, _ = server(config)
    first = invoke(port, "prepare", {"route": "report"})
    invoke(port, "consent", {"action": "approve", "request_id": first["request_id"]}, operator=True)
    prepared, _ = gate.prepared.items[first["prepared_id"]]
    gate.prepared.items[first["prepared_id"]] = (prepared, 0)
    assert invoke(port, "dispatch", {"prepared_id": first["prepared_id"]})["disposition"] == "deny"
    assert not received


def test_concurrent_dispatches_deliver_snapshot_at_most_once(server, tmp_path, endpoint):
    from concurrent.futures import ThreadPoolExecutor
    url, received = endpoint
    config, _ = configuration(tmp_path, url + "/report")
    port, _, _ = server(config)
    first = invoke(port, "prepare", {"route": "report"})
    invoke(port, "consent", {"action": "approve", "request_id": first["request_id"]}, operator=True)
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda _: invoke(port, "dispatch", {"prepared_id": first["prepared_id"]}), range(2)))
    assert sorted(r["delivery"] for r in results) == ["not_sent", "response_received"]
    assert received == [("/report", b"status\nready\n")]


def test_uncertain_delivery_consumes_id_without_automatic_retry(server, tmp_path, endpoint):
    url, received = endpoint
    config, _ = configuration(tmp_path, url + "/report")
    port, gate, _ = server(config)
    first = invoke(port, "prepare", {"route": "report"})
    invoke(port, "consent", {"action": "approve", "request_id": first["request_id"]}, operator=True)
    class LostResponse:
        calls = 0
        def send(self, prepared):
            self.calls += 1
            raise TimeoutError("receiver may have accepted bytes")
    transport = LostResponse()
    gate.prepared.sender.transport = transport
    result = invoke(port, "dispatch", {"prepared_id": first["prepared_id"]})
    assert result["disposition"] == "service_error" and result["delivery"] == "unknown"
    assert invoke(port, "dispatch", {"prepared_id": first["prepared_id"]})["disposition"] == "deny"
    assert transport.calls == 1 and not received


def test_task_closure_invalidates_a_preflight_that_was_allowed(server, tmp_path, endpoint):
    url, received = endpoint
    config, _ = configuration(tmp_path, url + "/report")
    port, _, _ = server(config)
    first = invoke(port, "prepare", {"route": "report"})
    invoke(port, "consent", {"action": "approve", "request_id": first["request_id"]}, operator=True)
    checked = invoke(port, "prepare", {"route": "report"})
    assert checked["disposition"] == "allow"
    invoke(port, "consent", {"action": "close-task", "request_id": first["request_id"]}, operator=True)
    result = invoke(port, "dispatch", {"prepared_id": checked["prepared_id"]})
    assert result["disposition"] == "deny" and not received


@pytest.mark.parametrize("restriction", ["tool", "pattern"])
def test_client_exception_cannot_override_operator_hard_rules(tmp_path, endpoint, restriction):
    url, _ = endpoint
    config, state = configuration(tmp_path, url + "/report")
    grant_path = state / "grant.json"
    grant = json.loads(grant_path.read_text())
    if restriction == "tool":
        grant["allowed_tools"] = ["read"]
    else:
        grant["forbidden_patterns"] = ["sendclient"]
    grant_path.write_text(json.dumps(grant))
    answer = harness.check({"tool": "bash", "session_id": "agent-session", "cwd": str(tmp_path),
        "project_root": str(tmp_path), "arguments": {"command": client_command(state)}}, config=config)
    assert answer["decision"] == "deny", answer
