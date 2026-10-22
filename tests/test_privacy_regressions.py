"""Privacy/permission integration regressions, using synthetic local fixtures."""
import json

import pytest

from semgate import Gate, harness
from semgate.devworker import VerifiedOfflineFacts
from semgate.privacy import PrivacyGate
from semgate.privacydata import Minimizer
from semgate.providers.fake import FakeProvider
from semgate.sendharness import PreparedBroker
from semgate.trustauth import Auth
from test_development_harness import enable
from test_development_git_facts import project
from test_harness_api import ALLOWING
from test_prepared_harness import configuration
from test_prepared_send import endpoint, sender_for


def test_one_value_retains_each_detected_category_without_duplicate_counts():
    cleaner = Minimizer()
    value = "synthetic.person@example.test"
    result = cleaner.clean({"name": value, "email": value, "again": value})
    assert result["name"] == result["email"]
    assert cleaner.counts["name"] == cleaner.counts["email"] == 1


@pytest.mark.parametrize("field", ["name", "email", "diagnosis"])
def test_structured_sensitive_values_cannot_drop_credential_prohibition(tmp_path, field):
    class NoDelivery:
        def send(self, prepared):
            pytest.fail("credential-shaped fixture must never reach transport")

    sender = sender_for(tmp_path, transport=NoDelivery())
    # Construct a synthetic detector fixture; no credential is read or used.
    value = "ghp_" + "aB3dE5gH7jK9mN2pQ4sT6vW8xY0zA1bC3dE5fG7h"
    prepared = sender.prepare(json.dumps({field: value}).encode(), destination="https://example.test/report",
        source="synthetic-report", categories=frozenset({"technical_diagnostics"}), classification_complete=True)
    # Even an explicit PII-category grant cannot authorize credential disclosure.
    pii = prepared.categories - {"secret", "credential"}
    request = sender.consents.evaluate(prepared.scope, pii, prepared.digest)
    sender.consents.approve(request.request_id, auth=Auth("test"))
    assert "secret" in prepared.categories
    assert sender.send(prepared).outcome.reason_code == "privacy_credentials_forbidden"


def test_privacy_history_follows_user_turns_and_keeps_same_turn_votes(tmp_path):
    gate = Gate("Develop this project", provider=FakeProvider(ALLOWING), project_root=str(tmp_path),
                ledger=tmp_path/"ledger.jsonl", session_id="private-session", privacy_gate=PrivacyGate())
    for index, request in enumerate(("List project files", "Count source files", "Count source files")):
        decision = gate.check(f"echo step{index}", user_message=request)
        assert decision.decision == "allow", decision.reason_code
    current = gate.envelope("echo next", user_message="Count source files")
    from semgate.judge import Decision
    gate.ledger.record_judgment(current, Decision("allow", stage="semantic", envelope_digest="earlier",
        predicate_votes=[{"predicate": "on_task", "p": 0.1}]), private=True)
    assert gate.ledger.session_on_task(current) == [0.1]


def test_prepared_route_uses_the_effective_work_profile_grant(tmp_path):
    config, _ = configuration(tmp_path, "http://127.0.0.1:12345/report")
    cfg = json.loads(config.read_text())
    cfg["profiles"] = {"enabled": True, "override": ["software-development"]}
    config.write_text(json.dumps(cfg))
    broker = PreparedBroker(str(config))
    try:
        prepared = broker.prepare("report")
        assert prepared["disposition"] == "needs_consent", prepared
        broker.consents.approve(prepared["request_id"], auth=Auth("test"))
        assert broker.prepare("report")["disposition"] == "allow"
    finally:
        broker.close()


def test_verified_development_paths_share_the_worker_namespace(tmp_path):
    config, _ = configuration(tmp_path, "http://127.0.0.1:12345/report")
    enable(config)
    facts = VerifiedOfflineFacts("0.12.0", "a"*64)
    for command in ("cat report.csv", "cat ./report.csv", "cat /workspace/report.csv", "cat /workspace/../workspace/report.csv"):
        answer = harness.check_development(command, project=str(tmp_path), task="prepared-harness-task",
                                           config=config, execution_facts=facts)
        assert answer.decision == "allow", (command, answer.reason_code)
    for command in ("cat /outside/report.csv", "cat /workspace/../outside/report.csv"):
        answer = harness.check_development(command, project=str(tmp_path), task="prepared-harness-task",
                                           config=config, execution_facts=facts)
        assert answer.decision == "deny" and answer.reason_code == "grant_scope"


def test_preparation_preserves_ordinary_approval_for_dispatch_and_revocation(tmp_path, endpoint):
    url, received = endpoint
    config, state = configuration(tmp_path, url+"/report")
    cfg = json.loads(config.read_text())
    cfg["enforcement"]["block_when_unsure"] = False
    config.write_text(json.dumps(cfg))
    grant = json.loads((state/"grant.json").read_text())
    grant["allowed_domains"] = []
    (state/"grant.json").write_text(json.dumps(grant))
    broker = PreparedBroker(str(config))
    try:
        first = broker.prepare("report")
        assert first["disposition"] == "needs_consent" and "approval_id" not in first
        broker.consents.approve(first["request_id"], auth=Auth("test"))
        pending = broker.prepare("report")
        assert pending["disposition"] == "needs_inspection" and pending["approval_id"]
        assert "request_id" not in pending
        harness.approve(pending["approval_id"], True, "synthetic operator", config=config)
        from semgate.approvals import store_for
        store = store_for(harness.load_config(config))
        for _ in range(2):
            assert broker.prepare("report")["disposition"] == "allow"
            assert store.get(pending["approval_id"])["status"] == "approved"
        sent = broker.dispatch(pending["prepared_id"])
        assert sent["delivery"] == "response_received" and len(received) == 1
        assert store.get(pending["approval_id"])["status"] == "used"
        retry = broker.prepare("report")
        assert retry["disposition"] == "needs_inspection"
        assert broker.dispatch(retry["prepared_id"])["delivery"] == "not_sent"
        harness.approve(retry["approval_id"], True, "synthetic operator", config=config)
        broker.consents.revoke(first["request_id"], auth=Auth("test"))
        refused = broker.dispatch(retry["prepared_id"])
        assert refused["reason_code"] == "privacy_consent_revoked" and len(received) == 1
        assert store.get(retry["approval_id"])["status"] == "approved"
    finally:
        broker.close()


def test_worker_source_evidence_reads_host_files_without_rewriting_command(tmp_path, monkeypatch):
    config, _ = configuration(tmp_path, "http://127.0.0.1:12345/report")
    enable(config)
    cfg = json.loads(config.read_text())
    cfg["script_source"] = True
    config.write_text(json.dumps(cfg))
    (tmp_path/"build.py").write_text("print('WORKER_SOURCE_EVIDENCE')\n")
    states = []
    original = FakeProvider.evaluate
    def observe(self, state, questions):
        states.append(state)
        return original(self, state, questions)
    monkeypatch.setattr(FakeProvider, "evaluate", observe)
    command = "python3 /workspace/build.py"
    result = harness.check_development(command, project=str(tmp_path), task="prepared-harness-task", config=config,
                                       execution_facts=VerifiedOfflineFacts("0.12.0", "a"*64))
    assert result.decision == "allow", result.reason_code
    assert any("WORKER_SOURCE_EVIDENCE" in state.get("script_source", "") for state in states)
    assert any(command in json.dumps(state) for state in states)


@pytest.mark.parametrize("dirty", [False, True])
def test_guest_absolute_overwrite_keeps_actual_git_recoverability(project, dirty):
    root, config, _ = project
    if dirty:
        (root/"report.csv").write_text("unsaved work\n")
    answer = harness.check_development("cp /workspace/source.csv /workspace/report.csv", project=str(root),
        task="prepared-harness-task", config=config, execution_facts=VerifiedOfflineFacts("0.12.0", "a"*64))
    if dirty:
        assert answer.decision != "allow" and answer.reason_code == "unrecoverable_write:dirty"
    else:
        assert answer.decision == "allow", answer.reason_code


def test_worker_mapping_keeps_narrow_path_grants_and_original_forbidden_patterns(tmp_path):
    config, state = configuration(tmp_path, "http://127.0.0.1:12345/report")
    enable(config)
    (tmp_path/"allowed").mkdir()
    (tmp_path/"allowed"/"readme.txt").write_text("synthetic fixture\n")
    grant = json.loads((state/"grant.json").read_text())
    grant.update(allowed_path_prefixes=[str(tmp_path/"allowed")], forbidden_patterns=["blocked-original"])
    (state/"grant.json").write_text(json.dumps(grant))
    for command, expected in (("cat /workspace/allowed/readme.txt", "allow"),
                              ("cat /workspace/report.csv", "deny"),
                              ("cat /workspace/allowed/../report.csv", "deny"),
                              ("cat /workspace/allowed/blocked-original", "deny")):
        result = harness.check_development(command, project=str(tmp_path), task="prepared-harness-task", config=config,
                                           execution_facts=VerifiedOfflineFacts("0.12.0", "a"*64))
        assert result.decision == expected, (command, result.reason_code)


@pytest.mark.parametrize("field", ["execution_paths", "consume_approval"])
def test_agent_json_cannot_supply_internal_execution_or_approval_controls(tmp_path, field):
    with pytest.raises(harness.RequestError, match="unknown field"):
        harness.validate_request({"tool": "bash", "session_id": "test", "project_root": str(tmp_path), field: True})


@pytest.mark.parametrize("identity", ["invalid", "hmac-sha256:00000000:"+"a"*64])
def test_private_history_with_uncomparable_turn_identity_still_requires_review(tmp_path, identity):
    from semgate.judge import Decision
    from semgate.ledger import IncompleteWindow, Ledger
    gate = Gate("Develop project", provider="none", project_root=str(tmp_path), session_id="turn-identity")
    envelope = gate.envelope("echo fixture", user_message="Count files")
    ledger = Ledger(str(tmp_path/"ledger.jsonl"))
    ledger.record_judgment(envelope, Decision("allow", stage="semantic", envelope_digest="previous"), private=True)
    row = json.loads(ledger.path.read_text())
    row["privacy_turn_id"] = identity
    ledger.path.write_text(json.dumps(row)+"\n")
    with pytest.raises(IncompleteWindow, match="privacy-minimized"):
        ledger.session_on_task(envelope)


def test_worker_view_keeps_feedback_bound_to_the_actual_host_project(tmp_path):
    from semgate.feedback import FeedbackStore
    shared = tmp_path/"feedback.jsonl"
    configs = []
    for name in ("one", "two"):
        root = tmp_path/name
        root.mkdir()
        config, _ = configuration(root, "http://127.0.0.1:12345/report")
        enable(config)
        cfg = json.loads(config.read_text())
        cfg["feedback"] = {"enabled": True, "feedback_file": str(shared)}
        config.write_text(json.dumps(cfg))
        configs.append((root, config))
    FeedbackStore(str(shared)).record("deny", "bash", {"command": "echo fixture"},
        session_id="prepared-harness-task", project_root=str(configs[0][0]))
    for (root, config), expected in zip(configs, ("deny", "allow")):
        decision = harness.check_development("echo fixture", project=str(root), task="prepared-harness-task", config=config,
                                             execution_facts=VerifiedOfflineFacts("0.12.0", "a"*64))
        assert decision.decision == expected, decision.reason_code
