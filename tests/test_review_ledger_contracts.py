"""Private history keeps enforcement controls and feedback joins trustworthy."""
import json
from pathlib import Path

import pytest

from semgate import Gate, calibration
from semgate.feedback import FeedbackStore, blocked_candidates
from semgate.judge import Decision
from semgate.ledger import IncompleteWindow, Ledger
from semgate.privacy import PrivacyGate
from semgate.privacyinspect import inspect
from semgate.sendharness import PreparedBroker
from test_development_harness import enable
from test_prepared_harness import configuration


@pytest.mark.parametrize("name", ["semantic", "judgment", "on_task", "predicate", "p", "0.1"])
def test_minimized_control_collision_never_silently_discards_adverse_votes(tmp_path, name):
    gate = Gate("Develop this project", provider="none", project_root=str(tmp_path), session_id="controls")
    ledger = Ledger(str(tmp_path/"state"/"ledger.jsonl"))
    env = gate.envelope("", tool="write", arguments={"path": "record.json", "content": json.dumps({"name": name})},
                        user_message="Develop this project")
    decision = Decision("ask", stage="semantic", reason_code="drift_review", envelope_digest=env.digest(),
                        evaluated_at="2026-10-22T12:00:00Z", predicate_votes=[{"predicate": "on_task", "p": 0.1}])
    ledger.record_judgment(env, decision, private=True, seed=inspect(env).cleaner)
    # Retaining the vote or explicitly marking history incomplete is safe;
    # an empty apparently-complete window would suppress the drift review.
    try:
        history = ledger.session_on_task(env)
    except IncompleteWindow:
        pass
    else:
        assert history == [0.1]
    row = json.loads(ledger.path.read_text())
    assert row["record_type"] == "judgment"
    assert name not in row.get("envelope", {}).get("action", {}).get("arguments", {}).get("content", "")


def _private_feedback_case(tmp_path):
    command = "printf 'synthetic.person@example.test\\n' > fixture.txt"
    ledger = tmp_path/"state"/"ledger.jsonl"
    gate = Gate("Develop the project", provider="none", project_root=str(tmp_path), session_id="calibration",
                ledger=ledger, privacy_gate=PrivacyGate())
    env = gate.envelope(command)
    gate.ledger.record_judgment(env, Decision("ask", stage="semantic", reason_code="uncertain_fit_review",
        envelope_digest=env.digest(), evaluated_at="2026-10-22T12:00:00Z",
        predicate_votes=[{"predicate": "on_task", "p": 0.2}]), private=True)
    candidate, = blocked_candidates(str(ledger), command, project_dir=str(tmp_path))
    feedback = FeedbackStore(str(tmp_path/"state"/"feedback.jsonl"))
    return ledger, feedback, command, candidate


@pytest.mark.parametrize("answer", ["allow", "deny"])
def test_private_calibration_uses_exact_judgment_and_occurrence_binding(tmp_path, answer):
    ledger, store, command, candidate = _private_feedback_case(tmp_path)
    store.record(answer, candidate["tool"], {"command": command}, session_id=candidate["session_id"],
                 project_root=candidate["project_root"],
                 bound_to={"judgment_id": candidate["judgment_id"], "asked_at": candidate["ts"]})
    before = {p.name: p.read_bytes() for p in store.path.parent.iterdir() if p.is_file()}
    samples = calibration.collect(str(ledger), feedback_path=str(store.path))
    assert len(samples) == 1
    assert samples[0]["approved"] is (answer == "allow")
    assert samples[0]["source"] == "feedback" and samples[0]["features"]["on_task"] == 0.2
    assert before == {p.name: p.read_bytes() for p in store.path.parent.iterdir() if p.is_file()}
    assert "synthetic.person@example.test" not in ledger.read_text()


@pytest.mark.parametrize("field,value", [("judgment_id", "different"), ("asked_at", "2026-10-22T11:00:00Z")])
def test_calibration_does_not_rebind_feedback_to_another_judgment(tmp_path, field, value):
    from test_calibration import judgment, write
    record = judgment(0, 0.2, command="make a")
    ledger = tmp_path/"ledger.jsonl"
    write(ledger, [record])
    binding = {"judgment_id": record["judgment_id"], "asked_at": record["ts"]}
    binding[field] = value
    store = FeedbackStore(str(tmp_path/"feedback.jsonl"))
    store.record("deny", "bash", {"command": "make a"}, bound_to=binding)
    assert calibration.collect(str(ledger), feedback_path=str(store.path)) == []


@pytest.mark.parametrize("field", ["ledger", "trust", "grant", "consent", "client", "config"])
def test_worker_rejects_operator_authority_inside_readable_git_tree(tmp_path, field):
    config, state = configuration(tmp_path, "http://127.0.0.1:12345/report")
    enable(config)
    cfg = json.loads(config.read_text())
    hidden = tmp_path/".git"/".semgate"
    hidden.mkdir(parents=True)
    if field == "ledger":
        cfg["ledger_file"] = str(hidden/"ledger.jsonl")
    elif field == "trust":
        cfg["trust"] = {"file": str(hidden/"trust.jsonl")}
    elif field == "grant":
        target = hidden/"grant.json"
        target.write_bytes((state/"grant.json").read_bytes())
        cfg["grant_file"] = str(target)
    elif field in {"consent", "client"}:
        cfg["prepared_sends"]["consent_store" if field == "consent" else "client_file"] = str(hidden/(field+".json"))
    else:
        config = hidden/"semgate.json"
    config.write_text(json.dumps(cfg))
    with pytest.raises(ValueError, match="operator state"):
        PreparedBroker(str(config))
