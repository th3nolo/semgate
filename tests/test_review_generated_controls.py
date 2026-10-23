"""Trusted metadata must not discover PII; actual input collisions stay closed."""
from dataclasses import replace
import json

import pytest

from conftest import make_envelope
from semgate.feedback import blocked_candidates
from semgate.judge import Decision, judge
from semgate.ledger import Ledger
from semgate.privacy import PrivacyGate
from semgate.privacydata import find
from semgate.privacyinspect import inspect

COMMAND = "printf 'synthetic.person@example.test\\n' > fixture.txt"
P = 0.4111111111111111


def envelope(nonce=0):
    return replace(make_envelope("bash", {"command": COMMAND}),
                   user_message="Synthetic metadata probe " + str(nonce))


def test_genuine_generated_digest_cannot_erase_private_feedback(tmp_path, policy):
    env = envelope(257)
    assert env.digest() == "9bf73fb47ad8f20d59593341d81ed8f10a039965e633cbcfe5f7613770960105"
    assert any(hit.category == "payment_card" for hit in find(env.digest()))
    ledger = Ledger(str(tmp_path / "state" / "ledger.jsonl"))
    result = judge(env, policy, provider=None, ledger=ledger, privacy_gate=PrivacyGate())
    assert result.decision == "ask"
    row = json.loads(ledger.path.read_text())
    assert not row.get("privacy_window_incomplete")
    assert row["judgment_id"] == row["decision"]["envelope_digest"] == env.digest()
    assert "synthetic.person@example.test" not in ledger.path.read_text()
    assert len(blocked_candidates(str(ledger.path), COMMAND, project_dir="/home/me/proj/subdirectory")) == 1


@pytest.mark.parametrize("field,value", [("p", P), ("mean", P), ("confidence", P), ("value", P),
                                        ("probabilities", {"allow": P, "review": 1 - P})])
def test_valid_typed_vote_metadata_is_not_reclassified_as_a_card(tmp_path, field, value):
    env = envelope()
    assert not any(hit.category == "payment_card" for hit in find(env.digest()))
    ledger = Ledger(str(tmp_path / "state" / "ledger.jsonl"))
    decision = Decision("ask", stage="semantic", reason_code="drift_review", envelope_digest=env.digest(),
                        evaluated_at=env.evaluated_at, predicate_votes=[{"predicate": "on_task", field: value}])
    ledger.record_judgment(env, decision, private=True)
    row = json.loads(ledger.path.read_text())
    assert not row.get("privacy_window_incomplete")
    assert row["decision"]["predicate_votes"][0][field] == value
    assert len(blocked_candidates(str(ledger.path), COMMAND, project_dir="/home/me/proj")) == 1
    if field == "p":
        assert ledger.session_on_task(env) == [P]


def test_real_private_value_equal_to_typed_control_still_marks_history_incomplete(tmp_path):
    env = make_envelope("write", {"path": "record.json", "content": json.dumps({"name": str(P)})})
    ledger = Ledger(str(tmp_path / "state" / "ledger.jsonl"))
    decision = Decision("ask", stage="semantic", envelope_digest=env.digest(), evaluated_at=env.evaluated_at,
                        predicate_votes=[{"predicate": "on_task", "p": P}])
    ledger.record_judgment(env, decision, private=True, seed=inspect(env).cleaner)
    row = json.loads(ledger.path.read_text())
    assert row["privacy_window_incomplete"] is True
    assert str(P) not in ledger.path.read_text()


def test_full_precision_latency_is_numeric_metadata(tmp_path):
    env = envelope()
    ledger = Ledger(str(tmp_path / "state" / "ledger.jsonl"))
    decision = Decision("ask", stage="semantic", envelope_digest=env.digest(), evaluated_at=env.evaluated_at,
                        latency_ms=P)
    ledger.record_judgment(env, decision, private=True)
    row = json.loads(ledger.path.read_text())
    assert not row.get("privacy_window_incomplete")
    assert row["decision"]["latency_ms"] == P


@pytest.mark.parametrize("field,value", [("envelope_digest", "a4111111111111111" + "b" * 47),
                                        ("policy_version", "synthetic.version@example.test")])
def test_unverified_identifier_or_private_control_text_is_not_exempted(tmp_path, field, value):
    env = envelope()
    ledger = Ledger(str(tmp_path / "state" / "ledger.jsonl"))
    decision = Decision("ask", stage="semantic", envelope_digest=env.digest(), evaluated_at=env.evaluated_at)
    decision = replace(decision, **{field: value})
    ledger.record_judgment(env, decision, private=True)
    assert json.loads(ledger.path.read_text())["privacy_window_incomplete"] is True


def test_card_detection_in_ordinary_data_remains_intact():
    assert any(hit.category == "payment_card" for hit in find("card: 4111111111111111"))
