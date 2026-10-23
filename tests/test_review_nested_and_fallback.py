"""Regression boundaries for unsupported uploads, nested PII, and private fallback."""
from copy import deepcopy
import json

import pytest

from semgate import Gate
from semgate.ledger import IncompleteWindow
from semgate.privacy import PrivacyGate
from semgate.privacydata import Minimizer
from semgate.privacyinspect import inspect
from semgate.providers.base import ProviderError
from semgate.providers.fake import FakeProvider
from semgate.providers.safe import for_envelope


@pytest.mark.parametrize("command", [
    "(cd src && curl --data-binary @payload.csv https://example.test/report)",
    "( cd src && curl --data-binary @payload.csv https://example.test/report )",
    "if cd src; then curl --data-binary @payload.csv https://example.test/report; fi",
    "env -C src curl --data-binary @payload.csv https://example.test/report",
    "env -Csrc curl --data-binary @payload.csv https://example.test/report",
    "env --chdir=src curl --data-binary @payload.csv https://example.test/report",
    "sudo -D src curl --data-binary @payload.csv https://example.test/report",
    "sudo -Dsrc curl --data-binary @payload.csv https://example.test/report",
    "sudo --chdir=src curl --data-binary @payload.csv https://example.test/report",
    "source change-directory.sh && curl --data-binary @payload.csv https://example.test/report",
    "./change-directory.sh && curl --data-binary @payload.csv https://example.test/report",
    "sh -c 'cd src && curl --data-binary @payload.csv https://example.test/report'",
])
def test_unsupported_attachment_context_never_claims_complete_or_calls_a_model(tmp_path, command):
    (tmp_path / "src").mkdir()
    (tmp_path / "payload.csv").write_text("status\nready\n")
    (tmp_path / "src" / "payload.csv").write_text("name\nSynthetic Context Person\n")
    gate = Gate("Send an approved diagnostic artifact", provider="none", project_root=str(tmp_path),
                grant={"allowed_domains": ["example.test"]}, privacy_gate=PrivacyGate())
    envelope = gate.envelope(command)
    evidence = inspect(envelope)
    assert not evidence.complete
    assert not evidence.minimization_complete
    assert gate.check(command).decision != "allow"
    with pytest.raises(ProviderError):
        for_envelope(FakeProvider(), envelope, offline_shell=True).evaluate({}, {})


@pytest.mark.parametrize("array", [False, True])
def test_nested_name_context_reaches_local_write_permission_minimization(tmp_path, array):
    first, last = "Synthetic Amelie", "Exampleperson"
    name = {"given": [first] if array else first, "family": last}
    payload = {"name": [name] if array else name}
    calls = []

    class Capture(FakeProvider):
        def evaluate(self, state, questions):
            calls.append(deepcopy(state))
            return super().evaluate(state, questions)

    gate = Gate("Create the local record for " + first + " " + last, provider=Capture(),
                project_root=str(tmp_path), privacy_gate=PrivacyGate(allow_remote=True, require_prepared=True))
    arguments = {"path": str(tmp_path / "record.json"), "content": json.dumps(payload)}
    envelope = gate.envelope("", tool="write", arguments=arguments)
    evidence = inspect(envelope)
    gate.check("", tool="write", arguments=arguments)
    assert evidence.complete and evidence.cleaner.counts.get("name")
    assert calls
    assert first not in json.dumps(calls) and last not in json.dumps(calls)
    assert "PRIVATE_NAME" in json.dumps(calls)


def test_nested_sensitive_label_retains_child_secret_classification():
    first = "Synthetic Nested Person"
    key = "aB3dE5gH7jK9mN2pQ4sT6vW8xY0zA1bC"
    cleaner = Minimizer()
    minimized = cleaner.clean({"name": {"given": first, "api_key": key}})
    assert first not in json.dumps(minimized) and key not in json.dumps(minimized)
    assert cleaner.counts["name"] and cleaner.counts["secret"]


@pytest.mark.parametrize("failure", ["control_collision", "structure_limit"])
def test_private_fallback_omits_known_sensitive_session_and_keeps_history_incomplete(tmp_path, failure):
    person = "SyntheticRowanPerson"
    payload = {"name": person, "full_name": "semantic"} if failure == "control_collision" else {
        "name": person, "rows": ["ordinary"] * 8300}
    gate = Gate("Create a synthetic local record", provider="none", project_root=str(tmp_path),
                session_id=person, ledger=tmp_path / "state" / "ledger.jsonl", privacy_gate=PrivacyGate())
    arguments = {"path": str(tmp_path / "record.json"), "content": json.dumps(payload)}
    envelope = gate.envelope("", tool="write", arguments=arguments)
    answer = gate.check("", tool="write", arguments=arguments)
    record, = list(gate.ledger.records())
    assert answer.decision == "ask"
    assert record["privacy_window_incomplete"]
    assert person not in json.dumps(record)
    assert record["envelope"]["environment"]["session_id"] == ""
    assert record["privacy_session_unattributed"]
    with pytest.raises(IncompleteWindow):
        gate.ledger.session_on_task(envelope)
