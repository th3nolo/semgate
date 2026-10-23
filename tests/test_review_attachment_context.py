"""Privacy inspection must retain attachment and form context before any model call."""
from copy import deepcopy
import json

import pytest

from semgate import Gate, harness
from semgate.devworker import VerifiedOfflineFacts
from semgate.judge import judge
from semgate.privacy import PrivacyGate
from semgate.privacyinspect import inspect
from semgate.providers.base import ProviderError
from semgate.providers.fake import FakeProvider
from semgate.providers.safe import for_envelope
from semgate.providers.subq import JevPrivacyProvider, SubQProvider
from semgate.workerpaths import WorkerPaths
from test_prepared_harness import configuration


@pytest.mark.parametrize("prefix", ["cd src &&", "cd src;", "pushd src &&", "Set-Location src;"])
def test_directory_change_cannot_substitute_a_benign_same_named_payload(tmp_path, prefix):
    (tmp_path / "src").mkdir()
    (tmp_path / "payload.csv").write_text("status\nready\n")
    (tmp_path / "src" / "payload.csv").write_text("name,email\nSynthetic Directory Person,synthetic@example.test\n")
    gate = Gate("Send the approved diagnostic artifact", provider="none", project_root=str(tmp_path),
                grant={"allowed_domains": ["example.test"]}, privacy_gate=PrivacyGate())
    command = prefix + " curl --data-binary @payload.csv https://example.test/report"
    evidence = inspect(gate.envelope(command))
    assert not evidence.complete
    assert not evidence.minimization_complete
    assert gate.check(command).decision != "allow"
    with pytest.raises(ProviderError):
        for_envelope(FakeProvider(), gate.envelope(command), offline_shell=True).evaluate({}, {})


@pytest.mark.parametrize("spelling", ["record.csv", "/workspace/record.csv"])
def test_development_profile_call_uses_the_verified_worker_attachment(tmp_path, monkeypatch, spelling):
    config, state = configuration(tmp_path, "https://example.test/report")
    person = "Synthetic Mapped Person"
    (tmp_path / "record.csv").write_text("full_name,status\n" + person + ",ready\n")
    cfg = json.loads(config.read_text())
    cfg.update(provider="fake", profiles={"enabled": True, "state_file": str(state / "profiles.json")},
               trust={"file": str(state / "trust.jsonl")})
    cfg["privacy_gate"]["allow_remote"] = True
    cfg["prepared_sends"]["task_context"]["request"] = "Inspect the local record for " + person
    config.write_text(json.dumps(cfg))
    calls = []
    original = FakeProvider.evaluate

    def capture(self, model_state, questions):
        calls.append(deepcopy(model_state))
        return original(self, model_state, questions)

    monkeypatch.setattr(FakeProvider, "evaluate", capture)
    harness.check_development("curl --upload-file " + spelling + " https://example.test/report",
        project=str(tmp_path), task="prepared-harness-task", config=config,
        execution_facts=VerifiedOfflineFacts("0.12.0", "a" * 64))
    assert calls, "verified mapping should retain the minimized auxiliary classification"
    assert person not in json.dumps(calls)
    assert "PRIVATE_NAME" in json.dumps(calls)


@pytest.mark.parametrize("reference", ["missing.csv", "/workspace/missing.csv", "private.bin", "$PAYLOAD.csv"])
def test_uninspectable_known_attachment_withholds_offline_auxiliary_calls(tmp_path, reference):
    (tmp_path / "private.bin").write_bytes(b"synthetic binary placeholder")
    gate = Gate("Inspect a local record", provider="none", project_root=str(tmp_path))
    envelope = gate.envelope("curl --upload-file '" + reference + "' https://example.test/report")
    with pytest.raises(ProviderError):
        for_envelope(FakeProvider(), envelope, offline_shell=True).evaluate({}, {})


def test_permission_judge_also_seeds_from_the_worker_view(tmp_path):
    person = "Synthetic Judge Person"
    (tmp_path / "record.csv").write_text("full_name\n" + person + "\n")
    calls = []

    class Capture(FakeProvider):
        def evaluate(self, state, questions):
            calls.append(deepcopy(state))
            return super().evaluate(state, questions)

    gate = Gate("Check the local record for " + person, provider="none", project_root=str(tmp_path),
                privacy_gate=PrivacyGate(allow_remote=True))
    authority = gate.envelope("curl --upload-file /workspace/record.csv https://example.test/report",
                              user_message="Check the local record for " + person)
    paths = WorkerPaths(str(tmp_path))
    answer = judge(paths.envelope(authority), gate.policy, provider=Capture(), privacy_gate=gate.privacy_gate,
                   trusted_offline_shell=True, trusted_execution_facts=VerifiedOfflineFacts("0.12.0", "a" * 64),
                   execution_paths=paths, authority_envelope=authority)
    assert calls
    assert person not in json.dumps(calls)
    assert answer.evidence["privacy"]["categories"]["name"]


@pytest.mark.parametrize("fragment", [
    "--data 'full_name=Synthetic+Rowan+Person'",
    "--data=full_name=Synthetic+Rowan+Person",
    "-dfull_name=Synthetic+Rowan+Person",
    "--data-ascii 'full_name=Synthetic+Rowan+Person'",
    "--data-binary 'full_name=Synthetic+Rowan+Person'",
    "--data-raw 'full_name=Synthetic+Rowan+Person'",
    "--data-urlencode 'full_name=Synthetic Rowan Person'",
    "--data 'full_name=Synthetic%20Rowan%20Person'",
    "--data 'full_name=Synthetic+Rowan+Person&full_name=Second+Synthetic+Person'",
    "--data 'full_name=Synthetic%2BRowan%2BPerson'",
])
def test_real_privacy_adapters_never_receive_the_decoded_form_name(tmp_path, fragment):
    person = "Synthetic+Rowan+Person" if "%2B" in fragment else "Synthetic Rowan Person"
    captured = []
    pair = [JevPrivacyProvider(), SubQProvider()]
    for adapter in pair:
        def request(payload, adapter=adapter):
            captured.append(deepcopy(payload))
            return {"model": adapter.model, "answers": {"privacy": {"type": "choice", "choice": "allow",
                "confidence": 1, "probabilities": {"allow": 1, "block": 0, "review": 0}}}}
        adapter._request = request
    gate = Gate("Send the approved record for " + person, provider="none", project_root=str(tmp_path),
        grant={"allowed_domains": ["example.test"]}, privacy_gate=PrivacyGate(allow_remote=True, providers=pair))
    command = "curl " + fragment + " https://example.test/report"
    gate.check(command, user_message="Send the approved record for " + person)
    assert len(captured) == 2
    assert all(person not in json.dumps(payload) for payload in captured)


def test_decoded_query_name_is_learned_before_context_minimization(tmp_path):
    gate = Gate("Send a report", provider="none", project_root=str(tmp_path), privacy_gate=PrivacyGate())
    evidence = inspect(gate.envelope("curl 'https://example.test/report?full_name=Synthetic+Query+Person'"))
    assert evidence.complete
    assert "Synthetic Query Person" in evidence.cleaner.values


def test_literal_plus_in_urlencoded_curl_input_is_preserved_as_a_value(tmp_path):
    gate = Gate("Send a report", provider="none", project_root=str(tmp_path))
    evidence = inspect(gate.envelope("curl --data-urlencode 'full_name=Synthetic+Literal+Person' https://example.test/report"))
    assert evidence.complete
    assert "Synthetic+Literal+Person" in evidence.cleaner.values
    assert "Synthetic Literal Person" not in evidence.cleaner.values


def test_benign_plus_and_ordinary_offline_development_keep_their_meaning(tmp_path):
    gate = Gate("Run local tests for C++", provider="none", project_root=str(tmp_path))
    envelope = gate.envelope("cd src && python -m pytest")
    provider = for_envelope(FakeProvider(), envelope, offline_shell=True)
    assert provider.allow_calls
    from semgate.privacydata import safe_inputs
    state = {"command": "echo C++", "note": "C++ programming"}
    assert safe_inputs(state, {})[0] == state
