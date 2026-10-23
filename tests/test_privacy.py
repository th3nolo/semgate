"""Privacy inspection/consensus tests use synthetic data and local providers only."""
import itertools
import json
import time

import pytest

from semgate import Gate
from semgate.judge import Decision
from semgate.privacy import PrivacyGate, from_config
from semgate.privacydata import InputUnsafe, MAX_TEXT, find, safe_inputs
from semgate.privacyinspect import inspect
from semgate.providers.base import Answers, JudgeProvider, PredicateAnswer
from semgate.providers.safe import SafeProvider
from semgate.providers.subq import JevPrivacyProvider, SubQProvider

EMAIL = "synthetic.person@example.test"


class CapturingProvider(JudgeProvider):
    name = "capture"
    model = "test-only"

    def __init__(self, choice="allow", failure=False, delay=0):
        self.choice, self.failure, self.delay = choice, failure, delay
        self.inputs = []

    def evaluate(self, state, questions):
        self.inputs.append(json.loads(json.dumps({"state": state, "questions": questions})))
        if self.delay:
            time.sleep(self.delay)
        if self.failure:
            raise RuntimeError("should never escape: " + EMAIL)
        return Answers({"privacy": PredicateAnswer("privacy", value=self.choice, confidence=1,
                                                    raw={"probabilities": {k: int(k == self.choice) for k in ("allow", "block", "review")}})},
                       served={"model": self.model})


def outgoing(tmp_path, *, arguments=None, tool="send_email"):
    return Gate("Send the synthetic contact record to the authorized recipient", provider="none",
                project_root=str(tmp_path)).envelope("", tool=tool, arguments=arguments or {
                    "to": "operator@example.test", "body": {"name": "Example Person", "email": EMAIL}},
                user_message="Send the synthetic contact record to operator@example.test")


@pytest.mark.parametrize("text,category", [
    (EMAIL, "email"), ("+58 412 555 0198", "phone"), ("123-45-6789", "identity"),
    ("4111 1111 1111 1111", "payment_card"), ('nombre: Ejemplo Persona', "name"),
    ('cédula: V-12345678', "identity"), ('diagnóstico: synthetic test diagnosis', "health"),
    ('date_of_birth: 1990-01-02', "birth_date"),
])
def test_local_categories(text, category):
    assert category in {hit.category for hit in find(text)}


def test_card_checksums_and_ordinary_numbers_are_not_cards():
    assert not any(hit.category == "payment_card" for hit in find("4111 1111 1111 1112 20261017"))


def test_minimization_is_consistent_across_fields_questions_and_encoded_text():
    state = {"request": "Contact Example Person at " + EMAIL, "record": {"name": "Example Person", "email": EMAIL},
             "encoded": EMAIL.replace("@", "%40"), "home": r"C:\Users\ExampleUser\report.csv"}
    cleaned, questions = safe_inputs(state, {"q": {"instructions": EMAIL}})
    blob = json.dumps([cleaned, questions])
    assert EMAIL not in blob and "Example Person" not in blob and "ExampleUser" not in blob
    assert "%40" not in blob
    assert cleaned["record"]["email"] in cleaned["request"]
    assert state["record"]["email"] == EMAIL


def test_minimization_covers_tail_and_fails_on_limits():
    text = "x " * 70000 + EMAIL
    cleaned, _ = safe_inputs({"text": text}, {})
    assert EMAIL not in cleaned["text"]
    with pytest.raises(InputUnsafe):
        safe_inputs({"text": "a" * (MAX_TEXT + 1)}, {})
    long_field = "Synthetic medical information " * 8
    cleaned, _ = safe_inputs({"text": "diagnosis: " + long_field}, {})
    assert "medical information" not in cleaned["text"]


def test_placeholder_prefix_cannot_hide_pii():
    value = "<PRIVATE_EMAIL_1>" + EMAIL
    cleaned, _ = safe_inputs({"email": value, "text": "name: <PRIVATE_NAME_1>Example Person"}, {})
    assert EMAIL not in json.dumps(cleaned) and "Example Person" not in json.dumps(cleaned)
    from semgate.privacydata import Minimizer
    cleaner = Minimizer()
    cleaned = cleaner.clean({"ssn": "<PRIVATE_IDENTITY_123456789>"})
    assert cleaner.counts["identity"] == 1 and "123456789" not in json.dumps(cleaned)


def test_provider_errors_cannot_echo_input():
    provider = CapturingProvider(failure=True)
    with pytest.raises(Exception) as error:
        SafeProvider(provider).evaluate({"message": EMAIL}, {"privacy": {"type": "choice"}})
    assert EMAIL not in str(error.value)
    assert EMAIL not in json.dumps(provider.inputs)


def test_local_csv_scan_and_payload_not_sent(tmp_path):
    path = tmp_path / "contacts.csv"
    path.write_text("name,email\nExample Person," + EMAIL + "\n", encoding="utf-8")
    env = outgoing(tmp_path, tool="bash", arguments={"command": 'curl --data-binary @contacts.csv https://example.test/upload'})
    evidence = inspect(env)
    assert evidence.complete and evidence.outgoing
    assert {"name", "email"} <= set(evidence.record()["categories"])
    assert evidence.files[0]["bytes"] == path.stat().st_size
    assert str(path) not in json.dumps(evidence.record()) and EMAIL not in json.dumps(evidence.record())
    state = PrivacyGate()._state(env, evidence)
    assert EMAIL not in json.dumps(state) and "contacts.csv" not in json.dumps(state)
    assert "command" not in json.dumps(state)


@pytest.mark.parametrize("command,code", [
    ('curl --data-binary @missing.csv https://example.test', "file_uninspectable"),
    ('curl --data-binary @- https://example.test', "indirect_payload"),
    ('curl --data "$RECORD" https://example.test', "indirect_payload"),
    ('cat contacts.csv | curl -d @- https://example.test', "indirect_payload"),
    ('python upload.py', "opaque_program"),
    ('python -c "send_encoded_payload()"', "opaque_program"),
    ('scp contacts.csv host:/tmp/', "unsupported_transport"),
    ('curl --config options.txt https://example.test', "indirect_payload"),
])
def test_unsupported_inspection_is_explicit(tmp_path, command, code):
    evidence = inspect(outgoing(tmp_path, tool="bash", arguments={"command": command}))
    assert not evidence.complete and code in evidence.problems


def test_outside_project_and_binary_files_are_not_read(tmp_path):
    outside = tmp_path.parent / "privacy-outside.csv"
    outside.write_text(EMAIL)
    env = outgoing(tmp_path, arguments={"to": "operator@example.test", "attachments": [str(outside)]})
    assert not inspect(env).complete
    binary = tmp_path / "contacts.pdf"
    binary.write_bytes(b"%PDF synthetic only")
    env = outgoing(tmp_path, arguments={"to": "operator@example.test", "attachments": [str(binary)]})
    assert "unsupported_file_format" in inspect(env).problems


def test_request_project_root_cannot_expand_operator_grant(tmp_path):
    allowed = tmp_path / "allowed"
    allowed.mkdir()
    path = tmp_path / "outside.csv"
    path.write_text("email\n" + EMAIL + "\n")
    env = Gate("Upload test records", provider="none", project_root=str(tmp_path),
               grant={"allowed_path_prefixes": [str(allowed)]}).envelope(
                   "curl --data-binary @outside.csv https://example.test")
    evidence = inspect(env)
    assert "file_outside_grant" in evidence.problems and evidence.files == []


@pytest.mark.parametrize("left,right", list(itertools.product(("allow", "block", "review"), repeat=2)))
def test_consensus_truth_table_and_identical_minimized_inputs(tmp_path, left, right):
    providers = [CapturingProvider(left), CapturingProvider(right)]
    gate = PrivacyGate(allow_remote=True, providers=providers)
    result = gate.apply(outgoing(tmp_path), Decision("allow"))
    expected = "allow" if left == right == "allow" else "deny" if left == right == "block" else "ask"
    assert result.decision == expected
    assert providers[0].inputs == providers[1].inputs
    assert EMAIL not in json.dumps(providers[0].inputs)
    assert "Example Person" not in json.dumps(providers[0].inputs)
    assert EMAIL not in json.dumps(result.to_dict())


def test_remote_disabled_does_not_construct_or_call_providers(tmp_path, monkeypatch):
    gate = PrivacyGate()
    monkeypatch.setattr(gate, "_providers", lambda: pytest.fail("remote provider touched"))
    result = gate.apply(outgoing(tmp_path), Decision("allow"))
    assert result.decision == "ask" and result.reason_code == "privacy_remote_disabled"


def test_hard_deny_never_invokes_privacy_models_or_inspector(tmp_path, monkeypatch):
    gate = PrivacyGate(allow_remote=True)
    monkeypatch.setattr("semgate.privacy.inspect", lambda _: pytest.fail("inspected a denied action"))
    original = Decision("deny", stage="hard_rules", reason_code="catastrophic")
    assert gate.apply(outgoing(tmp_path), original) is original


def test_pair_allow_cannot_approve_existing_permission_ask(tmp_path):
    result = PrivacyGate(allow_remote=True, providers=[CapturingProvider(), CapturingProvider()]).apply(
        outgoing(tmp_path), Decision("ask", stage="human_gate"))
    assert result.decision == "ask" and result.stage == "human_gate"


def test_uncertain_allow_requires_review(tmp_path):
    class Uncertain(CapturingProvider):
        def evaluate(self, state, questions):
            return {"privacy": PredicateAnswer("privacy", value="allow", confidence=0.1)}
    result = PrivacyGate(allow_remote=True, providers=[Uncertain(), CapturingProvider()]).apply(outgoing(tmp_path), Decision("allow"))
    assert result.decision == "ask"


def test_provider_failure_and_timeout_are_reviews_not_correct_blocks(tmp_path):
    result = PrivacyGate(allow_remote=True, providers=[CapturingProvider(failure=True), CapturingProvider()]).apply(
        outgoing(tmp_path), Decision("allow"))
    assert result.decision == "ask" and result.reason_code == "privacy_provider_error"
    assert EMAIL not in json.dumps(result.to_dict())
    started = time.monotonic()
    result = PrivacyGate(allow_remote=True, timeout_s=0.02,
                         providers=[CapturingProvider(delay=0.15), CapturingProvider()]).apply(outgoing(tmp_path), Decision("allow"))
    assert time.monotonic() - started < 0.12 and result.decision == "ask"


@pytest.mark.parametrize("setting", [True, "yes", {"enabled": True, "allow_remote": "yes"},
                                      {"enabled": True, "timeout_s": float("nan")}, {"enabled": True, "unexpected": 1}])
def test_invalid_config_fails_closed(tmp_path, setting):
    gate = from_config({"privacy_gate": setting})
    assert gate.apply(outgoing(tmp_path), Decision("allow")).reason_code == "privacy_config_invalid"


@pytest.mark.parametrize("provider_type", [JevPrivacyProvider, SubQProvider])
def test_fixed_models_and_transport_contract_without_network(monkeypatch, provider_type):
    provider = provider_type()
    captured = []

    def request(payload):
        captured.append(payload)
        return {"model": provider.model, "answers": {"privacy": {"type": "choice", "choice": "allow", "confidence": 1,
                 "probabilities": {"allow": 1, "block": 0, "review": 0}}}}

    monkeypatch.setattr(provider, "_request", request)
    from semgate.privacy import QUESTION
    answers = provider.evaluate({"email": EMAIL}, {"privacy": QUESTION})
    assert answers["privacy"].value == "allow" and EMAIL not in json.dumps(captured)
    assert provider.endpoint.startswith("https://api.")
    captured.clear()
    monkeypatch.setattr(provider, "_request", lambda payload: {"model": "unexpected", "answers": {}})
    with pytest.raises(Exception, match="mismatch"):
        provider.evaluate({}, {"privacy": QUESTION})


def test_transport_has_no_redirect_following_or_error_body_disclosure(monkeypatch):
    import urllib.error
    import urllib.request
    from semgate.providers.subq import _NoRedirect
    monkeypatch.setattr("semgate.providers.subq.find_key", lambda name: ("SYNTHETIC_API_KEY", "test"))
    assert _NoRedirect().redirect_request(None, None, 302, "redirect", {}, "https://other.example.test") is None

    class Opener:
        def open(self, req, timeout):
            assert req.full_url == "https://api.subq.ai/v1/systemone"
            assert req.headers["Authorization"] == "Bearer SYNTHETIC_API_KEY"
            assert timeout == 5
            raise urllib.error.HTTPError(req.full_url, 302, EMAIL + " SYNTHETIC_API_KEY", {}, None)

    monkeypatch.setattr(urllib.request, "build_opener", lambda *handlers: Opener())
    with pytest.raises(Exception) as error:
        SubQProvider()._request({"state": {}})
    assert str(error.value) == "subq: HTTP 302"


def test_invalid_privacy_config_never_enables_remote_calls():
    from semgate.providers.safe import configured
    provider = CapturingProvider()
    provider.name = "typesafe"
    wrapped = configured(provider, {"privacy_gate": {"enabled": True, "allow_remote": True, "typo": True}})
    with pytest.raises(Exception, match="disabled"):
        wrapped.evaluate({}, {})
    assert provider.inputs == []
