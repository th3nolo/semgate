"""Encoded structure and per-task prepared profile integration regressions."""
import json
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import quote, quote_plus, unquote_plus, urlencode

import pytest

from semgate import Gate
from semgate.privacy import PrivacyGate
from semgate.privacyinspect import inspect
from semgate.providers.fake import FakeProvider
from semgate.providers.base import ProviderError
from semgate.providers.safe import SafeProvider
from semgate.sendharness import PreparedBroker
from test_harness_api import ALLOWING
from test_prepared_harness import configuration


class Capture:
    name = "fake"

    def __init__(self):
        self.states = []

    def evaluate(self, state, questions):
        self.states.append(state)
        return {}


CONTAINERS = [
    ("full_name,status\nSynthetic Review Person,ready\n", "Synthetic Review Person", "name"),
    (json.dumps({"date of birth": "2001-02-03"}), "2001-02-03", "birth_date"),
    ('full_name,status\n"Synthetic ""Review"" Person",ready\n', "Synthetic", "name"),
    ("full_name\tstatus\nSynthetic Review Person\tready\n", "Synthetic Review Person", "name"),
]


@pytest.mark.parametrize("raw,private,category", CONTAINERS)
@pytest.mark.parametrize("encoding", [quote, quote_plus])
@pytest.mark.parametrize("layers", [1, 2])
def test_encoded_containers_are_minimized_before_inner_provider(raw, private, category, encoding, layers):
    encoded = raw
    for _ in range(layers):
        encoded = encoding(encoded, safe="")
    provider = Capture()
    SafeProvider(provider).evaluate({"body": encoded}, {})
    cleaned = provider.states[0]["body"]
    for _ in range(layers + 1):
        cleaned = unquote_plus(cleaned)
    assert private not in cleaned
    assert "PRIVATE_" + category.upper() in cleaned


@pytest.mark.parametrize("raw,private,category", CONTAINERS)
def test_urlencoded_structured_body_cannot_clear_privacy_without_review(tmp_path, raw, private, category):
    gate = Gate("Send the approved diagnostic report", provider="none", project_root=str(tmp_path),
                grant={"allowed_domains": ["example.test"]}, privacy_gate=PrivacyGate())
    args = {"url": "https://example.test/report", "body": urlencode({"record": raw})}
    evidence = inspect(gate.envelope("", tool="http_request", arguments=args))
    assert evidence.cleaner.counts[category] >= 1
    assert gate.check("", tool="http_request", arguments=args).decision != "allow"


def test_benign_encoded_json_keeps_original_spelling():
    value = urlencode({"record": json.dumps({"status": "ready"})})
    provider = Capture()
    SafeProvider(provider).evaluate({"body": value}, {})
    assert provider.states[0]["body"] == value


def test_encoded_duplicate_json_cannot_reach_provider_as_a_partial_projection():
    provider = Capture()
    value = quote('{"name":"Synthetic First","name":"Synthetic Second"}', safe="")
    with pytest.raises(ProviderError):
        SafeProvider(provider).evaluate({"body": value}, {})
    assert not provider.states


@pytest.mark.parametrize("messages,active", [(("Other protected task",), ("code-review",)),
                                           (("Current protected task",), ("unknown-kind",))])
def test_fixed_prepared_profile_cannot_override_another_task_or_unknown_kind(messages, active):
    from semgate.profiles import SessionKinds, resolve
    gate = Gate("Current protected task", provider="none")
    resolved = SessionKinds({}, active, "classified", messages)
    with pytest.raises(ValueError, match="protected task"):
        resolve(gate.grant, {"enabled": True}, session_id="synthetic-task",
                messages=["Current protected task"], provider=None, resolved=resolved)


@pytest.mark.parametrize("unrelated", [0, 1, 9])
@pytest.mark.parametrize("alternate", [False, True])
@pytest.mark.parametrize("concurrent", [False, True])
def test_prepared_profiles_use_current_payload_and_one_consistent_resolution(tmp_path, monkeypatch, unrelated, alternate, concurrent):
    config, state = configuration(tmp_path, "http://127.0.0.1:12345/report")
    cfg = json.loads(config.read_text())
    cfg.update(provider="fake", fake_answers=ALLOWING, trust={"file": str(state / "trust.jsonl")},
               profiles={"enabled": True})
    route = cfg["prepared_sends"]["routes"]["report"]
    for index in range(unrelated):
        path = tmp_path / ("future-" + str(index) + ".csv")
        if unrelated > 1:
            path.write_bytes(b"status\nready\n")
        cfg["prepared_sends"]["routes"]["future-" + str(index)] = {**route, "source_file": str(path)}
    config.write_text(json.dumps(cfg))
    original, calls = FakeProvider.evaluate, []

    def evaluate(self, model_state, questions):
        if "code-review" in questions:
            calls.append(model_state)
            kind = "software-development" if alternate and len(calls) > 1 else "code-review"
            return original(FakeProvider({key: float(key == kind) for key in questions}), model_state, questions)
        return original(self, model_state, questions)

    monkeypatch.setattr(FakeProvider, "evaluate", evaluate)
    broker = PreparedBroker(str(config))
    try:
        if concurrent:
            with ThreadPoolExecutor(max_workers=2) as executor:
                first, second = list(executor.map(lambda _: broker.prepare("report"), range(2)))
        else:
            first, second = broker.prepare("report"), broker.prepare("report")
        assert (first["disposition"], first["reason_code"]) == ("needs_consent", "privacy_consent_required"), first
        assert second["disposition"] == "needs_consent", second
        assert len(calls) == 1
    finally:
        broker.close()
