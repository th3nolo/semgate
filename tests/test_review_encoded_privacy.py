"""Supported encodings must not reveal detected data to either provider path."""
import csv
import io
import json

import pytest

from semgate import Gate
from semgate.privacy import PrivacyGate
from semgate.privacydata import Minimizer, safe_inputs
from semgate.privacyinspect import inspect
from semgate.providers.safe import SafeProvider
from test_privacy import CapturingProvider
from test_review_structured_inputs import Recording

CASES = [
    ("email", "synthetic@example.test", r'{"\u0065mail":"synthetic\u0040example\u002etest"}'),
    ("name", "Synthetic Person", r'{"\u006eame":"\u0053ynthetic \u0050erson"}'),
    ("api_key", "aB3dE5gH7jK9mN2pQ4sT6vW8xY0zA1bC", r'{"\u0061pi_key":"\u0061B3dE5gH7jK9mN2pQ4sT6vW8xY0zA1bC"}'),
]


@pytest.mark.parametrize("field,raw,encoded", CASES)
@pytest.mark.parametrize("container", ["json", "nested", "prefixed"])
def test_safe_provider_removes_decodable_sensitive_values(field, raw, encoded, container):
    seed = Minimizer()
    seed.clean({field: raw})
    value = json.dumps({"record": encoded}) if container == "nested" else (
        "Here is the record: " + encoded if container == "prefixed" else encoded)
    provider = Recording()
    SafeProvider(provider, seed=seed).evaluate({"content": value}, {})
    cleaned = provider.states[0]["content"]
    if container == "nested":
        cleaned = json.loads(cleaned)["record"]
    elif container == "prefixed":
        cleaned = cleaned.split(": ", 1)[1]
    assert json.loads(cleaned)[field] != raw


@pytest.mark.parametrize("field,raw,encoded", CASES)
def test_actual_local_write_provider_input_cannot_decode_original_json(tmp_path, field, raw, encoded):
    provider = Recording()
    gate = Gate("Create a synthetic fixture", provider=provider, project_root=str(tmp_path),
                privacy_gate=PrivacyGate(allow_remote=True))
    gate.check("", tool="write", arguments={"path": str(tmp_path / "record.json"), "content": encoded},
               user_message="Create a synthetic fixture")
    assert len(provider.states) == 1
    command = provider.states[0]["command"]
    arguments = json.loads(command.removeprefix("write "))
    assert json.loads(arguments["content"])[field] != raw


@pytest.mark.parametrize("field,raw,encoded", CASES)
def test_both_privacy_providers_receive_minimized_prefixed_json(tmp_path, field, raw, encoded):
    pair = [CapturingProvider(), CapturingProvider()]
    gate = Gate("Send the authorized synthetic record", provider="none", project_root=str(tmp_path),
                grant={"allowed_domains": ["example.test"]},
                privacy_gate=PrivacyGate(allow_remote=True, providers=pair))
    gate.check("", tool="http_request", arguments={"url": "https://example.test/report", "json": {field: raw}},
               user_message="Here is the record: " + encoded)
    assert pair[0].inputs and pair[0].inputs == pair[1].inputs
    request = pair[0].inputs[0]["state"]["user_requests"][0].split(": ", 1)[1]
    assert json.loads(request)[field] != raw


@pytest.mark.parametrize("delimiter", [",", "\t"])
def test_quoted_table_projection_keeps_cells_but_removes_complete_name(delimiter):
    raw = 'Synthetic "Person"\nSecond line'
    source = io.StringIO(newline="")
    writer = csv.writer(source, delimiter=delimiter, lineterminator="\n")
    writer.writerow(["name", "status"])
    writer.writerow([raw, "ready"])
    cleaned, _ = safe_inputs({"content": source.getvalue()}, {})
    row, = list(csv.DictReader(io.StringIO(cleaned["content"]), delimiter=delimiter))
    assert row["name"] != raw and "PRIVATE_NAME" in row["name"]
    assert row["status"] == "ready"


def test_json_in_another_table_column_cannot_hide_quoted_name():
    content = 'name,info\n"Synthetic ""Person""",{"note":"ordinary"}\n'
    cleaned, _ = safe_inputs({"content": content}, {})
    row, = list(csv.DictReader(io.StringIO(cleaned["content"])))
    assert "PRIVATE_NAME" in row["name"]
    assert json.loads(row["info"]) == {"note": "ordinary"}


def test_multiple_json_fragments_and_jsonl_are_all_sanitized():
    for separator in (" followed by ", "\n"):
        value = '{"name":"Synthetic First"}' + separator + '{"name":"Synthetic Second"}'
        cleaned, _ = safe_inputs({"content": value}, {})
        assert "Synthetic First" not in cleaned["content"] and "Synthetic Second" not in cleaned["content"]
        assert cleaned["content"].count("PRIVATE_NAME") == 2


@pytest.mark.parametrize("option", ["--json", "--data", "--data-binary", "--data-raw", "-d"])
def test_inline_escaped_json_has_same_privacy_requirement_as_literal(tmp_path, option):
    gate = Gate("Send authorized synthetic records", provider="none", project_root=str(tmp_path),
                grant={"allowed_domains": ["example.test"]}, privacy_gate=PrivacyGate())
    encoded = CASES[0][2]
    command = "curl " + option + " '" + encoded + "' https://example.test/report"
    evidence = inspect(gate.envelope(command))
    assert evidence.complete and evidence.cleaner.counts["email"] == 1
    decision = gate.check(command)
    assert (decision.decision, decision.reason_code) == ("ask", "privacy_remote_disabled")


@pytest.mark.parametrize("body", ['{"name":"first","name":"second"}', '{"name":'])
def test_invalid_inline_json_withholds_provider_calls(tmp_path, body):
    provider = Recording()
    gate = Gate("Send synthetic records", provider=provider, project_root=str(tmp_path),
                grant={"allowed_domains": ["example.test"]}, privacy_gate=PrivacyGate(allow_remote=True))
    envelope = gate.envelope("curl --json '" + body + "' https://example.test/report")
    evidence = inspect(envelope)
    assert not evidence.complete and not evidence.minimization_complete
    assert gate.check(envelope.action.arguments["command"]).decision != "allow"
    assert provider.states == []


def test_decoded_spelling_views_do_not_rewrite_benign_content():
    value = r'{"text":"hello\\world", "year":2021}'
    cleaned, _ = safe_inputs({"content": value}, {})
    assert cleaned["content"] == value


def test_surrogate_pairs_and_mixed_encoding_in_seeded_context():
    from urllib.parse import quote, unquote
    raw = "Synthetic \U0001d11e Person"
    seed = Minimizer()
    seed.clean({"name": raw})
    spelling = json.dumps(raw, ensure_ascii=True)[1:-1]
    cleaned, _ = safe_inputs({"context": "Known record: " + spelling}, {}, seed=seed)
    assert "PRIVATE_NAME" in cleaned["context"] and "\\ud834" not in cleaned["context"]
    encoded = quote(json.dumps({"name": raw}, ensure_ascii=True), safe="")
    cleaned, _ = safe_inputs({"context": encoded}, {}, seed=seed)
    assert json.loads(unquote(cleaned["context"]))["name"] != raw


def test_excessive_encoding_withholds_provider_calls():
    from urllib.parse import quote
    from semgate.providers.base import ProviderError
    value = "synthetic@example.test"
    for _ in range(25):
        value = quote(value, safe="")
    provider = Recording()
    with pytest.raises(ProviderError):
        SafeProvider(provider).evaluate({"content": value}, {})
    assert provider.states == []
