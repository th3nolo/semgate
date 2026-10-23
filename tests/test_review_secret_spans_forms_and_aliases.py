"""Whole detector spans, multipart literals, and known private inode aliases."""
import json
import os
from pathlib import Path
import textwrap

import pytest

from semgate import ConsentStore, Gate, PreparedSender
from semgate import devworker, secretfinder
from semgate.privacy import PrivacyGate
from semgate.privacydata import InputUnsafe, Minimizer, find, safe_inputs
from semgate.privacyinspect import inspect
from semgate.providers.base import ProviderError
from semgate.providers.safe import SafeProvider, for_envelope
from semgate.trustauth import Auth
from test_review_structured_inputs import Recording


def pem(width=64, body="QUJD" * 40):
    # Invalid synthetic data, not an actual cryptographic key.
    return "-----BEGIN PRIVATE KEY-----\n" + "\n".join(textwrap.wrap(body, width)) + "\n-----END PRIVATE KEY-----\n"


@pytest.mark.parametrize("width", [40, 64])
@pytest.mark.parametrize("prefix", ["", "ordinary " * 2200], ids=["plain", "after-window"])
def test_wrapped_private_key_uses_original_detector_spans(width, prefix):
    source = prefix + pem(width)
    assert any(hit.type == "PEM private key" for hit in secretfinder.find(source))
    assert any(hit.category == "secret" for hit in find(source))
    clean, _ = safe_inputs({"trace": source}, {})
    assert "BEGIN PRIVATE KEY" not in clean["trace"]
    assert "QUJD" * 10 not in clean["trace"]


def test_repeated_wrapped_key_with_different_formatting_is_removed_everywhere():
    source = pem(40) + "between fixtures\n" + pem(64)
    clean, _ = safe_inputs({"trace": source}, {})
    assert "BEGIN PRIVATE KEY" not in clean["trace"]
    assert "QUJD" * 10 not in clean["trace"]


def test_partial_pem_within_the_detector_bound_is_still_minimized():
    source = pem().split("-----END", 1)[0]
    clean, _ = safe_inputs({"trace": source}, {})
    assert "BEGIN PRIVATE KEY" not in clean["trace"]
    assert "QUJD" * 10 not in clean["trace"]


@pytest.mark.parametrize("case", ["body", "blocks"])
def test_exceeded_original_pem_bounds_withhold_provider_calls(case):
    source = pem(body="QUJD" * (secretfinder.PEM_MAX_BODY // 4 + 100)) if case == "body" else (
        pem() * (secretfinder.PEM_MAX_BLOCKS + 1))
    raw = Recording()
    with pytest.raises(ProviderError):
        SafeProvider(raw).evaluate({"trace": source}, {})
    assert not raw.states


def test_all_pem_occurrences_at_the_existing_block_bound_are_minimized():
    source = pem() * secretfinder.PEM_MAX_BLOCKS
    clean, _ = safe_inputs({"trace": source}, {})
    assert "BEGIN PRIVATE KEY" not in clean["trace"]
    assert "QUJD" * 10 not in clean["trace"]


def test_detected_private_key_cannot_be_sent_after_diagnostic_consent(tmp_path):
    store = ConsentStore(tmp_path / "state" / "consents.json")
    gate = Gate("Send approved diagnostics", provider="none", project_root=str(tmp_path),
                grant={"allowed_domains": ["example.test"]}, privacy_gate=PrivacyGate(consents=store))
    sender = PreparedSender(gate, store, task_id="synthetic-secret")
    prepared = sender.prepare(pem().encode(), destination="https://example.test/report", source="synthetic",
                              categories=frozenset({"technical_diagnostics"}), classification_complete=True)
    pending = store.evaluate(prepared.scope, prepared.categories, prepared.digest)
    if pending.request_id:
        store.approve(pending.request_id, auth=Auth("test"))
    assert "secret" in prepared.categories
    assert sender.check(prepared).decision == "deny"


@pytest.mark.parametrize("option", ["--form", "-F", "--form-string"])
@pytest.mark.parametrize("name", ["D'Arcy", "X", "A+B"])
def test_literal_multipart_fields_seed_the_complete_named_value(tmp_path, option, name):
    gate = Gate("Send the record for " + name, provider="none", project_root=str(tmp_path),
                grant={"allowed_domains": ["example.test"]}, privacy_gate=PrivacyGate())
    command = "curl " + option + " " + json.dumps("full_name=" + name) + " https://example.test/report"
    envelope = gate.envelope(command)
    evidence = inspect(envelope)
    assert evidence.complete and evidence.cleaner.counts.get("name")
    assert name in evidence.cleaner.values
    assert gate.check(command).decision != "allow"
    raw = Recording()
    for_envelope(raw, envelope).evaluate({"purpose": "Send the record for " + name}, {})
    assert raw.states and name not in raw.states[0]["purpose"]
    if "+" in name:
        assert name.replace("+", " ") not in evidence.cleaner.values


@pytest.mark.parametrize("value", ["@literal", "X&Y;Z", 'D"Arcy'])
def test_form_string_metacharacters_remain_literal_values(tmp_path, value):
    gate = Gate("Inspect a record", provider="none", project_root=str(tmp_path))
    command = "curl --form-string " + json.dumps("full_name=" + value) + " https://example.test/report"
    evidence = inspect(gate.envelope(command))
    assert evidence.complete and not evidence.files
    assert value in evidence.cleaner.values


@pytest.mark.parametrize("shape", [lambda value: {"value": value}, lambda value: [{"value": value}],
                                   lambda value: json.dumps({"value": value})], ids=["mapping", "list", "serialized"])
def test_nested_generic_secret_label_cannot_disappear_from_provider_inputs(shape):
    value = "aB3dE5gH7jK9mN2pQ4sT6vW8xY0zA1bC"
    raw = Recording()
    SafeProvider(raw).evaluate({"purpose": "Use " + value, "api_key": shape(value)}, {})
    assert raw.states and value not in json.dumps(raw.states)


def test_nonsecret_schema_metadata_is_preserved_under_a_secret_label():
    state = {"api_key": {"type": "string",
                         "description": "Optional credential configuration", "optional": True}}
    assert safe_inputs(state, {})[0] == state


def test_inherited_secret_context_retains_child_pii_categories():
    key, name = "aB3dE5gH7jK9mN2pQ4sT6vW8xY0zA1bC", "Synthetic Rowan"
    cleaner = Minimizer()
    state = cleaner.clean({"api_key": {"full_name": name, "value": key}})
    assert key not in json.dumps(state) and name not in json.dumps(state)
    assert cleaner.counts["secret"] and cleaner.counts["name"]


@pytest.mark.parametrize("tree", [".venv", ".git", "shared-git"])
def test_known_authority_alias_beneath_a_readable_directory_is_refused(tmp_path, tree):
    source = tmp_path / tree
    source.mkdir()
    state = tmp_path / "private" / ".semgate"
    state.mkdir(parents=True)
    key = state / "trust.key"
    key.write_text("synthetic operator key")
    alias = source / "ordinary-data"
    os.link(key, alias)
    assert alias.samefile(key)
    with pytest.raises(ValueError, match="operator authority"):
        devworker._require_hidden_authority([str(key)], (source,))


def test_harmless_readonly_aliases_keep_their_existing_admission(tmp_path):
    source = tmp_path / ".venv"
    source.mkdir()
    ordinary = source / "ordinary"
    ordinary.write_text("ordinary public source")
    os.link(ordinary, source / "second-name")
    key = tmp_path / "private.key"
    key.write_text("unaliased synthetic authority")
    devworker._require_hidden_authority([str(key)], (source,))
    assert not devworker.audit_write_confinement(tmp_path)["offenders"]


def test_private_store_directory_files_are_also_protected_by_identity(tmp_path):
    private, source = tmp_path / "private", tmp_path / ".git"
    private.mkdir()
    source.mkdir()
    key = private / "record.json"
    key.write_text("synthetic private record")
    os.link(key, source / "ordinary-data")
    with pytest.raises(ValueError, match="operator authority"):
        devworker._require_hidden_authority([str(private)], (source,))


def test_authority_alias_is_refused_before_any_native_probe(tmp_path, monkeypatch):
    project, private = tmp_path / "project", tmp_path / "private"
    (project / ".venv").mkdir(parents=True)
    private.mkdir()
    key = private / "trust.key"
    key.write_text("synthetic authority")
    os.link(key, project / ".venv" / "ordinary-data")
    with monkeypatch.context() as configured:
        configured.setattr(devworker.sys, "platform", "linux")
        worker = devworker.OfflineWorker({"backend": "bubblewrap"})
    monkeypatch.setattr(devworker.proc, "run", lambda *a, **kw: pytest.fail("authority alias reached native probe"))
    with pytest.raises(ValueError, match="operator authority"):
        worker.verify(str(project), protected=(str(key),))


def test_readonly_whole_project_audit_retains_known_authority_checks(tmp_path):
    project, private = tmp_path / "project", tmp_path / "private"
    project.mkdir()
    private.mkdir()
    key = private / "trust.key"
    key.write_text("synthetic authority")
    os.link(key, project / "ordinary-data")
    identities = devworker._authority_identities([str(key)])
    result = devworker.audit_write_confinement(project, read_only=True, authority_ids=identities)
    assert result["authority_aliases"] == ["ordinary-data"]
