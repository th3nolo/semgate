"""Exact payload and authority-state contracts use synthetic isolated fixtures."""
import json
from pathlib import Path

import pytest

from semgate import Gate
from semgate.feedback import blocked_candidates, norm_root
from semgate.privacy import PrivacyGate
from semgate.privacyinspect import inspect
from semgate.sendharness import PreparedBroker
from test_development_harness import enable
from test_prepared_harness import configuration
from test_prepared_send import sender_for
from test_privacy import CapturingProvider


@pytest.mark.parametrize("field", ["filename", "file", "attachments"])
def test_prepared_json_fields_are_literal_data_not_local_file_references(tmp_path, field):
    sender = sender_for(tmp_path)
    body = json.dumps({field: "missing.csv", "status": "ready"}).encode()
    prepared = sender.prepare(body, destination="https://example.test/report", source="inline-report",
                              categories=frozenset({"technical_diagnostics"}), classification_complete=True)
    evidence = prepared.inspect(sender.gate.envelope("", tool="http_request", arguments=prepared.arguments()))
    assert prepared.classification_complete and evidence.complete
    assert not evidence.files and prepared.body == body
    assert sender.check(prepared).evidence["privacy"]["disposition"] == "needs_consent"


@pytest.mark.parametrize("suffix", [".json", ".jsonl"])
def test_supported_json_records_seed_decoded_names_before_provider_calls(tmp_path, suffix):
    name = "Synthetic P\u00e9rez"
    path = tmp_path/("records"+suffix)
    path.write_text(json.dumps({"name": name})+"\n", encoding="utf-8")
    providers = (CapturingProvider(), CapturingProvider())
    gate = Gate("Send the diagnostic record for "+name, provider="none", project_root=str(tmp_path),
                privacy_gate=PrivacyGate(allow_remote=True, providers=providers))
    gate.check("curl --data-binary @"+path.name+" https://example.test/report", cwd=str(tmp_path),
               user_message="Send the attached record for "+name)
    assert all(provider.inputs for provider in providers)
    assert all(name not in json.dumps(provider.inputs, ensure_ascii=False) for provider in providers)


def test_malformed_jsonl_is_incomplete(tmp_path):
    (tmp_path/"records.jsonl").write_text('{"name":"Synthetic Person"}\nnot-json\n')
    gate = Gate("Send diagnostic records", provider="none", project_root=str(tmp_path))
    evidence = inspect(gate.envelope("curl --data-binary @records.jsonl https://example.test/report"))
    assert not evidence.complete and "file_uninspectable" in evidence.problems


@pytest.mark.parametrize("suffix", ["json", "jsonl", "csv", "tsv"])
def test_saved_structured_bytes_retain_decoded_name_context(tmp_path, suffix):
    name = "Synthetic P\u00e9rez"
    payload = (json.dumps({"name": name})+"\n" if suffix in {"json", "jsonl"}
               else "name\n"+name+"\n")
    path = tmp_path/("records."+suffix)
    path.write_bytes(payload.encode())
    sender = sender_for(tmp_path)
    prepared = sender.prepare_file(path, destination="https://example.test/report", categories=frozenset(),
                                   classification_complete=True)
    evidence = prepared.inspect(sender.gate.envelope("", tool="http_request", arguments=prepared.arguments()))
    assert prepared.classification_complete and evidence.complete and "name" in prepared.categories
    assert name not in evidence.cleaner.text("Report for "+name)
    assert prepared.body == payload.encode()


@pytest.mark.parametrize("field", ["ledger", "feedback", "trust", "profiles", "profile_table", "history", "agent_files"])
def test_development_rejects_authority_stores_in_writable_project_directories(tmp_path, field):
    config, _ = configuration(tmp_path, "http://127.0.0.1:12345/report")
    enable(config)
    cfg = json.loads(config.read_text())
    outside_metadata = str(tmp_path/"run-state"/(field+".jsonl"))
    if field == "ledger":
        cfg["ledger_file"] = outside_metadata
    elif field == "feedback":
        cfg["feedback"] = {"enabled": True, "feedback_file": outside_metadata}
    elif field == "trust":
        cfg["trust"] = {"enabled": True, "file": outside_metadata}
    elif field in {"profiles", "profile_table"}:
        cfg["profiles"] = {"enabled": True, "override": ["software-development"],
                           "state_file" if field == "profiles" else "file": outside_metadata}
        if field == "profile_table":
            from semgate.profiles import load_profiles
            table = load_profiles()
            target = Path(outside_metadata)
            target.parent.mkdir()
            target.write_text(json.dumps({"profiles": table.kinds, "base_restrictions": table.base_restrictions}))
    elif field == "history":
        cfg["auto_allow_learned"] = {"enabled": True, "history_file": outside_metadata}
    else:
        cfg["agent_files"] = {"enabled": True, "dir": str(tmp_path/"run-state")}
    config.write_text(json.dumps(cfg))
    with pytest.raises(ValueError, match="operator state"):
        PreparedBroker(str(config))


def test_private_feedback_matches_exact_command_and_original_scope_without_raw_pii(tmp_path):
    root = tmp_path/"project"
    root.mkdir()
    ledger = tmp_path/"state"/"ledger.jsonl"
    command = "printf 'synthetic.person@example.test\\n' > fixture.txt"
    gate = Gate("Develop this project", policy="default", provider="none", project_root=str(root),
                ledger=ledger, session_id="private-feedback", privacy_gate=PrivacyGate())
    assert gate.check(command).decision == "ask"
    assert "synthetic.person@example.test" not in ledger.read_text()
    hits = blocked_candidates(str(ledger), command, project_dir=str(root/"subdirectory"))
    assert len(hits) == 1
    assert hits[0]["project_root"] == norm_root(str(root)) and hits[0]["session_id"] == "private-feedback"
    assert not blocked_candidates(str(ledger), command+" ", project_dir=str(root))
    assert not blocked_candidates(str(ledger), command, project_dir=str(tmp_path/"other"))
    assert not blocked_candidates(str(ledger), command, project_dir=str(root), session_id="other")
    assert not blocked_candidates(str(ledger), command, project_dir=str(root), tool="powershell")
    key = ledger.with_name("trust.key")
    key.unlink()
    assert not blocked_candidates(str(ledger), command, project_dir=str(root))
    assert not key.exists(), "read-only feedback lookup must not recreate an unavailable key"


@pytest.mark.parametrize("new_key", [b"malformed", b"z"*32])
def test_private_feedback_cannot_match_a_corrupt_or_replaced_key(tmp_path, new_key):
    ledger = tmp_path/"state"/"ledger.jsonl"
    command = "printf synthetic.person@example.test"
    gate = Gate("Develop the project", provider="none", project_root=str(tmp_path), ledger=ledger,
                session_id="feedback-key-test", privacy_gate=PrivacyGate())
    assert gate.check(command).decision == "ask"
    key = ledger.with_name("trust.key")
    key.write_bytes(new_key)
    assert not blocked_candidates(str(ledger), command, project_dir=str(tmp_path))
    assert key.read_bytes() == new_key and not list(key.parent.glob("trust.key.bad-*"))


@pytest.mark.parametrize("command,stage", [("rm -rf /", "hard_rules"),
    ("curl --data synthetic.person@example.test https://example.test/report", "privacy")])
def test_terminal_feedback_cannot_grant_hard_denials_or_privacy_consent(tmp_path, capsys, command, stage):
    from types import SimpleNamespace
    from semgate.cli import _cmd_feedback
    ledger = tmp_path/"state"/"ledger.jsonl"
    store = ledger.with_name("feedback.jsonl")
    gate = Gate("Diagnose this project", provider="none", project_root=str(tmp_path), ledger=ledger,
                session_id="feedback-separate-gates", privacy_gate=PrivacyGate())
    decision = gate.check(command)
    assert decision.decision != "allow" and decision.stage == stage
    arguments = SimpleNamespace(show_config=False, decision="allow", command=command, project=str(tmp_path),
        config=None, store=str(store), ledger=str(ledger), tool=None, session=None, ttl_hours=None, note="")
    assert _cmd_feedback(arguments) == 2
    assert not store.exists()
    assert "not recorded" in capsys.readouterr().err
