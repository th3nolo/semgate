"""Recognized structured data and worker pin identity survive model boundaries."""
import json
from pathlib import Path

import pytest

from semgate import Gate, harness, pins, trust
from semgate.devworker import VerifiedOfflineFacts
from semgate.judge import judge
from semgate.privacy import PrivacyGate
from semgate.privacyinspect import inspect
from semgate.providers.base import ProviderError
from semgate.providers.fake import FakeProvider
from semgate.providers.safe import configured, for_envelope
from semgate.trustauth import Auth
from test_development_harness import enable
from test_prepared_harness import configuration

ROOT = Path(__file__).resolve().parents[1]
FACTS = VerifiedOfflineFacts("0.12.0", "a"*64)


class Recording(FakeProvider):
    def __init__(self):
        super().__init__()
        self.states = []
    def evaluate(self, state, questions):
        self.states.append(json.loads(json.dumps(state)))
        return super().evaluate(state, questions)


@pytest.mark.parametrize("suffix,delimiter", [("csv", ","), ("tsv", "\t"), ("json", None)])
@pytest.mark.parametrize("field,value,category", [("full_name", "Synthetic Rowan", "NAME"),
    ("api_key", "aB3dE5gH7jK9mN2pQ4sT6vW8xY0zA1bC", "SECRET")])
def test_literal_structured_values_are_minimized_before_permission_inference(tmp_path, suffix, delimiter, field, value, category):
    content = json.dumps({field: value}) if delimiter is None else delimiter.join((field, "status"))+"\n"+delimiter.join((value, "ready"))+"\n"
    raw = Recording()
    gate = Gate("Create the local fixture for "+value, provider="none", policy=str(ROOT/"policies/router_policy_dev.json"),
                project_root=str(tmp_path), privacy_gate=PrivacyGate(allow_remote=True, require_prepared=True))
    envelope = gate.envelope("", tool="write", arguments={"path": str(tmp_path/("fixture."+suffix)), "content": content},
                             user_message="Create the local fixture for "+value)
    config = {"privacy_gate": {"enabled": True, "allow_remote": True, "require_prepared": True}}
    provider = for_envelope(configured(raw, config), envelope, offline_shell=True)
    judge(envelope, gate.policy, provider=provider, privacy_gate=gate.privacy_gate,
          trusted_offline_shell=True, trusted_execution_facts=FACTS)
    serialized = json.dumps(raw.states)
    assert len(raw.states) == 1 and value not in serialized and "PRIVATE_"+category in serialized


@pytest.mark.parametrize("suffix", ["json", "jsonl"])
def test_duplicate_json_members_cannot_send_a_discarded_decoded_name(tmp_path, suffix):
    name = "Synthetic P\u00e9rez"
    (tmp_path/("records."+suffix)).write_text('{"name":'+json.dumps(name)+',"name":"Synthetic Second"}\n')
    providers = (Recording(), Recording())
    gate = Gate("Send the record for "+name, provider="none", project_root=str(tmp_path),
        grant={"allowed_domains": ["example.test"]}, privacy_gate=PrivacyGate(allow_remote=True, providers=providers))
    command = "curl --upload-file records."+suffix+" https://example.test/report"
    envelope = gate.envelope(command, user_message="Send the record for "+name)
    assert not inspect(envelope).complete
    assert gate.check(command).decision == "ask"
    assert all(not provider.states for provider in providers)
    auxiliary = Recording()
    with pytest.raises(ProviderError):
        for_envelope(auxiliary, envelope, offline_shell=True).evaluate({"purpose": name}, {})
    assert not auxiliary.states


@pytest.mark.parametrize("content,suffix", [('{"name":"first","name":"second"}', "json"),
    ('{"name": "unfinished"', "json"), ('name,name\nfirst,second\n', "csv")])
def test_incomplete_local_structured_inspection_withholds_model_calls(tmp_path, content, suffix):
    raw = Recording()
    gate = Gate("Create a local fixture", provider="none", project_root=str(tmp_path), privacy_gate=PrivacyGate())
    envelope = gate.envelope("", tool="write", arguments={"path": str(tmp_path/("fixture."+suffix)), "content": content})
    with pytest.raises(ProviderError):
        for_envelope(raw, envelope, offline_shell=True).evaluate({"content": content}, {})
    assert not raw.states


@pytest.mark.parametrize("summary,pinned,allow", [
    ("cat AGENTS.md", True, True), ("cat /workspace/AGENTS.md", True, True),
    ("cat /workspace/docs/../AGENTS.md", True, True), ("cat /workspace/../outside/AGENTS.md", True, False),
    ("cat /workspace-other/AGENTS.md", True, False), ("cat /workspace/AGENTS.md", False, False)])
def test_worker_instruction_pins_keep_host_identity_and_guest_scope(tmp_path, summary, pinned, allow):
    config, state = configuration(tmp_path, "http://127.0.0.1:12345/report")
    enable(config)
    cfg = json.loads(config.read_text())
    cfg["trust"] = {"enabled": True, "file": str(state/"trust.jsonl")}
    config.write_text(json.dumps(cfg))
    text = "Before committing, you must run ./scripts/check.sh\n"
    instruction = tmp_path/"AGENTS.md"
    instruction.write_text(text)
    store = pins.PinStore(state/"trust.jsonl")
    if pinned:
        lines, refused = pins.file_lines_to_pin(str(instruction), store)
        assert lines and not refused
        project = trust.project_of(str(tmp_path))
        relative = instruction.resolve().relative_to(Path(project)).as_posix()
        store.add(project, relative, lines, auth=Auth("test"))
    before = store.records()
    result = harness.check_development("./scripts/check.sh", project=str(tmp_path), task="prepared-harness-task",
        config=config, execution_facts=FACTS,
        recent=[{"tool": "bash", "summary": summary, "output": text, "decision": "allow"}])
    assert (result.decision == "allow") == allow
    assert store.records() == before, "path translation must not grant or rewrite operator pins"
