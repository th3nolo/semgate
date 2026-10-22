"""Effect authority and privacy history use synthetic, fixture-owned state."""
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import shlex
import subprocess
import sys

import pytest

from semgate import Gate, envelope, trustgate
from semgate.chatapproval import Conversation, Item
from semgate.devworker import OfflineWorker, VerifiedOfflineFacts
from semgate.gitstate import GitFacts
from semgate.judge import Decision
from semgate.ledger import Ledger
from semgate.pins import PinStore
from semgate.policy import Policy
from semgate.privacy import PrivacyGate
from semgate.privacyinspect import inspect
from semgate.providers.fake import FakeProvider
from semgate.sendharness import PreparedBroker
from test_development_harness import enable
from test_prepared_harness import configuration

ROOT = Path(__file__).resolve().parents[1]


@pytest.mark.parametrize("operation", ["run", "write"])
def test_expiring_grant_cannot_start_a_development_effect(tmp_path, monkeypatch, operation):
    config, state = configuration(tmp_path, "http://127.0.0.1:12345/report")
    enable(config)
    before = datetime(2090, 1, 1, tzinfo=timezone.utc)
    class Clock(datetime):
        current = before
        @classmethod
        def now(cls, tz=None):
            return cls.current if tz else cls.current.replace(tzinfo=None)
    grant = json.loads((state/"grant.json").read_text())
    grant["expires_at"] = (before+timedelta(seconds=1)).isoformat()
    (state/"grant.json").write_text(json.dumps(grant))
    cfg = json.loads(config.read_text())
    cfg["prepared_sends"]["task_context"]["expires_at"] = "2091-01-01T00:00:00Z"
    cfg["enforcement"]["auto_allow_tools"].append("write")
    cfg["trust"] = {"file": str(state/"trust.jsonl")}
    config.write_text(json.dumps(cfg))
    original = FakeProvider.evaluate
    calls, effects = [], []
    def evaluate(self, model_state, questions):
        calls.append(True)
        answer = original(self, model_state, questions)
        Clock.current = before+timedelta(seconds=2)
        return answer
    def execute(*args, **kwargs):
        effects.append(True)
        return {"exit_code": 0}
    monkeypatch.setattr(envelope, "datetime", Clock)
    monkeypatch.setattr(FakeProvider, "evaluate", evaluate)
    monkeypatch.setattr(OfflineWorker, "verify", lambda *a, **k: VerifiedOfflineFacts("0.12.0", "a"*64))
    monkeypatch.setattr(OfflineWorker, "run" if operation == "run" else "write", execute)
    broker = PreparedBroker(str(config))
    try:
        outcome = (broker.run_development("echo synthetic_fixture") if operation == "run" else
                   broker.write_development({"path": "fixture.py", "content": "value = 1\n"}))
    finally:
        broker.close()
    assert calls and not effects
    assert outcome["disposition"] == "deny" and outcome["delivery"] == "not_sent"


@pytest.mark.parametrize("arguments", ["--post-file=records.csv", "--post-file records.csv",
                                      "--method=POST --body-file=records.csv"])
def test_uninspected_wget_file_upload_requires_privacy_review(tmp_path, arguments):
    (tmp_path/"records.csv").write_text("name,email\nSynthetic Person,synthetic.person@example.test\n")
    gate = Gate("Send the diagnostic record", provider="none", project_root=str(tmp_path),
                grant={"allowed_domains": ["example.test"]}, privacy_gate=PrivacyGate())
    command = "wget "+arguments+" https://example.test/report"
    assert not inspect(gate.envelope(command)).complete
    decision = gate.check(command)
    assert decision.decision == "ask" and decision.stage == "privacy"


def test_judgment_storage_preserves_attachment_seeded_minimization(tmp_path):
    name = "Synthetic Review Person"
    (tmp_path/"records.csv").write_text("name,email\n"+name+",synthetic.person@example.test\n")
    providers = [FakeProvider({"privacy": {"value": "allow", "confidence": 1}}) for _ in range(2)]
    ledger = tmp_path/"state"/"ledger.jsonl"
    gate = Gate("Send the diagnostic record for "+name, provider="none", project_root=str(tmp_path),
                grant={"allowed_domains": ["example.test"]}, ledger=ledger,
                privacy_gate=PrivacyGate(allow_remote=True, providers=providers))
    gate.check("curl --upload-file records.csv https://example.test/report",
               user_message="Send the attached record for "+name)
    rows = [json.loads(line) for line in ledger.read_text().splitlines()]
    assert rows and rows[0]["privacy_minimized"]
    assert name not in json.dumps(rows)


@pytest.mark.parametrize("prior_trust", [False, True])
@pytest.mark.parametrize("session", ["private-history", "synthetic.session@example.test"])
@pytest.mark.parametrize("key_state", ["current", "missing", "replaced", "legacy"])
def test_private_history_preserves_terminal_only_trust_veto(tmp_path, prior_trust, session, key_state):
    target = "npm run deploy --recipient synthetic.person@example.test"
    command = 'semgate trust add "'+target+'"' if prior_trust else target
    gate = Gate("Read the notes", provider="none", project_root=str(tmp_path), session_id=session)
    ledger = Ledger(tmp_path/"state"/"ledger.jsonl")
    prior = gate.envelope(command)
    ledger.record_judgment(prior, Decision("deny", stage="semantic", reason_code="injection_deny",
        evaluated_at="2026-10-20T00:00:00Z", envelope_digest=prior.digest()), private=True)
    assert "synthetic.person@example.test" not in ledger.path.read_text()
    key_path = ledger.path.with_name("trust.key")
    if key_state == "missing":
        key_path.unlink()
    elif key_state == "replaced":
        key_path.write_bytes(b"z"*32)
    elif key_state == "legacy":
        row = json.loads(ledger.path.read_text())
        for field in ("privacy_command_id", "privacy_trust_target_ids", "privacy_session_id"):
            row.pop(field, None)
        ledger.path.write_text(json.dumps(row)+"\n")
    current = Decision("ask", stage="human_gate", gate_hits=[{"gate_class": "trust_request"}],
                       evaluated_at="2026-10-20T00:00:03Z", envelope_digest="current")
    conversation = Conversation((Item("call", ts=1792454400, call_id="earlier"),
        Item("user", "Always allow "+target, ts=1792454401), Item("call", ts=1792454403, call_id="current")),
        complete=True, timestamps=True, source="synthetic fixture")
    provider = FakeProvider({trustgate.QUESTION: 0.99})
    outcome = trustgate.decide('semgate trust add "'+target+'"', current, conversation, call_id="current",
        session_id=session, ledger_path=str(ledger.path), provider=provider,
        policy=Policy.load(str(ROOT/"policies/router_policy_dev_trust.json")), project=str(tmp_path),
        run_project=str(tmp_path), cwd=str(tmp_path), pin_store=PinStore(tmp_path/"state"/"trust.jsonl"))
    assert not outcome.allowed and provider.calls == 0
    if key_state == "missing":
        assert not key_path.exists()
    elif key_state == "replaced":
        assert key_path.read_bytes() == b"z"*32


def test_private_untrusted_history_can_distinguish_an_unrelated_exact_target(tmp_path):
    from semgate import fingerprints
    ledger = Ledger(tmp_path/"ledger.jsonl")
    target = "npm run deploy --recipient synthetic.person@example.test"
    gate = Gate("Read notes", provider="none", project_root=str(tmp_path), session_id="history-scope")
    prior = gate.envelope(target)
    ledger.record_judgment(prior, Decision("deny", stage="semantic", reason_code="injection_deny"), private=True)
    judgments = trustgate._session_judgments(str(ledger.path), "history-scope")
    assert judgments and not trustgate._session_judgments(str(ledger.path), "another-session")
    assert trustgate.untrusted_history(judgments, target, ledger_path=str(ledger.path))
    assert not trustgate.untrusted_history(judgments, target+" --dry-run", ledger_path=str(ledger.path))
    assert fingerprints.read_existing_key(ledger.path.with_name("trust.key"))


def test_omitted_private_history_cannot_establish_trust_origin(tmp_path):
    from semgate.ledger import IncompleteWindow
    path = tmp_path/"ledger.jsonl"
    path.write_text(json.dumps({"record_type": "judgment", "privacy_minimized": True,
        "privacy_window_incomplete": True, "envelope": {"environment": {"session_id": "history"}},
        "decision": {"stage": "semantic", "reason_code": "unknown"}})+"\n")
    with pytest.raises(IncompleteWindow):
        trustgate._session_judgments(str(path), "history")


def test_gitlink_recovery_never_recurses_into_a_submodule(tmp_path):
    repo = tmp_path/"repo"
    repo.mkdir()
    def git(*args):
        return subprocess.run(["git", *args], cwd=repo, check=True, capture_output=True)
    git("init", "-q")
    git("config", "user.email", "synthetic@example.test")
    git("config", "user.name", "Synthetic Fixture")
    (repo/"tracked.txt").write_text("fixture\n")
    git("add", ".")
    git("commit", "-qm", "fixture")
    commit = git("rev-parse", "HEAD").stdout.decode().strip()
    git("update-index", "--add", "--cacheinfo", "160000,"+commit+",vendor/component")
    (repo/"vendor"/"component").mkdir(parents=True)
    assert not GitFacts().state("vendor", str(repo)).recoverable


@pytest.mark.parametrize("kind", ["clean", "process"])
def test_git_recovery_reads_do_not_execute_configured_project_filters(tmp_path, kind):
    repo = tmp_path/"repo"
    repo.mkdir()
    def git(*args):
        return subprocess.run(["git", *args], cwd=repo, check=True, capture_output=True)
    git("init", "-q")
    git("config", "user.email", "synthetic@example.test")
    git("config", "user.name", "Synthetic Fixture")
    (repo/"record.txt").write_bytes(b"original\n")
    (repo/".gitattributes").write_text("record.txt filter=semgate_fixture\n")
    git("add", ".")
    git("commit", "-qm", "fixture")
    marker = repo/"filter-called.txt"
    helper = repo/"helper.py"
    helper.write_text("from pathlib import Path\nimport sys\n"
        "Path(__file__).with_name('filter-called.txt').write_text('called')\n"+
        ("sys.stdout.buffer.write(sys.stdin.buffer.read())\n" if kind == "clean" else ""))
    driver = shlex.join([sys.executable.replace("\\", "/"), helper.as_posix()])
    git("config", "filter.semgate_fixture."+kind, driver)
    git("config", "filter.semgate_fixture.required", "true")
    (repo/"record.txt").write_bytes(b"modified\n")
    result = GitFacts().state("record.txt", str(repo))
    assert not marker.exists()
    assert not result.recoverable
