"""Private metadata must preserve autonomy without inventing file recovery."""
from pathlib import Path
import shutil
import subprocess

import pytest

from semgate import Gate
from semgate.devworker import VerifiedOfflineFacts
from semgate.gitstate import GitFacts
from semgate.judge import judge
from semgate.preparedsend import PreparedSender
from semgate.privacy import PrivacyGate
from semgate.privacyconsent import ConsentStore
from semgate.providers.fake import FakeProvider
from semgate.workerpaths import WorkerGitFacts, WorkerPaths
from test_gitstate import EDIT, repo

FACTS = VerifiedOfflineFacts("0.12.0", "a" * 64)
ANSWERS = {"route": {"value": "run", "confidence": 1.0},
           "effect": {"value": 0.0, "confidence": 1.0}, "user_asked": 0.9, "on_task": 0.9,
           "instructed_by_context": 0.02, "executes": {"value": 0.0, "confidence": 1.0},
           "leaks_secrets": 0.01, "remote_code": 0.01, "needs_root": 0.01,
           "changes_running_system": 0.01, "can_judge": 0.99}
EMAIL = "synthetic.person@example.test"
TASK = "Develop the synthetic project"


@pytest.mark.parametrize("initial", ["offline", "prepared"])
def test_private_category_metadata_preserves_following_benign_decisions(tmp_path, initial):
    consents = ConsentStore(tmp_path / ".semgate" / "consents.json")
    gate = Gate(TASK, provider="none", project_root=str(tmp_path), session_id="metadata-history",
                grant={"allowed_domains": ["example.test"]},
                privacy_gate=PrivacyGate(consents=consents, require_prepared=True),
                ledger=tmp_path / ".semgate" / "ledger.jsonl")
    paths = WorkerPaths(str(tmp_path))
    def compute(command):
        authority = gate.envelope(command, user_message=TASK,
            recent=[{"tool": "read", "summary": "read synthetic fixture"}])
        return judge(paths.envelope(authority), gate.policy, provider=FakeProvider(ANSWERS), ledger=gate.ledger,
                     privacy_gate=gate.privacy_gate, trusted_offline_shell=True, trusted_execution_facts=FACTS,
                     execution_paths=paths, authority_envelope=authority)
    if initial == "offline":
        first = compute("python3 -c 'print(\"" + EMAIL + "\")'")
        assert first.decision == "allow"
    else:
        class NoTransport:
            def send(self, prepared):
                pytest.fail("consent preview reached transport")
        sender = PreparedSender(gate, consents, task_id="metadata-history", transport=NoTransport())
        prepared = sender.prepare(("email\n" + EMAIL + "\n").encode(), destination="https://example.test/report",
                                  source="synthetic-source", categories=frozenset({"email"}), classification_complete=True)
        first = sender.check(prepared)
        assert (first.decision, first.reason_code) == ("ask", "privacy_consent_required")
    row = list(gate.ledger.records())[-1]
    assert first.evidence["privacy"]["categories"] == {"email": 1}
    assert not row.get("privacy_window_incomplete") and not row.get("envelope_omitted")
    assert row["decision"]["evidence"]["privacy"]["categories"]["email"] == 1
    for number in (42, 43):
        result = compute("python3 -c 'print(" + str(number) + ")'")
        assert result.decision == "allow", result
    assert EMAIL not in gate.ledger.path.read_text()


@pytest.mark.skipif(shutil.which("git") is None, reason="git not installed")
@pytest.mark.parametrize("flag", ["--assume-unchanged", "--skip-worktree"])
@pytest.mark.parametrize("target", ["src/old.py", "src"])
def test_status_suppression_never_proves_recovery_or_rewrites_index(repo, flag, target):
    project = Path(repo)
    # Return the fixture's other changed file to its original bytes, so the
    # destination's hidden modification is the sole reason recovery is unsafe.
    (project / "src/wip.py").write_text("print(2)\n")
    def git(*args):
        return subprocess.run(["git", *args], cwd=project, capture_output=True, text=True, check=True).stdout
    git("update-index", flag, "--", "src/old.py")
    destination = project / "src/old.py"
    unique = "unique uncommitted fixture bytes\n"
    destination.write_text(unique)
    assert not git("status", "--porcelain", "--", target).strip()
    index_before = (project / ".git/index").read_bytes()
    state = GitFacts(project_root=repo).state(target, repo)
    assert not state.recoverable, state
    if target == "src/old.py":
        paths = WorkerPaths(repo)
        gate = Gate("Update the synthetic project", provider=FakeProvider(EDIT), project_root=repo)
        authority = gate.envelope("cp source.csv /workspace/src/old.py", user_message="Update the synthetic project")
        result = judge(paths.envelope(authority), gate.policy, provider=gate.provider, facts=WorkerGitFacts(paths),
                       trusted_offline_shell=True, trusted_execution_facts=FACTS,
                       execution_paths=paths, authority_envelope=authority)
        assert result.decision == "ask", result
        assert result.reason_code.startswith("unrecoverable_write:")
    assert destination.read_text() == unique
    assert (project / ".git/index").read_bytes() == index_before
