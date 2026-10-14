"""Git state as a structural fact: what git can restore flows, what it cannot asks."""
import os
from pathlib import Path
import shutil
import subprocess

import pytest

from semgate import Gate, catastrophic
from semgate.gitstate import GitFacts, write_targets
from semgate.providers.fake import FakeProvider

pytestmark = pytest.mark.skipif(shutil.which("git") is None, reason="git not installed")


@pytest.fixture()
def repo(tmp_path, monkeypatch):
    # The sibling outside.txt is unrecoverable by git but is deliberately in
    # allowed scratch space. Windows TEMP can use an 8.3 alias while pytest
    # resolves tmp_path to its long spelling; do not inherit that mismatch.
    scratch = str(tmp_path.resolve())
    for name in ("TMPDIR", "TEMP", "TMP"):
        monkeypatch.setenv(name, scratch)
    r = tmp_path / "repo"
    r.mkdir()
    run = lambda *a: subprocess.run(["git", *a], cwd=r, check=True, capture_output=True)  # noqa: E731
    run("init", "-q"); run("config", "user.email", "t@t"); run("config", "user.name", "t")
    for rel, text in {"src/app.py": "print(1)\n", "src/old.py": "x=1\n", "src/wip.py": "print(2)\n",
                      "config/settings.json": "{}\n", ".gitignore": "data/\n.env\n"}.items():
        (r / rel).parent.mkdir(parents=True, exist_ok=True)
        (r / rel).write_text(text)
    run("add", "."); run("commit", "-qm", "init")
    (r / "src/wip.py").write_text("print(3)\n")
    (r / "notes").mkdir(); (r / "notes/draft.md").write_text("draft\n")
    (r / "data").mkdir(); (r / "data/users.csv").write_text("id\n")
    (tmp_path / "outside.txt").write_text("x\n")
    return str(r)


def test_write_targets():
    assert write_targets("echo '{}' > config/settings.json") == ["config/settings.json"]
    assert write_targets("echo x >> log.txt") == [] and write_targets("pytest -q") == []
    assert write_targets("rm -rf build dist") == ["build", "dist"]
    assert write_targets("mv a.txt b.txt") == ["b.txt", "a.txt"]
    assert write_targets(r"Set-Content -Path src\app.py -Value x") == [r"src\app.py"]
    assert write_targets("git checkout -- src/") == ["src/"] and write_targets("git restore src/app.py") == ["src/app.py"]


def test_states(repo):
    f = GitFacts()
    got = {p: f.state(p, repo).state for p in ["src/app.py", "src/wip.py", "notes/draft.md", "data/users.csv", "../outside.txt", "src/new.py", "."]}
    assert got == {"src/app.py": "clean", "src/wip.py": "dirty", "notes/draft.md": "untracked", "data/users.csv": "ignored",
                   "../outside.txt": "outside", "src/new.py": "missing", ".": "outside"}
    assert f.state("x", os.path.dirname(repo)).state == "nogit"


ALLOW = {"route": {"value": "review", "confidence": 0.9}, "effect": {"value": 2.0, "confidence": 0.9}, "user_asked": 0.95,
         "on_task": 0.9, "executes": {"value": 0.0, "confidence": 1.0}}
EDIT = {"route": {"value": "run", "confidence": 1.0}, "effect": {"value": 1.0, "confidence": 1.0}, "user_asked": 0.9,
        "on_task": 0.9, "executes": {"value": 0.0, "confidence": 1.0}}


def gate(repo, answers, facts=True):
    return Gate(purpose="dev", provider=FakeProvider(answers), project_root=repo, git_facts=facts)


def test_restorable_delete_the_user_asked_for_flows(repo):
    d = gate(repo, ALLOW).check("rm src/old.py", user_message="remove old.py", cwd=repo)
    assert (d.decision, d.reason_code) == ("allow", "restorable_user_asked_allow")
    # without git facts the destructive gate asks, as before
    assert gate(repo, ALLOW, facts=False).check("rm src/old.py", user_message="remove old.py", cwd=repo).stage == "human_gate"


def test_restorable_delete_the_user_did_not_ask_for_still_asks(repo):
    d = gate(repo, {**ALLOW, "user_asked": 0.05}).check("rm src/old.py", user_message="fix the test", cwd=repo)
    assert d.decision == "ask"


def test_unrecoverable_targets_keep_the_gate_or_ask(repo):
    for cmd in ["rm notes/draft.md", "rm data/users.csv", "rm ../outside.txt", "git checkout -- src/wip.py"]:
        assert gate(repo, ALLOW).check(cmd, user_message="do it", cwd=repo).stage == "human_gate", cmd
    d = gate(repo, EDIT).check("echo 'print(0)' > src/wip.py", user_message="fix the test", cwd=repo)
    assert (d.decision, d.reason_code) == ("ask", "unrecoverable_write:dirty")
    # the same overwrite without git facts auto-runs: the hole this closes
    assert gate(repo, EDIT, facts=False).check("echo 'print(0)' > src/wip.py", user_message="fix the test", cwd=repo).decision == "allow"


@pytest.mark.parametrize("facts", [True, False])
@pytest.mark.parametrize("scratch_allowed", [True, False])
def test_outside_delete_respects_scratch_scope_before_git_recovery(repo, monkeypatch, facts, scratch_allowed):
    # An outside-repo file may still be in allowed scratch space. Control all
    # scratch roots so /tmp on POSIX or inherited Windows temp aliases cannot
    # silently decide which policy path this regression exercises.
    monkeypatch.setattr(catastrophic, "_SCRATCH_DIRS", ())
    scratch = Path(repo).parent if scratch_allowed else Path(repo)
    for name in ("TMPDIR", "TEMP", "TMP"):
        monkeypatch.setenv(name, str(scratch))
    assert GitFacts().state("../outside.txt", repo).state == "outside"
    provider = FakeProvider(ALLOW)
    d = Gate(purpose="dev", provider=provider, project_root=repo, git_facts=facts).check(
        "rm ../outside.txt", user_message="do it", cwd=repo)
    if scratch_allowed:
        assert (d.decision, d.stage) == ("ask", "human_gate")
    else:
        assert (d.decision, d.stage, d.reason_code) == ("deny", "hard_rules", "outside_project")
    assert provider.calls == 0


def test_non_file_destruction_is_never_relaxed(repo):
    for cmd in ["git reset --hard", "git push --force origin main", "shred src/app.py", "git clean -fd"]:
        assert gate(repo, ALLOW).check(cmd, user_message="do it", cwd=repo).stage == "human_gate", cmd
