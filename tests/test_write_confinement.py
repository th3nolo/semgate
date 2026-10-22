"""Write confinement: a hard link may not carry a project write outside the workspace.

A hard link is a second directory entry for one file, so it crosses the mount
boundary. The trusted host audits the writable project view before an ordinary
command runs and refuses when a project file also has a name outside it, and
refuses an audit it could not complete.
"""
import json
import os
from pathlib import Path
import subprocess
import sys

import pytest

from semgate.devworker import (AliasAuditError, IncompleteAuditError, OfflineWorker, VerifiedOfflineFacts,
                                WRITE_CONFINEMENT_FACT, audit_write_confinement, describe_audit)
from test_development_harness import enable
from test_http_serve import server, call, AUTH
from test_prepared_harness import configuration
from test_prepared_send import endpoint

FACTS = VerifiedOfflineFacts("0.12.0", "a" * 64)
PROTECTED = (".semgate", ".codex", ".agents", ".git", ".venv")


def backend():
    return ({"backend": "wsl-bubblewrap", "distribution": "Ubuntu"} if sys.platform == "win32"
            else {"backend": "bubblewrap"})


def linked_project(tmp_path):
    """A project file that is also a name outside the project workspace."""
    outside = tmp_path / "outside-canary.txt"
    outside.write_text("ORIGINAL\n")
    project = tmp_path / "project"
    project.mkdir()
    alias = project / "settings.txt"
    os.link(outside, alias)
    return project, outside, alias


def git_repository(path):
    """A committed repository: the deterministic git-facts rule needs one."""
    import subprocess
    env = {k: v for k, v in os.environ.items() if not k.upper().startswith("GIT_")}
    env.update(GIT_CONFIG_GLOBAL=os.devnull, GIT_CONFIG_SYSTEM=os.devnull, GIT_CONFIG_NOSYSTEM="1")
    options = {"check": True, "capture_output": True, "env": env, "timeout": 20, "cwd": str(path)}
    identity = ["-c", "core.autocrlf=false", "-c", "commit.gpgsign=false",
                "-c", "user.name=Test", "-c", "user.email=test@example.test"]
    subprocess.run(["git", *identity, "init", "--template=", "--object-format=sha1"], **options)
    (path / "report.csv").write_bytes(b"status\nready\n")
    subprocess.run(["git", *identity, "add", "--", "report.csv"], **options)
    subprocess.run(["git", *identity, "commit", "-qm", "baseline"], **options)


def make_junction(link: Path, target: Path) -> bool:
    """A Windows directory junction; False when this platform cannot make one."""
    result = subprocess.run(["cmd", "/c", "mklink", "/J", str(link), str(target)],
                            capture_output=True, text=True)
    return result.returncode == 0 and link.exists()


def test_audit_names_the_file_that_also_exists_outside_the_workspace(tmp_path):
    project, outside, alias = linked_project(tmp_path)
    audit = audit_write_confinement(project)
    assert audit["offenders"], audit
    offender = audit["offenders"][0]
    assert offender["names_in_view"] == 1 and offender["link_count"] == 2
    assert [Path(p).name for p in offender["paths"]] == ["settings.txt"]
    assert outside.read_text() == "ORIGINAL\n"


def test_audit_allows_a_hard_link_with_both_names_inside_the_project(tmp_path):
    project = tmp_path / "project"
    project.mkdir()
    (project / "one.txt").write_text("shared\n")
    os.link(project / "one.txt", project / "two.txt")
    audit = audit_write_confinement(project)
    assert audit["offenders"] == [] and audit["checked"] == 2


def test_protected_trees_are_outside_the_writable_view(tmp_path):
    project = tmp_path / "project"
    (project / ".semgate").mkdir(parents=True)
    (project / ".semgate" / "ledger.jsonl").write_text("{}\n")
    (project / "note.txt").write_text("note\n")
    os.link(project / ".semgate" / "ledger.jsonl", project / "copy.txt")
    audit = audit_write_confinement(project)
    assert audit["offenders"], audit
    assert [Path(p).name for p in audit["offenders"][0]["paths"]] == ["copy.txt"]


@pytest.mark.parametrize("name", PROTECTED)
def test_nested_protected_basename_is_audited_not_excluded(tmp_path, name):
    """Only the project-root names are masked by the mount plan.

    A directory with the same name deeper in the project is an ordinary
    writable directory in the guest, so its files must be audited.
    """
    outside = tmp_path / "outside-canary.txt"
    outside.write_text("ORIGINAL\n")
    project = tmp_path / "project"
    nested = project / "src" / name
    nested.mkdir(parents=True)
    alias = nested / "alias.txt"
    os.link(outside, alias)
    audit = audit_write_confinement(project)
    assert audit["offenders"], audit
    assert any("alias.txt" in path for item in audit["offenders"] for path in item["paths"]), audit


@pytest.mark.parametrize("name", PROTECTED)
def test_project_root_protected_tree_is_still_excluded(tmp_path, name):
    """The masked project-root tree stays outside the writable view."""
    outside = tmp_path / "outside-canary.txt"
    outside.write_text("ORIGINAL\n")
    project = tmp_path / "project"
    protected = project / name
    protected.mkdir(parents=True)
    os.link(outside, protected / "inside.txt")
    audit = audit_write_confinement(project)
    assert audit["offenders"] == [], audit
    assert audit["checked"] == 0


def test_alias_from_a_writable_file_to_protected_metadata_is_refused(tmp_path):
    """A project file that is also the operator's ledger is an outside name."""
    project = tmp_path / "project"
    (project / ".git").mkdir(parents=True)
    (project / ".git" / "config").write_text("[core]\n")
    os.link(project / ".git" / "config", project / "copy.txt")
    audit = audit_write_confinement(project)
    assert audit["offenders"], audit
    assert [Path(p).name for p in audit["offenders"][0]["paths"]] == ["copy.txt"]


def test_ordinary_command_is_refused_before_the_worker_starts(tmp_path):
    project, outside, alias = linked_project(tmp_path)
    worker = OfflineWorker(backend())
    try:
        with pytest.raises(AliasAuditError) as refusal:
            worker.run(str(project), "printf 'POISON\\n' > settings.txt")
    finally:
        worker.close()
    assert refusal.value.reason_code == "development_alias_audit_failed"
    assert "settings.txt" in refusal.value.summary()
    assert outside.read_text() == "ORIGINAL\n"
    assert not (project / "changed").exists()


def test_judge_facts_state_the_enforced_confinement(tmp_path):
    facts = VerifiedOfflineFacts("0.12.0", "a" * 64, confinement=WRITE_CONFINEMENT_FACT)
    assert "also has a name outside this workspace" in facts.render()
    # The capability fact does not name a project's alias in every judgment.
    assert "files checked" not in facts.render()
    project, outside, alias = linked_project(tmp_path)
    audit = audit_write_confinement(project)
    assert "settings.txt" in describe_audit(audit)


def test_broker_denies_the_command_and_reports_the_file(server, tmp_path, endpoint, monkeypatch):
    url, _ = endpoint
    config, state = configuration(tmp_path, url)
    enable(config)
    cfg = json.loads(config.read_text())
    cfg["prepared_sends"]["development"] = {**backend()}
    config.write_text(json.dumps(cfg))
    monkeypatch.setattr(OfflineWorker, "verify", lambda *a, **kw: FACTS)
    outside = tmp_path / "outside-canary.txt"
    outside.write_text("ORIGINAL\n")
    alias = tmp_path / "settings.txt"
    os.link(outside, alias)
    git_repository(tmp_path)
    audit = {"checked": 2, "inodes": 1, "unverifiable": 0,
             "offenders": [{"paths": ["settings.txt"], "names_in_view": 1, "link_count": 2}]}

    def refused(self, project, command, **kwargs):
        raise AliasAuditError(audit)

    monkeypatch.setattr(OfflineWorker, "run", refused)
    port, _, _ = server(config)
    status, result, _ = call(port, "POST", "/v1/send/run", {"command": "printf 'note\\n' > notes.txt"}, AUTH)
    assert status == 200 and result["disposition"] == "deny", result
    assert result["reason_code"] == "development_alias_audit_failed"
    assert "settings.txt" in json.dumps(result.get("alias_audit") or {})
    assert outside.read_text() == "ORIGINAL\n"
    assert not (tmp_path / "notes.txt").exists()


def test_unreadable_directory_makes_the_audit_incomplete(tmp_path, monkeypatch):
    """Listing a directory and writing inside it are different permissions."""
    project = tmp_path / "project"
    (project / "opaque").mkdir(parents=True)
    (project / "opaque" / "alias.txt").write_text("ORIGINAL\n")
    real_scandir = os.scandir

    def failing(path):
        if str(path).endswith("opaque"):
            raise PermissionError(13, "Permission denied")
        return real_scandir(path)

    monkeypatch.setattr(os, "scandir", failing)
    audit = audit_write_confinement(project)
    assert audit["unverifiable"] == 1, audit
    assert audit["offenders"] == [], audit


def test_unreadable_entry_makes_the_audit_incomplete(tmp_path, monkeypatch):
    project = tmp_path / "project"
    project.mkdir()
    (project / "alias.txt").write_text("ORIGINAL\n")
    real_lstat = os.lstat

    def failing(path):
        if str(path).endswith("alias.txt"):
            raise PermissionError(13, "Permission denied")
        return real_lstat(path)

    monkeypatch.setattr(os, "lstat", failing)
    audit = audit_write_confinement(project)
    assert audit["unverifiable"] == 1, audit


def test_incomplete_audit_refuses_the_ordinary_command(tmp_path, monkeypatch):
    """An audit that could not complete must not let the command run."""
    project = tmp_path / "project"
    (project / "opaque").mkdir(parents=True)
    outside = tmp_path / "outside-canary.txt"
    outside.write_text("ORIGINAL\n")
    os.link(outside, project / "opaque" / "alias.txt")
    real_scandir = os.scandir

    def failing(path):
        if str(path).endswith("opaque"):
            raise PermissionError(13, "Permission denied")
        return real_scandir(path)

    monkeypatch.setattr(os, "scandir", failing)
    worker = OfflineWorker(backend())
    try:
        with pytest.raises(IncompleteAuditError) as refusal:
            worker.run(str(project), "printf 'POISON\\n' > opaque/alias.txt")
    finally:
        worker.close()
    assert refusal.value.reason_code == "development_alias_audit_incomplete"
    assert outside.read_text() == "ORIGINAL\n"


def test_incomplete_audit_keeps_the_literal_writer_available(tmp_path, monkeypatch):
    """The literal writer replaces a directory entry; it cannot change a shared file."""
    project = tmp_path / "project"
    (project / "opaque").mkdir(parents=True)
    outside = tmp_path / "outside-canary.txt"
    outside.write_text("ORIGINAL\n")
    os.link(outside, project / "opaque" / "alias.txt")
    real_scandir = os.scandir

    def failing(path):
        if str(path).endswith("opaque"):
            raise PermissionError(13, "Permission denied")
        return real_scandir(path)

    monkeypatch.setattr(os, "scandir", failing)
    worker = OfflineWorker(backend())
    try:
        with pytest.raises(IncompleteAuditError):
            worker.run(str(project), "printf 'x\\n' > opaque/alias.txt")
    finally:
        worker.close()


@pytest.mark.skipif(sys.platform != "win32", reason="Windows directory junctions")
def test_junction_target_names_are_not_counted_as_inside_names(tmp_path):
    """A junction is a name surrogate: its target is not part of the project view."""
    outside = tmp_path / "outside"
    outside.mkdir()
    canary = outside / "canary.txt"
    canary.write_text("ORIGINAL\n")
    project = tmp_path / "project"
    project.mkdir()
    alias = project / "alias.txt"
    os.link(canary, alias)
    if not make_junction(project / "junction", outside):
        pytest.skip("this machine cannot create a directory junction")
    audit = audit_write_confinement(project)
    assert audit["offenders"], audit
    assert [Path(p).name for p in audit["offenders"][0]["paths"]] == ["alias.txt"]
    assert audit["checked"] == 1, audit


@pytest.mark.skipif(sys.platform != "win32", reason="Windows directory junctions")
def test_junction_into_the_project_does_not_duplicate_names(tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "other.txt").write_text("other\n")
    project = tmp_path / "project"
    project.mkdir()
    (project / "one.txt").write_text("shared\n")
    os.link(project / "one.txt", project / "two.txt")
    if not make_junction(project / "junction", project):
        pytest.skip("this machine cannot create a directory junction")
    audit = audit_write_confinement(project)
    assert audit["offenders"] == [], audit
    assert audit["checked"] == 2, audit


@pytest.mark.skipif(sys.platform != "win32", reason="Windows directory junctions")
def test_junction_cycle_terminates(tmp_path):
    """A junction to an ancestor must not make the audit loop."""
    project = tmp_path / "project"
    project.mkdir()
    (project / "file.txt").write_text("content\n")
    if not make_junction(project / "loop", project):
        pytest.skip("this machine cannot create a directory junction")
    script = (
        "import importlib.util,json,sys\n"
        "from pathlib import Path\n"
        "spec=importlib.util.spec_from_file_location('w', sys.argv[1])\n"
        "w=importlib.util.module_from_spec(spec); sys.modules['w']=w; spec.loader.exec_module(w)\n"
        "print(json.dumps(w.audit_write_confinement(Path(sys.argv[2]))))\n")
    worker_source = str(Path(__file__).resolve().parents[1] / "semgate" / "devworker.py")
    result = subprocess.run([sys.executable, "-I", "-c", script, worker_source, str(project)],
                            capture_output=True, text=True, timeout=30)
    assert result.returncode == 0, result.stderr[-400:]
    audit = json.loads(result.stdout.strip().splitlines()[-1])
    assert audit["offenders"] == [] and audit["checked"] == 1, audit
