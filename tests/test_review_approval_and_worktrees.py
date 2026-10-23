"""Ordinary approval failures and linked-worktree guest metadata."""
from contextlib import contextmanager
import json
import os
from pathlib import Path
import subprocess
from types import SimpleNamespace

import pytest

from semgate import approvals, devworker, harness
from semgate.chatapproval import envelope_key
from semgate.envelope import UserGrant
from semgate.gitstate import GitFacts
from semgate.sendharness import PreparedBroker
from semgate import workerrepo
from test_development_harness import enable
from test_prepared_harness import configuration
from test_write_confinement import git_repository


@pytest.mark.parametrize("failure", ["permission", "json", "shape", "duplicate", "record"])
def test_unreadable_ordinary_denial_never_reaches_the_broker_executor(tmp_path, monkeypatch, failure):
    config, state = configuration(tmp_path, "https://example.test/report")
    enable(config)
    cfg = json.loads(config.read_text())
    cfg["enforcement"].update(auto_allow_tools=["bash"], block_when_unsure=False)
    cfg["trust"] = {"file": str(state / "trust.jsonl")}
    config.write_text(json.dumps(cfg))
    command = "printf synthetic-approval-read-outage"
    req = harness.validate_request({"tool": "bash", "arguments": {"command": command},
        "session_id": "prepared-harness-task", "project_root": str(tmp_path), "cwd": str(tmp_path),
        "user_messages": [cfg["prepared_sends"]["task_context"]["request"]]})
    env = harness.build_envelope(req, UserGrant.from_dict(json.loads((state / "grant.json").read_text())))
    store = approvals.store_for(harness.load_config(config))
    pending = store.settle(key=envelope_key(env), session_id=req["session_id"], project_root=str(tmp_path), final="ask")
    store.decide(pending["record"]["approval_id"], False, "Test operator")
    original = store.path.read_bytes()
    facts = devworker.VerifiedOfflineFacts("0.12.0", "a" * 64)
    monkeypatch.setattr(devworker.OfflineWorker, "verify", lambda *a, **kw: facts)
    monkeypatch.setattr(GitFacts, "_git", lambda *a, **kw: (1, ""))
    effects = []

    def run(*args, **kwargs):
        effects.append(args[2])
        return {"exit_code": 0, "stdout": "", "stderr": "", "timed_out": False}

    monkeypatch.setattr(devworker.OfflineWorker, "run", run)
    broker = PreparedBroker(str(config))
    try:
        assert broker.run_development(command)["reason_code"] == "human_denied"
        assert not effects
        if failure == "json":
            store.path.write_text("{")
        elif failure == "shape":
            store.path.write_text('{"schema":1,"approvals":[]}')
        elif failure == "duplicate":
            store.path.write_text(original.decode().rstrip()[:-1] + ',"approvals":{}}')
        elif failure == "record":
            malformed = json.loads(original)
            next(iter(malformed["approvals"].values())).pop("decided")
            store.path.write_text(json.dumps(malformed))
        before_failure = store.path.read_bytes()
        read = Path.read_text

        def failed_read(path, *args, **kwargs):
            if path == store.path and failure == "permission":
                raise PermissionError("synthetic ordinary approval read outage")
            return read(path, *args, **kwargs)

        with monkeypatch.context() as failed:
            failed.setattr(Path, "read_text", failed_read)
            answer = broker.run_development(command)
        assert answer["disposition"] != "allow", answer
        assert not effects and not answer.get("approval_id"), answer
        assert store.path.read_bytes() == before_failure
        store.path.write_bytes(original)
        assert broker.run_development(command)["reason_code"] == "human_denied"
        assert not effects
    finally:
        broker.close()


def git(project, *args):
    env = {k: v for k, v in os.environ.items() if not k.upper().startswith("GIT_")}
    env.update(GIT_CONFIG_GLOBAL=os.devnull, GIT_CONFIG_SYSTEM=os.devnull, GIT_CONFIG_NOSYSTEM="1")
    return subprocess.run(["git", "-C", str(project), *args], env=env, check=True,
                          capture_output=True, text=True, timeout=20).stdout.strip()


def linked_project(tmp_path, relative=False, worktree_config=False):
    main, project = tmp_path / "main", tmp_path / "linked"
    main.mkdir()
    git_repository(main)
    git(main, "worktree", "add", "--detach", *(["--relative-paths"] if relative else []), str(project), "HEAD")
    admin = Path(git(project, "rev-parse", "--absolute-git-dir"))
    common = main / ".git"
    if worktree_config:
        git(main, "config", "extensions.worktreeConfig", "true")
        git(project, "config", "--worktree", "core.worktree", str(project))
    assert git(project, "status", "--porcelain") == ""
    return project, admin, common


def capture_guest(project, tmp_path, monkeypatch):
    seen = {}

    class Captured(Exception):
        pass

    def capture(argv, **kwargs):
        seen["argv"] = argv
        seen["data"] = {}
        for i, arg in enumerate(argv):
            if arg == "--ro-bind-data":
                fd = int(argv[i + 1])
                os.lseek(fd, 0, os.SEEK_SET)
                seen["data"][argv[i + 2]] = os.read(fd, 131072)
        raise Captured

    @contextmanager
    def synthetic_filter():
        yield SimpleNamespace(fileno=lambda: 123)

    exists = Path.exists
    monkeypatch.setattr(Path, "exists", lambda path: False if path.name.startswith(".SEMGATE-") else exists(path))
    monkeypatch.setattr(devworker, "_launcher", lambda *a: (tmp_path / "bwrap", "0.12.0", "a" * 64))
    monkeypatch.setattr(devworker, "_filter_file", synthetic_filter)
    monkeypatch.setattr(devworker.proc, "popen", capture)
    with pytest.raises(Captured):
        devworker.execute({"project": str(project), "command": "git status --short",
                           "tools": {}, "protected": [], "timeout_s": 5})
    return seen


@pytest.mark.parametrize("relative", [False, True])
@pytest.mark.parametrize("worktree_config", [False, True])
def test_linked_worktree_has_guest_valid_readonly_git_metadata(tmp_path, monkeypatch, relative, worktree_config):
    project, admin, common = linked_project(tmp_path, relative, worktree_config)
    original = (project / ".git").read_bytes()
    original_common = (admin / "commondir").read_bytes()
    seen = capture_guest(project, tmp_path, monkeypatch)
    argv = seen["argv"]
    mounts = [(argv[i + 1], argv[i + 2]) for i, arg in enumerate(argv) if arg == "--ro-bind"]
    common_mounts = [(source, target) for source, target in mounts if Path(source) == common]
    assert len(common_mounts) == 1, mounts
    guest_common = common_mounts[0][1]
    guest_admin = guest_common + "/" + admin.relative_to(common).as_posix()
    assert seen["data"]["/workspace/.git"] == ("gitdir: " + guest_admin + "\n").encode()
    assert seen["data"][guest_admin + "/commondir"] == (guest_common + "\n").encode()
    if worktree_config:
        assert b"worktree = /workspace" in seen["data"][guest_admin + "/config.worktree"]
    assert (project / ".git").read_bytes() == original
    assert (admin / "commondir").read_bytes() == original_common
    assert all(source != str(project.parent) for source, _ in mounts)


def test_shared_git_authority_is_refused_before_native_preflight(tmp_path, monkeypatch):
    project, admin, common = linked_project(tmp_path)
    def forbidden(*args, **kwargs):
        pytest.fail("unsafe metadata must be refused before native preflight")
    monkeypatch.setattr(devworker.proc, "run", forbidden)
    monkeypatch.setattr(devworker.proc, "popen", forbidden)
    settings = {"backend": "wsl-bubblewrap", "distribution": "Ubuntu"} if os.name == "nt" else {"backend": "bubblewrap"}
    instance = devworker.OfflineWorker(settings)
    try:
        with pytest.raises(ValueError, match="operator authority"):
            instance.verify(str(project), protected=(str(common / "authority.json"),))
    finally:
        instance.close()


def test_changed_or_escaping_git_metadata_projection_is_refused(tmp_path):
    project, admin, common = linked_project(tmp_path)
    layout = workerrepo.layout(project)
    assert workerrepo.validate(project, layout) == layout
    for changed in (dict(layout, pointer_sha256="0" * 64), dict(layout, relative="worktrees/../../escape"),
                    dict(layout, common=str(project)), dict(layout, relative="worktrees/bad\nname")):
        with pytest.raises(ValueError):
            workerrepo.validate(project, changed)


@pytest.mark.parametrize("name", [".git", ".venv"])
def test_readonly_project_metadata_still_refuses_special_endpoints(tmp_path, monkeypatch, name):
    import stat
    project = tmp_path / "project"
    metadata = project / name
    metadata.mkdir(parents=True)
    endpoint = metadata / "endpoint"
    endpoint.write_text("synthetic stand-in")
    original = devworker.os.lstat
    def fake_stat(path, *args, **kwargs):
        if Path(path) == endpoint:
            return SimpleNamespace(st_mode=stat.S_IFIFO | 0o600, st_nlink=1, st_dev=1, st_ino=2)
        return original(path, *args, **kwargs)
    monkeypatch.setattr(devworker.os, "lstat", fake_stat)
    assert devworker.audit_write_confinement(project)["unverifiable"] == 1
    assert devworker.audit_write_confinement(project, read_only=True)["unverifiable"] == 1


def test_genuine_first_use_absence_still_permits_normal_judgment(tmp_path):
    store = approvals.ApprovalStore(tmp_path / "new-approvals.json", 3600)
    assert store.settle(key="action", session_id="task", project_root=str(tmp_path), final="allow")["effect"] == "none"
    pending = store.settle(key="action", session_id="task", project_root=str(tmp_path), final="ask")
    assert pending["effect"] == "pending"
    store.decide(pending["record"]["approval_id"], True, "Test operator")
    assert store.settle(key="action", session_id="task", project_root=str(tmp_path), final="ask")["effect"] == "allow"


def test_readonly_source_aliases_remain_usable_without_persistent_write_capability(tmp_path):
    project = tmp_path / "project"
    project.mkdir()
    outside = tmp_path / "outside"
    outside.write_text("synthetic")
    os.link(outside, project / "alias")
    assert devworker.audit_write_confinement(project)["offenders"]
    readonly = devworker.audit_write_confinement(project, read_only=True)
    assert readonly["offenders"] == [] and readonly["unverifiable"] == 0
