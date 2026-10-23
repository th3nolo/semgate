"""Accepted auth tokens and declared authority must survive the real boundaries."""
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from semgate import devworker
from semgate.httpserve import HttpGate, read_token
from test_http_serve import server, call
from test_prepared_harness import configuration


@pytest.mark.parametrize("side", ["agent", "operator"])
@pytest.mark.parametrize("operator", [False, True])
def test_prepared_authorization_supports_the_same_utf8_token_files(tmp_path, side, operator):
    tokens = {"agent": "a" * 24, "operator": "b" * 24}
    tokens[side] = "synthetic\u00e9" + "x" * 24
    for role, token in tokens.items():
        path = tmp_path / (role + ".token")
        path.write_text(token, encoding="utf-8")
        tokens[role] = read_token(str(path))
    gate = object.__new__(HttpGate)
    gate.check_token, gate.approve_token = tokens["agent"], tokens["operator"]
    assert gate.check_allowed("Bearer " + tokens["agent"])
    assert gate.approve_allowed("Bearer " + tokens["operator"])[0]
    selected = "operator" if operator else "agent"
    assert gate.prepared_allowed("Bearer " + tokens[selected], operator=operator)
    assert not gate.prepared_allowed("Bearer " + tokens["agent" if operator else "operator"], operator=operator)
    assert not gate.prepared_allowed("Bearer wrong", operator=operator)
    gate.approve_token = gate.check_token
    assert not gate.prepared_allowed("Bearer " + gate.check_token, operator=operator)


def system_view(monkeypatch, source):
    """A fixture-backed /usr source; no system directory is created or mounted."""
    exists, resolve = Path.exists, Path.resolve
    marker = Path("/usr")

    def fixture_exists(path):
        if path.name.startswith(".SEMGATE-"):
            return False  # model the native worker's case-sensitive directory
        return True if path == marker else exists(path)

    def fixture_resolve(path, *args, **kwargs):
        return source if path == marker else resolve(path, *args, **kwargs)

    monkeypatch.setattr(Path, "exists", fixture_exists)
    monkeypatch.setattr(Path, "resolve", fixture_resolve)


@pytest.mark.parametrize("internal", [False, True])
def test_bootstrap_refuses_authority_visible_through_a_system_mount_before_launcher(tmp_path, monkeypatch, internal):
    source = tmp_path / "usr"
    project = source / "project" if internal else tmp_path / "project"
    project.mkdir(parents=True)
    authority = (project if internal else source / "local" / "share") / ".semgate" / "consents.json"
    authority.parent.mkdir(parents=True)
    authority.write_text("synthetic authority")
    system_view(monkeypatch, source)

    def unexpected(*args, **kwargs):
        pytest.fail("exposed authority reached launcher preflight")

    monkeypatch.setattr(devworker, "_launcher", unexpected)
    with pytest.raises(ValueError, match="operator authority"):
        devworker.execute({"project": str(project), "command": "printf local", "timeout_s": 5,
                           "tools": {}, "protected": [".semgate/consents.json"] if internal else [],
                           "authority": [] if internal else [str(authority)]})


def test_utf8_tokens_reach_real_prepared_http_handlers_without_sharing_roles(server, tmp_path):
    config, _ = configuration(tmp_path, "http://127.0.0.1:12345/report")
    port, gate, _ = server(config)
    gate.check_token = "synthetic-agent-\u00e9" + "a" * 24
    gate.approve_token = "synthetic-operator-\u00f1" + "b" * 24
    agent = {"Authorization": "Bearer " + gate.check_token}
    operator = {"Authorization": "Bearer " + gate.approve_token}
    status, prepared, _ = call(port, "POST", "/v1/send/prepare", {"route": "report"}, agent)
    assert status == 200 and prepared["disposition"] == "needs_consent"
    status, _, _ = call(port, "POST", "/v1/send/describe", {"prepared_id": prepared["prepared_id"]}, agent)
    assert status == 403
    status, described, _ = call(port, "POST", "/v1/send/describe", {"prepared_id": prepared["prepared_id"]}, operator)
    assert status == 200 and described["digest"] == prepared["digest"]


def test_resolved_authority_alias_is_checked_against_visible_sources(tmp_path, monkeypatch):
    source, project = tmp_path / "usr", tmp_path / "project"
    (source / "private" / ".semgate").mkdir(parents=True)
    project.mkdir()
    target = source / "private" / ".semgate" / "trust.key"
    target.write_text("synthetic key")
    alias = tmp_path / "private-alias"
    system_view(monkeypatch, source)
    resolve = Path.resolve
    monkeypatch.setattr(Path, "resolve", lambda path, *a, **kw: target if path == alias else resolve(path, *a, **kw))
    monkeypatch.setattr(devworker, "_launcher", lambda *a: pytest.fail("resolved authority reached launcher"))
    with pytest.raises(ValueError, match="operator authority"):
        devworker.execute({"project": str(project), "command": "printf local", "timeout_s": 5,
                           "tools": {}, "protected": [], "authority": [str(alias)]})


def test_authority_file_cannot_be_mounted_as_a_tool_even_through_a_hard_link(tmp_path, monkeypatch):
    import os
    project, state = tmp_path / "project", tmp_path / "private"
    project.mkdir()
    state.mkdir()
    authority = state / "trust.key"
    authority.write_text("synthetic key")
    alias = state / "tool-alias"
    os.link(authority, alias)
    system_view(monkeypatch, tmp_path / "usr")
    monkeypatch.setattr(devworker, "_launcher", lambda *a: pytest.fail("authority tool alias reached launcher"))
    with pytest.raises(ValueError, match="operator authority"):
        devworker.execute({"project": str(project), "command": "printf local", "timeout_s": 5,
                           "tools": {"tool": str(alias)}, "protected": [], "authority": [str(authority)]})


def test_unexposed_authority_keeps_the_normal_preflight_path(tmp_path, monkeypatch):
    project, state = tmp_path / "project", tmp_path / "private"
    project.mkdir()
    state.mkdir()
    authority = state / "consents.json"
    authority.write_text("synthetic authority")
    system_view(monkeypatch, tmp_path / "usr")
    class ReachedPreflight(Exception):
        pass
    def preflight(*args):
        raise ReachedPreflight
    monkeypatch.setattr(devworker, "_launcher", preflight)
    with pytest.raises(ReachedPreflight):
        devworker.execute({"project": str(project), "command": "printf local", "timeout_s": 5,
                           "tools": {}, "protected": [], "authority": [str(authority)]})


def test_wsl_payload_translates_all_authority_into_the_selected_guest_namespace(tmp_path, monkeypatch):
    project, state = tmp_path / "project", tmp_path / "private" / ".semgate"
    project.mkdir()
    state.mkdir(parents=True)
    files = (state / "consents.json", state / "trust.key", project / ".semgate" / "client.json")
    with monkeypatch.context() as configured:
        configured.setattr(devworker.sys, "platform", "linux")
        worker = devworker.OfflineWorker({"backend": "bubblewrap"})
    worker.settings.update(backend="wsl-bubblewrap", distribution="FixtureDistro")
    monkeypatch.setenv("SystemRoot", str(tmp_path / "Windows"))
    monkeypatch.setattr(devworker.proc, "popen", lambda *a, **kw: SimpleNamespace(poll=lambda: None))
    seen, conversions = [], []
    def converted(path):
        return "/mapped/" + Path(path).as_posix().replace(":", "").lstrip("/")
    def run(argv, **kwargs):
        if "--list" in argv:
            return SimpleNamespace(stdout=b"FixtureDistro")
        if "/usr/bin/wslpath" in argv:
            conversions.append(argv[-1])
            return SimpleNamespace(stdout=converted(argv[-1]))
        seen.append(json.loads(kwargs["input"]))
        return SimpleNamespace(returncode=0, stdout=b'{"boundary":"bubblewrap-offline/1"}')
    monkeypatch.setattr(devworker.proc, "run", run)
    worker._execute(str(project), {"command": "printf local"}, protected=tuple(map(str, files)),
                    expected_facts=None, check_confinement=False)
    assert len(seen) == 1
    assert set(seen[0]["authority"]) == {converted(path.resolve()) for path in files}
    assert seen[0]["protected"] == [".semgate/client.json"]
    if project.drive:
        assert conversions.count(str(Path(project.anchor))) == 1


def test_host_payload_preserves_external_and_internal_authority(tmp_path, monkeypatch):
    project = tmp_path / "project"
    project.mkdir()
    state = tmp_path / "private" / ".semgate"
    state.mkdir(parents=True)
    external = state / "consents.json"
    external.write_text("synthetic authority")
    internal = project / ".semgate" / "client.json"
    captured = []
    # Exercise the native producer on every platform without starting a worker.
    with monkeypatch.context() as configured:
        configured.setattr(devworker.sys, "platform", "linux")
        worker = devworker.OfflineWorker({"backend": "bubblewrap"})

    def capture(argv, **kwargs):
        captured.append(json.loads(kwargs["input"]))
        return SimpleNamespace(returncode=0, stdout=b'{"boundary":"bubblewrap-offline/1"}')

    monkeypatch.setattr(devworker.proc, "run", capture)
    worker._execute(str(project), {"command": "printf local"}, protected=(str(external), str(internal)),
                    expected_facts=None, check_confinement=False)
    assert len(captured) == 1
    assert str(external.resolve()) in captured[0]["authority"]
    assert str(internal.resolve()) in captured[0]["authority"]
    assert captured[0]["protected"] == [".semgate/client.json"]
