"""An absent metadata directory must be protected before the first worker launch."""
from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace
import json

import pytest

from semgate import devworker
from semgate.sendharness import PreparedBroker
from test_development_harness import enable
from test_prepared_harness import configuration


@pytest.mark.parametrize("profile", ["ordinary", "write", "inspect", "cleanup"])
def test_first_worker_launch_reserves_and_masks_uninitialized_consent_namespace(tmp_path, monkeypatch, profile):
    project = tmp_path / "project"
    project.mkdir()
    operator = tmp_path / "operator"
    operator.mkdir()
    config, state = configuration(operator, "http://127.0.0.1:12345/report")
    enable(config)
    cfg = json.loads(config.read_text())
    cfg["prepared_sends"].update(project_root=str(project), consent_store=str(project / ".semgate/consents.json"))
    cfg["trust"] = {"file": str(state / "trust.jsonl")}
    config.write_text(json.dumps(cfg))
    grant = json.loads((state / "grant.json").read_text())
    grant["allowed_path_prefixes"] = [str(project)]
    (state / "grant.json").write_text(json.dumps(grant))
    broker = PreparedBroker(str(config))
    assert not (project / ".semgate").exists()
    seen = []
    class LaunchCaptured(Exception):
        pass
    def capture(argv, **kwargs):
        seen.append(argv)
        raise LaunchCaptured
    @contextmanager
    def synthetic_filter():
        yield SimpleNamespace(fileno=lambda: 123)
    exists = Path.exists
    monkeypatch.setattr(Path, "exists", lambda path: False if path.name.startswith(".SEMGATE-") else exists(path))
    monkeypatch.setattr(devworker, "_launcher", lambda *a: (tmp_path / "external-bwrap", "0.12.0", "a" * 64))
    monkeypatch.setattr(devworker, "_filter_file", synthetic_filter)
    monkeypatch.setattr(devworker.proc, "popen", capture)
    payload = {"project": str(project), "tools": {}, "protected": [".semgate/consents.json", ".semgate/trust.key"], "timeout_s": 5}
    payload.update({"command": "printf ordinary"} if profile == "ordinary" else (
        {"write": {"path": "report.csv", "content": "synthetic"}} if profile == "write" else (
        {"inspect_script": "probe.py"} if profile == "inspect" else {"cache_cleanup": "rm -rf __pycache__"})))
    try:
        with pytest.raises(LaunchCaptured):
            devworker.execute(payload)
    finally:
        broker.close()
    assert len(seen) == 1
    argv = seen[0]
    for name in (".semgate", ".codex", ".agents"):
        assert (project / name).is_dir(), name
        assert list((project / name).iterdir()) == []
        if profile == "cleanup" and name == ".semgate":
            continue  # Only the fixed trusted archiver can access its recovery tree.
        point = "/workspace/" + name
        assert any(argv[i:i + 4] == ["--tmpfs", point, "--remount-ro", point] for i in range(len(argv) - 3))
    assert not (project / ".semgate/trust.key").exists()
    assert not (project / ".semgate/consents.json").exists()


def test_reservation_preserves_existing_authority_and_refuses_file_roots(tmp_path):
    root = tmp_path / "project"
    (root / ".semgate").mkdir(parents=True)
    key = root / ".semgate/trust.key"
    key.write_bytes(b"synthetic-existing-key")
    before = key.read_bytes()
    devworker._reserve_metadata(root)
    assert key.read_bytes() == before
    other = tmp_path / "other"
    other.mkdir()
    (other / ".semgate").write_text("ordinary file")
    with pytest.raises((ValueError, OSError)):
        devworker._reserve_metadata(other)
    assert (other / ".semgate").read_text() == "ordinary file"


@pytest.mark.parametrize("name", [".semgate", ".codex", ".agents"])
def test_reservation_refuses_linked_metadata_without_touching_target(tmp_path, name):
    root, outside = tmp_path / "project", tmp_path / "outside"
    root.mkdir()
    outside.mkdir()
    canary = outside / "canary"
    canary.write_text("unchanged")
    try:
        (root / name).symlink_to(outside, target_is_directory=True)
    except OSError:
        pytest.skip("symlinks not available")
    with pytest.raises(ValueError, match="must not be a link"):
        devworker._reserve_metadata(root)
    assert list(outside.iterdir()) == [canary]
    assert canary.read_text() == "unchanged"
