"""Regressions for ordinary permission projections and worker admission."""
from copy import deepcopy
import json
from pathlib import Path
import stat
import sys
from types import SimpleNamespace

import pytest

from semgate import ConsentStore, Gate, PreparedSender, PrivacyGate, harness
from semgate.approvals import store_for
from semgate import devworker
from semgate.feedback import FeedbackStore
from semgate.gitstate import GitFacts
from semgate.providers.fake import FakeProvider
from semgate.sendharness import PreparedBroker
from semgate.trustauth import Auth
from test_development_harness import enable
from test_harness_api import ALLOWING
from test_prepared_harness import configuration


@pytest.mark.parametrize("method", ["POST", "PUT"])
def test_prepared_permission_sees_the_upload_after_privacy_consent(tmp_path, method):
    class Capture(FakeProvider):
        def __init__(self):
            # The ordinary gate still requires review for an outbound effect.
            super().__init__(dict(ALLOWING, effect={"value": 3.0, "confidence": 1.0}))
            self.states = []

        def evaluate(self, state, questions):
            self.states.append(deepcopy(state))
            return super().evaluate(state, questions)

    provider = Capture()
    consents = ConsentStore(tmp_path / "consents.json")
    gate = Gate("Prepare diagnostic artifacts", provider=provider, project_root=str(tmp_path),
                privacy_gate=PrivacyGate(consents=consents))
    sender = PreparedSender(gate, consents, task_id="permission-test")
    prepared = sender.prepare(b"status\nready\n", destination="https://example.test/report",
                              source="diagnostics", method=method,
                              categories=frozenset({"technical_diagnostics"}), classification_complete=True)
    pending = consents.evaluate(prepared.scope, prepared.categories, prepared.digest)
    consents.approve(pending.request_id, auth=Auth("test"))
    answer = sender.check(prepared)
    assert provider.states
    command = provider.states[-1]["command"]
    assert f"HTTP {method}" in command, command
    assert "upload" in command.lower() and "13" in command, command
    assert "read-only" not in command and "HTTP GET" not in command, command
    assert "status\nready" not in command
    assert answer.decision == "ask", answer


def test_feedback_outage_preserves_an_unused_approval_and_never_calls_executor(tmp_path, monkeypatch):
    config, state = configuration(tmp_path, "https://example.test/report")
    enable(config)
    cfg = json.loads(config.read_text())
    cfg["enforcement"].update(auto_allow_tools=[], block_when_unsure=False)
    cfg["feedback"] = {"enabled": True, "feedback_file": str(state / "feedback.jsonl")}
    cfg["trust"] = {"file": str(state / "trust.jsonl")}
    config.write_text(json.dumps(cfg))
    facts = devworker.VerifiedOfflineFacts("0.12.0", "a" * 64)
    monkeypatch.setattr(devworker.OfflineWorker, "verify", lambda *a, **kw: facts)
    monkeypatch.setattr(GitFacts, "_git", lambda *a, **kw: (1, ""))
    effects = []

    def run(*args, **kwargs):
        effects.append(args[2])
        return {"exit_code": 0, "stdout": "", "stderr": "", "timed_out": False,
                "boundary": "synthetic-executor"}

    monkeypatch.setattr(devworker.OfflineWorker, "run", run)
    broker = PreparedBroker(str(config))
    command = "printf synthetic-local-output"
    try:
        asked = broker.run_development(command)
        aid = asked["approval_id"]
        assert asked["disposition"] == "needs_inspection" and not effects
        harness.approve(aid, True, "Test operator", config=config)
        FeedbackStore(str(state / "feedback.jsonl")).record(
            "deny", "bash", {"command": command},
            session_id="prepared-harness-task", project_root=str(tmp_path))
        readable = broker.run_development(command)
        assert (readable["disposition"], readable["reason_code"]) == ("deny", "human_blocked")
        assert store_for(broker.config).get(aid)["status"] == "approved" and not effects

        def outage(*args, **kwargs):
            raise OSError("synthetic feedback outage")

        with monkeypatch.context() as failed:
            failed.setattr(FeedbackStore, "latest", outage)
            answer = broker.run_development(command)
        assert answer["disposition"] != "allow", answer
        assert answer["reason_code"] == "feedback_unreadable", answer
        assert not effects
        assert store_for(broker.config).get(aid)["status"] == "approved"
        assert "approval_id" not in answer
        # Recovering the store restores the newer denial, without using the older approval.
        assert broker.run_development(command)["reason_code"] == "human_blocked"
        assert not effects
    finally:
        broker.close()


@pytest.mark.parametrize("kind", [stat.S_IFIFO, stat.S_IFSOCK, stat.S_IFCHR, stat.S_IFBLK])
@pytest.mark.parametrize("links", [1, 2])
def test_special_endpoint_is_refused_before_worker_or_host_inspection(tmp_path, monkeypatch, kind, links):
    project = tmp_path / "project"
    project.mkdir()
    endpoint = project / "endpoint"
    endpoint.write_text("synthetic stand-in")
    original = devworker.os.lstat

    def metadata(path, *args, **kwargs):
        if Path(path) == endpoint:
            return SimpleNamespace(st_mode=kind | 0o600, st_nlink=links, st_dev=1, st_ino=2)
        return original(path, *args, **kwargs)

    monkeypatch.setattr(devworker.os, "lstat", metadata)
    audit = devworker.audit_write_confinement(project)
    # A single-name FIFO can already have a host peer; alias counting alone is insufficient.
    assert audit["unverifiable"] == 1, audit

    def forbidden(*args, **kwargs):
        pytest.fail("special endpoint must be refused before inspecting or starting a native runtime")

    monkeypatch.setattr(devworker.proc, "run", forbidden)
    monkeypatch.setattr(devworker.proc, "popen", forbidden)
    settings = ({"backend": "wsl-bubblewrap", "distribution": "Ubuntu"} if sys.platform == "win32"
                else {"backend": "bubblewrap"})
    worker = devworker.OfflineWorker(settings)
    try:
        with pytest.raises(devworker.IncompleteAuditError):
            worker.run(str(project), "printf synthetic")
    finally:
        worker.close()
