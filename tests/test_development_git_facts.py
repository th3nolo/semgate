"""The protected harness checks real recovery state; Git never authorizes a send."""
import json
import subprocess

import pytest

from semgate import harness
from semgate.devworker import VerifiedOfflineFacts
from test_development_harness import enable
from test_prepared_harness import configuration

FACTS = VerifiedOfflineFacts("0.12.0", "a" * 64)


@pytest.fixture
def project(tmp_path):
    config, state = configuration(tmp_path, "http://127.0.0.1:12345/canary")
    enable(config)
    git = ["git", "-C", str(tmp_path), "-c", "core.autocrlf=false",
           "-c", "core.hooksPath=", "-c", "commit.gpgsign=false",
           "-c", "user.name=Test", "-c", "user.email=fixture@example.test"]
    for args in (("init", "--template="), ("add", "--", "report.csv"), ("commit", "-qm", "fixture")):
        subprocess.run(git + list(args), check=True, capture_output=True)
    (tmp_path / "source.csv").write_text("status\npassed\n")
    return tmp_path, config, state


def check(project, *, verified=True):
    root, config, _ = project
    return harness.check_development("cp source.csv report.csv", project=str(root),
        task="prepared-harness-task", config=config, execution_facts=FACTS if verified else None)


def test_verified_worker_inspects_git_without_changing_operator_configuration(project):
    root, config, state = project
    before = config.read_bytes()
    assert "git_facts" not in json.loads(before)
    assert check(project).decision == "allow"
    judgments = [json.loads(line) for line in (state / "ledger.jsonl").read_text().splitlines()]
    actual = next(row["decision"] for row in judgments if row.get("record_type") == "judgment")
    assert actual["evidence"]["git_targets"]["targets"] == [{"path": "report.csv", "state": "clean", "recoverable": True}]
    assert (root / "report.csv").read_bytes() == b"status\nready\n"  # Checking never edits the fixture.
    assert config.read_bytes() == before


@pytest.mark.parametrize("state", ["dirty", "untracked", "ignored", "nogit"])
def test_real_unrecoverable_work_still_withholds_model_allow(project, state):
    root, config, _ = project
    if state == "dirty":
        (root / "report.csv").write_text("unsaved work\n")
    else:
        # Move the request to a separate fresh project rather than rewriting Git state.
        other = root.parent / (root.name + "-other")
        other.mkdir()
        config, meta = configuration(other, "http://127.0.0.1:12345/canary")
        enable(config)
        (other / "source.csv").write_text("status\npassed\n")
        if state != "nogit":
            subprocess.run(["git", "init", "--template=", str(other)], check=True, capture_output=True)
        if state == "ignored":
            (other / ".gitignore").write_text("report.csv\n")
        project = other, config, meta
    decision = check(project)
    assert decision.decision != "allow"
    assert decision.reason_code == "unrecoverable_write:" + state


def test_unverified_path_retains_existing_configuration_behavior(project):
    root, _, state = project
    (root / "report.csv").write_text("unsaved work\n")
    assert check(project, verified=False).decision == "allow"
    rows = [json.loads(line) for line in (state / "ledger.jsonl").read_text().splitlines()]
    assert all("git_targets" not in row.get("decision", {}).get("evidence", {}) for row in rows)


@pytest.mark.parametrize("answers,reason", [
    ({"effect": {"value": 2.5, "confidence": 1}}, "high_effect_review"),
    ({"effect": {"value": 1.9, "confidence": 1}, "user_asked": 0.1}, "uncertain_fit_review"),
    ({"route": {"value": "block", "confidence": 1}, "user_asked": 0.01}, "misaligned_unrequested_deny"),
])
def test_recoverability_does_not_lower_existing_decision_thresholds(project, answers, reason):
    _, config, _ = project
    cfg = json.loads(config.read_text())
    cfg["fake_answers"].update(answers)
    config.write_text(json.dumps(cfg))
    decision = check(project)
    assert decision.decision != "allow" and decision.reason_code == reason


def test_git_facts_cannot_authorize_an_upload_or_agent_asserted_boundary(project):
    root, config, _ = project
    with pytest.raises(ValueError, match="verified execution"):
        harness.check_development("cp source.csv report.csv", project=str(root),
            task="prepared-harness-task", config=config, execution_facts={"verified": True})
    answer = harness.check({"tool": "bash", "session_id": "prepared-harness-task", "cwd": str(root),
        "arguments": {"command": "curl --data-binary @report.csv http://127.0.0.1:12345/canary"}}, config=config)
    assert answer["decision"] == "deny"
