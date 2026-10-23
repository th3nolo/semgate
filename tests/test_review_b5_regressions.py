"""Defensive privacy/evidence regressions with isolated pytest homes and stores."""
import json
import os
import subprocess
import sys

import pytest

from semgate import harness, secretfinder, testrun
from semgate.cachecleanup import PROGRAM
from semgate.privacy import PrivacyGate
from semgate.privacydata import Minimizer, safe_inputs
from semgate.privacyinspect import inspect
from semgate.providers.fake import FakeProvider
from semgate.sendharness import PreparedBroker
from semgate.scriptsource import SyntheticWorkspace
from semgate.trustauth import Auth
from test_harness_api import ALLOWING
from test_prepared_harness import configuration
from test_prepared_send import sender_for
from test_test_run import env, R


@pytest.mark.parametrize("field", ["api_key", "password", "bearer_token", "auth"])
def test_structured_secret_context_minimizes_values_everywhere(field):
    value = "aB3dE5gH7jK9mN2pQ4sT6vW8xY0zA1bC"
    assert secretfinder.find(json.dumps({field: value}))
    cleaner = Minimizer()
    assert value not in json.dumps(cleaner.clean({field: value}))
    assert cleaner.counts["secret"] == 1
    state, questions = safe_inputs({"reference": value, "record": {field: value}}, {"q": {"instructions": value}})
    assert value not in json.dumps([state, questions])
    assert state["reference"] == state["record"][field]
    ordinary, _ = safe_inputs({"cache_key": value, "api_key_name": value}, {})
    assert ordinary == {"cache_key": value, "api_key_name": value}


def test_numeric_pii_is_scanned_without_masking_ordinary_numbers():
    state, _ = safe_inputs({"card_number": 4111111111111111, "count": 42, "ratio": 1.25, "enabled": True}, {})
    assert str(4111111111111111) not in json.dumps(state)
    assert state["card_number"].startswith("<PRIVATE_PAYMENT_CARD_")
    assert (state["count"], state["ratio"], state["enabled"]) == (42, 1.25, True)


@pytest.mark.parametrize("record,category", [
    ({"api_key": "aB3dE5gH7jK9mN2pQ4sT6vW8xY0zA1bC"}, "secret"),
    ({"card_number": 4111111111111111}, "payment_card"),
])
def test_inline_inspection_and_prepared_sender_add_structured_categories(tmp_path, record, category):
    class NoDelivery:
        def send(self, prepared):
            pytest.fail("diagnostics-only consent must not authorize this structured payload")
    sender = sender_for(tmp_path, transport=NoDelivery())
    envelope = sender.gate.envelope("", tool="http_request", arguments={"url": "https://example.test/report", "json": record})
    assert category in inspect(envelope).record()["categories"]
    prepared = sender.prepare(json.dumps(record).encode(), destination="https://example.test/report", source="synthetic",
                              categories=frozenset({"technical_diagnostics"}), classification_complete=True)
    assert category in prepared.categories
    request = sender.consents.evaluate(prepared.scope, frozenset({"technical_diagnostics"}), prepared.digest)
    sender.consents.approve(request.request_id, auth=Auth("test"))
    outcome = sender.send(prepared).outcome
    assert outcome.disposition == ("deny" if category == "secret" else "needs_consent")


@pytest.mark.parametrize("prepared", [False, True])
def test_auxiliary_profile_calls_receive_attachment_seeded_minimization(tmp_path, monkeypatch, prepared):
    config, state = configuration(tmp_path, "http://127.0.0.1:12345/report")
    name = "Synthetic Rowan"
    (tmp_path/"report.csv").write_text("name\n"+name+"\n")
    cfg = json.loads(config.read_text())
    cfg.update(provider="fake", fake_answers=ALLOWING, trust={"file": str(state/"trust.jsonl")},
               profiles={"enabled": True, "state_file": str(state/"profiles.json")})
    cfg["privacy_gate"].update(allow_remote=True, require_prepared=prepared)
    cfg["prepared_sends"]["task_context"]["request"] = "Send the approved diagnostic report for "+name+"."
    cfg["prepared_sends"]["routes"]["report"]["contract"] = {
        "format": "csv", "fields": {"name": {"enum": [name]}}, "max_rows": 1}
    config.write_text(json.dumps(cfg))
    seen = []
    original = FakeProvider.evaluate
    def observe(self, model_state, questions):
        seen.append(json.loads(json.dumps({"state": model_state, "questions": questions})))
        return original(self, model_state, questions)
    monkeypatch.setattr(FakeProvider, "evaluate", observe)
    monkeypatch.setattr(PrivacyGate, "_providers", lambda self: (
        FakeProvider({"privacy": {"value": "allow", "confidence": 1}}),
        FakeProvider({"privacy": {"value": "allow", "confidence": 1}})))
    if prepared:
        broker = PreparedBroker(str(config))
        try:
            assert broker.prepare("report")["disposition"] == "needs_consent"
        finally:
            broker.close()
    else:
        harness.check({"tool": "http_request", "arguments": {"url": "http://127.0.0.1:12345/report",
            "attachments": [str(tmp_path/"report.csv")]}, "project_root": str(tmp_path), "cwd": str(tmp_path),
            "session_id": "isolated-auxiliary", "user_messages": ["Send the diagnostic report for "+name+"."]}, config=config)
    assert any("user_request" in call["state"] for call in seen)
    assert name not in json.dumps(seen)


@pytest.mark.parametrize("command,files,expected", [
    ("python3 -m unittest discover -s tests -q", {"tests/test_sample.py": "import helper\n", "tests/helper.py": "value = 1\n"},
     {"tests/test_sample.py", "tests/helper.py"}),
    ("python3 -m unittest discover --start-directory=tests -q", {"tests/test_sample.py": "import helper\n", "tests/helper.py": "value = 1\n"},
     {"tests/test_sample.py", "tests/helper.py"}),
    ("python3 -m unittest discover -stests -q", {"tests/test_sample.py": "import helper\n", "tests/helper.py": "value = 1\n"},
     {"tests/test_sample.py", "tests/helper.py"}),
    ("python3 -m unittest discover -s tests -t . -q", {"tests/__init__.py": "value = 2\n", "tests/test_sample.py": "from tests import helper\n", "tests/helper.py": "value = 1\n"},
     {"tests/__init__.py", "tests/test_sample.py", "tests/helper.py"}),
    ("python3 -m unittest pkg.test_sample -q", {"pkg/__init__.py": "value = 2\n", "pkg/test_sample.py": "pass\n"},
     {"pkg/__init__.py", "pkg/test_sample.py"}),
    ("python3 -m unittest pkg.test_sample.TestSample.test_value -q", {"pkg/__init__.py": "value = 2\n", "pkg/test_sample.py": "pass\n"},
     {"pkg/__init__.py", "pkg/test_sample.py"}),
    ("python3 -m unittest pkg -q", {"pkg/__init__.py": "pass\n"}, {"pkg/__init__.py"}),
])
def test_unittest_collects_actual_local_import_roots_and_package_initializers(command, files, expected):
    evidence = testrun.collect(env(command), SyntheticWorkspace({R+"/"+path: body for path, body in files.items()}),
                               read_test_sources=True)
    assert not evidence.skipped
    assert expected <= {file.rel for file in evidence.files}


@pytest.mark.skipif(os.name != "posix", reason="POSIX directory descriptors")
@pytest.mark.parametrize("present", [False, True])
def test_fixed_cache_program_handles_projects_without_local_operator_state(tmp_path, present):
    if present:
        (tmp_path/"__pycache__").mkdir()
        (tmp_path/"__pycache__"/"keep.txt").write_text("retained synthetic data")
    program = PROGRAM.replace("'/workspace'", repr(str(tmp_path)), 1)
    result = subprocess.run([sys.executable, "-I", "-c", program], cwd=tmp_path, capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    receipt = json.loads(result.stdout)["cache_cleanup"]
    assert receipt["state"] == ("retained" if present else "absent")
    if present:
        saved = tmp_path/".semgate/cache-recovery"/receipt["recovery_id"]/"tree/keep.txt"
        assert saved.read_text() == "retained synthetic data"
    else:
        assert not (tmp_path/".semgate").exists()
