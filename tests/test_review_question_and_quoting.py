"""Protect trusted definitions and native argument syntax with synthetic data."""
from copy import deepcopy
import json
from pathlib import Path
import shutil
import subprocess
import sys
from types import SimpleNamespace

import pytest

from semgate import Gate, router, sendclient
from semgate.devworker import VerifiedOfflineFacts
from semgate.judge import judge
from semgate.privacy import PrivacyGate
from semgate.providers.base import ProviderError
from semgate.providers.fake import FakeProvider
from semgate.providers.safe import configured, for_envelope
from semgate.workerquestions import contextualize
from test_harness_api import ALLOWING

ROOT = Path(__file__).resolve().parents[1]
QUOTES = "'\u2018\u2019\u201a\u201b"
CFG = {"privacy_gate": {"enabled": True, "allow_remote": True, "require_prepared": True}}


class Capture(FakeProvider):
    def __init__(self):
        super().__init__(ALLOWING)
        self.inputs = []

    def evaluate(self, state, questions):
        self.inputs.append(deepcopy((state, questions)))
        return super().evaluate(state, questions)


@pytest.mark.parametrize("private_value", [0, 1, 2, "run", "allow", "score"])
def test_private_payload_cannot_rewrite_core_permission_definitions(tmp_path, private_value):
    gate = Gate("Create the synthetic fixture", provider="none",
                policy=str(ROOT / "policies/router_policy_dev.json"), project_root=str(tmp_path),
                privacy_gate=PrivacyGate(allow_remote=True, require_prepared=True))
    envelope = gate.envelope("", tool="write",
        arguments={"path": str(tmp_path / "record.json"), "content": json.dumps({"ssn": private_value})},
        user_message="Create the synthetic fixture")
    raw = Capture()
    provider = for_envelope(configured(raw, CFG), envelope, offline_shell=True)
    judge(envelope, gate.policy, provider=provider, privacy_gate=gate.privacy_gate,
          trusted_offline_shell=True, trusted_execution_facts=VerifiedOfflineFacts("0.12.0", "a" * 64))
    assert len(raw.inputs) == 1
    state, questions = raw.inputs[0]
    expected = contextualize(router.questions(gate.policy), literal_write=True)
    for key in questions:
        if key in expected:
            assert questions[key] == expected[key]
    assert "<PRIVATE_IDENTITY_" in json.dumps(state)


def test_configured_boundary_preserves_numeric_definition_without_disclosing_private_value():
    raw = Capture()
    questions = {"q": {"type": "score", "instructions": "Choose level 1 when relevant.",
                       "criteria": ["level 0", "level 1"]}}
    configured(raw, CFG).evaluate({"record": {"ssn": 1}}, questions)
    state, sent_questions = raw.inputs[0]
    assert state["record"]["ssn"] != 1
    assert sent_questions == questions


def test_configured_boundary_abstains_if_trusted_definition_itself_contains_pii():
    raw = Capture()
    with pytest.raises(ProviderError):
        configured(raw, CFG).evaluate({}, {"q": {"instructions": "synthetic@example.test"}})
    assert not raw.inputs


@pytest.mark.parametrize("quote", QUOTES[1:])
def test_unescaped_smart_quote_is_not_a_verified_client_invocation(tmp_path, monkeypatch, quote):
    monkeypatch.setattr(sendclient, "os", SimpleNamespace(name="nt"))
    connection = tmp_path / ".semgate" / "client.json"
    target = "echo " + quote + "$(Write-Output SYNTHETIC_MARKER)" + quote
    arguments = [Path(sys.executable).as_posix(), "-I", Path(sendclient.__file__).resolve().as_posix(),
                 "run", target, "--connection", connection.resolve().as_posix()]
    unsafe = "& " + " ".join("'" + arg.replace("'", "''") + "'" for arg in arguments)
    envelope = SimpleNamespace(action=SimpleNamespace(tool="powershell", arguments={"command": unsafe}))
    config = {"prepared_sends": {"enabled": True, "development": {}, "client_file": str(connection)}}
    assert not sendclient.verified_invocation(envelope, config)
    envelope.action.arguments["command"] = sendclient.development_invocation(target, connection)
    assert sendclient.verified_invocation(envelope, config)
    envelope.action.arguments["command"] += "; Write-Output SYNTHETIC_MARKER"
    assert not sendclient.verified_invocation(envelope, config)


def test_windows_client_arguments_are_literal_in_actual_powershell_parser(tmp_path, monkeypatch):
    powershell = shutil.which("pwsh") or (shutil.which("powershell") if sys.platform == "win32" else None)
    if powershell is None:
        pytest.skip("PowerShell parser unavailable; this check is exercised on Windows CI")
    monkeypatch.setattr(sendclient, "os", SimpleNamespace(name="nt"))
    invocations, expected = [], []
    for quote in QUOTES:
        connection = tmp_path / ("operator" + quote + "data") / ".semgate" / "client.json"
        python = tmp_path / ("python" + quote + "tool")
        for target in ("echo " + quote + "; Write-Output SYNTHETIC_MARKER; #",
                       "echo " + quote + "$(Write-Output SYNTHETIC_MARKER)" + quote,
                       "echo " + quote * 3 + " ` $HOME \r\n literal \u201c\u201d\u201e"):
            invocations.append(sendclient.development_invocation(target, connection, python=python))
            expected.append([python.as_posix(), "-I", Path(sendclient.__file__).resolve().as_posix(),
                             "run", target, "--connection", connection.resolve().as_posix()])
    # Only ParseInput is called: generated invocations are stdin data, never executed.
    process = subprocess.run([powershell, "-NoLogo", "-NoProfile", "-NonInteractive", "-File",
                              str(ROOT / "tests/helpers/parse_literal_command.ps1")],
                             input=json.dumps(invocations), text=True, encoding="utf-8",
                             capture_output=True, timeout=30, check=True)
    parsed = json.loads(process.stdout)
    assert len(parsed) == len(expected)
    for index, (actual, values) in enumerate(zip(parsed, expected)):
        assert actual["errorCount"] == 0, (index, actual)
        assert actual["statementCount"] == actual["commandCount"] == 1, (index, actual)
        assert actual["elementTypes"] == ["StringConstantExpressionAst"] * 7, (index, actual)
        assert actual["values"] == values, (index, actual)
