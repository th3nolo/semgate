"""Literal writes keep permission thresholds and cannot acquire host authority."""
from dataclasses import replace
import json
from pathlib import Path

import pytest

from semgate import codexrunner, harness
from semgate.devworker import OfflineWorker, VerifiedOfflineFacts, validate_write
from semgate.envelope import ProposedAction
from semgate.judge import judge
from semgate.policy import Policy
from semgate.providers.fake import FakeProvider
from semgate.providers.safe import SafeProvider
from test_development_harness import enable
from test_harness_api import ALLOWING
from test_http_serve import server, call, AUTH
from test_prepared_harness import configuration
from test_prepared_send import endpoint
from test_test_run import env, Recording

FACTS = VerifiedOfflineFacts("0.12.0", "a"*64)
POLICY = Policy.load(str(Path(__file__).parents[1]/"policies/router_policy_dev.json"))


@pytest.mark.parametrize("change", [
    {"path":"../outside"}, {"path":"/outside"}, {"path":"a//b"}, {"path":"a/./b"},
    {"path":"C:outside"}, {"path":"a\\b"}, {"path":".semgate/grant.json"},
    {"path":"a/.GIT/config"}, {"path":".agents/skill"}, {"path":".venv/bin/python"},
    {"content":"x"*4097}, {"content":"\u00e9"*2049}, {"content":"a\0b"},
    {"content":[]}, {"approved":True},
])
def test_invalid_write_never_reaches_broker(monkeypatch, change):
    def forbidden(*args):
        pytest.fail("invalid write reached the broker")
    monkeypatch.setattr(codexrunner.sendclient,"request",forbidden)
    answer = codexrunner.execute_tool(Path("unused"),"semgate_write",{"path":"report.csv","content":"data",**change})
    assert answer["disposition"] == "service_error"


def test_dynamic_tool_sends_literal_data_unchanged(monkeypatch):
    seen = []
    monkeypatch.setattr(codexrunner.sendclient,"request",lambda *args: seen.append(args) or {"disposition":"deny"})
    data = {"path":"report.csv","content":"$(touch escaped); __import__('os').system('bad')\n"}
    codexrunner.execute_tool(Path("client"),"semgate_write",data)
    assert seen == [(Path("client"),"write",data)]
    schema = next(v["inputSchema"] for v in codexrunner.tool_specs() if v["name"] == "semgate_write")
    assert schema["required"] == ["path","content"] and schema["additionalProperties"] is False


def test_pii_write_is_minimized_before_remote_permission_call():
    raw = "synthetic.changed@example.test"
    envelope = replace(env("",user="Create a local synthetic privacy fixture."),
        action=ProposedAction(tool="write",arguments={"path":"report.csv","content":"email\n"+raw+"\n"}))
    provider = Recording()
    judge(envelope,POLICY,provider=SafeProvider(provider),trusted_offline_shell=True,trusted_execution_facts=FACTS)
    assert len(provider.states) == 1
    state = provider.states[0]
    assert raw not in json.dumps(state) and "literal UTF-8 data" in state["execution_boundary"]
    assert "PRIVATE_EMAIL" in state["command"]


@pytest.mark.parametrize("change", [{"effect":{"value":1,"confidence":0.49}},
                                   {"executes":{"value":1.5,"confidence":1}}])
def test_literal_writer_does_not_bypass_existing_thresholds(change):
    envelope = replace(env("",user="Create a local privacy fixture."),
        action=ProposedAction(tool="write",arguments={"path":"report.csv","content":"email\ndata\n"}))
    result = judge(envelope,POLICY,provider=FakeProvider({**ALLOWING,**change}),
                   trusted_offline_shell=True,trusted_execution_facts=FACTS)
    assert result.decision != "allow"


def test_denied_permission_and_worker_outage_have_no_writer_fallback(server,tmp_path,endpoint,monkeypatch):
    url, received = endpoint
    config, state = configuration(tmp_path,url)
    enable(config)
    cfg = json.loads(config.read_text())
    grant = json.loads((state/"grant.json").read_text())
    grant["forbidden_patterns"] = ["blocked-local.txt"]
    (state/"grant.json").write_text(json.dumps(grant))
    cfg["enforcement"]["auto_allow_tools"].append("write")
    config.write_text(json.dumps(cfg))
    monkeypatch.setattr(OfflineWorker,"verify",lambda *a,**kw: FACTS)
    def forbidden(*a,**kw):
        pytest.fail("denied action reached writer")
    monkeypatch.setattr(OfflineWorker,"write",forbidden)
    port, _, _ = server(config)
    status,result,_ = call(port,"POST","/v1/send/write",{"path":"blocked-local.txt","content":"data"},AUTH)
    assert status == 200 and result["disposition"] == "deny"
    assert not (tmp_path/"blocked-local.txt").exists() and not received
    def outage(*a,**kw):
        raise RuntimeError("synthetic worker outage")
    monkeypatch.setattr(OfflineWorker,"write",outage)
    status,result,_ = call(port,"POST","/v1/send/write",{"path":"report.csv","content":"changed"},AUTH)
    assert status == 503 and result["disposition"] == "service_error", result
    assert (tmp_path/"report.csv").read_bytes() == b"status\nready\n" and not received
    status,_,_ = call(port,"POST","/v1/send/write",{"path":"report.csv","content":"changed","approved":True},AUTH)
    assert status == 503
