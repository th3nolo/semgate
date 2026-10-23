"""The host executor cannot acquire authority through advisory failure or input."""
import json
import os
from pathlib import Path
import subprocess
import sys
import time

import pytest

from semgate import codexrunner as runner


@pytest.mark.parametrize("name,arguments,namespace", [
    ("exec_command", {"cmd": "echo escaped"}, None),
    ("apply_patch", {"patch": "anything"}, None),
    ("semgate_run", {"command": "echo test", "backend": "host"}, None),
    ("semgate_run", {"command": "echo test", "offline_shell": True}, None),
    ("semgate_run", {"command": "echo test"}, "another_server"),
    ("semgate_run", {"command": ""}, None),
    ("semgate_run", {"command": "x"*4097}, None),
    ("semgate_run", {"command": "a\0b"}, None),
    ("semgate_prepare", {"route": "https://attacker.test"}, None),
    ("semgate_prepare", {"route": "report", "destination": "https://attacker.test"}, None),
    ("semgate_dispatch", {"prepared_id": "not_an_opaque_id"}, None),
    ("semgate_dispatch", {"prepared_id": "a"*32, "approved": True}, None),
    ("semgate_consent", {"action": "approve"}, None),
])
def test_untrusted_authority_never_reaches_broker(monkeypatch, name, arguments, namespace):
    def forbidden(*args):
        pytest.fail("invalid invocation reached the broker")
    monkeypatch.setattr(runner.sendclient, "request", forbidden)
    assert runner.execute_tool(Path("unused"), name, arguments, namespace=namespace)["disposition"] == "service_error"


@pytest.mark.parametrize("failure", [TimeoutError, ConnectionRefusedError, ValueError])
def test_broker_failure_has_no_host_fallback(monkeypatch, tmp_path, failure):
    command = f"echo escaped > {tmp_path/'escaped'}"
    def fail(*args):
        raise failure("synthetic failure")
    monkeypatch.setattr(runner.sendclient, "request", fail)
    result = runner.execute_tool(tmp_path/"client.json", "semgate_run", {"command": command})
    assert result["disposition"] == "service_error" and not (tmp_path/"escaped").exists()


@pytest.mark.parametrize("name,key,value,action", [
    ("semgate_run", "command", "python3 -m unittest", "run"),
    ("semgate_prepare", "route", "diagnostics", "prepare"),
    ("semgate_dispatch", "prepared_id", "a"*32, "dispatch"),
])
def test_valid_calls_use_existing_broker_contract(monkeypatch, tmp_path, name, key, value, action):
    seen = []
    monkeypatch.setattr(runner.sendclient, "request", lambda *args: seen.append(args) or {"disposition": "deny"})
    assert runner.execute_tool(tmp_path/"client.json", name, {key: value}) == {"disposition": "deny"}
    assert seen == [(tmp_path/"client.json", action, value)]


def runtime_config():
    return {"features": dict.fromkeys(runner.DISABLED_FEATURES, False), "web_search": "disabled", "mcp_servers": {}, "plugins": {}}


def test_entrypoint_forwards_isolated_environment_and_observer_without_mutating_parent(tmp_path,monkeypatch):
    from test_prepared_harness import configuration
    from test_development_harness import enable
    project=tmp_path/'project';project.mkdir()
    config,_=configuration(project,'http://127.0.0.1:1234/report');enable(config)
    state=tmp_path/'state';state.mkdir()
    cfg=json.loads(config.read_text());prompt=cfg['prepared_sends']['task_context']['request']
    parent=dict(os.environ);selected={'SystemRoot':'synthetic-system','KEY':'synthetic-model'};seen=[];events=[]
    class Fake:
        def __init__(self,*a,**kw):seen.append(kw);self.event=kw['event']
        def run(self,p):
            assert p==prompt
            self.event({'method':'semgate/receipt','params':{'tool':'semgate_run','arguments':{'command':'pwd'},'receipt':{'disposition':'deny'}}})
            return {'status':'completed'}
    monkeypatch.setattr(runner,'CodexRunner',Fake)
    result=runner.main(['--config',str(config),'--state-dir',str(state),'--model','test-model','--base-url',
        'http://127.0.0.1:1234/v1','--env-key','KEY','--codex-bin',str(sys.executable),prompt],event=events.append,env=selected)
    assert result==0 and seen[0]['env'] is selected and events[0]['params']['arguments']=={'command':'pwd'}
    assert dict(os.environ)==parent


@pytest.mark.parametrize("change", [
    {"mcp_servers": {"other": {"command": "bad"}}}, {"plugins": {"other": {"enabled": True}}},
    {"web_search": "live"}, {"features": {"shell_tool": False}},
    {"features": dict.fromkeys(runner.DISABLED_FEATURES, True)},
])
def test_managed_ambient_capability_rejects_start(change):
    with pytest.raises(ValueError, match="ambient"):
        runner.validate_runtime({**runtime_config(), **change})


def test_fresh_runtime_does_not_inherit_host_keys(tmp_path, monkeypatch):
    home = runner.create_home(tmp_path, model="model", base_url="http://127.0.0.1:1234/v1", env_key="MODEL_KEY")
    monkeypatch.setenv("UNRELATED_SECRET", "synthetic-do-not-inherit")
    client = runner.CodexRunner(Path(sys.executable), home, tmp_path/"client.json", project=tmp_path/"project",
                                env={**os.environ, "MODEL_KEY": "synthetic-model-key"})
    assert "UNRELATED_SECRET" not in client.env and client.env["MODEL_KEY"] == "synthetic-model-key"
    assert all(Path(client.env[key]) == home for key in ("CODEX_HOME", "HOME", "USERPROFILE", "APPDATA", "TEMP"))



@pytest.mark.parametrize("url", ["http://example.test/v1", "https://user:password@example.test/v1", "https://example.test/v1?redirect=x"])
def test_provider_cannot_add_unreviewed_url_components(tmp_path, url):
    with pytest.raises(ValueError):
        runner.create_home(tmp_path, model="model", base_url=url, env_key="MODEL_KEY")
    assert not list(tmp_path.iterdir())


@pytest.mark.parametrize("ending", ["exit", "hang", "invalid", "native"])
def test_real_protocol_process_failure_cannot_execute_native_requests(monkeypatch, tmp_path, ending):
    home = runner.create_home(tmp_path, model="model", base_url="http://127.0.0.1:1234/v1", env_key="MODEL_KEY")
    fake = tmp_path/"fake_app_server.py"
    fake.write_text("\n".join([
        "import json,sys,time", f"cfg={runtime_config()!r}", f"ending={ending!r}",
        "for raw in sys.stdin:", " msg=json.loads(raw); method=msg.get('method')",
        " if method=='initialize': value={}",
        " elif method=='config/read': value={'config':cfg}",
        " elif method=='thread/start':",
        "  assert msg['params']['environments']==[]", "  value={'thread':{'id':'thread'}}",
        " elif method=='turn/start':",
        "  assert msg['params']['environments']==[]", "  value={'turn':{'id':'turn'}}",
        " else: continue",
        " print(json.dumps({'id':msg['id'],'result':value}),flush=True)",
        " if method!='turn/start': continue",
        " if ending=='exit': sys.exit(7)",
        " if ending=='hang': time.sleep(30)",
        " if ending=='invalid': print('not JSON',flush=True); sys.exit(0)",
        " if ending=='native':",
        "  print(json.dumps({'method':'item/commandExecution/requestApproval','id':100,'params':{'command':'echo escaped'}}),flush=True)",
        "  answer=json.loads(sys.stdin.readline()); assert 'error' in answer",
        "  print(json.dumps({'method':'item/tool/call','id':101,'params':{'threadId':'thread','callId':'native','tool':'exec_command','arguments':{'cmd':'echo escaped'}}}),flush=True)",
        "  answer=json.loads(sys.stdin.readline()); assert answer['result']['success']==False",
        "  print(json.dumps({'method':'turn/completed','params':{'threadId':'thread','turn':{'status':'completed'}}}),flush=True)",
        "  sys.stdin.read()", ""]))
    original = runner.proc.popen
    processes = []
    def start(*args, **kwargs):
        child = original([sys.executable, "-I", str(fake)], **kwargs)
        processes.append(child)
        return child
    monkeypatch.setattr(runner.proc, "popen", start)
    monkeypatch.setattr(runner.proc, "run", lambda *a, **kw: subprocess.CompletedProcess(a, 0, "codex-cli 0.153.1\n", ""))
    monkeypatch.setattr(runner.sendclient, "request", lambda *a: pytest.fail("native request reached broker"))
    client = runner.CodexRunner(Path(sys.executable), home, tmp_path/"client.json", project=tmp_path/"project", timeout_s=1)
    started = time.monotonic()
    if ending == "native":
        assert client.run("test")["status"] == "completed"
    else:
        with pytest.raises((RuntimeError, TimeoutError)):
            client.run("test")
    assert time.monotonic()-started < 10 and all(p.poll() is not None for p in processes)
