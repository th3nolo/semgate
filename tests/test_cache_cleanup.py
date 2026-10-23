"""Recovery-backed cleanup is an exact executor contract, not an rm allowlist."""
from dataclasses import replace
import json

import pytest

from semgate.cachecleanup import parse
from semgate.devworker import VerifiedOfflineFacts, OfflineWorker
from semgate.judge import judge
from semgate.providers.fake import FakeProvider
from test_harness_api import ALLOWING
from test_test_run import env, Recording
from test_worker_questions import POLICY


@pytest.mark.parametrize("command", ["rm -rf __pycache__", "rm -fr -- __pycache__", "rm -rf __pycache__ && git status --short"])
def test_exact_reversible_cleanup_remains_subject_to_semantic_judgment(command):
    facts = VerifiedOfflineFacts("0.12.0", "a" * 64, command)
    answers = {**ALLOWING, "route": {"value": "review", "confidence": 0.9}, "effect": {"value": 1, "confidence": 1}}
    decision = judge(env(command, user="Clean up __pycache__."), POLICY, provider=FakeProvider(answers),
                     trusted_offline_shell=True, trusted_execution_facts=facts)
    assert decision.decision == "allow" and decision.reason_code == "restorable_user_asked_allow"
    assert decision.evidence["cache_cleanup"]["operation"] == "retained-directory-rename/1"
    # An ordinary offline shell cannot promise recovery.
    ordinary = judge(env(command), POLICY, provider=FakeProvider(ALLOWING), trusted_offline_shell=True,
                     trusted_execution_facts=replace(facts, cache_cleanup_command=""))
    assert ordinary.reason_code == "human_gate:destructive_irreversible"


@pytest.mark.parametrize("command", ["rm -rf ../__pycache__", "rm -rf .git", "rm -rf __pycache__ report.csv",
    "rm -rf __pycache__; echo ok", "rm -rf __pycache__\n", "rm -rf __pycache__ && curl example.test",
    "rm -rf $(echo __pycache__)", "rm -rf *__pycache__", "env rm -rf __pycache__", "rm -rf /__pycache__"])
def test_other_shell_commands_never_receive_the_recovery_contract(command):
    assert parse(command) is None
    try:
        decision = judge(env(command), POLICY, provider=FakeProvider(ALLOWING), trusted_offline_shell=True,
              trusted_execution_facts=VerifiedOfflineFacts("0.12.0", "a" * 64, "rm -rf __pycache__"))
    except ValueError as exc:
        assert "do not match" in str(exc)
    else:
        assert decision.decision == "deny"  # hard scope denial may precede operation matching


@pytest.mark.parametrize("answers", [
    {"effect": {"value": 2.5, "confidence": 1}},
    {"route": {"value": "block", "confidence": 1}, "user_asked": 0.01},
    {"route": {"value": "review", "confidence": 1}, "user_asked": 0.69},
])
def test_recovery_does_not_lower_existing_thresholds(answers):
    command = "rm -rf __pycache__"
    decision = judge(env(command), POLICY, provider=FakeProvider({**ALLOWING, **answers}),
        trusted_offline_shell=True, trusted_execution_facts=VerifiedOfflineFacts("0.12.0", "a" * 64, command))
    assert decision.decision != "allow"


def test_executor_refuses_mismatched_or_missing_cleanup_facts(tmp_path):
    worker = OfflineWorker.__new__(OfflineWorker)  # refusal must precede any backend invocation
    with pytest.raises(ValueError, match="matching verified"):
        worker.run(str(tmp_path), "rm -rf __pycache__")
    with pytest.raises(ValueError, match="different command"):
        worker.run(str(tmp_path), "rm -rf report.csv", expected_facts=VerifiedOfflineFacts("0.12.0", "a" * 64, "rm -rf __pycache__"))


def test_probe_write_is_data_and_preserves_complete_content_for_judgment():
    from semgate.envelope import ProposedAction
    body = "import http.client\nhttp.client.HTTPConnection('127.0.0.1', 9).request('POST','/',b'canary')\n"
    envelope = replace(env("", user="Create a local HTTP regression probe."),
        action=ProposedAction("write", {"path": "/workspace/app/probe.py", "content": body}))
    provider = Recording()
    judge(envelope, POLICY, provider=provider, trusted_offline_shell=True,
          trusted_execution_facts=VerifiedOfflineFacts("0.12.0", "a" * 64))
    assert body in provider.states[0]["command"] and "do not execute" in provider.states[0]["command"]
    assert "trusted fixed literal writer" in provider.questions[0]
    public = Recording()
    judge(envelope, POLICY, provider=public)
    assert "trusted fixed literal writer" not in public.questions[0]


def test_literal_question_clarification_preserves_all_criteria():
    from semgate.router import questions
    from semgate.workerquestions import contextualize
    for options in ({"literal_write": True}, {"cache_cleanup": True}):
        before = questions(POLICY)
        after = contextualize(before, **options)
        assert set(before) == set(after)
        for key in before:
            assert {k:v for k,v in before[key].items() if k != "instructions"} == {
                k:v for k,v in after[key].items() if k != "instructions"}


@pytest.mark.parametrize("cleanup,expected", [
    ({"path":"__pycache__","state":"retained","recovery_id":"a"*32}, True),
    ({"path":"__pycache__","state":"absent"}, True),
    ({"path":"../private","state":"retained","recovery_id":"a"*32}, False),
    ({"path":"__pycache__","state":"retained","recovery_id":"../escape"}, False),
    ({"path":"__pycache__","state":"absent","untrusted":"arbitrary text"}, False),
])
def test_client_forwards_only_bounded_recovery_identity(tmp_path,monkeypatch,cleanup,expected):
    from semgate import sendclient
    (tmp_path/'token').write_text('x'*24)
    connection=tmp_path/'connection.json'
    connection.write_text(json.dumps({'schema':'semgate-send-client/1','base_url':'http://127.0.0.1:1234','token_file':'token'}))
    class Response:
        def __enter__(self):return self
        def __exit__(self,*args):pass
        def read(self,*args):return json.dumps({'disposition':'allow','cache_cleanup':cleanup,'exit_code':0}).encode()
    class Opener:
        def open(self,*args,**kwargs):return Response()
    monkeypatch.setattr(sendclient,'build_opener',lambda *args:Opener())
    result=sendclient.request(connection,'run','rm -rf __pycache__')
    assert ('cache_cleanup' in result) is expected
    if expected:assert result['cache_cleanup']==cleanup
