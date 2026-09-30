"""Catastrophic deletes and permission changes are a hard deny in every
spelling (semgate/catastrophic.py, called from rules.check_hard_deny).

Before (semgate 0.4.1) only `rm -rf /`, `rm -rf /*` and `rm -rf ~` in that
exact spelling were a hard deny. `rm -rf / --no-preserve-root`, `rm -fr /`,
`rm -r -f /` and the same inside bash -c or python -c were the human gate
destructive_irreversible: a person could approve them. The judge here is a
spy: a hard deny never asks it."""
import json
import time
from pathlib import Path

import pytest

from semgate import Gate, catastrophic, trust, trustauth
from semgate.envelope import Envelope, Environment, ProposedAction, SCHEMA_VERSION, Trajectory, UserGrant
from semgate.feedback import FeedbackStore
from semgate.judge import judge
from semgate.policy import Policy
from semgate.providers.base import JudgeProvider
from semgate.rules import check_hard_deny

ROOT = Path(__file__).resolve().parents[1]
DEV = ROOT / "policies" / "router_policy_dev.json"
PURPOSE = "Software development in this repository"
NPR = "sudo rm -rf / --no-preserve-root"


class SpyJudge(JudgeProvider):
    """Stands in for the LLM judge. Counts calls and gives no answers."""
    name = "spy"

    def __init__(self):
        self.calls = 0

    def evaluate(self, state, questions):
        self.calls += 1
        return {}


# Every line was ASK (human gate, approvable) on 0.4.1 unless marked "deny today".
DENY = [
    # deny today (the regexes); still deny, now also through the parsed rule
    "rm -rf /", "sudo rm -rf /", "rm -Rf /", "rm -rf /*", "rm -rf ~", "rm -rf ~/",
    # --no-preserve-root in any place
    "rm -rf / --no-preserve-root", NPR, "rm --no-preserve-root -rf /", "sudo rm -rf --no-preserve-root /",
    "sudo rm -r -f / --no-preserve-root", "sudo   rm  -rf   /   --no-preserve-root", "rm -rf --no-preserve-root /tmp/x",
    "rm -r --rec /x --no-pres",
    # flag spellings
    "rm -fr /", "rm -r -f /", "rm -R /", "rm -rfv /", "rm --recursive --force /", "rm -rf -- /", "rm / -rf",
    "rm -fr ~", "rm -r -f ~",
    # target spellings
    "rm -rf /;", "rm -rf //", "rm -rf '/'", 'rm -rf "/"', "rm -rf \\/", "rm -rf /.", "rm -rf /usr", "rm -rf /etc/",
    "rm -rf /var/*", "rm -rf /home/*", "rm -rf $HOME", 'rm -rf "${HOME}"/', "rm -rf ~/.", "rm -rf ~/*", "rm -rf ~/..",
    "rm -rf ~root", "rm -rf /home/me", "rm -rf /Users/me", "rm -rf /tmp/../usr", "rm -rf /{usr,etc}", "rm -rf /us*",
    # a Windows drive and its user folders (Git Bash, WSL, PowerShell's rm)
    "rm -rf /c", "rm -rf /mnt/c/Users/Manuel", "rm -r -Force C:\\", "rm -rf $env:USERPROFILE",
    # the program through quotes, escapes, paths and wrappers
    "\\rm -fr /", "'rm' -fr /", "/bin/rm -fr /", "/usr/bin/rm -fr /", '"C:\\Program Files\\Git\\usr\\bin\\rm.exe" -rf /',
    "busybox rm -fr /", "command rm -fr /", "exec rm -fr /", "doas rm -fr /", "sudo -u root rm -fr /",
    "sudo -s rm -fr /", "nice -n 10 rm -fr /", "ionice -c 3 rm -fr /", "stdbuf -oL rm -fr /", "time rm -fr /",
    "timeout 5 rm -fr /", "env X=1 rm -fr /", "nohup rm -fr /", "xargs rm -fr /",
    # code the command runs
    "bash -c 'rm -rf / --no-preserve-root'", "sh -c 'rm -fr /'", "bash -c 'sudo rm -rf / --no-preserve-root'",
    "python -c \"import os; os.system('rm -rf / --no-preserve-root')\"", "echo $(rm -fr /)", "echo `rm -fr /`",
    "su -c 'rm -rf / --no-preserve-root'", "watch 'rm -fr /'", "env -S 'rm -fr /'", "bash <<EOF\nrm -fr /\nEOF",
    # command lists and groups
    "echo ok && sudo rm -rf / --no-preserve-root", "true; rm -fr /", "true\nrm -fr /", "(rm -fr /)",
    "if rm -fr /; then :; fi", "cd / && rm -rf *", "cd ~ && rm -rf *", "cd && rm -rf ./*",
    # find
    "find / -delete", "sudo find /usr -delete", "find ~ -delete", "find / -exec rm -rf {} \\;",
    "find / -name '*.log' -delete", "find ~ -name '*' -delete", "find ~ ! -name keep -delete",
    "find ~ -not -name keep -delete", "find ~ -name a -o -name b -delete", "find ~ -regex '.*' -delete",
    "find /etc -type f -exec sh -c 'rm \"$1\"' _ {} \\;", "cd / && find . -delete",
    # recursive chmod, chown, chgrp
    "chmod -R 777 /", "sudo chmod -R 000 /etc", "chown -R me /usr", "chgrp -R staff /home", "chmod --recursive 755 /etc",
    "sudo chown -R me /{usr,home/me}",
    "find / -exec chmod 777 {} +",
    # a variable program with a literal catastrophic target (added after 0.4.2)
    "$R -rf /", "${RM} -rf /", "R=rm; $R -rf /", "sudo $R -rf /", "$R -rf ~", "$R --recursive --force /etc",
    # a listing piped to a recursive delete
    "find / | xargs rm -rf", "find / -print0 | xargs -0 rm -rf", "find ~ | xargs rm -rf",
    "find /usr -type f | xargs rm -f", "find / | xargs -0 rm -fr", "find /etc -type f | xargs rm",
    "find / -mount | xargs shred", "find ~ | xargs chmod -R 777",
    # a recursive delete through a library call, inline
    "python -c \"import shutil; shutil.rmtree('/')\"", "python -c \"import os; os.removedirs('/')\"",
    "python -c \"import subprocess; subprocess.run(['rm','-rf','/'])\"",
    "python -c \"import subprocess; subprocess.call(['rm','-fr','/'])\"",
    "python -c \"import shutil,pathlib; shutil.rmtree(pathlib.Path.home())\"",
    "python -c \"import shutil,os; shutil.rmtree(os.path.expanduser('~'))\"",
    "node -e \"require('fs').rmSync('/', {recursive: true})\"",
    "node -e \"const fs=require('fs'); fs.rmSync('/', {recursive:true, force:true})\"",
    "ruby -e \"require 'fileutils'; FileUtils.rm_rf('/')\"",
    # ANSI-C escapes in the program word
    "$'\\x72m' -rf /", "$'\\162m' -rf /", "$'\\x72\\x6d' -rf /",
    # PowerShell Remove-Item of the home folder
    "Remove-Item -Recurse $HOME", "Remove-Item -Recurse -Force -Path ~", "Remove-Item -Recurse ${HOME}",
    "ri -Recurse -Force $env:USERPROFILE",
]

# Not a hard deny from the new rule. Some are still a human gate (ask).
NOT_HARD_DENIED = [
    "rm -rf ./build", "rm -rf build/", "rm -r node_modules", "rm -rf /tmp/semgate-test", "rm -rf /home/me/project/build",
    "rm -rf /var/tmp/x", "rm -f /etc/hosts.bak", "rm -f /etc", "rm -rf /usr/local/lib/node_modules/foo",
    "rm -rf /mnt/c/Users/Manuel/Desktop/x", "rm -rf /tmp-semgate-*", "rm -rf /opt/myapp", "rm -rf *", "rm -rf ..",
    "find . -name '*.pyc' -delete", "find /tmp/x -delete", "find / -name foo", "chmod -R 755 ./dist",
    "chown -R me ./data", "cd / && chown -R root ./data", "chmod 755 /", "sudo chmod +x /usr/local/bin/x",
    # one user's home folder: a delete by name, or an ownership repair, is left to the human gate
    "find ~ -name .DS_Store -delete", "find ~ -name node_modules -exec rm -rf {} +", "find ~ -name '*.bak' -delete",
    "find /home/me -iname '*.pyc' -delete", "sudo chown -R $USER ~", "chgrp -R staff ~", "chmod -R go-w ~",
    'echo "rm -rf / --no-preserve-root"', 'grep -rn "rm -rf / --no-preserve-root" docs',
    'git commit -m "block rm -rf / --no-preserve-root"', "printf '%s\\n' 'sudo rm -fr /'",
    # the TARGET in a variable stays a human gate: a build script writes this with
    # $DIR set, so a hard deny would block real work (the ask still catches it)
    'rm -rf "$DIR/"', 'rm -rf "$DIR"/*', "rm -rf $DIR/*", "rm -rf ${BUILD}/",
    # a variable program with a non-catastrophic target: not rm-like enough to deny
    "$R -rf /home/me/project", "$R -rf ./build",
    # a listing piped to a delete, but the start folder is narrowed or safe
    "find ~ -name '*.bak' | xargs rm", "find /tmp/x | xargs rm -rf", "find . | xargs rm",
    "find ~ -iname node_modules | xargs rm -rf", "find /var/log | xargs gzip",
    # PowerShell Remove-Item of an in-project folder (needs a real catastrophic target)
    r"Remove-Item -Recurse -Force .\node_modules", r"Remove-Item C:\Users\me\Desktop\x.log",
    # the over-broad text regexes are gone: these mention a command but do not run it
    "grep -rn shutdown src/", 'git commit -m "fix reboot handling"', "echo rm -rf /",
    'git log --grep "rm -rf ~"', "rm -rf ~/project/build", "rm -rf /*.bak",
]


def _env(command, session="s1", root="/p"):
    grant = UserGrant(grant_id="g", principal="p", purpose=PURPOSE, expires_at="2099-01-01T00:00:00Z")
    return Envelope(schema=SCHEMA_VERSION, action=ProposedAction("bash", {"command": command}), grant=grant,
                    environment=Environment(project_root=root, cwd=root, session_id=session), trajectory=Trajectory())


@pytest.mark.parametrize("command", DENY)
def test_catastrophic_command_is_a_hard_deny_and_the_judge_is_never_asked(command):
    assert catastrophic.catastrophic_hit(command), command
    spy = SpyJudge()
    d = Gate(purpose=PURPOSE, provider=spy).check(command)
    assert (d.decision, d.stage, d.reason_code) == ("deny", "hard_rules", "hard_deny")
    assert spy.calls == 0


@pytest.mark.parametrize("command", NOT_HARD_DENIED)
def test_ordinary_deletes_and_text_that_mentions_the_command_are_not_hard_denied(command):
    assert catastrophic.catastrophic_hit(command) == ""
    d = Gate(purpose=PURPOSE, provider=SpyJudge()).check(command)
    assert not (d.decision == "deny" and d.stage == "hard_rules"), d.reasons


def test_the_reason_names_the_rule_and_the_command():
    hard = check_hard_deny(_env(NPR))
    assert hard.outcome == "deny" and hard.rule == "hard_deny"
    assert hard.detail == f"recursive rm of / with --no-preserve-root (catastrophic, irreversible): {NPR}"
    assert (catastrophic.catastrophic_hit("find ~ -delete")
            == "find ~ -delete (catastrophic, irreversible): find ~ -delete")
    assert (catastrophic.catastrophic_hit("chmod -R 777 /")
            == "recursive chmod of / (catastrophic, irreversible): chmod -R 777 /")


# ------------------------------------------------------------------ rm -rf * from / or home

@pytest.mark.parametrize("cwd", ["/", "/home/me", "/Users/me", "/mnt/c/Users/Manuel", r"C:\Users\Manuel"])
def test_rm_star_is_a_hard_deny_when_the_cwd_is_root_or_home(cwd):
    spy = SpyJudge()
    d = judge(_env("rm -rf *", root=cwd), Policy.load(str(DEV)), provider=spy)
    assert (d.decision, d.stage, d.reason_code) == ("deny", "hard_rules", "hard_deny"), (cwd, d.reasons)
    assert spy.calls == 0


@pytest.mark.parametrize("cwd", ["/p", "/home/me/project", "/tmp/work", r"C:\Users\Manuel\proj"])
def test_rm_star_is_not_a_hard_deny_from_an_ordinary_folder(cwd):
    d = judge(_env("rm -rf *", root=cwd), Policy.load(str(DEV)), provider=SpyJudge())
    assert not (d.decision == "deny" and d.stage == "hard_rules"), (cwd, d.reasons)


# ------------------------------------------------------------------ shutdown / reboot as a program

@pytest.mark.parametrize("command", ["shutdown", "sudo shutdown -h now", "shutdown -r now", "reboot", "sudo reboot",
                                     "bash -c 'reboot'", "Restart-Computer", "Stop-Computer -Force", "Stop-Computer"])
def test_shutdown_and_reboot_are_a_hard_deny_as_the_program(command):
    assert catastrophic.system_control_hit(command), command
    spy = SpyJudge()
    d = Gate(purpose=PURPOSE, provider=spy).check(command)
    assert (d.decision, d.stage) == ("deny", "hard_rules") and spy.calls == 0


@pytest.mark.parametrize("command", ["grep -rn shutdown src/", 'git commit -m "fix reboot handling"',
                                     "echo shutdown now", 'git log --grep "reboot"', "cat shutdown.md",
                                     "./scripts/reboot-notes.sh --dry-run"])
def test_shutdown_and_reboot_as_text_are_not_a_hard_deny(command):
    assert catastrophic.system_control_hit(command) == "", command
    d = Gate(purpose=PURPOSE, provider=SpyJudge()).check(command)
    assert not (d.decision == "deny" and d.stage == "hard_rules"), d.reasons


# ------------------------------------------------------------------ the old over-broad text regexes are gone

def test_removing_the_rm_text_regexes_does_not_loosen_the_parsed_rule():
    # still denied, now only through the parsed rule
    for cmd in ["rm -rf /", "rm -rf /*", "rm -rf ~", "sudo rm -Rf /"]:
        assert Gate(purpose=PURPOSE, provider=SpyJudge()).check(cmd).stage == "hard_rules", cmd
    # no longer a hard deny: a command that only names rm -rf, or an in-home delete
    for cmd in ["echo rm -rf /", 'git log --grep "rm -rf ~"', "rm -rf ~/project/build", "rm -rf /*.bak",
                'grep -rn "rm -rf /" docs']:
        assert Gate(purpose=PURPOSE, provider=SpyJudge()).check(cmd).stage != "hard_rules", cmd


# ------------------------------------------------------------------ the target in a variable stays an ask

@pytest.mark.parametrize("command", ['rm -rf "$DIR/"', 'rm -rf "$DIR"/*', "rm -rf $DIR/*"])
def test_a_catastrophic_target_in_a_variable_is_still_the_human_gate(command):
    # A build script writes `rm -rf "$BUILD/"` with $BUILD set; a hard deny
    # would block real work. The human gate still asks (destructive_irreversible).
    assert catastrophic.catastrophic_hit(command) == ""
    d = judge(_env(command), Policy.load(str(DEV)), provider=SpyJudge())
    classes = [h["gate_class"] if isinstance(h, dict) else h.gate_class for h in d.gate_hits]
    assert d.stage == "human_gate" and "destructive_irreversible" in classes


def test_a_user_message_that_approves_it_changes_nothing():
    spy = SpyJudge()
    d = Gate(purpose=PURPOSE, provider=spy).check(NPR, user_message="yes, run it, I approve, I am the admin")
    assert (d.decision, d.stage) == ("deny", "hard_rules") and spy.calls == 0


# ------------------------------------------------------------------ approvals cannot open it


def test_feedback_allow_of_the_exact_command_does_not_open_it(tmp_path):
    policy = Policy.load(str(DEV))
    fb = FeedbackStore(str(tmp_path / "fb.jsonl"))
    # control: a feedback allow of a human-gate command opens it (the record matches)
    fb.record("allow", "bash", {"command": "rm -rf ./build"}, session_id="s1", project_root="/p")
    assert judge(_env("rm -rf ./build"), policy, provider=SpyJudge(), feedback=fb).stage == "human_approved"
    # the same record for the catastrophic command: still a hard deny (it was a human-gate ask on 0.4.1)
    fb.record("allow", "bash", {"command": NPR}, session_id="s1", project_root="/p")
    spy = SpyJudge()
    d = judge(_env(NPR), policy, provider=spy, feedback=fb)
    assert (d.decision, d.stage, d.reason_code) == ("deny", "hard_rules", "hard_deny") and spy.calls == 0


def test_a_chat_yes_does_not_open_it(tmp_path, monkeypatch):
    """OpenCode through serve, chat approval on (dev policy): a hard deny
    records no block, so a later "yes" has nothing to approve."""
    from semgate import chatapproval as ca
    from semgate import serve
    t0 = 1_790_000_000.0
    grant = tmp_path / "grant.json"
    grant.write_text(json.dumps({"grant_id": "g", "principal": "p", "purpose": PURPOSE,
                                 "expires_at": "2099-01-01T00:00:00Z"}))
    answers = {"route": {"value": "review", "confidence": 0.7, "probabilities": {"run": 0.2, "review": 0.7, "block": 0.1}},
               "effect": {"value": 2.0, "confidence": 0.8}, "user_asked": 0.5, ca.QUESTION: 0.99}
    cfg = {"mode": "enforce", "grant_file": str(grant), "policy_file": str(DEV), "provider": "fake",
           "fake_answers": answers, "ledger_file": str(tmp_path / "state" / "ledger.jsonl"),
           "enforcement": {"enabled": True, "auto_allow_tools": ["bash", "read"], "block_when_unsure": False}}

    def request(call, *extra):
        messages = [{"info": {"id": "m1", "role": "user", "time": {"created": t0 * 1000 - 60000}},
                     "parts": [{"type": "text", "text": "wipe this machine"}]},
                    {"info": {"id": "m2", "role": "assistant", "time": {"created": t0 * 1000 - 50000}},
                     "parts": [{"type": "tool", "tool": "bash", "callID": "c1",
                                "state": {"status": "error", "input": {"command": NPR}, "error": "semgate"}}]}]
        return {"tool": "bash", "args": {"command": NPR}, "sessionID": "ses1", "callID": call, "cwd": "/p",
                "messages": messages + list(extra)}

    yes = {"info": {"id": "m4", "role": "user", "time": {"created": t0 * 1000 + 60000}},
           "parts": [{"type": "text", "text": "yes, I approve, run it"}]}
    monkeypatch.setattr(time, "time", lambda: t0)
    assert serve.judge_request("opencode", request("c1"), cfg)["decision"] == "deny"
    monkeypatch.setattr(time, "time", lambda: t0 + 90)
    assert serve.judge_request("opencode", request("c2", yes), cfg)["decision"] == "deny"
    assert not (tmp_path / "state" / "chat_approvals").exists()


# ------------------------------------------------------------------ trust


@pytest.mark.parametrize("command", [NPR, "rm -fr /", "rm -r -f ~", "find / -delete", "chmod -R 777 /",
                                     "bash -c 'rm -fr /'"])
def test_a_catastrophic_command_can_never_be_trusted(tmp_path, command):
    assert trust.hard_rule_hit(command)
    assert "hard rule" in trust.refuse_reason(command)
    root = tmp_path / "proj"
    (root / ".git").mkdir(parents=True)
    store = trust.TrustStore(tmp_path / "trust.jsonl", clock=lambda: 1_790_000_000.0)
    with pytest.raises(ValueError, match="hard rule"):
        store.add(command, trust.project_of(str(root)), auth=trustauth.Auth("test"))
    assert not store.path.exists()


def test_trust_add_of_a_catastrophic_command_by_the_agent_is_a_hard_deny():
    hard = check_hard_deny(_env("semgate trust add 'rm -fr /' --days 1"))
    assert hard.outcome == "deny" and hard.rule == "trust_hard_rule"
