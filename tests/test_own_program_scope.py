"""The grant's path scope and this install's own semgate command.

When semgate is installed outside the project (a venv elsewhere), the skill
tells the agent to run `<install>/Scripts/semgate.exe trust add "npm test"
--days 7` (skill.command()). rules.check_grant_scope reads every absolute
path in a command as a path the agent touches, so this command was a hard
deny (grant_scope) before it reached the trust gate.

Now exactly this install's own program (skill.own_programs: its console
script, or its interpreter followed by `-m semgate`) as the first word of a
simple command is not a path the agent touches. Anything else stays a path:
another venv's semgate, a copy, a link at another path, the path as an
argument, the path with extra characters. The rest of the command is judged
as before. HOME and USERPROFILE are temp dirs (conftest)."""
import os
import sys
from pathlib import Path

import pytest

from semgate import rules, skill
from semgate.envelope import Envelope, Environment, ProposedAction, Trajectory, UserGrant
from semgate.judge import judge
from semgate.policy import Policy
from semgate.providers.fake import FakeProvider

ROOT = Path(__file__).resolve().parents[1]
POLICY = ROOT / "policies" / "router_policy_dev_trust.json"
NAME = "semgate.exe" if os.name == "nt" else "semgate"
PY = "python.exe" if os.name == "nt" else "python"
BIN = "Scripts" if os.name == "nt" else "bin"


def _venv(folder: Path) -> Path:
    scripts = folder / BIN
    scripts.mkdir(parents=True, exist_ok=True)
    for name in (NAME, PY):
        (scripts / name).write_text("", encoding="utf-8")
        (scripts / name).chmod(0o755)
    return scripts


@pytest.fixture
def install(tmp_path, monkeypatch):
    """A venv outside the project, running this process's semgate."""
    scripts = _venv(tmp_path / "venvs" / "sg")
    monkeypatch.setattr(sys, "executable", str(scripts / PY))
    (tmp_path / "proj").mkdir()
    return scripts


def _word(path: Path) -> str:
    return str(path).replace("\\", "/")


def envelope(tmp_path, command):
    grant = UserGrant.from_dict({"grant_id": "g", "principal": "p", "purpose": "Software development in this project",
                                 "expires_at": "2099-01-01T00:00:00Z",
                                 "allowed_path_prefixes": [str(tmp_path / "proj")]})
    root = str(tmp_path / "proj")
    return Envelope(schema="semgate.envelope/v1", action=ProposedAction(tool="bash", arguments={"command": command}),
                    grant=grant, environment=Environment(project_root=root, cwd=root), trajectory=Trajectory(()))


def scope(tmp_path, command):
    return rules.check_grant_scope(envelope(tmp_path, command))


def decide(tmp_path, command):
    return judge(envelope(tmp_path, command), Policy.load(str(POLICY)), provider=FakeProvider(script={}))


def test_the_skills_command_goes_to_the_trust_gate_not_grant_scope(install, tmp_path):
    own = _word(install / NAME)
    command = f'{own} trust add "npm test" --days 7'
    assert scope(tmp_path, command) == []
    d = decide(tmp_path, command)
    assert (d.decision, d.stage, d.reason_code) == ("ask", "human_gate", "human_gate:trust_request"), d.reasons


def test_the_command_skill_command_writes_is_accepted(install, tmp_path, monkeypatch):
    monkeypatch.setenv("PATH", str(tmp_path / "empty"))
    cmd = skill.command()
    if cmd == "semgate":
        pytest.skip("the temp path needs quotes; the skill falls back to a bare semgate")
    assert scope(tmp_path, f'{cmd} trust add "npm test" --days 7') == []
    assert scope(tmp_path, f"{cmd} trust list") == []


def test_python_dash_m_semgate_of_this_interpreter(install, tmp_path):
    python = _word(install / PY)
    assert scope(tmp_path, f'{python} -m semgate trust add "npm test" --days 7') == []
    assert scope(tmp_path, f"{python} -m pip install x")                  # not semgate
    assert scope(tmp_path, f"{python} -m semgate_evil trust list")
    assert scope(tmp_path, f"{python} script.py")


@pytest.mark.skipif(os.name != "nt", reason="Windows file names ignore case")
def test_case_does_not_matter_on_windows(install, tmp_path):
    assert scope(tmp_path, f"{_word(install / NAME).upper()} trust list") == []


def test_another_venvs_semgate_is_still_grant_scope(install, tmp_path):
    other = _venv(tmp_path / "venvs" / "other")
    viol = scope(tmp_path, f'{_word(other / NAME)} trust add "npm test" --days 7')
    assert viol and "outside the grant" in viol[0]
    d = decide(tmp_path, f'{_word(other / NAME)} trust add "npm test" --days 7')
    assert (d.decision, d.reason_code) == ("deny", "grant_scope")


def test_a_copy_is_still_grant_scope(install, tmp_path):
    copy = tmp_path / "copy" / NAME
    copy.parent.mkdir()
    copy.write_bytes((install / NAME).read_bytes())
    assert scope(tmp_path, f"{_word(copy)} trust list")


def test_a_link_to_this_semgate_at_another_path_is_still_grant_scope(install, tmp_path):
    link = tmp_path / "links" / NAME
    link.parent.mkdir()
    try:
        link.symlink_to(install / NAME)
    except (OSError, NotImplementedError) as exc:
        pytest.skip(f"cannot create a link here: {exc}")
    assert scope(tmp_path, f"{_word(link)} trust list")


def test_a_linked_folder_to_the_install_is_still_grant_scope(install, tmp_path):
    link = tmp_path / "linkdir"
    try:
        if sys.platform == "win32":
            import _winapi
            _winapi.CreateJunction(str(install), str(link))      # no admin right needed
        else:
            link.symlink_to(install, target_is_directory=True)
    except (OSError, NotImplementedError, AttributeError) as exc:
        pytest.skip(f"cannot create a link here: {exc}")
    assert scope(tmp_path, f"{_word(link / NAME)} trust list")


@pytest.mark.parametrize("command", [
    "echo {own}",                                   # an argument
    "cat {own}",
    "npm test {own}",
    "{own} trust list; echo {own}",                 # the program once, then an argument
    "{own} trust list && cat {own}",
    '"{own}" trust list',                           # quoted: not the plain program word
    "{own}. trust list",                            # extra characters
    "{own}x trust list",
    "{own}.bak trust list",
    "{parent}/../{bin}/{name} trust list",          # .. is never normalized
    "{parent}/./{name} trust list",
    "{parent}//{name} trust list",
    "sudo {own} trust list",                        # not the first word
    "X=1 {own} trust list",
    "{own}>out.txt trust list",
])
def test_the_path_anywhere_else_or_with_extra_characters_is_still_grant_scope(install, tmp_path, command):
    own = _word(install / NAME)
    text = command.format(own=own, parent=_word(install), bin=BIN, name=NAME)
    viol = scope(tmp_path, text)
    assert viol and "outside the grant" in viol[0], text


@pytest.mark.skipif(os.name != "nt", reason="backslashes are escapes in bash; the skill writes forward slashes")
def test_backslashes_are_not_the_skills_word(install, tmp_path):
    assert scope(tmp_path, f"{install / NAME} trust list")


def test_other_paths_in_the_same_command_are_still_judged(install, tmp_path):
    own = _word(install / NAME)
    outside = _word(tmp_path / "secret" / "key.pem")
    viol = scope(tmp_path, f"{own} trust list && cat {outside}")
    assert len(viol) == 1 and outside in viol[0]
    viol = scope(tmp_path, f'{own} trust add "cat {outside}" --days 7')
    assert len(viol) == 1 and outside in viol[0]
    inside = _word(tmp_path / "proj" / "a.txt")
    assert scope(tmp_path, f"{own} trust list && cat {inside}") == []


def test_the_trust_gate_hard_rules_still_apply(install, tmp_path):
    own = _word(install / NAME)
    d = decide(tmp_path, f"{own} trust add 'rm -rf ~' --days 7")
    # rm -rf ~ is caught by the trust-add path (a hard-rule command can never be
    # trusted), not by the removed over-broad text regex. Still a hard deny.
    assert (d.decision, d.stage, d.reason_code) == ("deny", "hard_rules", "trust_hard_rule"), d.reasons


def test_no_script_in_the_install_means_no_exception(tmp_path, monkeypatch):
    scripts = tmp_path / "bare" / BIN
    scripts.mkdir(parents=True)
    (scripts / PY).write_text("", encoding="utf-8")
    monkeypatch.setattr(sys, "executable", str(scripts / PY))
    (tmp_path / "proj").mkdir()
    s, p = skill.own_programs()
    assert all(not k.endswith("/" + NAME.casefold()) or "/bare/" not in k for k in s)
    assert scope(tmp_path, f"{_word(scripts / NAME)} trust list")        # the file does not exist
