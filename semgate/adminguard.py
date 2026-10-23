"""semgate's admin commands: only the user runs them, in their own terminal.

The admin commands change how semgate itself is installed or how strict it
is: `semgate init <host>` (writes semgate.json, grant.json and the host's
hook or plugin; `--mode shadow` turns enforcement off), `semgate uninstall
<host>` (removes the hook), `semgate harness init` (writes the approve
token). Later phases add install, enable, disable, migrate, project and
settings; they are in the list already.

Two checks, both needed (the same pair as `semgate trust`, trustauth.py):

1. The hook (rules.check_hard_deny, rules.detect_gates). admin_hit() parses
   the command with the shell lexer (shellparse): quotes and escapes are
   removed, wrappers (env X=1, sudo, timeout, nohup ...) and runners (uv run,
   uvx, pipx run, poetry run, cmd `call`, `start` ...) are skipped, and the
   code the command runs from strings, heredocs and substitutions (bash -c,
   $(...), powershell -Command, python -c with os.system) is parsed the same
   way. A semgate program (`semgate`, `semgate.exe`, any path to them, or a
   python with `-m semgate`, `-m semgate.cli`, `-m semgate.__main__`) whose
   subcommand is an admin command is a hard deny. ADMIN_TEXT_RE is the broad
   text form (like trust.TRUST_REQUEST_RE): `S=semgate; $S init` or
   `$(echo semgate) init` hide the program from the parser, so the text
   `semgate ... init` is the human gate semgate_admin. A false match only
   asks.

2. The CLI (refuse_agent, confirm). The text checks cannot see every form
   (an alias, a wrapper script written in an earlier call, a detached
   start). So the admin commands themselves refuse to write when the process
   shows an agent sign (trustauth.agent_signs: an agent environment marker,
   an agent CLI or a recorded agent host among the parent processes, an
   orphaned launcher). There is no ticket path: the agent never gets
   permission to run them. A command that weakens protection (uninstall,
   an overwrite with --force, a switch from enforce to shadow) also needs
   the random word typed by the person (trustauth.ask_person).

What this does not stop: code that imports semgate's installer functions
and calls them (the library is not a boundary; the text gate sees
`semgate.init_antigravity` / `semgate.cli` in inline code and in script
files), and an agent that escapes its own process tree on purpose (each
step is visible in the command text the hook judges).
"""
from __future__ import annotations

import os
import re
import sys
from pathlib import Path
from typing import Callable, List, Mapping, Optional, Sequence

# Subcommands that change semgate's install or its strictness. `harness`
# counts only with `init` (HARNESS_ADMIN).
ADMIN_SUBCOMMANDS = frozenset({"init", "install", "uninstall", "enable", "disable", "migrate", "project", "settings", "consent"})
HARNESS_ADMIN = frozenset({"init"})
REASON = "only the user runs this, in their own terminal"

_PROGRAM_RE = re.compile(r"^semgate(?:\.exe|\.cmd|\.bat|\.ps1)?$", re.IGNORECASE)
_PYTHON_RE = re.compile(r"^(?:python(?:\d+(?:\.\d+)*)?w?|py|pyw|pypy\d*(?:\.\d+)?)(?:\.exe)?$", re.IGNORECASE)
_MODULES = frozenset({"semgate", "semgate.cli", "semgate.__main__"})
# Python options that take the next word as their value.
_PY_VALUE_OPTS = frozenset({"-X", "-W", "-Q", "--check-hash-based-pycs"})
# Programs that run another program named later in their arguments.
_RUNNERS = frozenset({"uv", "uvx", "pipx", "poetry", "pdm", "hatch", "pipenv", "conda", "mamba", "micromamba",
                      "pixi", "rye", "call", "start", "start-process", "saps", "invoke-command", "icm", "wsl"})

_ADMIN_WORDS = r"(?:init|install|uninstall|enable|disable|migrate|project|settings|consent)"
# semgate subcommands that are not admin commands: `semgate doctor | grep
# install` or `semgate feedback deny "npm install"` is not an admin command.
_OTHER_SUBS = (r"(?:feedback|trust|report|doctor|status|demo|judge|replay|eval|ledger|telemetry|telemetry-send|serve"
               r"|--version|-V|--help|-h)")
# The broad text form. `semgate` as a word (not `.semgate`, not a path part
# `semgate/`, not `semgate-demo`) whose next word is not another subcommand,
# then an admin word later on the same line (`S=semgate; $S init`,
# `$(echo semgate) init`); or an admin word piped into semgate (`echo init |
# xargs semgate`); or code that imports semgate's installer, or its CLI next
# to an admin word.
ADMIN_TEXT_RE = re.compile(
    r"(?<![\w./\\-])(?<!\bcd )(?<!pushd )semgate(?:\.exe|\.cli|\.__main__)?(?![\w/\\.-])"
    r"(?!['\"]?\s+" + _OTHER_SUBS + r"(?![\w-]))"
    r"[^\n]*?(?<![\w.-])" + _ADMIN_WORDS + r"(?![\w.-])"
    r"|(?<![\w.-])" + _ADMIN_WORDS + r"(?![\w.-])[^\n]*\|[^\n]*(?<![\w./\\-])semgate(?![\w/\\.-])"
    r"|\bsemgate\.init_antigravity\b|\bfrom\s+semgate\s+import\b[^\n]*\binit_antigravity\b"
    r"|\brunpy\b[^\n]*\bsemgate\b|\bsemgate\.privacyconsent\b"
    r"|\bfrom\s+semgate\s+import\b[^\n]*\bprivacyconsent\b",
    re.IGNORECASE)
# In python/node code the command runs: semgate's CLI or installer module
# together with an admin word as a string, or an argv list that runs one
# (["semgate", "init", ...], ["python", "-m", "semgate", "uninstall", ...]).
_CODE_MODULE_RE = re.compile(r"\bsemgate\.(?:cli|__main__|init_antigravity)\b|\bfrom\s+semgate\s+import\b[^\n]*"
                             r"\b(?:cli|init_antigravity)\b|\brunpy\b[^\n]*\bsemgate\b", re.IGNORECASE)
_CODE_ADMIN_WORD_RE = re.compile(r"""['"]""" + _ADMIN_WORDS + r"""['"]|\brun_uninstall\b|\bwrite_config\b""",
                                 re.IGNORECASE)
_Q = r"""['"]"""
_CODE_ARGV_RE = re.compile(
    _Q + r"(?:[^'\"]*[/\\])?semgate(?:\.exe)?" + _Q + r"\s*,\s*\[?\s*(?:" + _Q + r"-[^'\"]*" + _Q + r"\s*,\s*)*" + _Q
    + r"(?:" + _ADMIN_WORDS + r"|harness" + _Q + r"\s*,\s*" + _Q + r"init)" + _Q
    + r"|" + _Q + r"-m" + _Q + r"\s*,\s*" + _Q + r"semgate(?:\.cli|\.__main__)?" + _Q + r"\s*,\s*" + _Q + _ADMIN_WORDS + _Q,
    re.IGNORECASE)
# Escape characters of cmd (^) and PowerShell (`) that the shell drops.
_DROPPED = re.compile(r"[\^`]")


def _base(word: str) -> str:
    return _DROPPED.sub("", word).replace("\\", "/").rsplit("/", 1)[-1].lower()


def _strip_open(word: str) -> str:
    """A word that starts a subshell or group: `(semgate`, `{`, `!`."""
    return word.lstrip("({!")


def _subcommand_after(values: Sequence[str], k: int) -> Optional[List[str]]:
    """The words after a semgate program at index k: the first word that is
    not an option, and the rest. None when there is none."""
    rest = [v for v in values[k + 1:]]
    j = 0
    while j < len(rest) and (rest[j].startswith("-") and rest[j] not in ("-",)):
        j += 1
    if j >= len(rest):
        return None
    return [w.lower() for w in rest[j:]]


def _is_admin(words: Sequence[str]) -> str:
    """'semgate <sub>' when `words` (the subcommand and what follows) is an
    admin command, else ""."""
    if not words:
        return ""
    sub = words[0].rstrip(")};&")
    if sub in ADMIN_SUBCOMMANDS:
        return f"semgate {sub}"
    if sub == "harness":
        nxt = [w for w in words[1:] if not w.startswith("-")]
        if nxt and nxt[0].rstrip(")};&") in HARNESS_ADMIN:
            return "semgate harness init"
    return ""


def _python_module_at(values: Sequence[str], k: int) -> int:
    """For a python program at index k: the index of the module word when the
    command is `python [options] -m <semgate module>` ("-msemgate" too), else -1.
    Returns the index of the last word that belongs to the program."""
    j = k + 1
    while j < len(values):
        v = values[j]
        if v == "-m":
            if j + 1 < len(values) and values[j + 1].lower() in _MODULES:
                return j + 1
            return -1
        if v.startswith("-m") and len(v) > 2 and not v.startswith("--"):
            return j if v[2:].lower() in _MODULES else -1
        if v in ("-c",) or not v.startswith("-"):
            return -1                                  # code or a script file: not the module form
        if v in _PY_VALUE_OPTS:
            j += 2
            continue
        j += 1
    return -1


def _simple_hit(values: Sequence[str]) -> str:
    """The admin command in one simple command's words (wrappers already
    skipped), else ""."""
    if not values:
        return ""
    values = [_strip_open(v) for v in values]
    values = [v for v in values if v]
    if not values:
        return ""
    starts = [0]
    if _base(values[0]).removesuffix(".exe") in _RUNNERS:
        starts = list(range(1, len(values)))           # the program is somewhere after the runner's options
    for k in starts:
        base = _base(values[k])
        if _PROGRAM_RE.match(base):
            hit = _is_admin(_subcommand_after(values, k) or [])
            if hit:
                return hit
        elif _PYTHON_RE.match(base):
            m = _python_module_at(values, k)
            if m >= 0:
                hit = _is_admin(_subcommand_after(values, m) or [])
                if hit:
                    return hit
    # PowerShell Start-Process semgate -ArgumentList 'init','claude'
    first = _base(values[0])
    if first in ("start-process", "saps", "start"):
        for n, v in enumerate(values):
            if v.lower() in ("-argumentlist", "-args") and n + 1 < len(values):
                prog = next((w for w in values[1:n] if not w.startswith("-")), "")
                if _PROGRAM_RE.match(_base(prog)):
                    args = [w for w in re.split(r"[\s,]+", " ".join(values[n + 1:])) if w]
                    hit = _is_admin([a.strip("'\"").lower() for a in args if not a.startswith("-")])
                    if hit:
                        return hit
    return ""


def _texts(command: str) -> List[str]:
    from . import shellparse
    return [command] + shellparse.extract_scripts(command)


def _mentions_semgate(text: str) -> bool:
    """`semgate` in the text once quotes and escape characters are removed
    (`sem''gate`, `s\\emgate`, `se^mgate`)."""
    return "semgate" in re.sub(r"[\"'\\^`]", "", text).lower()


def admin_hit(command: str) -> str:
    """The admin command that `command` runs ("semgate init", ...), found by
    parsing the command and every piece of code it runs; "" when none. A
    strictly parsed help request (`semgate init --help`) is not one."""
    if not isinstance(command, str) or not command.strip() or not _mentions_semgate(command):
        return ""
    if harmless(command):
        return ""
    from . import shellparse
    for text in _texts(command):
        try:
            simples = shellparse.split_commands(text)
        except Exception:
            simples = []
        for simple in simples:
            argv = shellparse.effective_argv(simple.tokens)
            # the shell's words (quotes and escapes removed), and the words
            # as written without outer quotes (a Windows path keeps its
            # backslashes: cmd and PowerShell do not treat them as escapes)
            hit = (_simple_hit([t.value for t in argv])
                   or _simple_hit([t.raw[1:-1] if len(t.raw) > 1 and t.raw[0] == t.raw[-1] and t.raw[0] in "\"'"
                                   else t.raw for t in argv]))
            if hit:
                return hit
        if _CODE_ARGV_RE.search(text):
            return "semgate admin command in an argument list"
        if _CODE_MODULE_RE.search(text) and _CODE_ADMIN_WORD_RE.search(text):
            return "semgate's installer called from code"
    return ""


def text_hit(text: str) -> str:
    """The broad text form (ADMIN_TEXT_RE) in `text`, else ""."""
    if not isinstance(text, str) or "semgate" not in text.lower():
        return ""
    m = ADMIN_TEXT_RE.search(text)
    return m.group(0)[:120] if m else ""


_HELP = frozenset({"-h", "--help"})
_HOSTS_WORD = re.compile(r"^[a-z][a-z0-9-]{0,30}$")


def harmless(command: str) -> bool:
    """Exactly one simple `semgate <admin> [<host>] -h|--help` (or `python -m
    semgate ...`): argparse prints the help and exits before anything runs."""
    from .trust import _base as tbase, _PROGRAMS, _PYTHONS, _words
    if not isinstance(command, str) or "\n" in command or "\r" in command:
        return False
    words = _words(command.strip())
    if not words:
        return False
    if tbase(words[0]) in _PROGRAMS:
        rest = words[1:]
    elif _PYTHONS.match(tbase(words[0])) and len(words) > 2 and words[1] == "-m" and words[2] in _MODULES:
        rest = words[3:]
    else:
        return False
    if not rest or not _is_admin([w.lower() for w in rest]):
        return False
    tail = rest[1:]
    if rest[0].lower() == "harness":
        tail = tail[1:]
    return any(w in _HELP for w in tail) and all(w in _HELP or _HOSTS_WORD.match(w) for w in tail)


# ---------------------------------------------------------------- the CLI side


def _stores() -> List[Path]:
    """Where trustauth reads the agent-host registry: next to the default
    trust store in ~/.semgate (never an environment variable)."""
    return [Path(os.path.expanduser("~")) / ".semgate" / "trust.jsonl"]


def refuse_agent(what: str, env: Optional[Mapping[str, str]] = None, chain=None) -> str:
    """"" when this process shows no agent sign; else the refusal text for
    `semgate <what>` (the caller prints it and exits 2)."""
    from . import trustauth
    signs = trustauth.agent_signs(_stores(), env=env, chain=chain)
    if not signs:
        return ""
    lines = [f"semgate {what}: refused: {signs[0]}.", f"  {REASON[0].upper() + REASON[1:]}."]
    lines += [f"  also: {s}" for s in signs[1:]]
    return "\n".join(lines)


def confirm(lines: Sequence[str], read: Optional[Callable[[], str]] = None,
            write: Optional[Callable[[str], None]] = None) -> bool:
    """The person types the random word the CLI prints (trustauth.ask_person)."""
    from . import trustauth
    return trustauth.ask_person(lines, read=read, write=write)


def guard(what: str, weakening: Sequence[str] = ()) -> int:
    """0 when `semgate <what>` may write; else the exit code (2) after the
    reason was printed. `weakening`: lines that say how the command lowers
    protection; non-empty means the typed word is needed too."""
    refused = refuse_agent(what)
    if refused:
        print(refused, file=sys.stderr)
        return 2
    if weakening:
        if not confirm(list(weakening)):
            print(f"semgate {what}: not confirmed; nothing was changed.", file=sys.stderr)
            return 2
    return 0
