"""Trusted commands: `semgate trust add | list | remove`.

A trusted command is one exact command text that semgate allows without
asking, in one project, until an expiry. The user makes it (in a terminal, or
by asking the agent: see trustgate.py for the check semgate does when the
agent runs `semgate trust add`).

What a trust covers (all must hold):
  - the exact command text, character for character: no case or whitespace
    folding (the rule of an approval, feedback.exact_key). `npm run e2e` does
    not cover `npm run e2e -- --watch`. Any shell tool (Bash, run_command,
    bash, exec_command, PowerShell) carries it; the tool is not part of it;
  - the same project: project_of() of the hook's project folder (the host's
    project_root, else cwd) equals the project the trust was made for. The
    project of a folder is the git top folder above it (never the home folder
    or a drive root), else the folder itself;
  - before its expiry: `--days N`, default 7, at most 30.
An approval (`semgate feedback allow`) is bound to one session and 4 hours;
a trust drops the session and uses the expiry instead.

What a trust never overrides (judge.py, trust_override):
  - a deny of any kind: hard rules (hard_deny patterns, the self-protection
    patterns, grant_scope: the grant's forbidden patterns and paths), a
    semantic deny (injection_deny, drift_deny, misaligned_unrequested_deny),
    a human deny (`semgate feedback deny`);
  - an expired grant, a store that could not be read;
  - the human gates untrusted_instruction (a file or tool output named the
    command), trust_request (a `semgate trust add` itself), agent_config
    (writes to another agent's config or to the host's session record), and
    any gate found inside a local script file the command runs (F4): the
    agent can edit that file after the trust was made;
  - a semantic answer that says the command follows untrusted content
    (instructed_by_context >= 0.5, below the injection_deny threshold).
    A weaker on_task or session-drift ask IS replaced: the user said to stop
    asking about exactly this command (drift_deny stays a deny).
It turns a human-gate ask or a semantic ask/allow into an allow with stage
`trusted`, reason code `trusted_command`.

`semgate trust add` also refuses a command that matches a forbidden
pattern of a grant (--grant, default: the grant of every installed semgate
hook; grant_hit), and rules.check_hard_deny hard-denies the agent's trust
add of such a command (rule trust_grant_scope, the envelope's grant).

Commands that can never be trusted (refuse_reason): a hard-rule command
(HARD_DENY_PATTERNS on the command and on the code it runs, the same check
as the hook), a command that writes to another agent's config or a host's
session record (gate agent_config), a semgate command, an empty or
multi-line command, more than 1000 characters.

Who may write (trustauth.py): `semgate trust add` and `semgate trust file`
write only with an approval ticket that semgate's hook wrote when it
allowed the agent's request (trustgate.py), or in a terminal the user
opened (no agent sign in the process tree or environment, and the user
types a word the CLI prints). TrustStore.add needs an Auth; the record
keeps `via` (ticket / terminal / ...).

Store: one JSONL file for every host, default `~/.semgate/trust.jsonl`
(config `trust.file`; the CLI: --store). The environment variable
SEMGATE_TRUST_FILE is no longer read: a variable of the agent host's
environment could point the hook at a trust store it wrote. One file because a trust is
for a project, not for one agent CLI, and so that `semgate trust add` works
without choosing a hook config when several hosts are installed. Records are
events (`add`, `remove`), appended under the cross-process lock
(filelock.append_record, repair=True like the feedback store) and read under
the lock with the robust reader (a torn or malformed line is skipped). The
newest event for (match, project) wins. Every record (schema 2) carries a
keyed tag (trustauth.make_tag, the key `trust.key`); a record without a
valid tag (written by hand, by semgate before schema 2, or with another
key) is ignored, and the readers say how many they ignored.

Secrets: when secretfinder finds a secret in the command, the record keeps
only a masked copy (`command_masked`) and a keyed fingerprint (`match`,
HMAC-SHA256 with the key `~/.semgate/trust.key`, fingerprints.load_key).
Otherwise it keeps the command and `match` = sha256 of it.
"""
from __future__ import annotations

import hashlib
import os
import re
import sys
import time
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Mapping, Optional, Sequence

from . import filelock

SCHEMA = 2                        # 2: every record carries a keyed tag (trustauth.py)
TAG_LABEL = "trust record v2"
STORE_NAME = "trust.jsonl"
KEY_NAME = "trust.key"
DEFAULT_DAYS = 7
MAX_DAYS = 30
MAX_CHARS = 1000
CLOCK_SKEW_S = 300.0
STAGE = "trusted"
REASON_CODE = "trusted_command"
# Human gates a trust never overrides (see the module text).
NOT_OVERRIDABLE_GATES = frozenset({"untrusted_instruction", "trust_request", "script_denylisted", "agent_config",
                                   "semgate_admin"})


# ---------------------------------------------------------------- where


def default_store() -> Path:
    """~/.semgate/trust.jsonl. No environment variable changes it (the hook
    reads this store; SEMGATE_TRUST_FILE is ignored, env_notice())."""
    return Path(os.path.expanduser("~")) / ".semgate" / STORE_NAME


def env_notice() -> str:
    """The notice the CLI prints when SEMGATE_TRUST_FILE is still set."""
    if os.environ.get("SEMGATE_TRUST_FILE", "").strip():
        return "ignored: SEMGATE_TRUST_FILE is no longer read; use --store"
    return ""


def store_path(config: Mapping[str, Any]) -> Path:
    """`trust.file` of a (resolved) semgate.json, else default_store()."""
    tr = config.get("trust") if isinstance(config.get("trust"), Mapping) else {}
    value = tr.get("file")
    if isinstance(value, str) and value.strip():
        return Path(os.path.expanduser(value))
    return default_store()


def enabled(config: Mapping[str, Any]) -> bool:
    """Trusted commands are honoured unless `trust.enabled` is false."""
    tr = config.get("trust") if isinstance(config.get("trust"), Mapping) else {}
    return tr.get("enabled") is not False


def norm_root(path: str) -> str:
    from .feedback import norm_root as _norm
    return _norm(path)


def project_of(path: str) -> str:
    """The project a folder belongs to: the nearest folder at or above it that
    holds `.git` (a folder or a file), unless that is the home folder or a
    drive root; else the folder itself. Normalized like an approval's
    project root (realpath, normcase). "" for no path."""
    start = norm_root(path)
    if not start:
        return ""
    home = norm_root(os.path.expanduser("~"))
    cur = start
    for _ in range(64):
        parent = os.path.dirname(cur)
        if cur == home or parent == cur:
            return start
        if os.path.exists(os.path.join(cur, ".git")):
            return cur
        cur = parent
    return start


# ---------------------------------------------------------------- what can be trusted


_SEMGATE_WORD = re.compile(r"\bsemgate\b", re.IGNORECASE)
# Reverse-shell shapes. Not hard rules in rules.py (a `/dev/tcp` port check
# is a benign idiom there, and the gates plus the judge handle them), but a
# standing "always allow" for one is never right, so a trust refuses them.
NEVER_TRUST_PATTERNS = tuple(re.compile(p, re.IGNORECASE) for p in (
    r"/dev/(tcp|udp)/",
    r"\b(nc|ncat|netcat)\b[^\n]*\s(-e|-c|--exec|--sh-exec|--lua-exec)\b",
    r"\bsocat\b[^\n]*\b(exec|system):",
    r"\bmkfifo\b[^\n]*\b(nc|ncat|netcat|telnet|openssl)\b",
    r"\bnet\.sockets\.tcpclient\b",
))


def hard_rule_hit(command: str) -> str:
    """The hard-deny pattern text the command (or code it runs) matches, or
    the catastrophic.py rule it hits (rm -fr /, rm -rf / --no-preserve-root,
    find / -delete ...), or ""."""
    from . import catastrophic, rules, shellparse
    try:
        scripts = shellparse.extract_scripts(command)
    except Exception:
        scripts = []
    text = "bash\ncommand\n" + command + ("\n" + "\n".join(scripts) if scripts else "")
    for pattern in rules.HARD_DENY_PATTERNS:
        m = pattern.search(text)
        if m:
            return m.group(0)[:120]
    return (catastrophic.catastrophic_hit(command) or catastrophic.system_control_hit(command))[:120]


def refuse_reason(command: str) -> str:
    """Why this command can never be trusted, or "" when it can."""
    from . import rules
    if not isinstance(command, str) or not command.strip():
        return "the command is empty"
    if "\n" in command or "\r" in command:
        return "the command has more than one line"
    if len(command) > MAX_CHARS:
        return f"the command is longer than {MAX_CHARS} characters"
    hit = hard_rule_hit(command)
    if hit:
        return f"it matches a hard rule ({hit!r}): semgate always blocks it, a trust cannot change that"
    for pattern in NEVER_TRUST_PATTERNS:
        m = pattern.search(command)
        if m:
            return f"it has the shape of a reverse shell ({m.group(0)[:60]!r})"
    if _SEMGATE_WORD.search(command):
        return "it is a semgate command; semgate's own commands cannot be trusted"
    for pattern in rules.GATE_PATTERNS["agent_config"]:
        m = pattern.search("bash\ncommand\n" + command)
        if m:
            return (f"it writes to an agent's config or a host's session record ({m.group(0)[:60]!r}); "
                    "semgate relies on those files")
    return ""


def grant_hit(command: str, patterns: Sequence[str]) -> str:
    """The first of a grant's forbidden_patterns that the command matches
    (the same search as rules.check_grant_scope: case-insensitive, over the
    action text of a shell call), or ""."""
    text = "bash\ncommand\n" + command
    for pattern in patterns:
        try:
            if re.search(pattern, text, re.IGNORECASE):
                return str(pattern)
        except (re.error, TypeError):
            continue                     # the hook fails on it too; not a reason to trust
    return ""


def installed_grants() -> List[tuple]:
    """(grant file, forbidden_patterns) of every grant an installed semgate
    hook uses (hosts.installed: the --config of each hook), read only. A
    grant that cannot be read is returned with the pattern "(unreadable)",
    which grant_hit never matches; _cmd_add refuses on it."""
    import json
    from .hosts.base import HostEnv
    from .hosts.installed import installed_configs
    out: List[tuple] = []
    seen = set()
    try:
        configs = installed_configs(HostEnv.current(run_binaries=False))
    except Exception:
        return out
    for ic in configs:
        path = str(ic.config.get("grant_file") or "")
        if not path or path in seen:
            continue
        seen.add(path)
        try:
            raw = json.loads(Path(path).read_text(encoding="utf-8"))
            patterns = [str(x) for x in (raw.get("forbidden_patterns") or [])]
        except (OSError, ValueError, AttributeError):
            patterns = ["(unreadable)"]
        out.append((path, patterns))
    return out


# ---------------------------------------------------------------- parsing `semgate trust add`


# One word of a simple command: "double quoted" (no " $ ` inside), 'single
# quoted' (no ' inside), or a bare word without quotes, spaces or shell
# operators. Anything else (escapes, variables, command substitution,
# redirects, ;, &&, |) makes the command not a simple `semgate trust add`.
_WORD = re.compile(r"""\s*(?:"([^"$`]*)"|'([^']*)'|([^\s"'$`;&|<>(){}]+))(?=\s|$)""")
_PROGRAMS = ("semgate", "semgate.exe")
_PYTHONS = re.compile(r"^(python(3(\.\d+)?)?|py)(\.exe)?$", re.IGNORECASE)
# Any command that may run a `semgate trust` subcommand (the CLI, `python -m
# semgate`, or code that imports semgate's trust or pins module). Broad on
# purpose: a false match only makes the command a human gate. The words
# after "trust" are not required, so `semgate trust a""dd` or `semgate trust
# $(echo add)` match too; request_hit() also reads the shell's own words
# (quotes removed). Only a strictly parsed `semgate trust list` or `semgate
# trust remove ...` is left out (harmless: it reads, or it ends a trust).
TRUST_REQUEST_RE = re.compile(r"\bsemgate(?:\.exe|\.cli|\.__main__)?['\"]?(?:[\s;&|]|$)[^\n]*\btrust\b"
                              r"|\bsemgate\.(?:trust\w*|pins|pingate)\b"
                              r"|\bfrom\s+semgate\s+import\b[^\n]*\b(?:trust\w*|pins|pingate)\b", re.IGNORECASE)
TRUST_ADD_RE = TRUST_REQUEST_RE          # the older name


@dataclass(frozen=True)
class AddRequest:
    command: str          # add: the command to trust, exactly as the CLI will receive it; file: the file path
    days: int
    days_given: bool
    kind: str = "add"     # "add" (`semgate trust add`) or "file" (`semgate trust file`)


def _words(text: str) -> Optional[List[str]]:
    out: List[str] = []
    pos, n = 0, len(text)
    while pos < n:
        if not text[pos:].strip():
            break
        m = _WORD.match(text, pos)
        if not m:
            return None
        out.append(next(g for g in m.groups() if g is not None))
        pos = m.end()
    return out


def _base(word: str) -> str:
    return re.split(r"[/\\]", word)[-1].lower()


def _trust_words(command: str) -> Optional[List[str]]:
    """The words after `semgate trust` when `command` is exactly one simple
    `semgate trust ...` (or `python -m semgate trust ...`), else None."""
    if not isinstance(command, str) or "\n" in command or "\r" in command:
        return None
    words = _words(command.strip())
    if not words:
        return None
    if _base(words[0]) in _PROGRAMS:
        i = 1
    elif _PYTHONS.match(_base(words[0])) and len(words) > 2 and words[1] == "-m" and words[2] == "semgate":
        i = 3
    else:
        return None
    if words[i:i + 1] != ["trust"]:
        return None
    return words[i + 1:]


def parse_file(command: str) -> Optional[AddRequest]:
    """`semgate trust file <path>` exactly (one path, no options), else None."""
    rest = _trust_words(command)
    if not rest or rest[0] != "file" or len(rest) != 2 or rest[1].startswith("-"):
        return None
    return AddRequest(command=rest[1], days=0, days_given=False, kind="file")


def harmless(command: str) -> bool:
    """A strictly parsed `semgate trust list [--all] [--json]` or `semgate
    trust remove "<command>"` / `semgate trust remove --file <path>`: it
    reads the store or ends a trust, so it is not the trust_request gate."""
    rest = _trust_words(command)
    if not rest:
        return False
    if rest[0] == "list":
        return all(w in ("--all", "--json") for w in rest[1:])
    if rest[0] == "remove":
        return rest[1:2] == ["--file"] and len(rest) == 3 or (len(rest) == 2 and not rest[1].startswith("-"))
    return False


def request_hit(command: str) -> str:
    """What makes `command` a trust request (the human gate trust_request),
    or "": TRUST_REQUEST_RE on the text, or a simple command whose words
    (quotes removed by the shell parser) run semgate with `trust`. A
    harmless() command is not one."""
    if not isinstance(command, str) or not command.strip() or harmless(command):
        return ""
    m = TRUST_REQUEST_RE.search(command)
    if m:
        return m.group(0)[:120]
    try:
        from . import shellparse
        simples = shellparse.split_commands(command)
    except Exception:
        simples = []
    for simple in simples:
        values = [t.value for t in simple.tokens if not t.redirect]
        for k, v in enumerate(values):
            base = _base(v)
            if base in _PROGRAMS and values[k + 1:k + 2] == ["trust"]:
                return " ".join(values[k:k + 3])[:120]
            if base == "semgate" and k >= 1 and values[k - 1] == "-m" and values[k + 1:k + 2] == ["trust"]:
                return " ".join(values[k - 1:k + 3])[:120]
    return ""


def parse_request(command: str) -> Optional[AddRequest]:
    """parse_add or parse_file."""
    return parse_add(command) or parse_file(command)


def parse_add(command: str) -> Optional[AddRequest]:
    """The request when `command` is exactly one simple
    `semgate trust add "<command>" [--days N]` (or `python -m semgate trust
    add ...`), with quoting that bash and PowerShell read the same way; else
    None. The command to trust must not hold a backslash."""
    rest = _trust_words(command)
    if not rest or rest[0] != "add":
        return None
    rest = rest[1:]
    target: Optional[str] = None
    days, days_given = DEFAULT_DAYS, False
    j = 0
    while j < len(rest):
        w = rest[j]
        if w == "--days" and j + 1 < len(rest) and re.fullmatch(r"\d{1,4}", rest[j + 1]) and not days_given:
            days, days_given = int(rest[j + 1]), True
            j += 2
            continue
        m = re.fullmatch(r"--days=(\d{1,4})", w)
        if m and not days_given:
            days, days_given = int(m.group(1)), True
            j += 1
            continue
        if w.startswith("-") or target is not None:
            return None
        target = w
        j += 1
    if target is None or "\\" in target:
        return None
    return AddRequest(command=target, days=days, days_given=days_given)


def inner_commands(command: str) -> List[str]:
    """Every string that a `semgate trust add` in `command` may be asked to
    trust (a loose reading, for the hard-rule check: it may return more than
    the CLI gets, never less for the simple forms)."""
    out: List[str] = []
    strict = parse_add(command)
    if strict is not None:
        out.append(strict.command)
    try:
        from . import shellparse
        simples = shellparse.split_commands(command)
    except Exception:
        simples = []
    for simple in simples:
        values = [t.value for t in simple.tokens if not t.redirect]
        for k in range(len(values) - 1):
            if values[k] == "trust" and values[k + 1] == "add":
                skip = False
                for v in values[k + 2:]:
                    if skip:
                        skip = False
                        continue
                    if v == "--days":
                        skip = True
                        continue
                    if v.startswith("--"):
                        continue
                    if v and v not in out:
                        out.append(v)
    return out


def is_trust_add(command: str) -> bool:
    return bool(request_hit(command))


# ---------------------------------------------------------------- store


def _iso(epoch: float) -> str:
    return datetime.fromtimestamp(epoch, timezone.utc).isoformat().replace("+00:00", "Z")


def _epoch(value: Any) -> Optional[float]:
    from .gitstate import to_epoch
    return to_epoch(value)


def sha_match(command: str) -> str:
    return "sha256:" + hashlib.sha256(command.encode("utf-8")).hexdigest()


def _secrets(command: str) -> List[str]:
    from . import secretfinder
    try:
        return [f.value for f in secretfinder.find(command)]
    except Exception:
        return []


class TrustStore:
    """The trust event log. `clock` (tests) returns epoch seconds."""

    def __init__(self, path: Any, clock: Optional[Callable[[], float]] = None, lock_timeout: float = 0.0) -> None:
        self.path = Path(path)
        self.clock = clock or time.time
        self.lock_timeout = float(lock_timeout)

    @property
    def key_path(self) -> Path:
        return self.path.with_name(KEY_NAME)

    def _key(self) -> bytes:
        from . import fingerprints
        key, _note = fingerprints.load_key(self.key_path, self.lock_timeout)
        return key

    def _fp(self, command: str) -> str:
        from . import fingerprints
        return fingerprints.fingerprint(self._key(), command)

    ignored = 0                   # trust records the last records() call ignored (no valid tag)

    def _all(self) -> List[Dict[str, Any]]:
        if not self.path.exists():
            return []
        res = filelock.read_jsonl_locked(self.path, timeout=self.lock_timeout)
        if res.malformed:
            filelock.warn_malformed(self.path, res, "trust")
        return res.records

    def records(self) -> List[Dict[str, Any]]:
        """Trust events with a valid tag, read under the lock. Raises
        LockTimeout / OSError / fingerprints.KeyUnavailable."""
        from . import trustauth
        rows = [r for r in self._all() if r.get("record_type") == "trust"]
        if not rows:
            self.ignored = 0
            return []
        key = self._key()
        good = [r for r in rows if r.get("schema") == SCHEMA and trustauth.tag_ok(key, TAG_LABEL, r)]
        self.ignored = len(rows) - len(good)
        trustauth.warn_ignored(self.path, "trust", self.ignored)
        return good

    def refused(self) -> List[Dict[str, Any]]:
        """`semgate trust add | file` runs the CLI refused (trustauth.record_refused), oldest first."""
        from . import trustauth
        rows = [r for r in self._all() if r.get("record_type") == "trust_refused"]
        return trustauth.refused_records(rows, self._key()) if rows else []

    def _append(self, record: Dict[str, Any]) -> Dict[str, Any]:
        from . import trustauth
        record = trustauth.tagged(self._key(), TAG_LABEL, record)
        filelock.append_record(self.path, record, timeout=self.lock_timeout, spill=False, repair=True)
        return record

    def _state(self, records: Sequence[Mapping[str, Any]]) -> Dict[tuple, Dict[str, Any]]:
        state: Dict[tuple, Dict[str, Any]] = {}
        for r in records:
            key = (str(r.get("match", "")), str(r.get("project_root", "")))
            if not key[0] or not key[1]:
                continue
            if r.get("event") == "add":
                state[key] = dict(r)
            elif r.get("event") == "remove":
                state.pop(key, None)
        return state

    @staticmethod
    def _live(r: Mapping[str, Any], now: float) -> bool:
        exp, ts = _epoch(r.get("expires_at")), _epoch(r.get("ts"))
        if exp is None or ts is None:
            return False
        if ts > now + CLOCK_SKEW_S or now >= exp:
            return False
        return exp - ts <= MAX_DAYS * 86400 + 1

    def active(self, project_root: Optional[str] = None, now: Optional[float] = None) -> List[Dict[str, Any]]:
        """Trusts in force, newest first. `project_root` (a project_of value) narrows."""
        t = self.clock() if now is None else float(now)
        out = [r for r in self._state(self.records()).values() if self._live(r, t)
               and (project_root is None or str(r.get("project_root", "")) == project_root)]
        out.sort(key=lambda r: _epoch(r.get("ts")) or 0.0, reverse=True)
        return out

    def lookup(self, command: str, project_root: str, now: Optional[float] = None) -> Optional[Dict[str, Any]]:
        """The trust in force for this exact command in this project, or None.
        Raises LockTimeout / OSError when the store cannot be read."""
        if not command or not project_root or not self.path.exists():
            return None
        t = self.clock() if now is None else float(now)
        records = self.records()
        if not records:
            return None
        wanted = {sha_match(command)}
        if any(str(r.get("match", "")).startswith("hmac-") for r in records):
            try:
                wanted.add(self._fp(command))
            except Exception:
                pass                      # no key: a fingerprinted trust cannot be matched (stricter)
        for (match, root), r in self._state(records).items():
            if root != project_root or match not in wanted or not self._live(r, t):
                continue
            if match.startswith("sha256:") and r.get("command") != command:
                continue
            return r
        return None

    def _match_for(self, command: str) -> Dict[str, Any]:
        found = _secrets(command)
        if not found:
            return {"match": sha_match(command), "command": command, "has_secret": False}
        from . import secretfinder
        return {"match": self._fp(command), "command": "", "command_masked": secretfinder.mask_in(command, found),
                "has_secret": True}

    def add(self, command: str, project_root: str, days: int = DEFAULT_DAYS, note: str = "",
            now: Optional[float] = None, *, auth: Any) -> Dict[str, Any]:
        """Append a trust. `auth` (trustauth.Auth): why it may be written (the
        CLI gets one from trustauth.authorize). ValueError when the command
        cannot be trusted or `days` is not 1..MAX_DAYS. Raises LockTimeout,
        trustauth.NotAuthorized."""
        from . import trustauth
        auth = trustauth.require(auth)
        why = refuse_reason(command)
        if why:
            raise ValueError(f"cannot trust this command: {why}")
        if not isinstance(days, int) or isinstance(days, bool) or not 1 <= days <= MAX_DAYS:
            raise ValueError(f"--days must be a whole number from 1 to {MAX_DAYS}")
        if not project_root:
            raise ValueError("a trust needs a project folder")
        t = self.clock() if now is None else float(now)
        record: Dict[str, Any] = {"record_type": "trust", "schema": SCHEMA, "event": "add",
                                  "trust_id": uuid.uuid4().hex[:12], **self._match_for(command),
                                  "project_root": project_root, "days": days, "ts": _iso(t),
                                  "expires_at": _iso(t + days * 86400.0), "note": note[:200], **auth.fields()}
        return self._append(record)

    def remove(self, command: str, project_root: str, now: Optional[float] = None) -> Optional[Dict[str, Any]]:
        """End the trust of this exact command in this project. Returns the
        trust that was in force, or None (nothing written)."""
        t = self.clock() if now is None else float(now)
        current = self.lookup(command, project_root, now=t)
        if current is None:
            return None
        record = {"record_type": "trust", "schema": SCHEMA, "event": "remove", "trust_id": current.get("trust_id", ""),
                  "match": current.get("match", ""), "project_root": project_root, "ts": _iso(t)}
        self._append(record)
        return current


def shown(record: Mapping[str, Any]) -> str:
    """The command as it may be printed (masked when it held a secret)."""
    return str(record.get("command") or record.get("command_masked") or "")


# ---------------------------------------------------------------- CLI


def _store_from_args(args: Any) -> TrustStore:
    notice = env_notice()
    if notice:
        print(notice, file=sys.stderr)
    return TrustStore(Path(os.path.expanduser(args.store)) if getattr(args, "store", "") else default_store())


def _project_from_args(args: Any) -> str:
    return project_of(getattr(args, "project", "") or os.getcwd())


def _grants_from_args(args: Any) -> List[tuple]:
    """--grant files, else every grant an installed hook uses."""
    import json
    given = [g for g in (getattr(args, "grant", None) or []) if g]
    if not given:
        return installed_grants()
    out: List[tuple] = []
    for g in given:
        path = os.path.expanduser(g)
        try:
            raw = json.loads(Path(path).read_text(encoding="utf-8"))
            out.append((path, [str(x) for x in (raw.get("forbidden_patterns") or [])]))
        except (OSError, ValueError, AttributeError):
            out.append((path, ["(unreadable)"]))
    return out


REFUSED_HELP = ("If the user wants this: they ask for it in the agent's chat (semgate checks their own message, then "
                "the agent runs the same command once), or they run the command in a terminal they opened themselves.")


def _masked(text: str) -> str:
    found = _secrets(text)
    if not found:
        return text
    from . import secretfinder
    return secretfinder.mask_in(text, found)


def _authorize(store: "TrustStore", kind: str, target: str, days: int, project: str, summary: Sequence[str],
               lines: Sequence[str] = ()) -> tuple:
    """(Auth, 0) or (None, exit code) after printing why (trustauth.authorize)."""
    from . import fingerprints, trustauth
    try:
        return trustauth.authorize(store.path, kind=kind, target=target, days=days, project=project, lines=lines,
                                   summary=summary), 0
    except trustauth.NotAuthorized as exc:
        why = str(exc)
        if why != "not confirmed":
            trustauth.record_refused(store.path, kind=kind, target=target, project=project, why=why)
            print(f"not trusted: {why}.", file=sys.stderr)
            print(REFUSED_HELP, file=sys.stderr)
        else:
            print("not trusted: not confirmed", file=sys.stderr)
        return None, 2
    except (filelock.LockTimeout, fingerprints.KeyUnavailable) as exc:
        print(f"not trusted: {exc}. Try again.", file=sys.stderr)
        return None, 3


def _cmd_add(args: Any) -> int:
    store = _store_from_args(args)
    project = _project_from_args(args)
    # A pattern the user forbade in a grant: semgate denies the command for
    # that host, so a trust of it is refused too (a stored trust would never
    # override the deny anyway: judge.py runs hard rules first).
    for path, patterns in _grants_from_args(args):
        if patterns == ["(unreadable)"]:
            print(f"not trusted: the grant {path} could not be read, so its forbidden patterns cannot be checked",
                  file=sys.stderr)
            return 2
        hit = grant_hit(args.trusted_command, patterns)
        if hit:
            print(f"not trusted: cannot trust this command: it matches the forbidden pattern {hit!r} of the grant "
                  f"{path}; semgate always blocks it there", file=sys.stderr)
            return 2
    why = refuse_reason(args.trusted_command)
    if why or not 1 <= args.days <= MAX_DAYS:
        print(f"not trusted: cannot trust this command: {why}" if why else
              f"not trusted: --days must be a whole number from 1 to {MAX_DAYS}", file=sys.stderr)
        return 2
    shown_cmd = _masked(args.trusted_command)
    auth, code = _authorize(store, "add", args.trusted_command, args.days, project, summary=[
        f"semgate trust add: allow exactly `{shown_cmd}` without asking",
        f"  project  {project}",
        f"  for      {args.days} day{'s' if args.days != 1 else ''}"])
    if auth is None:
        return code
    try:
        rec = store.add(args.trusted_command, project, days=args.days, note=args.note or "", auth=auth)
    except ValueError as exc:
        print(f"not trusted: {exc}", file=sys.stderr)
        return 2
    except filelock.LockTimeout as exc:
        print(f"not trusted: {exc}. Try again.", file=sys.stderr)
        return 3
    except Exception as exc:
        print(f"not trusted: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 3
    print(f"trusted: `{shown(rec)}`")
    print(f"  project  {rec['project_root']}")
    print(f"  expires  {rec['expires_at']} ({rec['days']} day{'s' if rec['days'] != 1 else ''})")
    print(f"  store    {store.path}")
    print("semgate now allows exactly this command in this project without asking, until it expires.")
    print("Hard rules, injection and drift checks still apply. A different command text is not covered.")
    print(f"Remove it with: semgate trust remove \"{shown(rec)}\"")
    return 0


def _cmd_list(args: Any) -> int:
    import json
    store = _store_from_args(args)
    project = None if args.all else _project_from_args(args)
    from . import fingerprints
    from .pins import PinStore
    ps = PinStore(store.path, lock_timeout=store.lock_timeout)
    try:
        rows = store.active(project)
        pins = [dict(v, file_key=k[1]) for k, v in sorted(PinStore.state(ps.records(), project).items())]
        refused = [r for r in store.refused() if project is None or r.get("project_root") == project]
    except (filelock.LockTimeout, fingerprints.KeyUnavailable) as exc:
        print(f"could not read {store.path}: {exc}", file=sys.stderr)
        return 3
    ignored = store.ignored + ps.ignored
    if args.json:
        print(json.dumps({"commands": [{k: r.get(k) for k in ("trust_id", "project_root", "days", "ts", "expires_at", "has_secret", "via")}
                                       | {"command": shown(r)} for r in rows],
                          "instruction_files": [{"file": p["file"], "project_root": p["project_root"], "ts": p["ts"],
                                                 "lines": [dict(v) for v in p["lines"].values()]} for p in pins],
                          "ignored_records": ignored,
                          "refused_attempts": [{k: r.get(k) for k in ("ts", "kind", "target", "project_root", "why")}
                                               for r in refused]}, indent=1))
        return 0
    where = "every project" if project is None else f"project {project}"
    if not rows:
        print(f"no trusted commands for {where} ({store.path})")
    else:
        print(f"trusted commands for {where} ({store.path}):")
        for r in rows:
            line = f"  {r.get('trust_id', '')}  until {str(r.get('expires_at', ''))[:19]}Z  `{shown(r)}`"
            if r.get("via"):
                line += f"  (via {'the agent, approved by semgate' if r.get('via') == 'ticket' else r.get('via')})"
            if project is None:
                line += f"  in {r.get('project_root', '')}"
            print(line)
    if ignored:
        print(f"ignored: {ignored} record(s) in {store.path} have no valid semgate tag (written by hand, by an older "
              f"semgate, or with another trust.key); they allow nothing")
    if refused:
        last = refused[-1]
        print(f"refused: {len(refused)} `semgate trust {refused[-1].get('kind', 'add')}` run(s) without semgate's approval "
              f"(the last at {str(last.get('ts', ''))[:19]}Z: `{last.get('target', '')}`)")
    if pins:
        print(f"trusted instruction-file lines for {where}:")
        for p in pins:
            where_p = f"  in {p['project_root']}" if project is None else ""
            print(f"  {p['file']}: {len(p['lines'])} line{'s' if len(p['lines']) != 1 else ''} since {p['ts'][:19]}Z{where_p}")
            for v in sorted(p["lines"].values(), key=lambda v: (v.get("line") is None, v.get("line") or 0)):
                print(f"    line {v.get('line') or '?'}: {v.get('text', '')}")
    return 0


def _cmd_remove(args: Any) -> int:
    store = _store_from_args(args)
    project = _project_from_args(args)
    if getattr(args, "file", ""):
        from .pins import PinStore, resolve_cli_file
        try:
            rel, _abs = resolve_cli_file(args.file, project, getattr(args, "project", "") or os.getcwd())
        except ValueError:
            rel = args.file.replace("\\", "/")          # a file that is gone can still be unpinned by its name
        try:
            old = PinStore(store.path).remove(project, rel)
        except filelock.LockTimeout as exc:
            print(f"not removed: {exc}. Try again.", file=sys.stderr)
            return 3
        if old is None:
            print(f"nothing to remove: no trusted lines of {rel} in {project}", file=sys.stderr)
            return 2
        print(f"removed: the {len(old['lines'])} trusted line(s) of {rel} in {project}")
        return 0
    if not args.trusted_command:
        print("give the exact command, or --file <instruction file>", file=sys.stderr)
        return 2
    try:
        old = store.remove(args.trusted_command, project)
    except filelock.LockTimeout as exc:
        print(f"not removed: {exc}. Try again.", file=sys.stderr)
        return 3
    if old is None:
        print(f"nothing to remove: `{args.trusted_command}` is not trusted in {project}", file=sys.stderr)
        return 2
    print(f"removed: `{shown(old)}` in {project}")
    return 0


def _cmd_file(args: Any) -> int:
    """`semgate trust file <file>`: pin every current command line of a
    project instruction file (pins.py). Replaces the file's earlier pins."""
    from .pins import PinStore, file_lines_to_pin, resolve_cli_file
    store = _store_from_args(args)
    project = _project_from_args(args)
    ps = PinStore(store.path)
    try:
        rel, abs_path = resolve_cli_file(args.instruction_file, project, getattr(args, "project", "") or os.getcwd())
        lines, refused = file_lines_to_pin(abs_path, ps)
    except ValueError as exc:
        print(f"not trusted: {exc}", file=sys.stderr)
        return 2
    if not lines:
        print(f"not trusted: {rel} has no command lines semgate can trust"
              + (f" ({len(refused)} match a hard rule)" if refused else ""), file=sys.stderr)
        return 2
    from . import trustauth
    auth, code = _authorize(store, "file", trustauth.file_target(rel), 0, project, lines=[x["key"] for x in lines],
                            summary=[f"semgate trust file: stop treating these {len(lines)} command line(s) of {rel} "
                                     f"as untrusted text", *[f"  line {x['line']}: {x['text']}" for x in lines],
                                     f"  project  {project}"])
    if auth is None:
        return code
    try:
        ps.add(project, rel, [{"key": x["key"], "text": x["text"], "line": x["line"]} for x in lines], auth=auth,
               replace=True)
    except filelock.LockTimeout as exc:
        print(f"not trusted: {exc}. Try again.", file=sys.stderr)
        return 3
    print(f"trusted: {len(lines)} command line{'s' if len(lines) != 1 else ''} of {rel}")
    for x in lines:
        print(f"  line {x['line']}: {x['text']}")
    for x in refused:
        print(f"  NOT trusted, matches a hard rule: line {x['line']}: {x['text']}")
    print(f"  project  {project}")
    print(f"  store    {store.path}")
    print("semgate no longer treats these lines as untrusted text. Commands from them are still judged in the normal "
          "way; nothing is allowed without a check. A new or changed line is asked about again.")
    print(f"Remove it with: semgate trust remove --file {rel}")
    return 0


def add_parser(sub: Any) -> None:
    p = sub.add_parser(
        "trust", help="Trusted commands: allow one exact command in one project without asking, until an expiry",
        description="A trusted command is one exact command text that semgate allows without asking, only in this "
                    "project (the git top folder of the current directory, or --project), until it expires (--days, "
                    f"default {DEFAULT_DAYS}, at most {MAX_DAYS}). Hard-rule commands can never be trusted, and a trust "
                    "never overrides a hard rule, an injection or drift deny, or the grant's forbidden patterns.")
    tsub = p.add_subparsers(dest="trust_command", required=True)
    common = {"--store": dict(default="", help=f"trust store (default ~/.semgate/{STORE_NAME})"),
              "--project": dict(default="", help="project folder (default: the current directory)")}
    a = tsub.add_parser("add", help="trust one exact command in this project")
    a.add_argument("trusted_command", help="the exact command text")
    a.add_argument("--days", type=int, default=DEFAULT_DAYS, help=f"days until it expires (1..{MAX_DAYS}, default {DEFAULT_DAYS})")
    a.add_argument("--note", default="")
    a.add_argument("--grant", action="append", default=[],
                   help="grant.json whose forbidden_patterns the command must not match (repeatable; default: the "
                        "grant of every installed semgate hook)")
    for k, v in common.items():
        a.add_argument(k, **v)
    a.set_defaults(func=_cmd_add)
    ls = tsub.add_parser("list", help="list the trusted commands in force (this project, or --all)")
    ls.add_argument("--all", action="store_true", help="every project")
    ls.add_argument("--json", action="store_true")
    for k, v in common.items():
        ls.add_argument(k, **v)
    ls.set_defaults(func=_cmd_list)
    r = tsub.add_parser("remove", help="end the trust of one exact command (or --file: of an instruction file's lines) in this project")
    r.add_argument("trusted_command", nargs="?", default="")
    r.add_argument("--file", default="", help="end the trust of the command lines of this instruction file")
    for k, v in common.items():
        r.add_argument(k, **v)
    r.set_defaults(func=_cmd_remove)
    f = tsub.add_parser("file", help="trust the current command lines of a project instruction file (AGENTS.md, CLAUDE.md, ...)",
                        description="Pins every current command line of the file (lines with an instruction to the agent, "
                                    "inline code, fenced code, or '$ '). semgate then no longer treats them as untrusted "
                                    "text; commands from them are still judged in the normal way. A line that matches a "
                                    "hard rule is never pinned. A new or changed line is asked about again.")
    f.add_argument("instruction_file")
    for k, v in common.items():
        f.add_argument(k, **v)
    f.set_defaults(func=_cmd_file)
