"""Human decision store: what a person chose when Semgate asked or blocked.

The operator (never the agent) records `allow` or `deny` for an exact action,
with `semgate feedback allow|deny "<command>"`. The judge then honours it: an
approved action that Semgate would ask/deny is let through; a denied action
is blocked. Two uses:
  - close the loop live: blocked -> the agent asks the human -> human approves ->
    the action runs on retry;
  - build the dataset of decisions people actually want (calibration).

Scope of an approval (record schema 2). An `allow` applies only when ALL hold:
  - the same tool and the exact same command text (no lowercasing, no
    whitespace folding: `rm -rf Dist` is not `rm -rf dist`);
  - the same host session id;
  - the same project root;
  - before its expiry (`expires_at`, default 4 hours after the approval,
    `feedback.approval_ttl_hours`), and never longer than the hook's own
    `feedback.approval_ttl_hours` after it was written.
Inside that scope it can be used more than once (the agent may retry the
same command in the same session). Other sessions, projects or commands are
not affected. The CLI binds an approval to the most recent session of the
current project whose ledger shows the exact command was asked or blocked.

Legacy records (written before schema 2: no session, no project, no expiry):
an `allow` is NOT honoured any more (treated as expired). A legacy `deny` is
still honoured.

Scope of a `deny`: every session and project unless the operator gave
`--session` / `--project`, and no expiry unless `--ttl-hours` is given. A deny
only ever makes a decision stricter, so a wide deny cannot open anything. It
matches the normalized command (case and whitespace folded), which is wider
than the exact text, for the same reason. The newest applicable record wins, so
an operator can still approve a denied command for one session afterwards.

Safety: a human `allow` never overrides a hard-deny (catastrophic patterns,
disabling the gate) or an expired grant; it only overrides a human gate or a
semantic ask/deny. The agent must never write here (the hook blocks it), so it
cannot approve its own actions.

Concurrency: writes are one line under a cross-process lock (filelock); reads
take the same lock. A read that cannot get the lock raises LockTimeout and
the judge fails closed (an allow becomes an ask).
"""
from __future__ import annotations

import hashlib
import hmac
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional

from . import filelock
from .history import action_key, normalize_args

VALID = ("allow", "deny")
SCHEMA = 2
DEFAULT_TTL_HOURS = 4.0
CLOCK_SKEW_S = 300.0


def _command_of(arguments: Mapping[str, Any]) -> str:
    """The command text, from whichever alias carries it. Feedback is keyed on the
    command alone, so the operator's CLI record and the hook's full event (which
    also carries cwd, CommandLine, ...) produce the same key."""
    for k in ("command", "commandline", "CommandLine"):
        v = arguments.get(k)
        if isinstance(v, str) and v.strip():
            return v
    return ""


def _key(tool: str, arguments: Mapping[str, Any]) -> str:
    """Normalized key (case and whitespace folded). Used for denies, legacy
    records and calibration; never for an approval."""
    return action_key(tool, {"command": _command_of(arguments)})


def exact_key(tool: str, command: str) -> str:
    """Approval key: the tool name and the exact command text."""
    return hashlib.sha256((tool.strip().lower() + "\n" + command).encode("utf-8")).hexdigest()


def norm_root(path: str) -> str:
    if not path or not str(path).strip():
        return ""
    return os.path.normcase(os.path.realpath(os.path.expanduser(str(path))))


def _epoch(value: Any) -> Optional[float]:
    from .gitstate import to_epoch
    return to_epoch(value)


def _iso(epoch: float) -> str:
    return datetime.fromtimestamp(epoch, timezone.utc).isoformat().replace("+00:00", "Z")


def ttl_hours_from(config: Mapping[str, Any]) -> float:
    """feedback.approval_ttl_hours from a semgate config; default 4 h. A value
    that is not a positive number falls back to the default."""
    fb = config.get("feedback") if isinstance(config.get("feedback"), Mapping) else {}
    try:
        value = float(fb.get("approval_ttl_hours", DEFAULT_TTL_HOURS))
    except (TypeError, ValueError):
        return DEFAULT_TTL_HOURS
    return value if value > 0 else DEFAULT_TTL_HOURS


class FeedbackStore:
    def __init__(self, path: str, max_ttl_hours: float = DEFAULT_TTL_HOURS):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.max_ttl_hours = float(max_ttl_hours) if max_ttl_hours and max_ttl_hours > 0 else DEFAULT_TTL_HOURS

    def record(self, decision: str, tool: str, arguments: Mapping[str, Any], reviewer: str = "operator", note: str = "",
               *, session_id: str = "", project_root: str = "", ttl_hours: Optional[float] = None,
               now: Optional[float] = None, bound_to: Optional[Mapping[str, Any]] = None) -> Dict[str, Any]:
        """Append one human decision. An `allow` needs a session id and a
        project root (ValueError otherwise) and always gets an expiry."""
        if decision not in VALID:
            raise ValueError(f"feedback decision must be one of {VALID}")
        command = _command_of(arguments)
        if not command:
            raise ValueError("feedback needs a non-empty command")
        root = norm_root(project_root)
        if decision == "allow" and (not session_id or not root):
            raise ValueError("an approval needs a session id and a project root")
        t = time_now() if now is None else float(now)
        ttl = self.max_ttl_hours if (decision == "allow" and ttl_hours is None) else ttl_hours
        if ttl is not None and not (float(ttl) > 0):
            raise ValueError("ttl_hours must be a positive number")
        record: Dict[str, Any] = {
            "record_type": "feedback",
            "schema": SCHEMA,
            "decision": decision,
            "tool": tool,
            "command": command,
            "exact_key": exact_key(tool, command),
            "args_normalized": normalize_args({"command": command}),
            "action_key": _key(tool, arguments),
            "session_id": session_id,
            "project_root": root,
            "expires_at": _iso(t + float(ttl) * 3600.0) if ttl is not None else "",
            "reviewer": reviewer,
            "note": note,
            "ts": _iso(t),
        }
        if bound_to:
            record["bound_to"] = dict(bound_to)
        filelock.append_record(self.path, record, repair=True)   # rare CLI writes: keep a deny off a torn line
        return record

    def records(self) -> List[Dict[str, Any]]:
        """All well-formed records, read under the lock. Raises LockTimeout."""
        return filelock.read_jsonl_locked(self.path).records

    def _applies(self, r: Mapping[str, Any], tool: str, command: str, norm_key: str, session_id: str, root: str,
                 now: float) -> bool:
        decision = r.get("decision")
        if r.get("record_type") != "feedback" or decision not in VALID:
            return False
        expires = r.get("expires_at")
        if expires:
            e = _epoch(expires)
            if e is None or now >= e:
                return False
        if decision == "deny":
            if r.get("action_key") != norm_key:
                return False
            if r.get("session_id") and r.get("session_id") != session_id:
                return False
            if r.get("project_root") and norm_root(str(r.get("project_root"))) != root:
                return False
            return True
        # allow: schema 2 only, exact action, same session, same project, unexpired
        if r.get("schema") != SCHEMA or not expires:
            return False
        if r.get("exact_key") != exact_key(tool, command) or r.get("command") != command:
            return False
        if not session_id or r.get("session_id") != session_id:
            return False
        if not root or norm_root(str(r.get("project_root", ""))) != root:
            return False
        ts = _epoch(r.get("ts"))
        if ts is None or ts > now + CLOCK_SKEW_S or now >= ts + self.max_ttl_hours * 3600.0:
            return False
        return True

    def latest(self, tool: str, arguments: Mapping[str, Any], session_id: str = "", project_root: str = "",
               now: Optional[float] = None) -> Optional[str]:
        """The newest human decision that applies to this action in this
        session and project, or None. Raises LockTimeout / OSError when the
        store cannot be read (the judge then fails closed)."""
        command = _command_of(arguments)
        if not command or not self.path.exists():
            return None
        t = time_now() if now is None else float(now)
        norm_key = _key(tool, arguments)
        root = norm_root(project_root)
        found: Optional[str] = None
        for r in self.records():
            if self._applies(r, tool, command, norm_key, session_id, root, t):
                found = str(r.get("decision"))     # the newest applicable record wins
        return found


def time_now() -> float:
    return datetime.now(timezone.utc).timestamp()


# ---------------- CLI binding: which session does an approval belong to ----------------

def _under(child: str, parent: str) -> bool:
    return bool(child and parent) and (child == parent or child.startswith(parent.rstrip(os.sep) + os.sep))


def _private_scope(record: Mapping[str, Any], key: bytes, command: str, want_dir: str,
                   tool: str, session_id: str) -> Optional[tuple[str, str, str]]:
    """Recover only identities verified against operator-supplied scope hints."""
    from .ledger import private_identity

    def matches(field: str, value: str) -> bool:
        saved = record.get("privacy_" + field + "_id")
        return (isinstance(saved, str) and saved.isascii()
                and hmac.compare_digest(saved, private_identity(key, field, value)))

    if not matches("command", command):
        return None
    env = record.get("envelope") or {}
    action = env.get("action") or {}
    environment = env.get("environment") or {}
    env_tool = tool if record.get("privacy_tool_unattributed") else str(action.get("tool", ""))
    sid = session_id if record.get("privacy_session_unattributed") else str(environment.get("session_id", ""))
    if (not env_tool or not sid or not matches("tool", env_tool) or not matches("session", sid)
            or (tool and env_tool.lower() != tool.lower()) or (session_id and sid != session_id)):
        return None
    if want_dir:
        # A CLI invoked in a subdirectory still binds to the original root.
        root = want_dir
        while not matches("project", root):
            parent = os.path.dirname(root)
            if parent == root:
                return None
            root = parent
    else:
        root = norm_root(str(environment.get("project_root") or environment.get("cwd") or ""))
        if not root or not matches("project", root):
            return None
    return env_tool, sid, root


def blocked_candidates(ledger_path: str, command: str, project_dir: str = "", tool: str = "",
                       session_id: str = "", any_decision: bool = False) -> List[Dict[str, Any]]:
    """Steps in the ledger where this exact command was asked or blocked.
    Newest first. Each: session_id, project_root, tool, ts, judgment_id,
    decision (what the host got), stage.

    A step qualifies when its judgment decision is ask/deny, or when the host
    got a non-allow answer for it (host_response with the same content digest
    in the same session); with `any_decision`, every judged step of the
    command (`semgate feedback deny` of a command that was allowed).
    `project_dir`, when given, must be the judgment's project root or a
    directory inside it. `tool` and `session_id` narrow. A ledger that does
    not exist has no steps."""
    from . import fingerprints, trust
    path = Path(os.path.expanduser(str(ledger_path)))
    if not path.is_file():
        return []
    try:
        key = fingerprints.read_existing_key(path.with_name(trust.KEY_NAME))
    except fingerprints.KeyUnavailable:
        key = None
    from .ledger import private_identity
    private_needle = private_identity(key, "command", command).encode("ascii") if key else b""
    needle = filelock.json_needle(command)
    records = filelock.read_jsonl(path, keep=lambda line: needle in line or (private_needle and private_needle in line)
                                 or b'"host_response"' in line).records
    host_block: Dict[tuple, str] = {}
    for r in records:
        if r.get("record_type") == "host_response":
            native = r.get("native") or {}
            dec = str(native.get("decision", "")) if isinstance(native, Mapping) else ""
            if dec and dec != "allow":
                host_block[(str(r.get("conversation_id", "")), str(r.get("content_digest", "")))] = dec
    want_dir = norm_root(project_dir) if project_dir else ""
    out: List[Dict[str, Any]] = []
    for r in records:
        if r.get("record_type") != "judgment":
            continue
        env = r.get("envelope") or {}
        action = env.get("action") or {}
        args = action.get("arguments") or {}
        if r.get("privacy_minimized"):
            scope = _private_scope(r, key, command, want_dir, tool, session_id) if key else None
            if scope is None:
                continue
            env_tool, sid, root = scope
        else:
            if _command_of(args) != command:
                continue
            env_tool = str(action.get("tool", ""))
            if tool and env_tool.lower() != tool.lower():
                continue
            environment = env.get("environment") or {}
            sid = str(environment.get("session_id", ""))
            if not sid or (session_id and sid != session_id):
                continue
            root = norm_root(str(environment.get("project_root") or environment.get("cwd") or ""))
            if not root or (want_dir and not _under(want_dir, root)):
                continue
        decision = r.get("decision") or {}
        judged = str(decision.get("decision", ""))
        host = host_block.get((sid, str(r.get("judgment_id", ""))), "")
        if judged not in ("ask", "deny") and not host and not any_decision:
            continue
        out.append({"session_id": sid, "project_root": root, "tool": env_tool, "ts": str(r.get("ts", "")),
                    "judgment_id": str(r.get("judgment_id", "")), "decision": host or judged,
                    "stage": str(decision.get("stage", ""))})
    out.sort(key=lambda c: _epoch(c["ts"]) or 0.0, reverse=True)
    return out
