"""Human approvals by id, for harnesses without a host prompt (semgate.harness,
`semgate serve --http`).

A hook host (Claude Code, agy, ...) shows semgate's ask to the user and runs
the tool when the user says yes. A custom harness has no such prompt. Here the
harness gets an `approval_id` with every ask, shows the reason to a human,
and the human side records the answer (POST /v1/approve, or
semgate.harness.approve()). The next check of the same action then gets:

  approved: allow, once. The record is used up; a second run needs a new ask
            and a new approval.
  denied:   deny, for every check of the same action in the same session and
            project until the record expires.

Scope (the same as `semgate feedback allow`): one session id, one project
root, the exact action (chatapproval.action_key: tool + exact command text +
folder, or the exact arguments of a non-shell tool; no case or space
folding), and a time limit (`feedback.approval_ttl_hours`, default 4 h): a
pending record can be answered until it expires; an approval must be used
before approved_at + ttl.

An approval only turns an ask into an allow. It never changes a deny (hard
rules, grant scope, a semantic deny, a human feedback deny) or a store
failure answer: the check that uses it runs the full pipeline again first.

Storage: one JSON file (approvals.json next to the ledger) under the
cross-process lock (filelock). Any store error fails closed: no approval
is used, no approval id is given.
"""
from __future__ import annotations

import secrets
import time
from pathlib import Path
from typing import Any, Dict, Mapping, Optional

from . import filelock

SCHEMA = 1
DEFAULT_TTL_HOURS = 4.0
MAX_RECORDS = 5000            # oldest records are dropped beyond this (the file stays small)
ID_BYTES = 16                 # approval ids are 32 hex characters (128 random bits)
BY_MAX = 200
NOTE_MAX = 500


class ApprovalError(ValueError):
    """An approve() call that cannot be applied. `code`: not_found (unknown or
    expired id), conflict (already answered or used), invalid (bad input)."""

    def __init__(self, message: str, code: str):
        super().__init__(message)
        self.code = code


def ttl_hours(config: Mapping[str, Any]) -> float:
    from .feedback import ttl_hours_from
    return ttl_hours_from(config)


def store_path(config: Mapping[str, Any]) -> Path:
    from .storepaths import state_path
    return Path(state_path(config, "approvals.json"))


def norm_root(path: str) -> str:
    from .feedback import norm_root as _norm
    return _norm(path)


def _iso(epoch: float) -> str:
    from .feedback import _iso as iso
    return iso(epoch)


def _valid_id(value: Any) -> bool:
    return isinstance(value, str) and len(value) == ID_BYTES * 2 and all(c in "0123456789abcdef" for c in value)


class ApprovalStore:
    """{approval_id: record} in one JSON file. Every read-modify-write holds
    the file's lock. Raises filelock.LockTimeout."""

    def __init__(self, path: Path, ttl_s: float):
        self.path = Path(path)
        self.ttl_s = float(ttl_s)

    # ---------- file ----------
    def _load(self, now: float) -> Dict[str, Dict[str, Any]]:
        import json
        import math
        def unique(pairs):
            out = {}
            for key, value in pairs:
                if key in out:
                    raise ValueError("duplicate approval-store field")
                out[key] = value
            return out
        def timestamp(value):
            try:
                return type(value) in (int, float) and math.isfinite(value)
            except OverflowError:
                return False
        try:
            raw = json.loads(self.path.read_text(encoding="utf-8"), object_pairs_hook=unique)
        except FileNotFoundError:
            return {}
        except (OSError, ValueError) as exc:
            raise ApprovalError("approval store cannot be read", "unreadable") from exc
        if (not isinstance(raw, dict) or type(raw.get("schema")) is not int or raw["schema"] != SCHEMA
                or not isinstance(raw.get("approvals"), dict)):
            raise ApprovalError("approval store has an invalid schema", "unreadable")
        items = raw["approvals"]
        if any(not _valid_id(k) or not isinstance(v, dict) or v.get("approval_id") != k
               or v.get("status") not in {"pending", "approved", "denied", "used"}
               or not timestamp(v.get("created"))
               or v.get("status") in {"approved", "denied"} and not timestamp(v.get("decided"))
               or not all(isinstance(v.get(field), str) and v[field] for field in ("action_key", "session_id", "project_root"))
               for k, v in items.items()):
            raise ApprovalError("approval store has an invalid record", "unreadable")
        return {k: v for k, v in items.items() if not self._expired(v, now)}

    def _save(self, items: Mapping[str, Any]) -> None:
        if len(items) > MAX_RECORDS:
            keep = sorted(items.items(), key=lambda kv: float(kv[1].get("created", 0)))[-MAX_RECORDS:]
            items = dict(keep)
        filelock.write_json_atomic(self.path, {"schema": SCHEMA, "approvals": dict(items)})

    def _expired(self, r: Mapping[str, Any], now: float) -> bool:
        try:
            created = float(r.get("created", 0))
        except (TypeError, ValueError):
            return True
        if created > now + 300.0:          # from the future: clock skew or a written file
            return True
        if r.get("status") == "approved":
            try:
                return now >= float(r.get("decided", 0)) + self.ttl_s
            except (TypeError, ValueError):
                return True
        if r.get("status") == "denied":
            try:
                return now >= float(r.get("decided", 0)) + self.ttl_s
            except (TypeError, ValueError):
                return True
        if r.get("status") == "used":
            return now >= created + 2 * self.ttl_s      # kept a while so a late approve() says "already used"
        return now >= created + self.ttl_s               # pending

    @staticmethod
    def _matches(r: Mapping[str, Any], key: str, session_id: str, root: str) -> bool:
        return r.get("action_key") == key and r.get("session_id") == session_id and r.get("project_root") == root

    # ---------- check side ----------
    def settle(self, *, key: str, session_id: str, project_root: str, final: str, now: Optional[float] = None,
               summary: str = "", tool: str = "", reason_code: str = "", judgment_id: str = "",
               approvable: bool = True, consume: bool = True) -> Dict[str, Any]:
        """The approval step of one check, after the pipeline's answer `final`
        (allow / ask / deny). Returns {"effect": ..., "record": ...}:
          "deny"    a human denied this action (final was allow or ask)
          "allow"   final was ask and a human approved it; the record is used now
          "pending" final was ask; record (new, or the pending one of the same action)
          "none"    nothing to do (final deny, allow without a human deny, or
                    an ask that is not `approvable`)
        `approvable` False (the judge said deny, e.g. in shadow mode, or the
        grant expired): a human no still applies; nothing is approved or
        recorded, like `semgate feedback allow` never opens those.
        `consume=False` previews an approval for preparation; dispatch must
        settle it again with consumption under this same cross-process lock."""
        t = time.time() if now is None else float(now)
        root = norm_root(project_root)
        if not session_id or not root:
            return {"effect": "none", "record": None}
        with filelock.exclusive(self.path):
            items = self._load(t)
            mine = [r for r in items.values() if self._matches(r, key, session_id, root)]
            mine.sort(key=lambda r: float(r.get("decided") or r.get("created") or 0))
            denied = [r for r in mine if r.get("status") == "denied"]
            if denied and final in ("allow", "ask"):
                return {"effect": "deny", "record": dict(denied[-1])}
            if final != "ask" or not approvable:
                return {"effect": "none", "record": None}
            approved = [r for r in mine if r.get("status") == "approved"]
            if approved:
                r = approved[-1]
                if consume:
                    r["status"], r["used"] = "used", t
                    self._save(items)
                return {"effect": "allow", "record": dict(r)}
            pending = [r for r in mine if r.get("status") == "pending"]
            if pending:
                return {"effect": "pending", "record": dict(pending[-1])}
            rid = secrets.token_hex(ID_BYTES)
            r = {"approval_id": rid, "status": "pending", "action_key": key, "session_id": session_id,
                 "project_root": root, "tool": tool, "summary": summary[:300], "reason_code": reason_code,
                 "judgment_id": judgment_id, "created": t}
            items[rid] = r
            self._save(items)
            return {"effect": "pending", "record": dict(r), "new": True}

    # ---------- human side ----------
    def decide(self, approval_id: str, approved: bool, by: str, note: str = "",
               now: Optional[float] = None) -> Dict[str, Any]:
        """Record the human's answer to a pending approval. Raises ApprovalError."""
        if not _valid_id(approval_id):
            raise ApprovalError("approval_id must be 32 lowercase hex characters", "invalid")
        if not isinstance(approved, bool):
            raise ApprovalError("approved must be true or false", "invalid")
        if not isinstance(by, str) or not by.strip() or len(by) > BY_MAX:
            raise ApprovalError(f"by must be a non-empty name of at most {BY_MAX} characters", "invalid")
        if not isinstance(note, str) or len(note) > NOTE_MAX:
            raise ApprovalError(f"note must be a string of at most {NOTE_MAX} characters", "invalid")
        t = time.time() if now is None else float(now)
        with filelock.exclusive(self.path):
            items = self._load(t)
            r = items.get(approval_id)
            if r is None:
                raise ApprovalError("no pending approval with this id (unknown, or expired)", "not_found")
            if r.get("status") != "pending":
                raise ApprovalError(f"this approval is already {r.get('status')}", "conflict")
            r.update(status="approved" if approved else "denied", decided=t, by=by.strip(), note=note)
            self._save(items)
            return dict(r)

    def get(self, approval_id: str, now: Optional[float] = None) -> Optional[Dict[str, Any]]:
        if not _valid_id(approval_id):
            return None
        t = time.time() if now is None else float(now)
        with filelock.exclusive(self.path):
            r = self._load(t).get(approval_id)
            return dict(r) if r else None


def store_for(config: Mapping[str, Any]) -> ApprovalStore:
    return ApprovalStore(store_path(config), ttl_s=ttl_hours(config) * 3600.0)


def public(record: Mapping[str, Any], ttl_s: float) -> Dict[str, Any]:
    """What an approve() answer shows: never the session, project or command."""
    out: Dict[str, Any] = {"approval_id": record.get("approval_id"), "status": record.get("status")}
    if record.get("status") in ("approved", "denied") and record.get("decided") is not None:
        out["expires_at"] = _iso(float(record["decided"]) + ttl_s)
    elif record.get("created") is not None:
        out["expires_at"] = _iso(float(record["created"]) + ttl_s)
    return out
