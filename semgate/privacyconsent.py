"""Task-scoped disclosure consent, using semgate's locks and signed records.

The embedding application owns identity, task lifetime and data classification.
Only its authenticated operator side may call approve/revoke/close_task. The
CLI uses the existing admin guard. Same-user Python imports are not a sandbox.
No payload, recipient, purpose or source text is persisted in this store.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
import hashlib
import hmac
import json
import math
from pathlib import Path
import secrets
import time
from typing import Callable, Dict, Literal, Optional, TypeVar

from . import filelock, trustauth
from .envelope import canonical_json
from .feedback import norm_root

POLICY_VERSION = "semgate-disclosure/1"
MAX_RECORDS = 5000
MAX_STORE_BYTES = 4 * 1024 * 1024
MAX_TTL_S = 4 * 3600
_TAG = "privacy-consent/1"
T = TypeVar("T")
Disposition = Literal["allow", "deny", "needs_consent", "needs_inspection", "service_error"]


@dataclass(frozen=True)
class DisclosureScope:
    principal: str
    project: str
    task: str
    source: str
    operation: str
    destination: str
    purpose: str
    policy_version: str = POLICY_VERSION

    def __post_init__(self) -> None:
        for value in asdict(self).values():
            if not isinstance(value, str) or not value.strip() or len(value) > 8192 or any(c in value for c in "\r\n\x00"):
                raise ValueError("disclosure scope fields must be bounded non-empty strings")
        object.__setattr__(self, "project", norm_root(self.project))


@dataclass(frozen=True)
class ConsentOutcome:
    disposition: Disposition
    reason_code: str
    request_id: str = ""
    grant_id: str = ""

    def record(self) -> Dict[str, str]:
        return {k: v for k, v in asdict(self).items() if v}


def _now(value: Optional[float]) -> float:
    result = time.time() if value is None else float(value)
    if not math.isfinite(result):
        raise ValueError("invalid consent time")
    return result


def validate_categories(categories: frozenset[str]) -> list[str]:
    if not isinstance(categories, frozenset) or not categories or len(categories) > 32:
        raise ValueError("disclosure requires explicit data categories")
    if any(not isinstance(c, str) or not c or len(c) > 64 or not all(ch.isascii() and (ch.isalnum() or ch == "_") for ch in c)
           for c in categories):
        raise ValueError("invalid data category")
    return sorted(categories)


class ConsentStore:
    def __init__(self, path: Path, *, ttl_s: float = MAX_TTL_S) -> None:
        if isinstance(ttl_s, bool) or not math.isfinite(ttl_s) or not 0 < ttl_s <= MAX_TTL_S:
            raise ValueError("consent TTL must be positive and at most four hours")
        self.path, self.ttl_s = Path(path).expanduser().resolve(), float(ttl_s)

    def _key(self) -> bytes:
        return trustauth.key_for_store(self.path)

    @staticmethod
    def _fingerprint(key: bytes, kind: str, value: object) -> str:
        return hmac.new(key, (kind + "\n" + canonical_json(value)).encode(), hashlib.sha256).hexdigest()

    def _load(self, key: bytes) -> Dict[str, dict]:
        try:
            with self.path.open("rb") as stream:
                data = stream.read(MAX_STORE_BYTES + 1)
        except FileNotFoundError:
            return {}
        if len(data) > MAX_STORE_BYTES:
            raise ValueError("consent store exceeds limit")
        value = json.loads(data)
        if not isinstance(value, dict) or value.get("schema") != 1 or not isinstance(value.get("records"), dict):
            raise ValueError("invalid consent store")
        rows = value["records"]
        if len(rows) > MAX_RECORDS or any(not isinstance(r, dict) or r.get("id") != ident
                                          or not trustauth.tag_ok(key, _TAG, r) for ident, r in rows.items()):
            raise ValueError("invalid consent integrity")
        return rows

    def _save(self, rows: Dict[str, dict], key: bytes) -> None:
        if len(rows) > MAX_RECORDS:
            raise ValueError("consent store is full")
        signed = {ident: trustauth.tagged(key, _TAG, row) for ident, row in rows.items()}
        filelock.write_json_atomic(self.path, {"schema": 1, "records": signed})

    def _scope(self, scope: DisclosureScope, key: bytes) -> tuple[str, str]:
        return (self._fingerprint(key, "scope", asdict(scope)),
                self._fingerprint(key, "task", [scope.principal, scope.project, scope.task]))

    def _evaluate(self, rows: Dict[str, dict], scope: DisclosureScope, categories: frozenset[str], digest: str,
                  key: bytes, now: float, create: bool) -> tuple[ConsentOutcome, bool]:
        labels = validate_categories(categories)
        if not isinstance(digest, str) or len(digest) != 64 or any(c not in "0123456789abcdef" for c in digest):
            raise ValueError("invalid payload digest")
        if "secret" in categories or "credential" in categories:
            return ConsentOutcome("deny", "privacy_credentials_forbidden"), False
        scope_key, task_key = self._scope(scope, key)
        if any(r.get("kind") == "closed" and r.get("task") == task_key for r in rows.values()):
            return ConsentOutcome("deny", "privacy_task_closed"), False
        matching = [r for r in rows.values() if r.get("scope") == scope_key and set(labels) <= set(r.get("categories", []))]
        if any(r.get("status") in {"revoked", "denied"} for r in matching):
            return ConsentOutcome("deny", "privacy_consent_revoked"), False
        for row in matching:
            if (row.get("status") == "approved" and now >= row["approved_at"]
                    and now < min(row["expires"], row["approved_at"] + self.ttl_s)
                    and (not row.get("digest") or row["digest"] == digest)):
                return ConsentOutcome("allow", "privacy_task_consent", grant_id=row["id"]), False
        request_key = self._fingerprint(key, "request", [scope_key, labels, digest])
        for row in rows.values():
            if (row.get("request") == request_key and row.get("status") == "pending"
                    and row["created"] <= now < row["expires"]):
                return ConsentOutcome("needs_consent", "privacy_consent_required", request_id=row["id"]), False
        if not create:
            return ConsentOutcome("needs_consent", "privacy_consent_required"), False
        ident = secrets.token_hex(16)
        rows[ident] = {"id": ident, "kind": "consent", "status": "pending", "scope": scope_key, "task": task_key,
                       "categories": labels, "request": request_key, "requested_digest": digest,
                       "created": now, "expires": now + self.ttl_s, "ttl_limit": self.ttl_s}
        return ConsentOutcome("needs_consent", "privacy_consent_required", request_id=ident), True

    def evaluate(self, scope: DisclosureScope, categories: frozenset[str], digest: str, *,
                 now: Optional[float] = None) -> ConsentOutcome:
        with filelock.exclusive(self.path):
            key = self._key()
            rows = self._load(key)
            outcome, changed = self._evaluate(rows, scope, categories, digest, key, _now(now), True)
            if changed:
                self._save(rows, key)
            return outcome

    def approve(self, request_id: str, *, auth: trustauth.Auth, task_scope: bool = True,
                ttl_s: Optional[float] = None, now: Optional[float] = None) -> str:
        """Operator side only. Task scope is explicit; snapshot scope is available."""
        trustauth.require(auth)
        if not isinstance(task_scope, bool):
            raise ValueError("task_scope must be boolean")
        t = _now(now)
        with filelock.exclusive(self.path):
            key = self._key()
            rows = self._load(key)
            row = rows.get(request_id)
            if not row or row.get("status") != "pending" or not row["created"] <= t < row["expires"]:
                raise ValueError("no live pending consent with that id")
            limit = min(self.ttl_s, row["ttl_limit"])
            ttl = limit if ttl_s is None else ttl_s
            if isinstance(ttl, bool) or not math.isfinite(ttl) or not 0 < ttl <= limit:
                raise ValueError("approval TTL exceeds the operator's consent limit")
            if any(r.get("kind") == "closed" and r.get("task") == row["task"] for r in rows.values()):
                raise ValueError("the task is closed")
            row.update(status="approved", approved_at=t, expires=t + ttl,
                       digest="" if task_scope else row["requested_digest"], via=auth.via)
            self._save(rows, key)
        return request_id

    def revoke(self, grant_id: str, *, auth: trustauth.Auth) -> None:
        trustauth.require(auth)
        with filelock.exclusive(self.path):
            key = self._key()
            rows = self._load(key)
            if grant_id not in rows or rows[grant_id].get("kind") != "consent":
                raise ValueError("unknown consent id")
            rows[grant_id].update(status="revoked", via=auth.via)
            self._save(rows, key)

    def close_task(self, scope: DisclosureScope, *, auth: trustauth.Auth) -> None:
        trustauth.require(auth)
        with filelock.exclusive(self.path):
            key = self._key()
            rows = self._load(key)
            _, task_key = self._scope(scope, key)
            if not any(r.get("kind") == "closed" and r.get("task") == task_key for r in rows.values()):
                ident = secrets.token_hex(16)
                rows[ident] = {"id": ident, "kind": "closed", "task": task_key, "via": auth.via}
                self._save(rows, key)

    def close_task_of(self, request_id: str, *, auth: trustauth.Auth) -> None:
        """Operator CLI can end a task using a displayed request/grant id."""
        trustauth.require(auth)
        with filelock.exclusive(self.path):
            key = self._key()
            rows = self._load(key)
            if request_id not in rows or rows[request_id].get("kind") != "consent":
                raise ValueError("unknown consent id")
            task_key = rows[request_id]["task"]
            if not any(r.get("kind") == "closed" and r.get("task") == task_key for r in rows.values()):
                ident = secrets.token_hex(16)
                rows[ident] = {"id": ident, "kind": "closed", "task": task_key, "via": auth.via}
                self._save(rows, key)

    def use(self, scope: DisclosureScope, categories: frozenset[str], digest: str,
            action: Callable[[], T]) -> tuple[ConsentOutcome, Optional[T]]:
        """Serialize dispatch with revocation. In-flight I/O is not retroactively cancelled."""
        with filelock.exclusive(self.path):
            key = self._key()
            outcome, _ = self._evaluate(self._load(key), scope, categories, digest, key, _now(None), False)
            return (outcome, action()) if outcome.disposition == "allow" else (outcome, None)
