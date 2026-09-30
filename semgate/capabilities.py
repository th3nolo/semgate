"""Exact, predeclared capability matching for deterministic policy allows."""
from __future__ import annotations
from datetime import datetime, timezone
from typing import Any, Mapping, Optional

REQUIRED = ("action", "target", "scope", "issued_by", "expires_at")

def _canonical(value: Any) -> Any:
    if isinstance(value, dict):
        return {str(k): _canonical(value[k]) for k in sorted(value)}
    if isinstance(value, list):
        return [_canonical(v) for v in value]
    return value

def _parse_ts(value: Any) -> Optional[datetime]:
    """An RFC3339 timestamp with an explicit offset, or None (malformed)."""
    try:
        ts = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None
    if ts.tzinfo is None:
        return None
    return ts

def matches_capability(proposal: Mapping[str, Any], capability: Mapping[str, Any], *, now: datetime) -> bool:
    """Match exact action/target/scope against a trusted, unexpired capability.

    No substring, category, wildcard, label, or model-score matching is allowed.

    Validity window: `expires_at` is required; `not_before` is optional and,
    when present, must already have passed. Any non-null `revoked_at` disables
    the capability: revocation is recorded when the grant is revoked, so a
    future-dated one is inconsistent data and fails closed like any other.
    A malformed timestamp never matches.
    """
    if any(k not in capability for k in REQUIRED):
        return False
    if capability.get("issued_by") != "trusted_owner_channel":
        return False
    if set(proposal) != {"action", "target", "scope"}:
        return False
    if any("*" in str(capability[k]) for k in ("action", "target", "scope")):
        return False
    expiry = _parse_ts(capability["expires_at"])
    if expiry is None:
        return False
    now_utc = now.astimezone(timezone.utc)
    if now_utc >= expiry.astimezone(timezone.utc):
        return False
    if capability.get("not_before") is not None:
        start = _parse_ts(capability["not_before"])
        if start is None or now_utc < start.astimezone(timezone.utc):
            return False
    if capability.get("revoked_at") is not None:
        return False
    return all(_canonical(proposal[k]) == _canonical(capability[k]) for k in ("action", "target", "scope"))
