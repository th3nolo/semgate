"""Operator-owned task binding for prepared execution, never tool arguments."""
from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path


def request_for(config: dict, *, task: str, project: str, now: datetime | None = None) -> str:
    from .envelope import USER_MESSAGE_CHARS_MAX
    settings = config.get("prepared_sends", {})
    context = settings.get("task_context")
    if (not isinstance(context, dict) or set(context) != {"request", "expires_at"}
            or not isinstance(context["request"], str) or not context["request"].strip()
            or len(context["request"]) > USER_MESSAGE_CHARS_MAX or "\0" in context["request"]
            or not isinstance(context["expires_at"], str)):
        raise ValueError("protected task context with request and expiry is required")
    if task != settings.get("task_id") or Path(project).resolve() != Path(settings["project_root"]).resolve():
        raise ValueError("trusted task context identity mismatch")
    expiry = datetime.fromisoformat(context["expires_at"].replace("Z", "+00:00"))
    if expiry.tzinfo is None or expiry <= (now or datetime.now(timezone.utc)):
        raise ValueError("trusted task context expired or missing timezone")
    return context["request"]
