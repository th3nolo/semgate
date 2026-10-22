"""Append-only JSONL ledger: judgments, reviewer overrides, outcomes.

Record types share one file, distinguished by `record_type`:
  - judgment: the decision semgate produced, with policy version and votes.
              `judgment_id` is the envelope content digest, not an event id.
  - host_response: the exact object a harness hook returned to its host,
              keyed by (conversation_id, step_idx)
  - override: a reviewer disagreeing with a judgment
  - outcome:  what eventually happened (human approved/denied, action reverted)
  - incident: something seen after a decision that it did not see (F4:
              a script changed between the decision and the run)
  - chat_approval: a step of approval by chat reply (chatapproval.py)
  - trust_request: the agent ran `semgate trust add` (trustgate.py)
  - pin_request: semgate asked about instruction-file lines (pingate.py)
  - serve_event: `semgate serve --stdio` saw a plugin stamp, or its code
              changed on disk (hot reload; serve.py)

The ledger is the only thing the judge writes. It is the evidence trail that
later calibration and (much later) any non-shadow behavior must be built on.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional

from . import filelock
from .envelope import Envelope, utcnow_iso


class IncompleteWindow(RuntimeError):
    """The session-drift reader could not read every earlier judgment of the
    window (lock timeout, unreadable file, a malformed line that may belong
    to this session, or a record of this session kept in a lock-timeout
    spill file). The judge turns an allow into an ask."""


def turn_key(envelope: Dict[str, Any]) -> str:
    """Identifies "the latest user turn" of an envelope dict: the number of
    user turns and the latest turn's text (whitespace collapsed)."""
    msgs = [str(m) for m in (envelope.get("user_messages") or []) if str(m).strip()]
    latest = str(envelope.get("user_message") or (msgs[-1] if msgs else ""))
    count = len(msgs) if msgs else (1 if latest.strip() else 0)
    return f"{count}:" + " ".join(latest.split())


class Ledger:
    def __init__(self, path: str):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def _append(self, record: Dict[str, Any], spill: bool = True) -> None:
        """One line, one write, under the cross-process lock (filelock).
        Raises filelock.LockTimeout (after keeping the record in a spill
        file, unless spill is False); callers fail closed."""
        filelock.append_record(self.path, record, spill=spill)

    def _private_turn_id(self, envelope: Dict[str, Any]) -> str:
        from . import fingerprints, trustauth
        # A keyed identity preserves turn boundaries without storing or
        # exposing a guessable hash of a user's private request.
        key = trustauth.key_for_store(self.path)
        return fingerprints.fingerprint(key, "privacy-ledger-turn/1\x00" + turn_key(envelope))

    def record_judgment(self, envelope: Envelope, decision: "Any", *, private: bool = False) -> str:
        record = {
            "record_type": "judgment",
            "judgment_id": decision.envelope_digest,
            "ts": decision.evaluated_at,
            "decision": decision.to_dict(),
            "envelope": envelope.to_dict(),
        }
        if private:
            from .privacydata import safe_inputs
            try:
                private_turn = self._private_turn_id(record["envelope"])
                record, _ = safe_inputs(record, {})
                record["privacy_minimized"] = True
                record["privacy_turn_id"] = private_turn
                if record["envelope"]["environment"].get("session_id") != envelope.environment.session_id:
                    record["privacy_session_unattributed"] = True
            except Exception:
                # Inspection overflow must never fall back to writing the raw
                # envelope or exception message. Missing history stays unknown.
                record = {"record_type": "judgment", "judgment_id": decision.envelope_digest,
                          "ts": decision.evaluated_at, "privacy_minimized": True, "envelope_omitted": True,
                          "privacy_window_incomplete": True,
                          "envelope": {"environment": {"session_id": ""}},
                          "decision": {"decision": decision.decision, "stage": decision.stage,
                                       "reason_code": decision.reason_code}}
                from .privacydata import Minimizer
                try:
                    record["envelope"]["environment"]["session_id"] = Minimizer().text(envelope.environment.session_id)
                except Exception:
                    pass
                if record["envelope"]["environment"]["session_id"] != envelope.environment.session_id:
                    record["privacy_session_unattributed"] = True
        self._append(record)
        return decision.envelope_digest

    def record_override(self, judgment_id: str, reviewer: str, verdict: str, note: str = "") -> None:
        self._append({
            "record_type": "override",
            "judgment_id": judgment_id,
            "reviewer": reviewer,
            "verdict": verdict,
            "note": note,
            "ts": utcnow_iso(),
        })

    def record_outcome(self, judgment_id: str, outcome: str, detail: str = "") -> None:
        self._append({
            "record_type": "outcome",
            "judgment_id": judgment_id,
            "outcome": outcome,
            "detail": detail,
            "ts": utcnow_iso(),
        })

    def record_host_response(
        self,
        conversation_id: str,
        step_idx: Any,
        native: Dict[str, Any],
        tool: str = "",
        content_digest: str = "",
        spill: bool = True,
        invalid_session_id: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """The exact object the hook returned to the host for one tool step.
        The event identity is (conversation_id, step_idx). `content_digest` is
        the envelope digest: identical actions share it, so it is not an event id.
        `invalid_session_id` ({"length", "sha256_12"}) replaces a session id the
        hook rejected; conversation_id is then "". Returns the record written."""
        record = {
            "record_type": "host_response",
            "conversation_id": conversation_id,
            "step_idx": step_idx,
            "tool": tool,
            "content_digest": content_digest,
            "native": dict(native),
            "ts": utcnow_iso(),
        }
        if invalid_session_id is not None:
            record["invalid_session_id"] = dict(invalid_session_id)
        self._append(record, spill=spill)
        return record

    def record_incident(self, kind: str, detail: Dict[str, Any]) -> None:
        """Something observed after a decision that the decision did not see,
        e.g. `script_changed`: a script's sha256 after the run differs from
        the one read at decision time (F4 TOCTOU). A record, not a block."""
        self._append({"record_type": "incident", "kind": kind, "detail": dict(detail), "ts": utcnow_iso()})

    def record_serve_event(self, event: str, detail: Dict[str, Any]) -> None:
        """`semgate serve --stdio` about itself (serve.py): `client` (the
        plugin stamp a serve process saw first, and whether that plugin is
        older than the installed asset), `reload` (serve's code changed on
        disk; how the plugin moves to a new process). Never a decision."""
        self._append({"record_type": "serve_event", "event": event, "detail": dict(detail), "ts": utcnow_iso()})

    def record_chat_approval(self, event: str, detail: Dict[str, Any]) -> None:
        """Approval by chat reply (chatapproval.py): `block_recorded`,
        `approved`, `not_approved` (the judge's answer did not approve, or no
        answer), `code_rejected` (a code check failed before the judge was
        asked), `lock_timeout`. Holds the block id, a hash of the user turns
        (never their text), p, and for a judged reply `outcome`: allow,
        clarify (unclear: the agent asks one clear yes/no question),
        declined, or unchecked (provider error, timeout, no provider)."""
        self._append({"record_type": "chat_approval", "event": event, "detail": dict(detail), "ts": utcnow_iso()})

    def record_human_approval(self, event: str, detail: Dict[str, Any]) -> None:
        """Approval by id (approvals.py; semgate.harness, `semgate serve
        --http`): `pending` (an ask got an approval id), `approved` /
        `denied` (the human's answer, with `by`), `used` (an approval turned
        the ask of a later check into an allow), `denied_applied` (a human
        no turned a later check into a deny). Holds the approval id, the
        session id, the tool, the judgment id; never a token."""
        self._append({"record_type": "human_approval", "event": event, "detail": dict(detail), "ts": utcnow_iso()})

    def record_trust_request(self, event: str, detail: Dict[str, Any]) -> None:
        """`semgate trust add` run by the agent (trustgate.py): `allowed`,
        `not_allowed` (the judge said no, or no answer), `code_rejected` (a
        code check failed before the judge was asked). Holds the command to
        trust, the days, p, why and a hash of the user turns (never their
        text)."""
        self._append({"record_type": "trust_request", "event": event, "detail": dict(detail), "ts": utcnow_iso()})

    def record_pin_request(self, event: str, detail: Dict[str, Any]) -> None:
        """semgate's question about the command lines of a project
        instruction file (pingate.py): `recorded` (asked; waiting for the
        user), `pinned`, `not_pinned` (the judge said no, or no answer),
        `code_rejected`, `lock_timeout`, `store_failed`. Holds the file, the
        number of lines, p, why and a hash of the user turns (never their
        text)."""
        self._append({"record_type": "pin_request", "event": event, "detail": dict(detail), "ts": utcnow_iso()})

    def session_first_seen(self, session_id: str) -> Optional[float]:
        """Epoch seconds of the earliest judgment or host_response recorded
        for `session_id` (from the host event, never from the command), or
        None. Used as one bound of the session start (G2 signal S1)."""
        from .gitstate import to_epoch
        if not session_id or not self.path.exists():
            return None
        earliest: Optional[float] = None
        needle = filelock.json_needle(session_id)
        try:
            for r in filelock.read_jsonl(self.path, keep=lambda line: needle in line).records:
                kind = r.get("record_type")
                if kind == "judgment":
                    sid = str(((r.get("envelope") or {}).get("environment") or {}).get("session_id", ""))
                elif kind == "host_response":
                    sid = str(r.get("conversation_id", ""))
                else:
                    continue
                ts = to_epoch(r.get("ts")) if sid == session_id else None
                if ts is not None and (earliest is None or ts < earliest):
                    earliest = ts
        except OSError:
            return None
        return earliest

    def session_on_task(self, envelope: Envelope, exclude: str = "", limit: int = 50) -> List[float]:
        """Session drift: the on_task probabilities of this session's earlier
        semantic judgments since the latest user turn, oldest first (at most
        `limit`). "Since the latest user turn" = judgments whose envelope has
        the same number of user turns and the same latest turn text. The
        judgment `exclude` (the current envelope digest: a retried identical
        step) is left out. [] without a session id or without a ledger.

        Raises IncompleteWindow when the window may be incomplete: the lock
        was not free in time or the file could not be read; a line from the
        session's first line onward (or any line naming the session) is
        malformed; or a lock-timeout spill file holds a line of this session.
        The file is read under the lock, so a write in progress is never
        mistaken for a malformed line."""
        sid = envelope.environment.session_id
        if not sid:
            return []
        needle = filelock.json_needle(sid)
        for spill in filelock.spill_files(self.path):
            try:
                spill_bytes = spill.read_bytes()
                if needle in spill_bytes or b'"privacy_session_unattributed"' in spill_bytes:
                    raise IncompleteWindow(f"a record of this session is in {spill.name} (lock timeout)")
            except OSError as exc:
                raise IncompleteWindow(f"cannot read {spill.name}: {exc}")
        try:
            raw = filelock.read_bytes_locked(self.path)
        except (filelock.LockTimeout, OSError) as exc:
            raise IncompleteWindow(f"ledger not readable: {type(exc).__name__}: {exc}")
        if b'"privacy_session_unattributed"' in raw:
            if any(r.get("privacy_session_unattributed") is True for r in filelock.parse_jsonl_bytes(raw).records):
                raise IncompleteWindow("privacy-minimized history contains an unattributed session")
        first = raw.find(needle)
        if first < 0:
            return []
        start = raw.rfind(b"\n", 0, first) + 1          # the session's first line
        key = turn_key(envelope.to_dict())
        out: List[float] = []
        private_turn = None
        parsed = filelock.parse_jsonl_bytes(raw[start:])
        if parsed.malformed or parsed.partial_tail:
            raise IncompleteWindow(f"{len(parsed.malformed) + int(parsed.partial_tail)} malformed line(s) since this session's first record")
        for r in parsed.records:
            if r.get("record_type") != "judgment":
                continue
            env = r.get("envelope") or {}
            d = r.get("decision") or {}
            if (str((env.get("environment") or {}).get("session_id", "")) != sid
                    or (exclude and r.get("judgment_id") == exclude)):
                continue
            if r.get("privacy_minimized"):
                if r.get("privacy_window_incomplete"):
                    raise IncompleteWindow("privacy-minimized history cannot establish the user-turn window")
                if d.get("stage") != "semantic":
                    continue
                if r.get("privacy_turn_id"):
                    if private_turn is None:
                        try:
                            private_turn = self._private_turn_id(envelope.to_dict())
                        except Exception as exc:
                            raise IncompleteWindow("privacy-minimized turn identity unavailable") from exc
                    stored_turn = r["privacy_turn_id"]
                    if (not isinstance(stored_turn, str) or len(stored_turn) != len(private_turn)
                            or stored_turn.rsplit(":", 1)[0] != private_turn.rsplit(":", 1)[0]
                            or any(c not in "0123456789abcdef" for c in stored_turn.rsplit(":", 1)[-1])):
                        raise IncompleteWindow("privacy-minimized turn identity cannot be compared")
                    if r["privacy_turn_id"] != private_turn:
                        continue
                elif turn_key(env) != key:
                    # Legacy minimized records cannot reliably distinguish an
                    # old turn from a redacted current turn. Do not drop them.
                    raise IncompleteWindow("privacy-minimized history cannot establish the user-turn window")
            elif d.get("stage") != "semantic" or turn_key(env) != key:
                continue
            p = next((v.get("p") for v in d.get("predicate_votes") or [] if v.get("predicate") == "on_task"), None)
            if isinstance(p, (int, float)):
                out.append(float(p))
        return out[-limit:]

    def host_responses(self) -> List[Dict[str, Any]]:
        return [r for r in self.records() if r.get("record_type") == "host_response"]

    def records(self) -> Iterator[Dict[str, Any]]:
        """Well-formed records. A malformed line is skipped (never parsed
        tolerantly) and gets one `store_warning` record."""
        result = filelock.read_jsonl(self.path)
        filelock.warn_malformed(self.path, result, "ledger")
        yield from result.records

    def judgments(self) -> List[Dict[str, Any]]:
        return [r for r in self.records() if r.get("record_type") == "judgment"]

    def overrides(self) -> List[Dict[str, Any]]:
        return [r for r in self.records() if r.get("record_type") == "override"]

    def outcomes(self) -> List[Dict[str, Any]]:
        return [r for r in self.records() if r.get("record_type") == "outcome"]
