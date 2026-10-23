"""Work kinds: the purpose comes from what the user asked for, and a session
can cover several kinds of work at once.

One person with an agent now does development, research, data analysis and
deployment in the same afternoon. So there is no single "profile" per session.
Instead:

1. Session kinds. Each user message (agy USER_INPUT from USER_EXPLICIT; never
   model output or tool results) is checked with one yes/no question per kind
   of work, in one provider call, cached by message. The session covers every
   kind the user has asked for so far, so "now deploy it" an hour later adds
   devops without resetting anything.

2. Purpose. The grant purpose Jev judges against becomes:
       "This session covers: <labels>. Authorized: <authorized text of every
        active kind>. Not authorized: <base_restrictions>[; <the kind's own
        restricted text, only when exactly one kind is active>]."
       + "The user's requests this session: <messages>"
   A kind's own restrictions are left out when several kinds are active: the
   review kind says "no edits" and the development kind says "edits", and a
   purpose that says both confuses the model (Jev 1.13 known limitation).
   The user's own words ("don't change anything") are always included.

3. Work-kind check (see `check_command`). When Jev would ALLOW a command, one
   more call names the command's kind. If the kind is not "general" and the
   user has not asked for it this session, the hook asks the human instead,
   and says which kind of work it is and what was asked for. Sensitive kinds
   (devops) need a higher probability to count as requested.

Everything is operator-authored (policies/profiles.json) or typed by the user.
A work kind can only ADD domains to the grant and can only turn an allow into
an ask; it never touches hard rules, human gates or a deny.
"""
from __future__ import annotations

import dataclasses
import hashlib
import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple

from .envelope import UserGrant
from .gate import policy_dir
from .providers.base import JudgeProvider

GENERAL = "general"
GENERAL_LABEL = ("General: listing, reading or printing files, checking status, navigating, "
                 "simple inspection that fits any kind of work.")
DEFAULT_KIND = "software-development"
REQUEST_THRESHOLD = 0.5            # P(user asked for kind) to count it as requested
SENSITIVE_THRESHOLD = 0.85         # the same, for kinds marked sensitive
MESSAGE_MAX = 600                  # chars of each user message kept in the purpose
MESSAGES_KEPT = 5                  # most recent user messages kept in the purpose
_DOMAIN_RE = re.compile(r"^(\*\.)?([a-z0-9-]+\.)+[a-z0-9-]{2,}$|^localhost$|^\d{1,3}(\.\d{1,3}){3}$", re.I)


# --------------------------------------------------------------------------- table

@dataclass(frozen=True)
class KindTable:
    kinds: Dict[str, Dict[str, Any]]
    base_restrictions: str

    def label(self, kind: str) -> str:
        return GENERAL_LABEL if kind == GENERAL else str(self.kinds.get(kind, {}).get("label", kind))

    def short(self, kind: str) -> str:
        return self.label(kind).split(":")[0].strip()


def load_profiles(path: Optional[str] = None) -> KindTable:
    p = Path(path) if path else policy_dir() / "profiles.json"
    data = json.loads(p.read_text(encoding="utf-8"))
    kinds = data.get("profiles") if isinstance(data, Mapping) else None
    if not isinstance(kinds, Mapping) or not kinds:
        raise ValueError(f"{p}: no profiles")
    base = str(data.get("base_restrictions", "")).strip()
    if not base:
        raise ValueError(f"{p}: base_restrictions is required (the restrictions shared by every kind of work)")
    for kid, k in kinds.items():
        if kid == GENERAL:
            raise ValueError(f"{p}: '{GENERAL}' is reserved")
        if not isinstance(k, Mapping) or not str(k.get("label", "")).strip() or not str(k.get("authorized", "")).strip():
            raise ValueError(f"{p}: profile {kid!r} needs a label and an authorized text")
        domains = k.get("allowed_domains", [])
        if not isinstance(domains, list) or not all(isinstance(x, str) for x in domains):
            raise ValueError(f"{p}: profile {kid!r}: allowed_domains must be a list of host names")
        for host in domains:
            if not _DOMAIN_RE.match(host):
                raise ValueError(f"{p}: profile {kid!r}: {host!r} is not a plain host name "
                                 "(no scheme, path, port or bare wildcard; '*.example.com' is allowed)")
    return KindTable({str(k): dict(v) for k, v in kinds.items()}, base)


# ------------------------------------------------------------------ state (cache)

def _digest(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()[:16]


def _load_state(state_file: str) -> Dict[str, Any]:
    if not state_file:
        return {}
    try:
        data = json.loads(Path(state_file).read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def _save_state(state_file: str, state: Mapping[str, Any]) -> None:
    if not state_file:
        return
    try:
        data = dict(state)
        if len(data) > 200:  # keep the file small: drop the oldest sessions
            for old in list(data)[: len(data) - 200]:
                data.pop(old, None)
        target = Path(state_file)
        target.parent.mkdir(parents=True, exist_ok=True)
        # unique temp file + os.replace: a parallel hook never reads a half-written
        # cache (key order kept: the oldest sessions are dropped first). No lock:
        # a lost update is only a cache miss.
        import os
        import random
        tmp = target.with_name(f"{target.name}.{os.getpid()}.{random.getrandbits(32):08x}.tmp")
        try:
            tmp.write_text(json.dumps(data), encoding="utf-8")
            os.replace(tmp, target)
        finally:
            if tmp.exists():
                tmp.unlink()
    except Exception:
        pass  # a cache write error must never change a decision


# --------------------------------------------------------------- session kinds

@dataclass(frozen=True)
class SessionKinds:
    probabilities: Dict[str, float]          # kind -> max P(user asked for it) over the session's messages
    active: Tuple[str, ...]                  # kinds counted as requested, in table order
    source: str                              # "override" | "classified" | "default"
    messages: Tuple[str, ...] = field(default=())


def _kind_questions(table: KindTable) -> Dict[str, Dict[str, Any]]:
    return {kid: {"type": "noul", "instructions":
                  "Does `user_request` ask for this kind of work, possibly together with other kinds? "
                  f"Answer only from what the user asks for. {k['label']}"}
            for kid, k in table.kinds.items()}


def _threshold(table: KindTable, kind: str, cfg: Mapping[str, Any]) -> float:
    if table.kinds.get(kind, {}).get("sensitive"):
        return float(cfg.get("sensitive_threshold", SENSITIVE_THRESHOLD))
    return float(cfg.get("threshold", REQUEST_THRESHOLD))


def session_kinds(cfg: Mapping[str, Any], *, session_id: str, messages: Sequence[str],
                  provider: Optional[JudgeProvider], table: KindTable) -> SessionKinds:
    """Which kinds of work the user has asked for this session. `override`
    (a list or one kind) pins them; otherwise each message is classified once
    (cached) and a kind is active when any message asks for it."""
    msgs = tuple(m.strip() for m in messages if m and m.strip())
    override = cfg.get("override")
    if override:
        wanted = [override] if isinstance(override, str) else list(override)
        active = tuple(k for k in table.kinds if k in wanted) or (DEFAULT_KIND,)
        return SessionKinds({k: 1.0 for k in active}, active, "override", msgs)
    default = str(cfg.get("default") or DEFAULT_KIND)
    if default not in table.kinds:
        default = next(iter(table.kinds))
    if provider is None or not msgs:
        return SessionKinds({default: 1.0}, (default,), "default", msgs)
    state_file = str(cfg.get("state_file") or "")
    state = _load_state(state_file)
    sess = state.get(session_id) if isinstance(state.get(session_id), dict) else {}
    per_msg: Dict[str, Dict[str, float]] = dict(sess.get("messages") or {})
    changed = False
    for m in msgs:
        key = _digest(m)
        if key in per_msg:
            continue
        try:
            answers = provider.evaluate({"user_request": m[:1500]}, _kind_questions(table))
            per_msg[key] = {k: float(a.probability) for k, a in answers.items()
                            if k in table.kinds and getattr(a, "probability", None) is not None}
        except Exception:
            per_msg[key] = {}
        changed = True
    probs: Dict[str, float] = {}
    for m in msgs:
        for k, p in per_msg.get(_digest(m), {}).items():
            probs[k] = max(probs.get(k, 0.0), p)
    active = tuple(k for k in table.kinds if probs.get(k, 0.0) >= _threshold(table, k, cfg))
    source = "classified"
    if not active:
        active, source = (default,), "default"
    if changed and state_file and session_id:
        sess = dict(sess)
        sess["messages"] = per_msg
        sess["active"] = list(active)
        state[session_id] = sess
        _save_state(state_file, state)
    return SessionKinds(probs, active, source, msgs)


# -------------------------------------------------------------------- purpose

def resolve(grant: UserGrant, cfg: Mapping[str, Any], *, session_id: str, messages: Sequence[str],
            provider: Optional[JudgeProvider], resolved: Optional[SessionKinds] = None):
    """Resolve the same effective grant for preparation and permission checks."""
    if cfg.get("enabled") is not True:
        return grant, None, None
    table = load_profiles(str(cfg.get("file") or "") or None)
    if resolved is None:
        kinds = session_kinds(cfg, session_id=session_id, messages=messages, provider=provider, table=table)
    else:
        if (not isinstance(resolved, SessionKinds) or resolved.messages != tuple(m.strip() for m in messages if m and m.strip())
                or not resolved.active or any(kind not in table.kinds for kind in resolved.active)):
            raise ValueError("prepared profile resolution does not match the protected task")
        kinds = resolved
    return apply(grant, kinds, table), kinds, table


def compose_purpose(table: KindTable, kinds: SessionKinds) -> str:
    labels = [table.short(k) for k in kinds.active]
    authorized = "; ".join(str(table.kinds[k]["authorized"]).strip() for k in kinds.active)
    restricted = table.base_restrictions
    if len(kinds.active) == 1:
        own = str(table.kinds[kinds.active[0]].get("restricted", "")).strip()
        if own:
            restricted = f"{restricted}; {own}"
    text = (f"This session covers: {', '.join(labels)}. Authorized: {authorized}. "
            f"Not authorized: {restricted}.")
    recent = [" ".join(m.split())[:MESSAGE_MAX] for m in kinds.messages[-MESSAGES_KEPT:]]
    if recent:
        text += "\nThe user's requests this session, in their own words: " + " | ".join(recent)
    return text


def apply(grant: UserGrant, kinds: SessionKinds, table: KindTable) -> UserGrant:
    """The grant with its purpose composed from the active kinds and the user's
    messages, plus the active kinds' allowed_domains. Hard scope fields are kept;
    provenance records what was used."""
    prov = f"{grant.provenance} | purpose: kinds {list(kinds.active)} ({kinds.source})"
    have = {d.lower() for d in grant.allowed_domains}
    extra: List[str] = []
    for k in kinds.active:
        for d in table.kinds[k].get("allowed_domains", []):
            if d.lower() not in have and d.lower() not in extra:
                extra.append(d.lower())
    if extra:
        prov += f" | domains from kinds: {', '.join(extra)}"
    return dataclasses.replace(grant, purpose=compose_purpose(table, kinds), provenance=prov,
                               allowed_domains=tuple(grant.allowed_domains) + tuple(extra))


# --------------------------------------------------------- work-kind check

@dataclass(frozen=True)
class KindCheck:
    kind: str                      # the command's kind, or "general"
    confidence: Optional[float]
    requested: bool                # the user asked for this kind (or it is general)
    message: str                   # explanation for the human, empty when requested


def check_command(command: str, cfg: Mapping[str, Any], *, session_id: str, kinds: SessionKinds,
                  provider: Optional[JudgeProvider], table: KindTable) -> Optional[KindCheck]:
    """Name the command's kind of work and say whether the user asked for it.
    Cached per session + exact command. None when it cannot be decided (no
    provider, no command, provider error): the caller then keeps its decision."""
    if provider is None or not command.strip():
        return None
    state_file = str(cfg.get("state_file") or "")
    state = _load_state(state_file)
    sess = state.get(session_id) if isinstance(state.get(session_id), dict) else {}
    cache: Dict[str, Any] = dict(sess.get("commands") or {})
    key = _digest(command)
    hit = cache.get(key)
    if isinstance(hit, Mapping) and (hit.get("kind") == GENERAL or hit.get("kind") in table.kinds):
        kind, conf = str(hit["kind"]), hit.get("confidence")
    else:
        criteria = {GENERAL: GENERAL_LABEL}
        criteria.update({k: v["label"] for k, v in table.kinds.items()})
        try:
            answer = provider.evaluate({"command": command[:1500]}, {"kind": {
                "type": "choice",
                "instructions": "Which kind of work does `command` belong to? Choose general when the command is "
                                "simple inspection that any kind of work would use.",
                "criteria": criteria}})["kind"]
            kind = str(answer.value)
            conf = float(answer.confidence) if answer.confidence is not None else None
        except Exception:
            return None
        if kind != GENERAL and kind not in table.kinds:
            return None
        if state_file and session_id:
            cache[key] = {"kind": kind, "confidence": conf}
            sess = dict(sess)
            sess["commands"] = dict(list(cache.items())[-500:])
            state[session_id] = sess
            _save_state(state_file, state)
    if kind == GENERAL or kind in kinds.active:
        return KindCheck(kind, conf, True, "")
    asked = ", ".join(table.short(k) for k in kinds.active)
    msg = (f"Approve? This looks like {table.short(kind)} work, which you have not asked for this session "
           f"(you asked for: {asked}). If you want the agent doing {table.short(kind)} work, approve it here; "
           f"asking for it in the chat makes it part of the session.")
    return KindCheck(kind, conf, False, msg)
