"""Secrets exposed to the agent: fingerprint, tell the agent once, report.

The owner's rule:
  1. Never send secrets to an agent.
  2. If a secret is sent to an agent, treat it as leaked.
  3. Use short-lived secrets (1 hour, or at most 24 hours) and revoke them
     after the task.

What happens: after a tool runs, the host's post-tool event gives semgate the
tool's output (Claude Code family PostToolUse, OpenCode V1
tool.execute.after through `semgate serve`). semgate.secretfinder looks for
secrets in it. For each secret this session has not shown before:

  - one `exposure` record is appended to the session's file (never the
    value):
      {"record_type": "exposure", "session_id", "host", "type", "masked"
       (first 4 + last 4 chars, fewer for short values), "fingerprint"
       (HMAC-SHA256 of the value with this install's key, see
       semgate.fingerprints; for de-duplication only), "where": {"tool",
       "detail" (short command or path, secrets in it masked), "step"
       (tool_use_id / callID)}, "first_seen", "epoch", "told_agent"}
  - on a host whose manifest says C33 (post-tool context) = yes, the agent
    gets NOTICE (once per secret per session, by fingerprint).

De-duplication key (dedup_key): the fingerprint; for records of the earlier
format, "sha256:" + their plain sha256 (another namespace: it never equals a
keyed fingerprint, so such a secret is told once more after the upgrade; the
old records are read, never rewritten); when no key could be read or created
(fingerprints.key_for), the record has "fingerprint": null, the ledger gets
the incident `fingerprint_key_unavailable`, and the key is
"masked:<type>:<masked preview>". A key file that was unusable and replaced
gives the incident `fingerprint_key_replaced`.

Intent (policy `router.exposure_questions.user_shared_secret` with the
threshold `exposure_intended_min`; see decide_intent): before the notice,
the judge is asked one noul question per new secret, "did the user
deliberately give the agent this secret for the current task?", with
non-secret facts only (type, masked preview, tool and command with secrets
masked, the user's turns with every secret value replaced by a label). It
is asked outside the store lock, at most INTENT_ASKS_MAX secrets per output,
in parallel, bounded by `secret_exposures.intent_timeout_s` (default
INTENT_TIMEOUT_S). P >= threshold: INTENDED_NOTICE. Otherwise, and on a
provider error, a timeout, a missing answer, no user turns, no provider, or
a policy without the question: NOTICE (fail closed = unintended). The answer
is kept in the record as "intent".

At the end of a turn (Claude Code Stop hook, manifest C34 = yes) the user sees
one block with every secret exposed in the session, when the session has an
exposure not shown in an earlier block (`summary_shown` records). The Stop
hook never blocks.

`semgate report --exposures` lists the records per session.

Where: `<dir>/<session key>.jsonl`, dir = semgate.json `secret_exposures.dir`,
default `exposures/` next to `ledger_file` (~/.semgate/<host>/exposures).
`<session key>` = sha256(session id)[:32] (agentfiles.session_key). Off with
`"secret_exposures": false` or `{"enabled": false}`. A session file not
modified for KEEP_DAYS is deleted when another session's first record is
written.

Locks (filelock): the read (which secrets are known) and the append happen
under one cross-process lock, so two parallel post events cannot both tell
the agent about the same secret. A lock timeout records nothing and writes a
ledger incident `secret_exposure_not_recorded` (type and masked value only);
the agent is still told (without de-duplication). Nothing here blocks a tool.
"""
from __future__ import annotations

import os
import sys
import threading
import time
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

from . import filelock, fingerprints, secretfinder
from .providers.registry import LIVE as LIVE_PROVIDERS

KEEP_DAYS = 30
DETAIL_MAX = 80
RULES = (
    "Never send secrets to an agent.",
    "If a secret is sent to an agent, treat it as leaked.",
    "Use short-lived secrets (1 hour, or at most 24 hours) and revoke them after the task.",
)
NOTICE = ("[semgate] A secret was exposed to you in this step: {type} {masked}, in the output of `{where}`. "
          "Treat it as leaked. Tell the user now: if showing it to you was intended, rotate this secret when this "
          "session ends; if it was not intended, rotate it right away.")
INTENDED_NOTICE = ("[semgate] The user gave you this secret for this task: {type} {masked}. Treat it as exposed. "
                   "Remind the user to rotate or revoke it when this session ends.")
INTENT_TIMEOUT_S = 10.0     # = typesafe-sdk 0.7.0 DEFAULT_TIMEOUT, the provider's own HTTP timeout per attempt
INTENT_ASKS_MAX = 4         # new secrets in one output that are asked about; the others count as not intended
TURN_CHARS = 1100           # user_message cut (router.DEFAULT_TASK_CONTEXT_LIMITS requests_chars)


# ---------------------------------------------------------------- config


def enabled(config: Mapping[str, Any]) -> bool:
    value = config.get("secret_exposures") if isinstance(config, Mapping) else None
    if value is False:
        return False
    if isinstance(value, Mapping) and value.get("enabled") is False:
        return False
    return True


def store_dir(config: Mapping[str, Any]) -> Path:
    value = config.get("secret_exposures") if isinstance(config.get("secret_exposures"), Mapping) else {}
    if value.get("dir"):
        return Path(os.path.expanduser(str(value["dir"])))
    from .storepaths import state_path
    return Path(state_path(config, "exposures"))


def session_path(directory: Path, session_id: str) -> Path:
    from .agentfiles import session_key
    return Path(directory) / f"{session_key(session_id)}.jsonl"


def host_supports(manifest_host: str, capability: str) -> bool:
    """Manifest cell `capability` is "yes" for `manifest_host` (fail closed:
    a host without a manifest, or any other status, is not supported)."""
    if not manifest_host:
        return False
    try:
        from .hosts.base import load_manifest
        return load_manifest(manifest_host).supports(capability)
    except Exception:
        return False


# ---------------------------------------------------------------- text


def _now_iso(epoch: float) -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(epoch))


def where_label(tool: str, detail: str) -> str:
    tool = str(tool or "tool")
    return f"{tool}: {detail}" if detail else tool


def safe_detail(detail: str, values: Sequence[str]) -> str:
    """The command / path shown as `where`: one line, secrets masked
    (the output's values and any secret the command itself carries), cut to
    DETAIL_MAX, no backticks (the notice quotes it with backticks)."""
    text = " ".join(str(detail or "").split())
    text = secretfinder.mask_in(text, list(values))
    if len(text) > DETAIL_MAX:
        text = text[:DETAIL_MAX - 1] + "…"
    return text.replace("`", "'")


def intended(record: Mapping[str, Any]) -> bool:
    intent = record.get("intent")
    return isinstance(intent, Mapping) and intent.get("intended") is True


def notice_text(records: Iterable[Mapping[str, Any]]) -> str:
    lines = []
    for r in records:
        w = r.get("where") or {}
        template = INTENDED_NOTICE if intended(r) else NOTICE
        lines.append(template.format(type=r.get("type", "secret"), masked=r.get("masked", "…"),
                                     where=where_label(w.get("tool", ""), w.get("detail", ""))))
    return "\n".join(lines)


def intent_text(record: Mapping[str, Any]) -> str:
    """For the report and the Stop summary: `intended p=0.91`, `unintended
    p=0.12`, `unintended (not asked: ...)`, `unintended (timeout)`; `-` for a
    record written before intent was kept."""
    i = record.get("intent")
    if not isinstance(i, Mapping):
        return "-"
    word = "intended" if i.get("intended") is True else "unintended"
    if i.get("p") is not None:
        return f"{word} p={float(i['p']):.2f}"
    return f"{word} ({i.get('why') or 'not asked'})"


# ---------------------------------------------------------------- store


def _read(path: Path) -> List[Dict[str, Any]]:
    try:
        raw = path.read_bytes()
    except FileNotFoundError:
        return []
    return filelock.parse_jsonl_bytes(raw).records


def _drop_stale(directory: Path, own: Path, now: float) -> None:
    try:
        candidates = [p for p in directory.glob("*.jsonl") if p != own]
    except OSError:
        return
    limit = KEEP_DAYS * 86400
    for p in candidates:
        try:
            if now - p.stat().st_mtime <= limit:
                continue
            with filelock.exclusive(p, 0.2):
                if now - p.stat().st_mtime > limit:
                    p.unlink()
        except (OSError, filelock.LockTimeout):
            continue


def _incident(config: Mapping[str, Any], kind: str, detail: Dict[str, Any]) -> None:
    try:
        from .ledger import Ledger
        from .storepaths import ledger_file
        Ledger(ledger_file(config)).record_incident(kind, detail)
    except Exception as exc:
        print(f"semgate: could not record {kind}: {type(exc).__name__}: {exc}", file=sys.stderr)


def dedup_key(record: Mapping[str, Any]) -> str:
    """See the module docstring: fingerprint, legacy "sha256:<hex>", or
    "masked:<type>:<masked>" when the record has no fingerprint."""
    if record.get("fingerprint"):
        return str(record["fingerprint"])
    if record.get("sha256"):
        return "sha256:" + str(record["sha256"])
    return f"masked:{record.get('type', '')}:{record.get('masked', '')}"


def _key(config: Mapping[str, Any]) -> Optional[bytes]:
    key, problem = fingerprints.key_for(config)
    if key is None:
        _incident(config, "fingerprint_key_unavailable", {"reason": problem, "path": str(fingerprints.key_path(config))})
        print(f"semgate: no fingerprint key ({problem}); secrets are de-duplicated by masked preview", file=sys.stderr)
    elif problem:
        _incident(config, "fingerprint_key_replaced", {"reason": problem, "path": str(fingerprints.key_path(config))})
    return key


def build_records(session_id: str, host: str, tool: str, detail: str, step: Any,
                  found: Sequence[secretfinder.Found], now: float, key: Optional[bytes] = None) -> List[Dict[str, Any]]:
    safe = safe_detail(detail, [f.value for f in found])
    out = []
    for f in found:
        out.append({
            "record_type": "exposure",
            "schema": 1,
            "session_id": session_id,
            "host": host,
            "type": f.type,
            "masked": secretfinder.mask(f.value),
            "fingerprint": fingerprints.fingerprint(key, f.value) if key else None,
            "where": {"tool": str(tool or ""), "detail": safe, "step": "" if step is None else str(step)[:120]},
            "first_seen": _now_iso(now),
            "epoch": now,
        })
    return out


# ---------------------------------------------------------------- intent: did the user give this secret on purpose?


class _Turns:
    """The two envelope members router.render_task_requests reads."""

    def __init__(self, turns: Sequence[str]) -> None:
        self._turns = tuple(turns)
        self.user_message = self._turns[-1] if self._turns else ""

    def all_user_messages(self) -> Tuple[str, ...]:
        return self._turns


def intent_state(found: secretfinder.Found, all_found: Sequence[secretfinder.Found], tool: str, detail: str,
                 messages: Sequence[str]) -> Dict[str, str]:
    """The judge's state for one secret, non-secret facts only:
    `secret` (type and masked preview), `where` (tool and the command, its
    secrets already masked: safe_detail), `user_message` (the latest user
    turn, cut to TURN_CHARS) and `task_requests` (every user turn, as the
    router's task context renders them; omitted with one turn). In the turns
    every secret the detector finds, and every value found in this output,
    is replaced by `<secret TYPE MASKED>` (secretfinder.label_secrets)."""
    from . import router
    turns = []
    for m in messages:
        flat = " ".join(str(m or "").split())
        if flat:
            turns.append(secretfinder.label_secrets(flat, extra=all_found)[0])
    state = {"secret": f"{found.type} {secretfinder.mask(found.value)}", "where": where_label(tool, detail),
             "user_message": router._cut_middle(turns[-1], TURN_CHARS) if turns else ""}
    requests = router.render_task_requests(_Turns(turns), router.DEFAULT_TASK_CONTEXT_LIMITS)
    if requests:
        state["task_requests"] = requests
    return state


def carries_value(state: Mapping[str, str], found: Sequence[secretfinder.Found]) -> bool:
    """True when any found value is in the state text (then it is not sent)."""
    blob = "\n".join(str(v) for v in state.values())
    return any(f.value and f.value in blob for f in found)


def _intent_provider(config: Mapping[str, Any]) -> Tuple[Any, str]:
    name = str(config.get("provider") or "none")   # JSON null = none (init wrote null up to 0.4.0)
    if name == "fake":
        from .providers.fake import FakeProvider
        return FakeProvider(script=config.get("fake_answers") or {}, fail=bool(config.get("provider_fail"))), ""
    if name in LIVE_PROVIDERS:
        from .providers.registry import live_provider
        from .providers.safe import configured
        return configured(live_provider(name, str(config.get("judge_model") or "") or None), config), ""
    return None, f"no judge (provider {name})"


def _intent_timeout(config: Mapping[str, Any]) -> float:
    value = config.get("secret_exposures") if isinstance(config.get("secret_exposures"), Mapping) else {}
    try:
        t = float(value.get("intent_timeout_s", INTENT_TIMEOUT_S))
    except (TypeError, ValueError):
        t = INTENT_TIMEOUT_S
    return t if t > 0 else INTENT_TIMEOUT_S


def ask_intent(provider: Any, states: Sequence[Mapping[str, str]], question: Mapping[str, Any],
               timeout: float) -> List[Tuple[Optional[float], str]]:
    """One provider call per state, in parallel threads, all bounded by one
    deadline `timeout` seconds from now. Per state: (p, "") or (None, why):
    "timeout", "missing answer", "provider error: <type>"."""
    from .router import EXPOSURE_QUESTION
    results: List[Tuple[Optional[float], str]] = [(None, "timeout")] * len(states)

    def run(i: int, state: Mapping[str, str]) -> None:
        try:
            answer = provider.evaluate(dict(state), {EXPOSURE_QUESTION: dict(question)}).get(EXPOSURE_QUESTION)
            p = getattr(answer, "probability", None)
            results[i] = (min(1.0, max(0.0, float(p))), "") if p is not None else (None, "missing answer")
        except Exception as exc:
            results[i] = (None, f"provider error: {type(exc).__name__}")

    threads = [threading.Thread(target=run, args=(i, st), name="semgate-exposure-intent", daemon=True)
               for i, st in enumerate(states)]
    for th in threads:
        th.start()
    deadline = time.monotonic() + timeout
    for th in threads:
        th.join(max(0.0, deadline - time.monotonic()))
    return [(None, "timeout") if th.is_alive() else results[i] for i, th in enumerate(threads)]


def decide_intent(config: Mapping[str, Any], pairs: Sequence[Tuple[secretfinder.Found, Dict[str, Any]]],
                  all_found: Sequence[secretfinder.Found], tool: str, detail: str,
                  user_messages: Optional[Callable[[], Sequence[str]]] = None,
                  provider: Any = None, policy: Any = None) -> None:
    """Sets record["intent"] for each (secret, record) pair. See the module
    docstring. `provider` and `policy` override the ones the config names
    (evals). Never raises; every failure leaves "intended": false."""
    for _, r in pairs:
        r["intent"] = {"intended": False, "asked": False}
    try:
        from . import router
        from .policy import Policy
        if policy is None:
            policy_file = str(config.get("policy_file") or "")
            if not policy_file:
                from .antigravity_hook import DEFAULT_POLICY
                policy_file = DEFAULT_POLICY
            policy = Policy.load(policy_file)
        question = router.exposure_question(policy)
        threshold = router.thresholds(policy).get("exposure_intended_min")
        why = ""
        if question is None:
            why = "no user_shared_secret question in the policy"
        elif threshold is None:
            why = "no exposure_intended_min in the policy"
        if not why and provider is None:
            provider, why = _intent_provider(config)
        messages: List[str] = []
        if not why:
            messages = [str(m) for m in (user_messages() if user_messages is not None else []) if str(m or "").strip()]
            if not messages:
                why = "no user turns"
        if why:
            for _, r in pairs:
                r["intent"]["why"] = why
            return
        jobs = []
        for n, (f, r) in enumerate(pairs):
            if n >= INTENT_ASKS_MAX:
                r["intent"]["why"] = f"more than {INTENT_ASKS_MAX} new secrets in one output"
                continue
            state = intent_state(f, all_found, tool, detail, messages)
            if carries_value(state, all_found):
                r["intent"]["why"] = "the question would carry the value"
                continue
            jobs.append((r, state))
        answers = ask_intent(provider, [st for _, st in jobs], question, _intent_timeout(config)) if jobs else []
        for (r, _), (p, err) in zip(jobs, answers):
            r["intent"] = {"intended": p is not None and p >= float(threshold), "asked": True,
                           "p": None if p is None else round(p, 4), "min": float(threshold), "policy": policy.version}
            if err:
                r["intent"]["why"] = err
    except Exception as exc:
        for _, r in pairs:
            r["intent"] = {"intended": False, "asked": False, "why": f"intent check failed: {type(exc).__name__}"}
        print(f"semgate: secret exposure intent check failed: {type(exc).__name__}: {exc}", file=sys.stderr)


# ---------------------------------------------------------------- post-tool entry point


def _known(path: Path) -> set:
    return {dedup_key(r) for r in _read(path) if r.get("record_type") == "exposure"}


def _not_recorded(config: Mapping[str, Any], session_id: str, tool: str, records: Sequence[Mapping[str, Any]],
                  exc: Exception, tell: bool) -> str:
    _incident(config, "secret_exposure_not_recorded",
              {"reason": "lock_timeout", "session_id": session_id, "tool": str(tool or ""),
               "secrets": [{"type": r["type"], "masked": r["masked"]} for r in records], "message": str(exc)[:300]})
    print(f"semgate: secret exposure not recorded: {exc}", file=sys.stderr)
    return notice_text(records) if tell else ""


def on_tool_output(config: Mapping[str, Any], *, host: str, manifest_host: str, session_id: str, tool: str,
                   detail: str, step: Any, output: Any, timeout: float = 0.0, now: Optional[float] = None,
                   user_messages: Optional[Callable[[], Sequence[str]]] = None) -> str:
    """Post-tool side. Finds secrets in `output`, asks the judge about the
    ones this session has not seen (decide_intent; `user_messages` returns
    the user's turns, called only then), records them and returns the notice
    for the agent ("" when there is nothing new, or the host cannot take
    post-tool context: manifest C33). Never raises. `session_id` must
    already be checked (hookinput); "" means no record and no
    de-duplication.

    Locks: the known fingerprints are read under the session lock, the judge
    is asked without the lock (a provider call never holds up a parallel
    post event), then the lock is taken again and a secret is appended and
    told only if it is still unknown, so the agent is told once."""
    try:
        if not enabled(config):
            return ""
        if isinstance(output, str):
            text = output
        else:
            from .tooloutputs import response_text
            text = response_text(output)
        found = secretfinder.find(text)
        if not found:
            return ""
        t = time.time() if now is None else float(now)
        tell = host_supports(manifest_host, "C33")
        fresh = build_records(session_id, host, tool, detail, step, found, t, key=_key(config))
        for r in fresh:
            r["told_agent"] = tell
        pairs = list(zip(found, fresh))
        safe = fresh[0]["where"]["detail"]
        if not session_id:
            decide_intent(config, pairs, found, tool, safe, user_messages)
            return notice_text(fresh) if tell else ""
        directory = store_dir(config)
        path = session_path(directory, session_id)
        new_session = not path.exists()
        try:
            with filelock.exclusive(path, timeout):
                known = _known(path)
        except filelock.LockTimeout as exc:
            return _not_recorded(config, session_id, tool, fresh, exc, tell)
        pending = []
        for f, r in pairs:
            if dedup_key(r) not in known:
                known.add(dedup_key(r))
                pending.append((f, r))
        if not pending:
            return ""
        decide_intent(config, pending, found, tool, safe, user_messages)
        try:
            with filelock.exclusive(path, timeout):
                known = _known(path)
                new = []
                for _, r in pending:
                    if dedup_key(r) not in known:
                        known.add(dedup_key(r))
                        new.append(r)
                if new:
                    filelock.append_bytes(path, b"".join(filelock.encode_record(r) for r in new))
        except filelock.LockTimeout as exc:
            return _not_recorded(config, session_id, tool, [r for _, r in pending], exc, tell)
        if new_session and new:
            _drop_stale(directory, path, t)
        return notice_text(new) if (tell and new) else ""
    except Exception as exc:
        _incident(config, "secret_exposure_not_recorded", {"reason": type(exc).__name__, "message": str(exc)[:300]})
        print(f"semgate: secret exposure check failed: {type(exc).__name__}: {exc}", file=sys.stderr)
        return ""


# ---------------------------------------------------------------- session summary (Stop)


def summary_text(session_id: str, exposures: Sequence[Mapping[str, Any]]) -> str:
    lines = [f"[semgate] {len(exposures)} secret(s) were exposed to the agent in this session. Treat them as leaked.",
             "Rotate or revoke these secrets (right away if showing them was not intended, otherwise when this session ends):"]
    for r in exposures:
        w = r.get("where") or {}
        lines.append(f"  - {r.get('type')} {r.get('masked')}, in the output of `{where_label(w.get('tool', ''), w.get('detail', ''))}`,"
                     f" first seen {r.get('first_seen')}, {intent_text(r)}")
    lines.append("Rules: " + " ".join(f"{i}. {rule}" for i, rule in enumerate(RULES, 1)))
    lines.append(f"List: semgate report --exposures --session {session_id}")
    return "\n".join(lines)


def stop_summary(config: Mapping[str, Any], session_id: str, timeout: float = 0.0) -> str:
    """The block to show the user at the end of a turn: every exposure of the
    session, when at least one was not in an earlier block; "" otherwise.
    Marks the shown exposures (summary_shown). Never raises."""
    try:
        if not session_id or not enabled(config):
            return ""
        path = session_path(store_dir(config), session_id)
        if not path.exists():
            return ""
        with filelock.exclusive(path, timeout):
            records = _read(path)
            exposures = [r for r in records if r.get("record_type") == "exposure" and r.get("session_id") == session_id]
            shown = set()
            for r in records:
                if r.get("record_type") == "summary_shown":
                    shown.update(str(s) for s in r.get("fingerprints") or [])
                    shown.update("sha256:" + str(s) for s in r.get("sha256") or [])     # earlier format
            if not exposures or all(dedup_key(r) in shown for r in exposures):
                return ""
            filelock.append_bytes(path, filelock.encode_record({
                "record_type": "summary_shown", "session_id": session_id,
                "fingerprints": [dedup_key(r) for r in exposures], "ts": _now_iso(time.time())}))
        return summary_text(session_id, exposures)
    except filelock.LockTimeout as exc:
        _incident(config, "secret_exposure_summary_skipped", {"reason": "lock_timeout", "session_id": session_id,
                                                              "message": str(exc)[:300]})
        return ""
    except Exception as exc:
        print(f"semgate: secret exposure summary failed: {type(exc).__name__}: {exc}", file=sys.stderr)
        return ""


# ---------------------------------------------------------------- report


def default_dirs(home: Optional[Path] = None) -> List[Path]:
    """Exposure dirs of every semgate config under ~/.semgate/*/semgate.json
    (and SEMGATE_CONFIG), plus ~/.semgate/*/exposures."""
    from . import storepaths
    base = Path(home) if home else Path.home()
    configs = []
    env = os.environ.get("SEMGATE_CONFIG", "")
    if env:
        configs.append(Path(env))
    try:
        configs += sorted((base / ".semgate").glob("*/semgate.json"))
    except OSError:
        pass
    dirs: List[Path] = []
    for c in configs:
        try:
            dirs.append(store_dir(storepaths.load(str(c), storepaths.guess_host(str(c)))))
        except (OSError, ValueError, AttributeError):
            continue
    try:
        dirs += sorted((base / ".semgate").glob("*/exposures"))
    except OSError:
        pass
    out: List[Path] = []
    seen = set()
    for d in dirs:
        key = os.path.normcase(os.path.abspath(str(d)))
        if key not in seen and d.is_dir():
            seen.add(key)
            out.append(d)
    return out


def collect(dirs: Sequence[Path], session: str = "") -> Dict[str, Any]:
    """{"sessions": [{"session_id", "host", "exposures": [...]}], "rules", "advice"},
    oldest session first. Reads each file under its lock (skipped on timeout)."""
    sessions: Dict[str, Dict[str, Any]] = {}
    skipped: List[str] = []
    for d in dirs:
        files = [session_path(d, session)] if session else sorted(Path(d).glob("*.jsonl"))
        for f in files:
            if not f.is_file() or ".lock-timeout." in f.name:
                continue
            try:
                records = filelock.read_jsonl_locked(f).records
            except (filelock.LockTimeout, OSError) as exc:
                skipped.append(f"{f}: {type(exc).__name__}")
                continue
            for r in records:
                if r.get("record_type") != "exposure":
                    continue
                sid = str(r.get("session_id", ""))
                if session and sid != session:
                    continue
                s = sessions.setdefault(sid, {"session_id": sid, "host": str(r.get("host", "")), "exposures": []})
                if all(e["fingerprint"] != dedup_key(r) for e in s["exposures"]):
                    e = {k: r.get(k) for k in ("type", "masked", "where", "first_seen", "host", "intent")}
                    e["fingerprint"] = dedup_key(r)
                    s["exposures"].append(e)
    out = sorted(sessions.values(), key=lambda s: min(str(e.get("first_seen")) for e in s["exposures"]))
    for s in out:
        s["exposures"].sort(key=lambda e: str(e.get("first_seen")))
    return {"sessions": out, "rules": list(RULES), "advice": "Rotate or revoke these secrets.", "unreadable": skipped}


def render(rep: Mapping[str, Any]) -> str:
    total = sum(len(s["exposures"]) for s in rep["sessions"])
    lines = [f"Secrets exposed to agents: {total} in {len(rep['sessions'])} session(s). "
             "semgate keeps only a masked preview and a keyed fingerprint (HMAC-SHA256), never the value."]
    for s in rep["sessions"]:
        lines += ["", f"session {s['session_id']}" + (f"  ({s['host']})" if s.get("host") else "")]
        for e in s["exposures"]:
            w = e.get("where") or {}
            lines.append(f"  {e.get('first_seen')}  {str(e.get('type')):28} {str(e.get('masked')):12} "
                         f"{intent_text(e):18} {where_label(w.get('tool', ''), w.get('detail', ''))}")
    if total:
        lines += ["", "Rotate or revoke these secrets."]
    lines += ["", "Rules:"] + [f"  {i}. {rule}" for i, rule in enumerate(RULES, 1)]
    for u in rep.get("unreadable") or []:
        lines.append(f"not read (try again): {u}")
    return "\n".join(lines)
