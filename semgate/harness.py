"""semgate for any agent framework or custom harness: one JSON request per
proposed tool call, one JSON answer. Python (`semgate.check`,
`semgate.approve`) and HTTP (`semgate serve --http`, semgate.httpserve) take
the same JSON.

    from semgate import check, approve

    d = check({
        "tool": "bash",
        "arguments": {"command": "curl -s https://cdn.example.net/setup.sh -o setup.sh"},
        "session_id": "run-42",
        "cwd": "/home/me/proj",
        "user_messages": ["fix the failing test in tests/test_api.py"],
        "recent": [{"tool": "read", "summary": "README.md", "output": readme_text}],
    }, config="~/.semgate/http/semgate.json")
    d["decision"]      # "allow" | "ask" | "deny"
    d["reason"], d["reason_code"], d.get("approval_id")

    # later, on the HUMAN side (never from the agent):
    approve(d["approval_id"], approved=True, by="manuel", config="~/.semgate/http/semgate.json")
    check(same_request, config=...)["decision"]    # "allow", once

Pipeline. `check` runs the same pipeline as the hooks (antigravity_hook.run_core,
the function every hook and `semgate serve --stdio` call): the operator's
grant from `grant_file`, work kinds, semgate's own earlier messages removed
from tool outputs, hard rules, human gates, trusted commands and pinned
instruction-file lines (trust store), human feedback (`semgate feedback`),
learned allows, git facts, script source, the model (Jev), the pin question,
the trust gate, the enforcement mapping of the config (mode,
auto_allow_tools, block_when_unsure), deny escalation, the ledger judgment
and one host_response record per call with the exact answer returned.

What differs from a hook host (and why):
  - approval by chat reply (router.chat_approval) is not used: this path has
    no host transcript, and a chat "yes" inside the check request would let
    the agent side approve its own call. The human answers through
    `approve()` / POST /v1/approve instead (semgate.approvals).
  - after the pipeline, the approval step (semgate.approvals): an ask gets an
    `approval_id`; an approved id turns the next ask of the same action into
    an allow, once; a denied id turns the same action into a deny. No id is
    given when the judge itself said deny (every answer is ask in shadow
    mode) or the grant expired: like `semgate feedback allow`, an approval
    never opens those.
    Privacy-stage asks also have no approval id: the payload must pass its
    privacy check before any ordinary approval can be applied.
  - the deny text for the agent does not say "ask the user in chat, then
    re-run" (that is the chat approval flow); it says the action was blocked.
  - no post-tool event: tool outputs come in `recent` with each request, so
    the tool output store (tooloutputs) and the secret exposure notices
    (exposures) are not used, and F6 created-file records (agent_files) get
    no post record.
  - answers are masked: secret values (secretfinder) and the home folder are
    replaced in `reason` (see public_text).

Gate.check (semgate.gate) is different again: it calls the judge only (no
config, no stores, no enforcement mapping). Use `check` here when you want
the hook behavior.
"""
from __future__ import annotations

import json
import os
import re
import sys
import threading
from pathlib import Path
from typing import Any, Callable, Dict, List, Mapping, Optional, Union

from .harnesstools import HOST_NAMES

REQUEST_SCHEMA = "semgate-check/1"
RESPONSE_SCHEMA = "semgate-decision/1"
APPROVE_SCHEMA = "semgate-approve/1"
HOST = "http"                     # storepaths host name: ~/.semgate/http/
DEFAULT_HARNESS = "custom"
TIMEOUT_MIN_MS, TIMEOUT_MAX_MS = 1000, 600000
_LIST_MAX = 1000                  # items of user_messages / recent accepted (the envelope keeps fewer)
_TEXT_MAX = 1 << 20               # chars of one text field accepted before the envelope bounds apply
_TOKEN_RE = re.compile(r"[A-Za-z0-9._-]{1,64}")

# Host-neutral tool names. Names the rules and gates know (bash, read, edit,
# write, glob, grep, ls, web_fetch, web_search) keep their meaning; common
# aliases map to them (the same map as the OpenCode adapter, plus the usual
# shell tool names). Any other name is judged as given (lowercased).
TOOL_ALIASES: Dict[str, str] = {
    "bash": "bash", "shell": "bash", "sh": "bash", "run_command": "bash", "run_shell_command": "bash",
    "execute_command": "bash", "execute_bash": "bash", "exec_command": "bash", "terminal": "bash",
    "edit": "edit", "patch": "edit", "multiedit": "edit", "apply_patch": "edit", "str_replace": "edit",
    "write": "write", "write_file": "write", "create_file": "write",
    "read": "read", "read_file": "read", "view_file": "read",
    "glob": "glob", "grep": "grep", "list": "ls", "ls": "ls", "list_dir": "ls",
    "webfetch": "web_fetch", "web_fetch": "web_fetch", "fetch": "web_fetch",
    "websearch": "web_search", "web_search": "web_search",
    # harness tools: ask the user, to-do list, load a skill (harnesstools.py)
    **HOST_NAMES, "todo": "todo",
}
_TO_HOST = {"allow": "allow", "ask": "ask", "force_ask": "ask", "deny": "deny", "deny_unless_prior_grant": "deny"}

FIELDS = ("schema", "tool", "arguments", "session_id", "call_id", "cwd", "project_root", "user_messages",
          "user_message", "recent", "agent_intent", "model", "harness", "session_started_at", "timeout_ms")
RECENT_FIELDS = ("tool", "summary", "output", "result", "files_changed", "decision", "call_id")
APPROVE_FIELDS = ("schema", "approval_id", "approved", "by", "note")

# The hook text tells the agent to ask the user in chat and re-run (chat
# approval). Here the human answers through approve(), so the agent is told
# only that the call was blocked.
HARNESS_BLOCKED_SUFFIX = (" | Semgate blocked this. Do not try to bypass, rename, or disable the gate. If the action is "
                          "needed, say so to the user; a human decides.")


def _input_rejected() -> type:
    from .hookinput import InputRejected
    return InputRejected


class RequestError(_input_rejected()):
    """The request does not match semgate-check/1 (or semgate-approve/1).
    An InputRejected (kind request_invalid), so the ledger gets the same
    hook_input_rejected incident as a bad hook payload."""

    def __init__(self, message: str):
        super().__init__(message, "request_invalid")


# ---------------------------------------------------------------- config


def default_config_path() -> str:
    """$SEMGATE_CONFIG, else ~/.semgate/http/semgate.json (`semgate harness init`)."""
    return os.environ.get("SEMGATE_CONFIG") or os.path.join(os.path.expanduser("~"), ".semgate", HOST, "semgate.json")


def load_config(config: Union[str, Path, None] = None) -> Dict[str, Any]:
    from . import storepaths
    return storepaths.load(str(config) if config else default_config_path(), HOST)


# ---------------------------------------------------------------- masking


def public_text(text: Any) -> str:
    """Text safe to return to a caller: every secret value secretfinder sees
    is masked (`ghp_…WXYZ`) and the home folder becomes `~`."""
    from . import secretfinder
    out = str(text or "")
    try:
        out = secretfinder.mask_in(out, [])
    except Exception:
        pass
    home = os.path.expanduser("~")
    if home and len(home) > 3:
        variants = {home, home.replace("\\", "/"), home.replace("/", "\\"), home.replace("\\", "\\\\")}
        for v in sorted(variants, key=len, reverse=True):
            out = re.sub(re.escape(v), "~", out, flags=re.IGNORECASE if os.name == "nt" else 0)
    return out


def failure_text(exc: BaseException) -> str:
    """semgate's own input errors keep their message; any other exception
    gives only its type (the message can hold paths; it goes to stderr)."""
    from .approvals import ApprovalError
    from .hookinput import InputRejected
    if isinstance(exc, (RequestError, InputRejected, ApprovalError)):
        return f"{type(exc).__name__}: {public_text(exc)}"
    return f"{type(exc).__name__} (details on semgate's stderr)"


# ---------------------------------------------------------------- request


def _text(req: Mapping[str, Any], key: str, limit: int = _TEXT_MAX) -> str:
    value = req.get(key, "")
    if value is None:
        return ""
    if not isinstance(value, str):
        raise RequestError(f"{key} must be a string")
    if len(value) > limit:
        raise RequestError(f"{key} is longer than {limit} characters")
    return value


def _json_ok(value: Any, depth: int = 0) -> None:
    if depth > 32:
        raise RequestError("arguments nest deeper than 32 levels")
    if value is None or isinstance(value, (bool, int, str)):
        return
    if isinstance(value, float):
        if value != value or value in (float("inf"), float("-inf")):
            raise RequestError("arguments hold a number that is not finite")
        return
    if isinstance(value, Mapping):
        for k, v in value.items():
            if not isinstance(k, str):
                raise RequestError("argument names must be strings")
            _json_ok(v, depth + 1)
        return
    if isinstance(value, (list, tuple)):
        for v in value:
            _json_ok(v, depth + 1)
        return
    raise RequestError(f"arguments hold a {type(value).__name__}, not a JSON value")


def validate_request(req: Any) -> Dict[str, Any]:
    """The request as semgate-check/1 (schema file: semgate/data/check_request.schema.json).
    Returns a normalized copy. Raises RequestError."""
    from . import hookinput
    if not isinstance(req, Mapping):
        raise RequestError("the request must be a JSON object")
    unknown = sorted(str(k) for k in req if k not in FIELDS)
    if unknown:
        raise RequestError(f"unknown field(s): {', '.join(unknown)} (schema {REQUEST_SCHEMA})")
    if "schema" in req and req.get("schema") != REQUEST_SCHEMA:
        raise RequestError(f"schema must be {REQUEST_SCHEMA!r}")
    out: Dict[str, Any] = {}
    tool = req.get("tool")
    if not isinstance(tool, str) or not tool.strip() or len(tool) > 200:
        raise RequestError("tool must be a non-empty string of at most 200 characters")
    out["tool"] = tool.strip()
    args = req.get("arguments", {})
    if args is None:
        args = {}
    if not isinstance(args, Mapping):
        raise RequestError("arguments must be a JSON object")
    _json_ok(args)
    out["arguments"] = dict(args)
    sid = req.get("session_id")
    if not isinstance(sid, str) or not sid:
        raise RequestError("session_id must be a non-empty string")
    problem = hookinput.session_id_problem(sid)
    if problem:
        raise RequestError(problem)
    out["session_id"] = sid
    call_id = req.get("call_id")
    if call_id is not None and call_id != "":
        if not isinstance(call_id, str) or hookinput.session_id_problem(call_id):
            raise RequestError("call_id must be a string of at most 256 characters of [A-Za-z0-9._:-]")
        out["call_id"] = call_id
    out["cwd"] = _text(req, "cwd", 4096)
    out["project_root"] = _text(req, "project_root", 4096) or out["cwd"]
    if not out["project_root"].strip():
        raise RequestError("cwd or project_root is required (approvals are scoped to one project)")
    users = req.get("user_messages", [])
    if users is None:
        users = []
    if not isinstance(users, list) or len(users) > _LIST_MAX or not all(isinstance(u, str) for u in users):
        raise RequestError(f"user_messages must be a list of at most {_LIST_MAX} strings")
    if any(len(u) > _TEXT_MAX for u in users):
        raise RequestError(f"a user message is longer than {_TEXT_MAX} characters")
    out["user_messages"] = list(users)
    out["user_message"] = _text(req, "user_message")
    recent = req.get("recent", [])
    if recent is None:
        recent = []
    if not isinstance(recent, list) or len(recent) > _LIST_MAX:
        raise RequestError(f"recent must be a list of at most {_LIST_MAX} objects")
    items: List[Dict[str, Any]] = []
    for i, item in enumerate(recent):
        if not isinstance(item, Mapping):
            raise RequestError(f"recent[{i}] must be an object")
        extra = sorted(str(k) for k in item if k not in RECENT_FIELDS)
        if extra:
            raise RequestError(f"recent[{i}] has unknown field(s): {', '.join(extra)}")
        entry = {k: _text(item, k) for k in ("tool", "summary", "output", "result", "decision", "call_id")}
        files = item.get("files_changed", [])
        if files is None:
            files = []
        if not isinstance(files, list) or not all(isinstance(f, str) for f in files):
            raise RequestError(f"recent[{i}].files_changed must be a list of strings")
        entry["files_changed"] = [f for f in files[:200]]
        items.append(entry)
    out["recent"] = items
    out["agent_intent"] = _text(req, "agent_intent")
    out["model"] = _text(req, "model", 200)
    harness = req.get("harness", DEFAULT_HARNESS) or DEFAULT_HARNESS
    if not isinstance(harness, str) or not _TOKEN_RE.fullmatch(harness):
        raise RequestError("harness must be 1-64 characters of [A-Za-z0-9._-]")
    out["harness"] = harness
    started = req.get("session_started_at", "")
    if started not in ("", None) and (isinstance(started, bool) or not isinstance(started, (str, int, float))):
        raise RequestError("session_started_at must be an ISO time or epoch seconds")
    out["session_started_at"] = started if started is not None else ""
    if req.get("timeout_ms") is not None:
        t = req.get("timeout_ms")
        if isinstance(t, bool) or not isinstance(t, int) or not TIMEOUT_MIN_MS <= t <= TIMEOUT_MAX_MS:
            raise RequestError(f"timeout_ms must be an integer from {TIMEOUT_MIN_MS} to {TIMEOUT_MAX_MS}")
        out["timeout_ms"] = t
    return out


def canonical_tool(name: str) -> str:
    low = name.strip().lower()
    return TOOL_ALIASES.get(low, low or "unknown")


def build_envelope(req: Mapping[str, Any], grant: Any) -> Any:
    """The canonical envelope of a validated request (validate_request)."""
    from .envelope import (AGENT_INTENT_MAX, Envelope, Environment, ProposedAction, SCHEMA_VERSION, Trajectory,
                           TrajectoryEntry, bound_user_messages, short_result)
    tool = canonical_tool(req["tool"])
    args = dict(req["arguments"])
    if "path" not in args:                     # the same as the OpenCode adapter
        for k in ("filePath", "file_path"):
            if isinstance(args.get(k), str) and args[k]:
                args["path"] = args[k]
                break
    entries = []
    for e in req["recent"][-20:]:
        entries.append(TrajectoryEntry(tool=e["tool"] or "unknown", decision=e["decision"], summary=e["summary"][:500],
                                       output=e["output"][:6000], result=short_result(e["result"]) if e["result"] else "",
                                       files_changed=tuple(e["files_changed"])))
    users = req["user_messages"]
    latest = req["user_message"] or (users[-1] if users else "")
    return Envelope(
        schema=SCHEMA_VERSION,
        action=ProposedAction(tool=tool, arguments=args),
        grant=grant,
        environment=Environment(project_root=req["project_root"], cwd=req["cwd"] or req["project_root"],
                                harness=req["harness"], session_id=req["session_id"]),
        trajectory=Trajectory(recent=tuple(entries)),
        user_message=latest,
        user_messages=bound_user_messages(users),
        agent_intent=req["agent_intent"][:AGENT_INTENT_MAX],
    )


def _summary(envelope: Any) -> str:
    args = envelope.action.arguments
    for k in ("command", "path", "url", "pattern"):
        if isinstance(args.get(k), str) and args[k]:
            return public_text(args[k])[:300]
    try:
        return public_text(json.dumps(dict(args), sort_keys=True, default=str))[:300]
    except Exception:
        return ""


# ---------------------------------------------------------------- the pipeline


def _ledger_event(config: Mapping[str, Any], event: str, detail: Dict[str, Any]) -> None:
    try:
        from .ledger import Ledger
        from .storepaths import ledger_file
        Ledger(ledger_file(config)).record_human_approval(event, detail)
    except Exception as exc:
        print(f"semgate: human_approval {event} not recorded: {type(exc).__name__}: {exc}", file=sys.stderr)


def judge_check(req: Mapping[str, Any], config: Mapping[str, Any], meta: Optional[Dict[str, Any]] = None,
                line_bytes: int = 0, *, prepared: Any = None, consents: Any = None,
                offline_shell: bool = False, execution_facts: Any = None,
                consume_approval: bool = True, execution_paths: Any = None) -> Dict[str, Any]:
    """One check through run_core and the approval step. `req` is validated
    here (again). Returns the answer object (not yet recorded as
    host_response: the caller does that, as serve does). Raises on errors;
    callers answer ask."""
    from . import payloadsize
    from .antigravity_hook import _BLOCKED_SUFFIX, run_core
    req = validate_request(req)
    meta = meta if meta is not None else {}
    built: Dict[str, Any] = {}

    def build(grant: Any) -> Any:
        env = build_envelope(req, grant)
        built["envelope"] = env
        return env

    result = run_core(
        config,
        payload=payloadsize.describe(line_bytes, req["arguments"], req["model"]),
        build_envelope=build,
        session_id=req["session_id"],
        step_idx=req.get("call_id"),
        user_messages=lambda: list(req["user_messages"]),
        session_started_at=lambda: req["session_started_at"],
        meta=meta,
        chat=None,       # no approval by chat reply on this path (see the module text)
        prepared_disclosure=prepared, consent_store=consents, trusted_offline_shell=offline_shell,
        trusted_execution_facts=execution_facts,
        execution_paths=execution_paths,
    )
    decision = _TO_HOST.get(str(result.get("decision")), "ask")
    reason = str(result.get("reason", ""))
    if reason.endswith(_BLOCKED_SUFFIX):
        reason = reason[: -len(_BLOCKED_SUFFIX)] + HARNESS_BLOCKED_SUFFIX
    out: Dict[str, Any] = {"schema": RESPONSE_SCHEMA, "decision": decision, "reason": reason,
                           "reason_code": str(meta.get("judged_reason_code", "") or ""),
                           "stage": str(meta.get("judged_stage", "") or ""),
                           "judgment_id": str(meta.get("content_digest", "") or "")}
    env = built.get("envelope")
    if env is not None and decision in ("allow", "ask") and not meta.get("privacy_blocked"):
        out = _approval_step(out, env, config, req, meta, consume=consume_approval)
    out["reason"] = public_text(out["reason"])[:1000]
    return out


def check_prepared(prepared: Any, *, consents: Any, config: Union[str, Path],
                   consume_approval: bool = True, recent: Optional[List[dict]] = None) -> Any:
    """Trusted broker path through the complete hook/harness pipeline, synchronously.

    This function only judges. PreparedSender owns dispatch; a caller deadline
    must never abandon a worker that can later perform an undisclosed send.
    """
    from .judge import Decision
    cfg = load_config(config)
    if cfg.get("mode") != "enforce":
        return Decision("deny", stage="privacy", reason_code="prepared_harness_requires_enforce")
    task_request = _task_request(cfg, prepared.scope.task, prepared.scope.project)
    req = validate_request({"tool": "http_request", "arguments": prepared.arguments(),
                            "session_id": prepared.scope.task, "project_root": prepared.scope.project,
                            "cwd": prepared.scope.project,
                            "user_message": task_request, "user_messages": [task_request], "recent": recent or []})
    meta: Dict[str, Any] = {}
    out = judge_check(req, cfg, meta, prepared=prepared, consents=consents, consume_approval=consume_approval)
    # judge_check settles only ordinary approvable asks, after privacy passes.
    # Keep that authorized result; preparation previews do not consume it.
    out = _record_answer(cfg, req, out, meta)
    return Decision(out["decision"], reasons=[out["reason"]], stage=out["stage"], reason_code=out["reason_code"],
                    envelope_digest=out["judgment_id"], evidence={"privacy": meta.get("prepared_privacy", {}),
                                                               "approval_id": out.get("approval_id", "")})


def _task_request(config: dict, task: str, project: str) -> str:
    from .taskcontext import request_for
    return request_for(config, task=task, project=project)


def check_development(command: str, *, project: str, task: str, config: Union[str, Path],
                      execution_facts: Any = None, recent: Optional[List[dict]] = None) -> Any:
    """Broker-only check. An allow may execute only through OfflineWorker."""
    return _check_development("bash", {"command": command}, project=project, task=task,
                              config=config, execution_facts=execution_facts, recent=recent)


def check_local_write(arguments: dict, *, project: str, task: str, config: Union[str, Path],
                      execution_facts: Any, recent: Optional[List[dict]] = None) -> Any:
    from .devworker import validate_write
    literal = validate_write(arguments)
    # Scope rules compare host paths; the worker receives the same project-
    # relative name and independently refuses symlink traversal in its namespace.
    literal["path"] = str(Path(project) / literal["path"])
    return _check_development("write", literal, project=project, task=task,
                              config=config, execution_facts=execution_facts, recent=recent)


def _check_development(tool: str, arguments: dict, *, project: str, task: str, config: Union[str, Path],
                       execution_facts: Any, recent: Optional[List[dict]] = None) -> Any:
    from .judge import Decision
    cfg = load_config(config)
    if cfg.get("mode") != "enforce":
        return Decision("deny", reason_code="development_requires_enforce")
    # The broker has a real project checkout: inspect its recovery state rather
    # than asking the model to guess whether a shell overwrite loses work.
    # GitFacts is read-only; dirty/untracked targets still withhold an allow.
    # Keep the public check API and unverified judgment path unchanged.
    paths = None
    if execution_facts is not None:
        from .devworker import VerifiedOfflineFacts
        if not isinstance(execution_facts, VerifiedOfflineFacts):
            raise ValueError("verified execution facts required")
        cfg = dict(cfg, git_facts=True)
        from .workerpaths import WorkerPaths
        paths = WorkerPaths(project)
    task_request = _task_request(cfg, task, project)
    req = validate_request({"tool": tool, "arguments": arguments,
                            "session_id": task, "project_root": project, "cwd": project,
                            "user_message": task_request, "user_messages": [task_request], "recent": recent or []})
    meta: Dict[str, Any] = {}
    out = _record_answer(cfg, req, judge_check(req, cfg, meta, offline_shell=True,
                                            execution_facts=execution_facts, execution_paths=paths), meta)
    return Decision(out["decision"], reasons=[out["reason"]], stage=out["stage"], reason_code=out["reason_code"],
                    evidence={"approval_id": out.get("approval_id", "")})


def _approval_step(out: Dict[str, Any], env: Any, config: Mapping[str, Any], req: Mapping[str, Any],
                   meta: Mapping[str, Any], *, consume: bool = True) -> Dict[str, Any]:
    from . import approvals
    from .chatapproval import envelope_key
    store = approvals.store_for(config)
    root = env.environment.project_root or env.environment.cwd
    # An approval never opens what the judge denied (an ask in shadow mode)
    # or an expired grant: the same limits as `semgate feedback allow`.
    approvable = out["decision"] == "ask" and meta.get("judged_decision") != "deny" and         meta.get("judged_stage") != "grant_validity"
    try:
        res = store.settle(key=envelope_key(env), session_id=req["session_id"], project_root=root, final=out["decision"],
                           summary=_summary(env), tool=env.action.tool, reason_code=out["reason_code"],
                           judgment_id=out["judgment_id"], approvable=approvable, consume=consume)
    except Exception as exc:
        # The store may hold a human "no": an allow becomes an ask; an ask
        # stays an ask without an approval id.
        print(f"semgate: approval store not usable: {type(exc).__name__}: {exc}", file=sys.stderr)
        note = " | semgate could not read the approval store; asking a human"
        return dict(out, decision="ask", reason=(out["reason"] + note)[:1000])
    rec = res.get("record") or {}
    base = {"approval_id": rec.get("approval_id", ""), "session_id": req["session_id"], "tool": env.action.tool,
            "judgment_id": out["judgment_id"]}
    effect = res.get("effect")
    if effect == "deny":
        _ledger_event(config, "denied_applied", dict(base, by=rec.get("by", ""), was=out["decision"]))
        return dict(out, decision="deny", reason_code="human_denied", approval_id=rec.get("approval_id"),
                    reason=(f"semgate: a human said no to this exact action (approval {rec.get('approval_id')}, "
                            f"by {rec.get('by', '')}). | " + out["reason"])[:1000])
    if effect == "allow":
        if consume:
            _ledger_event(config, "used", dict(base, by=rec.get("by", "")))
        status = "now used" if consume else "ready for dispatch"
        return dict(out, decision="allow", reason_code="human_approved_once" if consume else "human_approval_ready",
                    approval_id=rec.get("approval_id"),
                    reason=(f"semgate: approved once by {rec.get('by', '')} (approval {rec.get('approval_id')}); "
                            f"this approval is {status}. Was: " + out["reason"])[:1000])
    if effect == "pending":
        if res.get("new"):
            _ledger_event(config, "pending", base)
        return dict(out, approval_id=rec.get("approval_id"))
    if out["decision"] == "ask" and not approvable:
        why = "the grant expired" if meta.get("judged_stage") == "grant_validity" else "semgate's judge denied it"
        return dict(out, reason=(f"semgate: this ask cannot be approved by id ({why}). | " + out["reason"])[:1000])
    return out


def _record_answer(config: Mapping[str, Any], req: Mapping[str, Any], answer: Dict[str, Any],
                   meta: Mapping[str, Any]) -> Dict[str, Any]:
    """host_response record + own-message record of the final answer (what
    serve does for every judge request). A ledger lock timeout makes an
    allow an ask (record_host_response)."""
    from .antigravity_hook import record_host_response, remember_sent
    sid = req.get("session_id") if isinstance(req, Mapping) else ""
    step = req.get("call_id") if isinstance(req, Mapping) else None
    if not (isinstance(step, str) and len(step) <= 256):
        step = None
    native = {"decision": answer.get("decision", "ask"), "reason": answer.get("reason", "")}
    final = record_host_response({"conversationId": sid if isinstance(sid, str) else "", "stepIdx": step},
                                 config, native, meta)
    out = dict(answer, decision=_TO_HOST.get(str(final.get("decision")), "ask"),
               reason=public_text(final.get("reason", ""))[:1000])
    remember_sent(config, sid if isinstance(sid, str) else "", meta, out.get("decision"), out.get("reason"))
    return out


def fail_answer(reason: str, *, timeout: bool = False) -> Dict[str, Any]:
    out = {"schema": RESPONSE_SCHEMA, "decision": "ask", "reason": public_text(reason)[:1000], "reason_code": "semgate_failure",
           "stage": "", "judgment_id": ""}
    if timeout:
        out["timeout"] = True
        out["reason_code"] = "semgate_timeout"
    return out


def check(request: Mapping[str, Any], config: Union[str, Path, None] = None, *,
          timeout_ms: Optional[int] = None) -> Dict[str, Any]:
    """Judge one proposed tool call. Never executes it. Never raises: any
    error, and a judgment slower than the deadline (timeout_ms, or the
    request's timeout_ms; none: no deadline), answers "ask".

    `config`: the semgate.json path (default default_config_path())."""
    cfg: Any = None
    meta: Dict[str, Any] = {}
    req: Dict[str, Any] = {}
    cfg_path = str(config) if config else default_config_path()
    try:
        cfg = load_config(cfg_path)
        req = validate_request(request)
        size = len(json.dumps(request, default=str).encode("utf-8"))
        limit = _payload_limit(cfg)
        if size > limit:
            from .hookinput import InputRejected
            raise InputRejected(f"request is {size} bytes, above hook_max_payload_bytes ({limit}); not judged",
                                "payload_over_limit", {"bytes": size, "limit": limit})
        wait = timeout_ms if timeout_ms is not None else req.get("timeout_ms")
        if wait is None:
            answer = judge_check(req, cfg, meta, size)
        else:
            answer = _with_deadline(lambda: judge_check(req, cfg, meta, size), int(wait) / 1000.0)
    except Exception as exc:
        from . import hookinput
        hookinput.note_rejection(cfg if cfg is not None else cfg_path, exc, HOST)
        print(f"semgate check failed: {type(exc).__name__}: {exc}", file=sys.stderr)
        answer = fail_answer(f"semgate failure; asking human: {failure_text(exc)}", timeout=isinstance(exc, _Timeout))
    if cfg is None:
        return answer
    try:
        return _record_answer(cfg, req or (request if isinstance(request, Mapping) else {}), answer, meta)
    except Exception as exc:
        print(f"semgate: host_response not recorded: {type(exc).__name__}: {exc}", file=sys.stderr)
        return answer if answer.get("decision") != "allow" else fail_answer("semgate could not record the answer; asking human")


class _Timeout(Exception):
    pass


def _with_deadline(fn: Callable[[], Dict[str, Any]], seconds: float) -> Dict[str, Any]:
    box: Dict[str, Any] = {}

    def run() -> None:
        try:
            box["value"] = fn()
        except BaseException as exc:      # handed to the caller's thread
            box["error"] = exc

    th = threading.Thread(target=run, name="semgate-check", daemon=True)
    th.start()
    th.join(max(0.0, seconds))
    if th.is_alive():
        raise _Timeout(f"semgate did not decide within {int(seconds * 1000)} ms")
    if "error" in box:
        raise box["error"]
    return box["value"]


def _payload_limit(config: Mapping[str, Any]) -> int:
    from .hookinput import max_payload_bytes
    return max_payload_bytes(config)


# ---------------------------------------------------------------- the human side


def validate_approve(body: Any) -> Dict[str, Any]:
    """semgate-approve/1 (schema file: semgate/data/approve_request.schema.json). Raises RequestError."""
    if not isinstance(body, Mapping):
        raise RequestError("the request must be a JSON object")
    unknown = sorted(str(k) for k in body if k not in APPROVE_FIELDS)
    if unknown:
        raise RequestError(f"unknown field(s): {', '.join(unknown)} (schema {APPROVE_SCHEMA})")
    if "schema" in body and body.get("schema") != APPROVE_SCHEMA:
        raise RequestError(f"schema must be {APPROVE_SCHEMA!r}")
    for key in ("approval_id", "approved", "by"):
        if key not in body:
            raise RequestError(f"{key} is required")
    note = body.get("note", "")
    return {"approval_id": body["approval_id"], "approved": body["approved"], "by": body["by"],
            "note": note if note is not None else ""}


def approve(approval_id: str, approved: bool, by: str, *, config: Union[str, Path, None] = None,
            note: str = "") -> Dict[str, Any]:
    """Record a human's answer to an ask. HUMAN SIDE ONLY: call it from the
    code that received the person's answer (a LangGraph resume value, an n8n
    approval step, a chat UI button), never from a tool the agent can run.
    Raises approvals.ApprovalError (code not_found / conflict / invalid).
    Returns {"approval_id", "status", "expires_at"}."""
    from . import approvals
    body = validate_approve({"approval_id": approval_id, "approved": approved, "by": by, "note": note})
    cfg = load_config(config)
    store = approvals.store_for(cfg)
    rec = store.decide(body["approval_id"], body["approved"], body["by"], body["note"])
    _ledger_event(cfg, "approved" if body["approved"] else "denied",
                  {"approval_id": rec.get("approval_id"), "session_id": rec.get("session_id"), "tool": rec.get("tool"),
                   "judgment_id": rec.get("judgment_id"), "by": rec.get("by")})
    return approvals.public(rec, store.ttl_s)


# ---------------------------------------------------------------- setup


def write_config(directory: Union[str, Path], purpose: str, *, provider: str = "typesafe", mode: str = "enforce",
                 project: str = "", policy: str = "dev", days: int = 30, force: bool = False) -> Dict[str, str]:
    """Write semgate.json, grant.json and two token files (check and approve)
    into `directory` for a harness (`semgate harness init`). Existing files
    are kept unless force. Returns {name: path}."""
    import secrets as _secrets
    from .gate import POLICY_ALIASES
    from .init_antigravity import READ_ONLY_TOOLS, _config, _grant
    if not purpose or not purpose.strip():
        raise ValueError("a purpose is required: what the operator authorises the agent to do")
    if mode not in ("enforce", "shadow"):
        raise ValueError("mode must be enforce or shadow")
    if provider not in ("typesafe", "openrouter", "none", "recorded", "fake"):
        raise ValueError("provider must be typesafe, openrouter, none, recorded or fake")
    target = Path(directory).expanduser().resolve()
    pol = POLICY_ALIASES.get(policy, Path(policy)).resolve()
    if not pol.is_file():
        raise ValueError(f"policy not found: {pol}")
    cfg = _config(target, pol, mode, provider)
    enf = cfg["enforcement"]
    # A harness can show an ask (it gets an approval id), so asks stay asks.
    enf["block_when_unsure"] = False
    # bash runs on a model allow (the current agy posture); add your own
    # tool names here: a model allow of a tool not listed becomes an ask.
    enf["auto_allow_tools"] = list(READ_ONLY_TOOLS) + ["bash"]
    grant = _grant(purpose.strip(), days, project)
    grant["grant_id"] = "http-" + grant["grant_id"].split("-", 1)[-1]
    grant["provenance"] = "written by `semgate harness init`; edit by hand, never from the agent"
    files = {"config": target / "semgate.json", "grant": target / "grant.json",
             "token": target / "check.token", "approve_token": target / "approve.token"}
    target.mkdir(parents=True, exist_ok=True)
    contents = {"config": json.dumps(cfg, indent=2) + "\n", "grant": json.dumps(grant, indent=2) + "\n",
                "token": _secrets.token_urlsafe(32) + "\n", "approve_token": _secrets.token_urlsafe(32) + "\n"}
    written: Dict[str, str] = {}
    for name, path in files.items():
        if path.exists() and not force:
            written[name] = f"{path} (kept)"
            continue
        path.write_text(contents[name], encoding="utf-8")
        if name.endswith("token"):
            try:
                os.chmod(path, 0o600)
            except OSError:
                pass
        written[name] = str(path)
    return written
