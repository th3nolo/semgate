"""Antigravity PreToolUse command.

One JSON event is read from stdin and exactly one Antigravity decision object
is written to stdout. Diagnostics never share stdout. No tool is executed.
"""
from __future__ import annotations
import argparse, json, os, sys
from pathlib import Path
from typing import Any, Callable, Dict, List, Mapping, Optional
from . import codesignals, harnesstools, hookinput, payloadsize, storepaths
from . import enforcement as enforce_cfg
from . import router as router_mod
from .adapters.antigravity import envelope_from_pre_tool_use, grant_from_config
from .history import ToolHistory
from .judge import Decision, judge
from .ledger import Ledger
from .policy import Policy
from .providers.fake import FakeProvider
from .providers.registry import LIVE as LIVE_PROVIDERS
from .gate import policy_dir

# policy_dir(): the packaged semgate/policies in a wheel install, ./policies in
# a repo checkout (a wheel has no <site-packages>/policies folder).
DEFAULT_POLICY = str(policy_dir() / "default_policy.json")
VALID_NATIVE_DECISIONS = {"allow", "deny", "ask", "force_ask", "deny_unless_prior_grant"}
ABSOLUTE_GATES = {"credentials_secrets", "money", "external_communication", "destructive_irreversible", "privilege_escalation"}

def load_json(path: str) -> Mapping[str, Any]:
    with open(path, encoding="utf-8") as handle:
        value = json.load(handle)
    if not isinstance(value, dict):
        raise ValueError(f"{path} must contain a JSON object")
    return value

def history_path(config: Mapping[str, Any]) -> str:
    """Tool history store path, or "" when execution recording is off."""
    learned = config.get("auto_allow_learned") if isinstance(config.get("auto_allow_learned"), Mapping) else {}
    # record_outcomes: keep the pending/executed record (did an asked command
    # run, i.e. did the human approve it) WITHOUT learning from it. Labels for
    # `semgate report`; never an allow.
    if learned.get("enabled") is not True and config.get("record_outcomes") is not True:
        return ""
    value = learned.get("history_file")
    return os.path.expanduser(str(value)) if value else storepaths.state_path(config, "tool_history.jsonl")

def feedback_path(config: Mapping[str, Any]) -> str:
    """Human-decision store path, or "" when feedback is off."""
    fb = config.get("feedback") if isinstance(config.get("feedback"), Mapping) else {}
    if fb.get("enabled") is not True:
        return ""
    value = fb.get("feedback_file")
    return os.path.expanduser(str(value)) if value else storepaths.state_path(config, "feedback.jsonl")

def agent_files_enabled(config: Mapping[str, Any]) -> bool:
    """F6: record files the agent creates (hash + snapshot) so a later delete
    of an unchanged one counts as restorable. Off unless
    agent_files.enabled is true; only used when git_facts is also true."""
    af = config.get("agent_files") if isinstance(config.get("agent_files"), Mapping) else {}
    return af.get("enabled") is True


def script_source_enabled(config: Mapping[str, Any]) -> bool:
    """F4: read local scripts the command runs (gates + evidence for the model).
    Off unless `script_source` is true (or {"enabled": true})."""
    value = config.get("script_source")
    return value is True or (isinstance(value, Mapping) and value.get("enabled") is True)


def agent_files_store(config: Mapping[str, Any]):
    """The per-session step store, or None when neither F6 nor F4 is on.
    Directory: agent_files.dir (default ~/.semgate; storepaths)."""
    if not (agent_files_enabled(config) or script_source_enabled(config)):
        return None
    from .agentfiles import MAX_BYTES, AgentFiles
    af = config.get("agent_files") if isinstance(config.get("agent_files"), Mapping) else {}
    return AgentFiles(storepaths.agent_files_dir(config), max_bytes=int(af.get("max_bytes") or MAX_BYTES))


_PATH_ARG_KEYS = ("path", "file_path", "filePath", "TargetFile", "targetFile", "target_file", "FilePath", "AbsolutePath")


def action_write_targets(envelope: Any) -> List[str]:
    """Paths an action may create: shell write targets, or a file tool's path."""
    args = envelope.action.arguments
    command = args.get("command")
    if isinstance(command, str) and command.strip():
        from .gitstate import write_targets
        return write_targets(command)
    out: List[str] = []
    for key in _PATH_ARG_KEYS:
        value = args.get(key)
        if isinstance(value, str) and len(value) >= 2 and value.startswith('"') and value.endswith('"'):
            try:                     # agy sends some string args JSON-encoded ('"c:\\p\\a.py"')
                decoded = json.loads(value)
                value = decoded if isinstance(decoded, str) else value
            except ValueError:
                pass
        if isinstance(value, str) and value and value not in out:
            out.append(value)
    return out


_CONTENT_ARG_KEYS = ("content", "CodeContent", "codeContent", "file_text", "contents")
_WRITE_TOOLS = frozenset({"write", "write_to_file", "create_file", "create"})


def action_expected_hashes(envelope: Any) -> Dict[str, List[str]]:
    """F6 (U2): for a file tool that carries the whole new content, the
    sha256 values the written file can have, per target path. {} for a
    shell command (its output is unknown before it runs) and for edit tools
    (they change an existing file, which is never agent-created)."""
    args = envelope.action.arguments
    command = args.get("command")
    if (isinstance(command, str) and command.strip()) or str(envelope.action.tool).lower() not in _WRITE_TOOLS:
        return {}
    from .agentfiles import expected_hashes
    shas: List[str] = []
    for key in _CONTENT_ARG_KEYS:
        value = args.get(key)
        if not isinstance(value, str):
            continue
        shas.extend(expected_hashes(value))
        # agy sends some string args JSON-encoded ('"hola"'): the decoded
        # text is also what the tool may write.
        if len(value) >= 2 and value.startswith('"') and value.endswith('"'):
            try:
                decoded = json.loads(value)
            except ValueError:
                decoded = None
            shas.extend(expected_hashes(decoded))
        break
    if not shas:
        return {}
    return {target: sorted(set(shas)) for target in action_write_targets(envelope)}


def record_post_event(config: Mapping[str, Any], session_id: str, step_idx: Any, error: str = "") -> None:
    """PostToolUse side of F6/F4, shared by every host that has a post event.
    Records created files (hash + snapshot) and writes a ledger incident when a
    script the decision read changed before or during the run. Never raises."""
    try:
        store = agent_files_store(config)
        if store is None or not session_id or step_idx is None:
            return
        result = store.record_post(session_id, step_idx, error)
        if result.get("script_changed"):
            ledger = Ledger(storepaths.ledger_file(config))
            for item in result["script_changed"]:
                ledger.record_incident("script_changed", {k: v for k, v in item.items() if k != "record_type"})
    except Exception as exc:
        print(f"semgate: post-event record failed: {type(exc).__name__}: {exc}", file=sys.stderr)


# Shown to the agent when we block, so it can explain to the human and ask for
# approval instead of silently failing or trying to route around the gate.
_BLOCKED_SUFFIX = (" | Semgate blocked this. If it is needed for the task, tell the user plainly in the chat what this "
                   "command does and why, and ask whether to run exactly this command now. If they clearly say yes, "
                   "re-run the exact same command once; semgate checks their reply. Some actions stay blocked even "
                   "with approval. Do not try to bypass, rename, or disable the gate.")

def chat_can_approve(chat_host: Optional[str]) -> bool:
    """True when a yes in the chat can approve a block on this host: its
    manifest says C35 (chat approval) = yes. None (no host reader, e.g. the
    HTTP gate, which puts its own text in place of _BLOCKED_SUFFIX): True.
    A host without a manifest (Copilot CLI, VS Code, Devin) or with C35 not
    yes (Droid: unknown): False."""
    if chat_host is None:
        return True
    from .chatapproval import CAPABILITY
    from .hosts.base import load_manifest
    return load_manifest(str(chat_host)).supports(CAPABILITY)


def terminal_suffix() -> str:
    """The block text for a host where a chat reply cannot approve: the
    user approves the exact command in their own terminal with semgate's
    feedback command (the install's own command path, as the skill writes
    it: skill.command()), or runs it themselves."""
    try:
        from .skill import command
        cmd = command()
    except Exception:
        cmd = "semgate"
    return (" | Semgate blocked this. On this host a reply in the chat cannot approve it. If it is needed for the task, "
            "tell the user plainly what this command does and why. The user approves exactly this command in their own "
            f"terminal, in the project folder, with: {cmd} feedback allow \"<exact command>\" - or runs it themselves. "
            "When they say it is approved, re-run the exact same command once. Some actions stay blocked even with "
            "approval. Do not try to bypass, rename, or disable the gate.")


def antigravity_decision(sem: Decision, config: Mapping[str, Any], tool: str,
                         chat_host: Optional[str] = None) -> Dict[str, Any]:
    """`chat_host`: the host's manifest name (HostChat.manifest_host) or
    None; a block on a host without chat approval (chat_can_approve) tells
    the agent that the user approves in their own terminal.

    A config that is neither a complete enforce config nor the developer
    shadow switch fails closed for the host (semgate.enforcement.fail_closed): a
    deny where the host cannot show an ask, an ask where it can."""
    problem = enforce_cfg.mode_problem(config)
    if problem:
        return enforce_cfg.fail_closed(problem, chat_host, config)
    if sem.stage == "privacy" and not enforce_cfg.is_shadow(config):
        # Never offer ordinary feedback/chat approval for an uninspected or
        # disputed payload. Hosts that cannot reliably prompt must block it.
        decision = "deny" if sem.decision == "deny" or not enforce_cfg.shows_ask(chat_host) else "force_ask"
        if sem.reason_code == "privacy_prepared_send_required":
            return {"decision": "deny", "reason": "semgate privacy: privacy_prepared_send_required; "
                    "use the configured prepared-send client: prepare and dispatch for uploads, "
                    "or run for a configured offline development worker. Direct host shell execution is disabled."}
        return {"decision": decision, "reason": (f"semgate privacy: {sem.reason_code}; "
                "the data, recipient and purpose must pass privacy inspection before retrying.")}
    result = _base_decision(sem, config, tool)
    # YOLO guard: when the host auto-runs (no prompt), a "please ask" is not safe
    # because it becomes a silent run. block_when_unsure turns every ask/force_ask
    # into a hard deny, so only a confident allow runs and everything else is
    # blocked. A deny stays a deny; an allow stays an allow. A config without
    # the key gets the host rule (semgate.enforcement.block_when_unsure).
    if enforce_cfg.block_when_unsure(config, chat_host) and result.get("decision") in {"ask", "force_ask"}:
        result = {"decision": "deny", "reason": "block_when_unsure: not a confident allow, so blocked; " + result.get("reason", "")}
    # Make a block actionable for the agent: explain, ask the human, do not bypass.
    # A command that carries out an instruction from content the agent read
    # cannot be approved in chat: the agent is told so first (never cut by the
    # cap) and is not told to ask for a yes (chatapproval.NOT_APPROVABLE_GATES).
    if result.get("decision") in {"deny", "deny_unless_prior_grant"}:
        from .chatapproval import UNTRUSTED_NOTE, from_untrusted_content
        if from_untrusted_content(sem):
            result = {"decision": result["decision"], "reason": (UNTRUSTED_NOTE + result.get("reason", ""))[:1000]}
        elif chat_can_approve(chat_host):
            result = {"decision": result["decision"], "reason": (result.get("reason", "") + _BLOCKED_SUFFIX)[:1000]}
        else:
            # The how-to-approve text is never cut by the 1000-char cap.
            suffix = terminal_suffix()
            result = {"decision": result["decision"], "reason": result.get("reason", "")[:max(0, 1000 - len(suffix))] + suffix}
    return result

def _base_decision(sem: Decision, config: Mapping[str, Any], tool: str) -> Dict[str, Any]:
    # No "mode" is enforce (the production default); "shadow" is the
    # developer switch (record only: every answer is an ask).
    mode = enforce_cfg.mode(config)
    code = f" [{sem.reason_code}]" if sem.reason_code else ""
    reason = f"semgate {mode}: {sem.stage}/{sem.decision}{code}; " + ("; ".join(sem.reasons) or "no reason")
    if mode != "enforce":
        return {"decision": "ask", "reason": reason[:1000]}
    enforcement = config.get("enforcement") if isinstance(config.get("enforcement"), Mapping) else {}
    if enforcement.get("enabled") is not True:
        return {"decision": "ask", "reason": "semgate enforcement requested but not explicitly enabled; asking human"}
    if sem.stage == "hard_rules" and sem.decision == "deny":
        return {"decision": "deny", "reason": reason[:1000]}
    if sem.stage in {"grant_validity", "human_gate"} or sem.gate_hits or sem.error or sem.missing_evidence:
        return {"decision": "force_ask", "reason": reason[:1000]}
    if sem.decision == "ask":
        return {"decision": "force_ask", "reason": reason[:1000]}
    if sem.decision == "deny":
        response = str(enforcement.get("semantic_deny_response", "deny"))
        if response not in {"deny", "deny_unless_prior_grant"}:
            response = "deny"
        return {"decision": response, "reason": reason[:1000]}
    # A human approved this exact command in their own terminal (semgate feedback
    # allow). judge() only produces a human_approved allow on an exact action_key
    # match (tool + normalized command) and never over a hard-deny or expired
    # grant, so this is scoped to the one command approved, never the tool in
    # general and never a variation. It is honored even when the tool is outside
    # auto_allow_tools; otherwise the documented "blocked -> human approves -> it
    # runs" loop is dead for any tool (e.g. bash) not in that list.
    if sem.decision == "allow" and sem.stage == "human_approved":
        return {"decision": "allow", "reason": reason[:1000]}
    # A command the user trusted in this project (semgate trust add; judge
    # trust_override): the same exact-command rule, with an expiry instead of
    # a session. Never produced over a deny or the gates the agent can steer.
    if sem.decision == "allow" and sem.stage == "trusted":
        return {"decision": "allow", "reason": reason[:1000]}
    # Learned allow reaches the host only with its own explicit flag. Deny,
    # human_gate, grant_validity, error and missing_evidence returned above.
    if sem.decision == "allow" and sem.stage == "auto_allow" and enforcement.get("propagate_learned_allow") is True:
        return {"decision": "allow", "reason": reason[:1000]}
    # A harness tool code allowed (harnesstools.py: ask the user, the to-do
    # list, a skill load that runs no command): no effect outside the host's
    # own session, so it does not need the local auto-allow list, which is
    # for allows the model made. A deny or ask of such a tool returned above.
    if sem.decision == "allow" and sem.stage == "hard_rules" and sem.reason_code == harnesstools.REASON_CODE:
        return {"decision": "allow", "reason": reason[:1000]}
    allowed ={str(x) for x in enforcement.get("auto_allow_tools", [])}
    if sem.decision == "allow" and tool in allowed:
        return {"decision": "allow", "reason": reason[:1000]}
    return {"decision": "ask", "reason": "semgate enforce: allow was outside the local auto-allow tool set"}

def _deny_streak_update(state_file: str, session: str, is_block: bool) -> Dict[str, int]:
    """Read-modify-write per-session {consecutive, total} deny counts, under a
    cross-process lock on `<state_file>.lock`, written as a unique temp file
    plus os.replace (a reader never sees a half-written file).

    A file that does not parse is rewritten from zero, with a warning on
    stderr (before, it stayed corrupt and escalation stayed off for good).
    Raises filelock.LockTimeout when the lock is not free in time (the caller
    fails closed). Any other store error returns zeros: escalation only adds
    a note, it never changes a decision."""
    from . import filelock
    p = Path(state_file)
    try:
        with filelock.exclusive(p):
            try:
                data = json.loads(p.read_text(encoding="utf-8")) if p.exists() else {}
            except ValueError:
                print(f"semgate: {p} did not parse; deny counts restart from zero", file=sys.stderr)
                data = {}
            if not isinstance(data, dict):
                data = {}
            entry = data.get(session) if isinstance(data.get(session), Mapping) else {}
            c = int(entry.get("consecutive", 0)) + 1 if is_block else 0
            t = int(entry.get("total", 0)) + (1 if is_block else 0)
            data[session] = {"consecutive": c, "total": t}
            filelock.write_json_atomic(p, data)
            return {"consecutive": c, "total": t}
    except filelock.LockTimeout:
        raise
    except (OSError, ValueError, TypeError) as exc:
        print(f"semgate: deny streak not updated: {type(exc).__name__}: {exc}", file=sys.stderr)
        return {"consecutive": 0, "total": 0}

def _store_failed(result: Mapping[str, Any], what: str, verb: str = "record") -> Dict[str, Any]:
    """A store write of this hook call did not get its lock in time. Fail
    closed: an allow becomes force_ask; ask, force_ask and deny stay as they
    are (never softer). The reason says which store."""
    out = dict(result)
    note = f" | semgate could not {verb} {what}; asking a human"
    if out.get("decision") == "allow":
        out = {"decision": "force_ask", "reason": ("semgate: store lock timeout" + note + " | " + str(result.get("reason", "")))[:1000]}
    else:
        out["reason"] = (str(out.get("reason", "")) + note)[:1000]
    return out


def _apply_deny_escalation(result: Dict[str, Any], config: Mapping[str, Any], session: str,
                           chat_ok: bool = True) -> Dict[str, Any]:
    """After N consecutive or M total blocks in one session, surface a message that
    auto mode is stuck and needs a human. It NEVER changes the decision (a deny
    stays a deny; a hard-deny is never softened) - it only adds the note and hands
    attention to the operator. Mirrors Claude Code's auto-mode fallback (3
    consecutive or 20 total classifier blocks -> stop auto-deciding, ask the human).
    Off unless enforcement.deny_escalation.enabled is true. Only DENY counts as a
    block; an allow or an ask (force_ask) resets the consecutive counter."""
    enf = config.get("enforcement") if isinstance(config.get("enforcement"), Mapping) else {}
    esc = enf.get("deny_escalation") if isinstance(enf.get("deny_escalation"), Mapping) else {}
    if esc.get("enabled") is not True or not session:
        return result
    is_block = result.get("decision") in {"deny", "deny_unless_prior_grant"}
    consecutive_limit = max(1, int(esc.get("consecutive", 3)))
    total_limit = max(1, int(esc.get("total", 20)))
    state_file = storepaths.deny_streak_file(config)
    from .filelock import LockTimeout
    try:
        counts = _deny_streak_update(state_file, session, is_block)
    except LockTimeout as exc:
        return _store_failed(result, f"deny-streak state ({exc})")
    if is_block and (counts["consecutive"] >= consecutive_limit or counts["total"] >= total_limit):
        how = ("ask the user in the chat to approve the exact command" if chat_ok else
               "ask the user to approve the exact command in their own terminal (semgate feedback allow)")
        note = (f" | AUTO MODE PAUSED: {counts['consecutive']} commands were blocked in a row this session "
                f"({counts['total']} total). Stop retrying and review the transcript. If this work is legitimate, "
                f"{how}, or to widen the grant - do not bypass the gate.")
        result = dict(result)
        result["reason"] = (str(result.get("reason", "")) + note)[:1000]
    return result

def run(event: Mapping[str, Any], config: Mapping[str, Any], meta: Optional[Dict[str, Any]] = None,
        payload: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """`meta`, when given, receives the canonical tool name and the envelope digest.
    `payload`: payloadsize.describe() of the raw event (evidence only)."""
    from .adapters.antigravity import chat_conversation, transcript_started_at, user_requests
    from .chatapproval import HostChat
    transcript = event.get("transcriptPath")
    return run_core(
        config,
        payload=payload,
        build_envelope=lambda grant: envelope_from_pre_tool_use(event, grant),
        session_id=str(event.get("conversationId", "")),
        step_idx=event.get("stepIdx"),
        user_messages=lambda: user_requests(transcript),
        meta=meta,
        session_started_at=lambda: transcript_started_at(transcript),
        chat=HostChat("antigravity", lambda: chat_conversation(transcript)),
    )


DEMO_NOTE = "[semgate DEMO: no TypeSafe key, recorded answers only; anything else asks] "


def configured_provider(config: Mapping[str, Any]) -> Any:
    """Provider selection shared by the hook and trusted snapshot preparation."""
    name = str(config.get("provider") or "none")
    provider = None
    if name == "fake":
        provider = FakeProvider(script=config.get("fake_answers") or {}, fail=bool(config.get("provider_fail")))
    elif name in LIVE_PROVIDERS:
        from .providers.registry import live_provider
        provider = live_provider(name, str(config.get("judge_model") or "") or None)
    elif name == "recorded":
        from .providers.recorded import RecordedProvider
        provider = RecordedProvider()
    elif name != "none":
        raise ValueError(f"unknown provider {name!r}")
    from .providers.safe import configured
    return configured(provider, config)


def run_core(config: Mapping[str, Any], **kwargs: Any) -> Dict[str, Any]:
    """The pipeline (_run_core). In demo mode (provider "recorded") every
    reason the host shows starts with DEMO_NOTE, so nobody mistakes a demo
    answer for a live one. The decision itself is not changed.

    A non-allow answer's text is recorded as sent for this action
    (ownmessages.remember): the host shows it to the agent as the call's
    result, and the next call's scans must not read it as untrusted
    content. The hook entry points record the final text again after their
    own changes (ledger lock note, host prefixes)."""
    if kwargs.get("meta") is None:
        kwargs["meta"] = {}
    result = _run_core(config, **kwargs)
    if str(config.get("provider", "")) == "recorded" and isinstance(result, dict) and "reason" in result:
        reason = str(result.get("reason") or "")
        if not reason.startswith(DEMO_NOTE):
            result = {**result, "reason": (DEMO_NOTE + reason)[:1000]}
    if isinstance(result, dict):
        remember_sent(config, kwargs.get("session_id"), kwargs["meta"], result.get("decision"), result.get("reason"))
    return result


def remember_sent(config: Any, session_id: Any, meta: Mapping[str, Any], decision: Any, text: Any) -> None:
    """ownmessages.remember for the action in `meta` (run_core puts its
    arguments there). Never raises; never changes the answer."""
    from . import ownmessages
    arguments = meta.get("action_arguments") if isinstance(meta, Mapping) else None
    if isinstance(arguments, Mapping) and isinstance(config, Mapping):
        ownmessages.remember(config, session_id, arguments, decision, text)


def _run_core(
    config: Mapping[str, Any],
    *,
    build_envelope: Callable[[Any], Any],
    session_id: str,
    step_idx: Any,
    user_messages: Callable[[], List[str]],
    meta: Optional[Dict[str, Any]] = None,
    record_step: Any = "__same__",
    session_started_at: Optional[Callable[[], Any]] = None,
    payload: Optional[Dict[str, Any]] = None,
    store_problems: Optional[List[str]] = None,
    extra_evidence: Optional[Dict[str, Any]] = None,
    chat: Any = None,
    _after_pin: bool = False,
    prepared_disclosure: Any = None,
    consent_store: Any = None,
    trusted_offline_shell: bool = False,
    trusted_execution_facts: Any = None,
    execution_paths: Any = None,
) -> Dict[str, Any]:
    """Host-neutral decision pipeline shared by every hook adapter.

    The host adapter supplies how to build the envelope from the operator's
    grant, the session id, the host's step id (for outcome recording) and a
    function returning the user's own messages this session. `record_step`
    is the per-call id the host's post-tool event will carry (default: the
    same as step_idx; None when the host has no per-call id, which turns off
    the F4/F6 pre-records for that host). `session_started_at` returns the
    host transcript's first timestamp (ISO string or epoch; "" when unknown);
    with the G2 switch on (policy router.code_signals) the session start for
    signal S1 is the earliest of it and the first ledger entry for this
    session. `store_problems`: stores the adapter could not read before the
    decision (e.g. the tool output store, semgate.tooloutputs); each one
    fails closed like a lock timeout (an allow becomes force_ask).
    `extra_evidence`: {key: dict} added to the judgment's evidence when the
    dict is non-empty at judge time (it may be filled by build_envelope).
    `chat` (chatapproval.HostChat): the host's conversation reader for
    approval by chat reply (policy router.chat_approval, off by default;
    see chatapproval.py). None: never used.
    `_after_pin` (internal): this call is the second judgment of the same
    action, after pingate.maybe_pin pinned the instruction-file lines the
    user trusted in chat; no second pin is tried.
    Returns the
    native Antigravity vocabulary (allow / ask / force_ask / deny /
    deny_unless_prior_grant); other hosts map it to theirs."""
    # Config problems fail closed for the host (semgate.enforcement):
    # never an ask a host runs unattended, and no judge call is spent.
    chat_host = getattr(chat, "manifest_host", None) if chat is not None else None
    ask_word = "ask" if enforce_cfg.is_shadow(config) else "force_ask"
    problem = enforce_cfg.mode_problem(config)
    if problem:
        return enforce_cfg.fail_closed(problem, chat_host, config, ask_as=ask_word)
    grant_path = str(config.get("grant_file", ""))
    if not grant_path:
        return enforce_cfg.fail_closed("semgate: no operator grant_file configured", chat_host, config, ask_as=ask_word)
    grant = grant_from_config(load_json(grant_path))
    policy = Policy.load(str(config.get("policy_file", DEFAULT_POLICY)))
    # The process that runs the agent (by pid and start time): `semgate trust
    # add` run under it is the agent's, not the user's own terminal
    # (trustauth.py). Never changes the decision.
    from . import trust as _trust_store
    from .trustauth import note_agent_host
    note_agent_host(_trust_store.store_path(config), host=str(getattr(chat, "manifest_host", "") or ""),
                    session_id=session_id)
    # JSON null means no provider: `semgate init --provider none` wrote null
    # up to 0.4.0; str(None) would be the unknown provider 'None' and ask on
    # every call, the deterministic denies included.
    provider_name = str(config.get("provider") or "none")
    if provider_name not in {"none", "fake", "recorded", *LIVE_PROVIDERS}:
        return enforce_cfg.fail_closed(f"semgate: unknown provider {provider_name!r}", chat_host, config, ask_as=ask_word)
    provider = configured_provider(config)
    from .privacy import from_config as privacy_from_config
    privacy_gate = privacy_from_config(config)
    if privacy_gate is not None and prepared_disclosure is not None:
        privacy_gate.consents = consent_store
    if privacy_gate is not None:
        from .providers.safe import for_envelope
        provider = for_envelope(provider, build_envelope(grant), prepared=prepared_disclosure,
                                offline_shell=trusted_offline_shell)
    # Work kinds: the purpose Jev judges against is composed from every kind of
    # work the user has asked for this session (see profiles.py). The grant's
    # hard scope (forbidden patterns, expiry) is untouched; kinds may only add
    # the operator's declared domains.
    prof_cfg = config.get("profiles") if isinstance(config.get("profiles"), Mapping) else {}
    from . import profiles as _profiles
    grant, kinds, table = _profiles.resolve(grant, prof_cfg, session_id=session_id,
                                           messages=user_messages(), provider=provider)
    envelope = build_envelope(grant)
    if execution_paths is not None:
        from .devworker import VerifiedOfflineFacts
        from .workerpaths import WorkerPaths
        if (not trusted_offline_shell or not isinstance(trusted_execution_facts, VerifiedOfflineFacts)
                or not isinstance(execution_paths, WorkerPaths)):
            raise ValueError("worker path mapping requires verified private execution")
    from .sendclient import verified_invocation
    trusted_send_client = verified_invocation(envelope, config)
    # semgate's own earlier answers in this session, which the host shows as
    # the blocked call's result, are not untrusted content: each copy in the
    # output of the same action is replaced before any scan (ownmessages.py).
    # A store problem removes nothing (the scans read more, never less).
    from . import ownmessages
    own_records, _own_problem = ownmessages.load(config, session_id)
    envelope, own_stats = ownmessages.clean_envelope(envelope, own_records)
    if own_stats.entries:
        extra_evidence = dict(extra_evidence or {}, own_messages=own_stats.to_dict())
    if meta is not None:
        meta["action_arguments"] = dict(envelope.action.arguments)
    ledger_path = storepaths.ledger_file(config)
    store = history_path(config)
    history = ToolHistory(store) if store else None
    learned = config.get("auto_allow_learned") if isinstance(config.get("auto_allow_learned"), Mapping) else {}
    min_count = max(2, int(learned.get("min_count", 2)))
    fb_path = feedback_path(config)
    feedback = None
    if fb_path:
        from .feedback import FeedbackStore, ttl_hours_from
        feedback = FeedbackStore(fb_path, max_ttl_hours=ttl_hours_from(config))
    store = agent_files_store(config)
    facts = None
    if config.get("git_facts") is True:
        from .gitstate import GitFacts
        # The session id comes from the host event (run_core's caller), never
        # from the command or the envelope's tool arguments.
        facts = GitFacts(agent_files=store if agent_files_enabled(config) else None,
                         session_id=session_id, project_root=envelope.environment.project_root)
        if execution_paths is not None:
            from .workerpaths import WorkerGitFacts
            facts = WorkerGitFacts(execution_paths, agent_files=store if agent_files_enabled(config) else None,
                                   session_id=session_id)
    workspace = None
    if script_source_enabled(config):
        from .scriptsource import LocalWorkspace
        workspace = LocalWorkspace()
        if execution_paths is not None:
            from .workerpaths import WorkerWorkspace
            workspace = WorkerWorkspace(execution_paths)
    git_history = None
    if policy.kind == "router" and codesignals.S1_ID in router_mod.enabled_code_signals(policy):
        # G2/S1: git log runs only when the command rewrites history, and the
        # session start is looked up only then (read-only, lazy).
        from .gitstate import GitHistory, to_epoch

        def session_start() -> Optional[float]:
            bounds = [Ledger(ledger_path).session_first_seen(session_id)]
            if session_started_at is not None:
                try:
                    bounds.append(to_epoch(session_started_at()))
                except Exception:
                    pass
            known = [b for b in bounds if b is not None]
            return min(known) if known else None
        git_history = GitHistory(session_start=session_start)
        if execution_paths is not None:
            from .workerpaths import WorkerGitHistory
            git_history = WorkerGitHistory(execution_paths, session_start=session_start)
    learn_history = history if learned.get("enabled") is True else None   # recording outcomes never turns on learning
    trust_store = None
    pin_view = None
    from . import trust as _trust
    if _trust.enabled(config):
        trust_store = _trust.TrustStore(_trust.store_path(config))
        # Pinned command lines of instruction files live in the same store (pins.py).
        from . import pins as _pins
        pin_view = _pins.PinView(_pins.PinStore(_trust.store_path(config)), envelope.environment.project_root,
                                 envelope.environment.cwd)
        if execution_paths is not None:
            from .workerpaths import WorkerPinView
            pin_view = WorkerPinView(execution_paths, pin_view.store)
    view = execution_paths.envelope(envelope) if execution_paths is not None else envelope
    sem = judge(view, policy, provider=provider, ledger=Ledger(ledger_path), history=learn_history, learn_min_count=min_count,
                feedback=feedback, facts=facts, workspace=workspace, git_history=git_history, payload=payload,
                extra_evidence=extra_evidence, trust=trust_store, pins=pin_view,
                # The hook runs as a child of the agent CLI: this PATH is the one
                # the agent's commands use (folders on it count for persistence_link).
                path_env=os.environ.get("PATH", ""), privacy_gate=privacy_gate, prepared_disclosure=prepared_disclosure,
                trusted_send_client=trusted_send_client, trusted_offline_shell=trusted_offline_shell,
                trusted_execution_facts=trusted_execution_facts, execution_paths=execution_paths,
                authority_envelope=envelope if execution_paths is not None else None)
    # A command from a project instruction file whose lines the user has not
    # pinned (pingate.py). On the retry after semgate's question, the user's
    # yes in chat pins exactly the lines semgate quoted; then the same action
    # is judged again, in the normal way.
    from . import pingate
    if (not _after_pin and pingate.candidate(sem) is not None
            and pingate.maybe_pin(config, policy, provider, sem=sem, envelope=envelope, chat=chat, session_id=session_id,
                                  pins=pin_view)):
        return run_core(config, build_envelope=build_envelope, session_id=session_id, step_idx=step_idx,
                        user_messages=user_messages, meta=meta, record_step=record_step,
                        session_started_at=session_started_at, payload=payload, store_problems=store_problems,
                        extra_evidence=extra_evidence, chat=chat, _after_pin=True,
                        prepared_disclosure=prepared_disclosure, consent_store=consent_store,
                        trusted_offline_shell=trusted_offline_shell, trusted_execution_facts=trusted_execution_facts,
                        execution_paths=execution_paths)
    from .filelock import LockTimeout
    lock_failures: List[str] = []
    step_for_record = step_idx if record_step == "__same__" else record_step
    if store is not None and session_id and step_for_record is not None:
        try:
            # F4 script files and the code files a test command runs (testrun.py):
            # re-hashed after the run (TOCTOU record).
            scripts = [{"path": f.get("path", ""), "sha256": f.get("sha256", "")}
                       for key in ("script_source", "test_run")
                       for f in (sem.evidence.get(key) or {}).get("files", [])]
            store.record_pre(session_id, step_for_record, project_root=envelope.environment.project_root,
                             cwd=envelope.environment.cwd or envelope.environment.project_root,
                             targets=action_write_targets(envelope) if agent_files_enabled(config) else [],
                             scripts=scripts,
                             expected=action_expected_hashes(envelope) if agent_files_enabled(config) else None)
        except LockTimeout as exc:
            lock_failures.append(f"the pre-step record ({exc})")
        except Exception as exc:   # other recording errors never change the decision
            print(f"semgate: pre-event record failed: {type(exc).__name__}: {exc}", file=sys.stderr)
    if meta is not None:
        # judged_*: the judge's own answer, for callers that report it next to
        # the final answer (semgate.harness). Never read back by the pipeline.
        meta.update(tool=envelope.action.tool, content_digest=sem.envelope_digest, judged_stage=sem.stage,
                    judged_decision=sem.decision, judged_reason_code=sem.reason_code,
                    privacy_blocked=sem.stage == "privacy" and sem.decision != "allow")
        if prepared_disclosure is not None:
            meta["prepared_privacy"] = sem.evidence.get("privacy", {})
    if history is not None:
        # The PostToolUse hook joins on (conversationId, stepIdx).
        try:
            history.record_pending(
                envelope.environment.session_id, step_idx,
                envelope.action.tool, envelope.action.arguments,
                sem.decision, sem.stage, sem.envelope_digest,
            )
        except LockTimeout as exc:
            lock_failures.append(f"the tool-history pending record ({exc})")
    chat_ok = chat_can_approve(chat_host)
    result = antigravity_decision(sem, config, envelope.action.tool, chat_host=chat_host)
    if sem.stage == "privacy":
        return _apply_deny_escalation(result, config, envelope.environment.session_id, False)
    for what in lock_failures:
        result = _store_failed(result, what)
    for what in (store_problems or []):
        if what:
            result = _store_failed(result, what, verb="read")
    # Work-kind check: only a model-made allow is re-examined. If the command is
    # a kind of work the user has not asked for this session, the human decides,
    # and is told which kind it is. It can only turn an allow into an ask.
    if (kinds is not None and table is not None and result.get("decision") == "allow"
            and sem.stage == "semantic" and prof_cfg.get("kind_check", True) is not False):
        from . import profiles as _profiles
        command = str(envelope.action.arguments.get("command", ""))
        check = _profiles.check_command(command, prof_cfg, session_id=session_id, kinds=kinds, provider=provider, table=table)
        if check is not None and not check.requested:
            result = {"decision": "force_ask",
                      "reason": (f"semgate enforce: work_kind/ask [unrequested_kind:{check.kind}]; {check.message} | "
                                 + str(result.get("reason", "")))[:1000]}
    # Not pinned: semgate's question about the instruction-file lines goes to
    # the user (the host's prompt), or to the agent to ask in chat.
    if pingate.candidate(sem) is not None:
        result = pingate.finish(config, policy, sem=sem, envelope=envelope, result=result,
                                base_reason=_base_decision(sem, config, envelope.action.tool)["reason"], chat=chat,
                                session_id=session_id,
                                store_trouble=bool(lock_failures or [p for p in (store_problems or []) if p]))
        return _apply_deny_escalation(result, config, envelope.environment.session_id, chat_ok)
    # `semgate trust add` run by the agent (human gate trust_request): allowed
    # only when the user's own latest turn asked for it (trustgate.py). It is
    # never approved by a chat reply (the step below): the trust gate is the
    # stricter check of the same question.
    from . import trustgate
    if trustgate.is_request(sem):
        result = trustgate.apply(
            config, policy, provider, sem=sem, envelope=envelope, result=result,
            base_reason=_base_decision(sem, config, envelope.action.tool)["reason"], chat=chat, session_id=session_id,
            ledger_path=ledger_path,
            store_trouble=bool(lock_failures or [p for p in (store_problems or []) if p]))
        return _apply_deny_escalation(result, config, envelope.environment.session_id, chat_ok)
    # Approval by chat reply: on a host that cannot show this ask (or with
    # block_when_unsure), record the block; on a retry after a new user turn
    # the judge decides whether that turn approves it (allow once).
    if chat is not None:
        from . import chatapproval
        if chatapproval.enabled(policy):
            result = chatapproval.apply(
                config, policy, provider, sem=sem, envelope=envelope, result=result,
                pre=_base_decision(sem, config, envelope.action.tool)["decision"], chat=chat, session_id=session_id,
                store_trouble=bool(lock_failures or [p for p in (store_problems or []) if p]))
    return _apply_deny_escalation(result, config, envelope.environment.session_id, chat_ok)

def record_host_response(event: Any, config: Any, result: Mapping[str, Any], meta: Mapping[str, Any]) -> Dict[str, Any]:
    """Write the exact object returned to the host, keyed by (conversationId,
    stepIdx). Runs for failures too. Returns the object to return.

    When the ledger lock is not free in time, the answer fails closed (an
    allow becomes force_ask) and that final answer is kept, with
    `lock_timeout: true`, in a spill file next to the ledger, so the record
    of what the host got is never silently lost. Any other write error goes
    to stderr and does not change the decision."""
    from .envelope import utcnow_iso
    from .filelock import LockTimeout, spill_record
    out = dict(result)
    event = event if isinstance(event, Mapping) else {}
    config = config if isinstance(config, Mapping) else {}
    ledger_path = storepaths.ledger_file(config)
    ids = dict(conversation_id=str(event.get("conversationId", "")), step_idx=event.get("stepIdx"),
               tool=str(meta.get("tool", "")), content_digest=str(meta.get("content_digest", "")))
    if hookinput.session_id_problem(event.get("conversationId")):
        # A rejected id is never written: keep its length and sha256_12 only,
        # the same form as the hook_input_rejected incident.
        ids["conversation_id"] = ""
        ids["invalid_session_id"] = hookinput.session_id_digest(event.get("conversationId"))
    try:
        Ledger(ledger_path).record_host_response(ids["conversation_id"], ids["step_idx"], out, tool=ids["tool"],
                                                 content_digest=ids["content_digest"], spill=False,
                                                 invalid_session_id=ids.get("invalid_session_id"))
    except LockTimeout as exc:
        final = _store_failed(out, f"the host_response ({exc})")
        spill_record(ledger_path, {"record_type": "host_response", **ids, "native": dict(final), "ts": utcnow_iso()}, str(exc))
        return final
    except Exception as exc:
        print(f"semgate: could not record host_response: {type(exc).__name__}: {exc}", file=sys.stderr)
    return out

def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="semgate-antigravity-hook")
    parser.add_argument("--config", default=os.environ.get("SEMGATE_ANTIGRAVITY_CONFIG", "~/.semgate/antigravity/semgate.json"))
    args = parser.parse_args(argv)
    event: Any = None
    config: Any = None
    meta: Dict[str, Any] = {}
    try:
        # Bounded read (hook_max_payload_bytes) and session id check: hookinput.
        event, size = hookinput.read_event(args.config)
        hookinput.require_session_id(event.get("conversationId"))
        # Relative store paths resolve against the config's folder, never the cwd (storepaths).
        config = storepaths.load(args.config, "antigravity")
        call = event.get("toolCall") if isinstance(event.get("toolCall"), Mapping) else {}
        payload = payloadsize.describe(size, call.get("args"), str(event.get("modelName") or ""))
        result = run(event, config, meta, payload=payload)
        if result.get("decision") not in VALID_NATIVE_DECISIONS:
            raise ValueError("invalid Antigravity decision")
    except Exception as exc:
        hookinput.note_rejection(config if config is not None else args.config, exc, "antigravity")
        # A hook failure must never become execution permission. agy runs a
        # force_ask without a prompt under --dangerously-skip-permissions, so
        # the answer is a deny (semgate.enforcement.fail_closed); the developer
        # shadow switch keeps its force_ask.
        result = enforce_cfg.fail_closed(f"semgate hook failure: {type(exc).__name__}: {exc}", "antigravity",
                                         config, ask_as="force_ask")
        if config is None:
            # Failed before the config was loaded: record where --config says
            # (or ~/.semgate/antigravity/), never in the current directory.
            config = {"ledger_file": hookinput.early_ledger_path(args.config, "antigravity")}
    result = record_host_response(event, config, result, meta)
    # The exact text agy shows the agent (ownmessages.py).
    remember_sent(config, event.get("conversationId") if isinstance(event, Mapping) else "", meta,
                  result.get("decision"), result.get("reason"))
    json.dump(result, sys.stdout, sort_keys=True)
    sys.stdout.write("\n")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
