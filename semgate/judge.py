"""The judge orchestrator. Shadow mode: it produces a Decision and a ledger
record. It never executes the proposed action, never touches the network
outside the configured provider, and never mutates anything but its own
append-only ledger.
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from . import codesignals, evidence, harnesstools, linkplace, payloadsize, router, rules, scriptsource, testrun
from .envelope import Envelope, utcnow_iso
from .filelock import LockTimeout
from .history import ToolHistory
from .ledger import IncompleteWindow, Ledger
from .policy import Policy, combine
from .providers.base import JudgeProvider, ProviderError, served_of
from .providers.registry import provider_model


@dataclass(frozen=True)
class Decision:
    decision: str                              # "allow" | "ask" | "deny"
    reasons: List[str] = field(default_factory=list)
    stage: str = ""                            # which layer produced the outcome
    reason_code: str = ""                      # machine-readable outcome code (for agent self-correction)
    gate_hits: List[Dict[str, str]] = field(default_factory=list)
    predicate_votes: List[Dict[str, Any]] = field(default_factory=list)
    missing_evidence: Dict[str, List[str]] = field(default_factory=dict)
    policy_version: str = ""
    provider: str = ""
    envelope_digest: str = ""
    evaluated_at: str = ""
    latency_ms: float = 0.0
    error: Optional[str] = None
    # Code-verified facts used for this decision (F4 script source: path,
    # sha256, size, redactions, injection flag, sent). Omitted when empty.
    evidence: Dict[str, Any] = field(default_factory=dict)
    # The model id the provider sends (e.g. jev-latest on TypeSafe,
    # typesafe/jev-1.13 on OpenRouter); "" without a live provider. Omitted when empty.
    judge_model: str = ""
    # Who answered this decision's model calls, as the provider's response
    # says (providers.base.Answers): the served model id (e.g.
    # typesafe/jev-1.13-20260917) and, on OpenRouter, the upstream provider.
    # Several calls with different values: the distinct values joined with
    # ",". "" when no call answered (hard rules, gates, a provider failure).
    # Omitted when empty.
    judge_served_model: str = ""
    judge_served_by: str = ""

    def to_dict(self) -> Dict[str, Any]:
        out = {
            "decision": self.decision,
            "reasons": list(self.reasons),
            "stage": self.stage,
            "reason_code": self.reason_code,
            "gate_hits": [dict(h) for h in self.gate_hits],
            "predicate_votes": [dict(v) for v in self.predicate_votes],
            "missing_evidence": {k: list(v) for k, v in self.missing_evidence.items()},
            "policy_version": self.policy_version,
            "provider": self.provider,
            "envelope_digest": self.envelope_digest,
            "evaluated_at": self.evaluated_at,
            "latency_ms": self.latency_ms,
            "error": self.error,
        }
        if self.evidence:
            out["evidence"] = dict(self.evidence)
        if self.judge_model:
            out["judge_model"] = self.judge_model
        if self.judge_served_model:
            out["judge_served_model"] = self.judge_served_model
        if self.judge_served_by:
            out["judge_served_by"] = self.judge_served_by
        return out


def fail_closed(decision: Decision, code: str, why: str) -> Decision:
    """A store needed for this decision could not be used (lock timeout,
    unreadable file). An allow becomes an ask; an ask or a deny stays as it
    is (never softer)."""
    if decision.decision != "allow":
        return decision
    return Decision(
        decision="ask", reasons=[f"{why}; asking a human", *decision.reasons], stage="store_unavailable",
        reason_code=code, gate_hits=decision.gate_hits, predicate_votes=decision.predicate_votes,
        missing_evidence=decision.missing_evidence, policy_version=decision.policy_version, provider=decision.provider,
        envelope_digest=decision.envelope_digest, evaluated_at=decision.evaluated_at, latency_ms=decision.latency_ms,
        error=decision.error, evidence=decision.evidence)


_STATE_TEXT = {
    "clean": "committed, no uncommitted changes",
    "missing": "does not exist yet",
    "agent_created": "created by the agent in this session; content unchanged since (checked by code); snapshot kept",
}


def restore_status_text(states: List[Any]) -> str:
    """The `restore_status` fact given to the model. The text for clean and
    missing targets is unchanged from before agent_created existed, so
    evaluations without agent-created files see exactly the same state."""
    body = ", ".join(f"{x.path}: {_STATE_TEXT.get(x.state, x.state)}" for x in states)
    if any(x.state == "agent_created" for x in states):
        return ("Checked by code, not a claim from the agent: every file this command deletes or overwrites ("
                + body + ") can be restored, from git or from the snapshot semgate kept of the agent-created file.")
    return "Checked by code, not a claim from the agent: every file this command deletes or overwrites (" + body + ") can be restored with git."


# Stages whose "ask" may be replaced by a learned allow. "grant_validity" is
# left out: an expired grant is stale configuration the operator must fix, not
# something learning may hide. "human_gate" is left out: credentials, money,
# external communication, destructive and privilege-escalation actions always
# reach a human.
DEFAULT_LEARN_STAGES: Tuple[str, ...] = ("semantic", "grant_scope")


def judge(
    envelope: Envelope,
    policy: Policy,
    provider: Optional[JudgeProvider] = None,
    ledger: Optional[Ledger] = None,
    history: Optional[ToolHistory] = None,
    learn_stages: Tuple[str, ...] = DEFAULT_LEARN_STAGES,
    learn_min_count: int = 2,
    feedback: "Optional[Any]" = None,
    facts: "Optional[Any]" = None,
    workspace: "Optional[Any]" = None,
    git_history: "Optional[Any]" = None,
    prior_on_task: "Optional[List[float]]" = None,
    payload: "Optional[Dict[str, Any]]" = None,
    extra_evidence: "Optional[Dict[str, Any]]" = None,
    trust: "Optional[Any]" = None,
    pins: "Optional[Any]" = None,
    path_env: "Optional[str]" = None,
) -> Decision:
    """`facts` (a gitstate.GitFacts) enables the git-state check: a delete or
    overwrite whose targets git can restore skips the destructive gate, and a
    model allow that overwrites or deletes something git cannot restore becomes
    an ask. `workspace` (scriptsource.LocalWorkspace, or SyntheticWorkspace in
    evals) enables F4: a local script the command runs is read, checked by the
    gates, and given to the model as `script_source`. `git_history`
    (gitstate.GitHistory, or SyntheticHistory in evals) lets the G2 signal S1
    say whether rewritten commits predate the session; without it S1 says it
    could not check. Without them the judge does no filesystem or git access.
    `prior_on_task` (session drift, policy threshold drift_session_ask_max):
    the on_task probabilities of this session's earlier semantic decisions
    since the latest user turn, oldest first. None: read from `ledger` when
    the knob is on (evals pass the case's synthetic values instead).
    `payload` (payloadsize.describe: hook payload and tool input sizes, the
    model's expected maximum) is recorded as evidence.payload on every
    decision; an anomaly adds a ledger incident and, with S5_payload_size in
    router.code_signals, a code signal. It never decides.
    `extra_evidence` ({key: dict}): recorded as evidence[key] when the dict
    is non-empty (e.g. tool_outputs: how the post-hook tool output records
    were merged into the trajectory). It never decides.
    `trust` (trust.TrustStore): trusted commands (`semgate trust add`). A
    trust in force for this exact command in this project turns a
    human-gate ask or a semantic ask/allow into an allow (stage `trusted`),
    never a deny and never the gates in trust.NOT_OVERRIDABLE_GATES; see
    trust_override below and trust.py.
    `pins` (pins.PinView): command lines of project instruction files the
    user pinned. A marker hit whose lines are all pinned is not the gate
    untrusted_instruction, and those lines reach the model as
    `project_instructions` instead of untrusted_context. A hit from an
    instruction file with unpinned lines stays the gate; its first reason is
    semgate's question about those lines, and evidence["instruction_lines"]
    holds the lines a yes pins (pingate.py).
    `path_env`: the PATH value of the agent process (hooks pass os.environ
    PATH). Each folder on it, except folders inside the project, counts as a
    PATH folder for the persistence_link gate, in addition to the fixed list.
    None (the default, and every eval runner unless the case sets a fake PATH):
    the fixed list only, so a decision never depends on the machine's PATH."""
    started = time.monotonic()
    evaluated_at = envelope.evaluated_at or utcnow_iso()
    digest = envelope.digest()
    provider_name = provider.name if provider else "none"
    judge_model = provider_model(provider)
    served_calls: List[Dict[str, str]] = []     # served_of() of each answered call of this decision

    def ask_provider(state: Any, questions: Any) -> Any:
        answers = provider.evaluate(state, questions)
        served_calls.append(served_of(answers))
        return answers

    def stamp(decision: Decision) -> None:
        """The judge model fields, on the final decision object."""
        object.__setattr__(decision, "judge_model", judge_model)
        for attr, key in (("judge_served_model", "model"), ("judge_served_by", "upstream")):
            values = list(dict.fromkeys(c[key] for c in served_calls if c.get(key)))
            object.__setattr__(decision, attr, ",".join(values)[:300])

    def learned(decision: Decision) -> Decision:
        """Replace an "ask" with "allow" when a human already approved this
        exact action `learn_min_count` times. A "deny" never changes."""
        if decision.decision != "ask" or history is None:
            return decision
        if decision.stage not in learn_stages or decision.gate_hits:
            return decision
        try:
            count = history.count_executed_after_ask(envelope.action.tool, envelope.action.arguments)
        except Exception:  # an unreadable history store must not become an allow
            return decision
        if count < learn_min_count:
            return decision
        return Decision(
            decision="allow",
            reasons=[f"auto_allow/learned (n={count})", f"replaced {decision.stage}/ask: " + "; ".join(decision.reasons)],
            stage="auto_allow",
            reason_code="learned_allow",
            predicate_votes=decision.predicate_votes,
            missing_evidence=decision.missing_evidence,
            policy_version=decision.policy_version,
            provider=decision.provider,
            envelope_digest=decision.envelope_digest,
            evaluated_at=decision.evaluated_at,
            error=decision.error,
        )

    def _human_decision() -> Optional[str]:
        if feedback is None:
            return None
        env = envelope.environment
        try:
            return feedback.latest(envelope.action.tool, envelope.action.arguments,
                                   session_id=env.session_id, project_root=env.project_root or env.cwd)
        except Exception as exc:  # unreadable (lock timeout, I/O): a human deny may be hidden
            return "unreadable:" + type(exc).__name__

    def human_override(decision: Decision) -> Decision:
        """Apply a recorded human decision. A human `allow` overrides a human gate
        or a semantic ask/deny (the human was asked and said yes); it never
        overrides a hard-deny or an expired grant. A human `deny` always blocks.
        An unreadable store may hide a deny, so an allow becomes an ask."""
        human = _human_decision()
        if human is None:
            return decision
        if human.startswith("unreadable:"):
            return fail_closed(decision, "feedback_unreadable",
                               f"the human-decision store could not be read ({human.split(':', 1)[1]}); a human deny may apply")
        common = dict(predicate_votes=decision.predicate_votes, missing_evidence=decision.missing_evidence,
                      policy_version=decision.policy_version, provider=decision.provider,
                      envelope_digest=decision.envelope_digest, evaluated_at=decision.evaluated_at, error=decision.error)
        if human == "deny" and decision.decision != "deny":
            return Decision(decision="deny", stage="human_blocked", reason_code="human_blocked",
                            reasons=["operator feedback: a human blocked this action", *decision.reasons], **common)
        # A semantic allow is marked too: with bash outside auto_allow_tools
        # the host blocks a model allow, and only a human_approved allow gets
        # through (antigravity_decision). Before, an approval of such a
        # command had no effect and the "blocked -> approve -> run" loop was dead.
        if (human == "allow" and decision.stage in ("human_gate", "semantic")
                and (decision.decision in ("ask", "deny") or (decision.decision == "allow" and decision.stage == "semantic"))):
            return Decision(decision="allow", stage="human_approved", reason_code="human_approved",
                            reasons=["operator feedback: a human approved this action", *decision.reasons], **common)
        return decision

    evidence_record: Dict[str, Any] = {}
    if payload:
        evidence_record["payload"] = dict(payload)
    for key, value in (extra_evidence or {}).items():
        if value and key not in evidence_record:
            evidence_record[key] = dict(value)

    script_gates: List[Any] = []

    def trust_override(decision: Decision) -> Decision:
        """A trusted command (trust.py). Order in finish(): after learning,
        before the human decision, so a human deny still wins. Only an ask
        or allow of stage human_gate / semantic changes; any deny (hard
        rules, grant scope, injection_deny, drift_deny, human deny), an
        expired grant, a store problem, the gates the agent can steer
        (untrusted_instruction, trust_request, agent_config, a gate found
        in a script file) and an instructed_by_context vote "injected" keep
        the decision. A weak on_task or session-drift ask is replaced: the
        user said to stop asking about exactly this command. An unreadable trust store keeps it too (a trust only
        opens, so not reading it is the stricter answer)."""
        if trust is None or decision.decision not in ("ask", "allow") or decision.stage not in ("human_gate", "semantic"):
            return decision
        from . import trust as trust_mod
        command = envelope.action.arguments.get("command")
        if not isinstance(command, str) or not command:
            return decision
        if script_gates or decision.reason_code == "script_source_scrub_failed":
            return decision
        if any(str(h.get("gate_class", "")) in trust_mod.NOT_OVERRIDABLE_GATES for h in decision.gate_hits):
            return decision
        # The judge says the command follows content the agent read (below the
        # injection_deny threshold, or the user asked): the trust is not used.
        if any((v.get("predicate"), v.get("vote")) == ("instructed_by_context", "injected") for v in decision.predicate_votes):
            return decision
        env = envelope.environment
        project = trust_mod.project_of(env.project_root or env.cwd)
        try:
            rec = trust.lookup(command, project)
        except Exception as exc:
            evidence_record["trusted_command"] = {"error": f"{type(exc).__name__}: {exc}"[:300]}
            return decision
        if rec is None or trust_mod.refuse_reason(command):
            return decision                  # refuse_reason: also a record written by hand around `trust add`
        evidence_record["trusted_command"] = {
            "trust_id": str(rec.get("trust_id", "")), "project_root": project, "expires_at": str(rec.get("expires_at", "")),
            "replaced": {"decision": decision.decision, "stage": decision.stage, "reason_code": decision.reason_code,
                         "gate_hits": [dict(h) for h in decision.gate_hits], "error": decision.error,
                         "missing_evidence": {k: list(v) for k, v in decision.missing_evidence.items()}}}
        return Decision(
            decision="allow", stage=trust_mod.STAGE, reason_code=trust_mod.REASON_CODE,
            reasons=[f"trusted command: the user trusted exactly this command in this project until "
                     f"{rec.get('expires_at', '')} (semgate trust {rec.get('trust_id', '')})",
                     f"replaced {decision.stage}/{decision.decision}: " + "; ".join(decision.reasons)],
            predicate_votes=decision.predicate_votes, policy_version=decision.policy_version, provider=decision.provider,
            envelope_digest=decision.envelope_digest, evaluated_at=decision.evaluated_at)

    def finish(decision: Decision) -> Decision:
        decision = human_override(trust_override(learned(decision)))
        object.__setattr__(decision, "latency_ms", round((time.monotonic() - started) * 1000.0, 3))
        stamp(decision)
        if evidence_record:
            object.__setattr__(decision, "evidence", {k: dict(v) for k, v in evidence_record.items()})
        if ledger is not None:
            try:
                ledger.record_judgment(envelope, decision)
            except LockTimeout:
                # The judgment is kept in a spill file (filelock.append_record);
                # the ledger could not take it in time. Fail closed.
                decision = fail_closed(decision, "store_lock_timeout", "the ledger lock was not free in time")
                stamp(decision)
                if evidence_record:
                    object.__setattr__(decision, "evidence", {k: dict(v) for k, v in evidence_record.items()})
            if (evidence_record.get("payload") or {}).get("anomaly"):
                try:
                    ledger.record_incident("payload_anomaly", {"judgment_id": digest, **evidence_record["payload"]})
                except Exception:   # recording must never change the decision
                    pass
        return decision

    base = {
        "policy_version": policy.version,
        "provider": provider_name,
        "envelope_digest": digest,
        "evaluated_at": evaluated_at,
    }

    # 0. Grant validity. An expired grant cannot auto-allow; a human re-decides.
    if envelope.grant.is_expired(at=evaluated_at):
        return finish(Decision(
            decision="ask",
            reasons=[f"grant '{envelope.grant.grant_id}' expired at {envelope.grant.expires_at}"],
            stage="grant_validity",
            reason_code="grant_expired",
            **base,
        ))

    # 0b. Harness tools with no effect outside the host's own session (ask
    #     the user a question, the to-do list): allowed by code, inside the
    #     grant's scope. Before the pattern rules: their arguments are text
    #     for the person, not an action (harnesstools.py).
    if harnesstools.display_allow(envelope) and not rules.check_grant_scope(envelope):
        return finish(Decision(
            decision="allow",
            reasons=[f"harness tool '{envelope.action.tool}': {harnesstools.tools_text(envelope.action.tool)}"],
            stage="hard_rules",
            reason_code=harnesstools.REASON_CODE,
            **base,
        ))

    # 1. Hard deny: grant-scope violations and denylisted commands. No model.
    hard = rules.check_hard_deny(envelope)
    if hard.outcome == "deny":
        return finish(Decision(
            decision="deny",
            reasons=[f"{hard.rule}: {hard.detail}"],
            stage="hard_rules",
            reason_code=hard.rule,
            **base,
        ))

    # 1b. Shell commands the action runs that are not its `command`
    #     argument (harnesstools.inner_commands): a skill's !`command` lines
    #     (Claude Code runs them when the skill loads) and the `command:`
    #     strings of OpenCode code-mode JavaScript (`execute`). Each one goes
    #     through the hard-deny patterns and the gates as a shell command;
    #     a skill load that runs commands is also the human gate
    #     skill_commands.
    skill = harnesstools.skill_check(envelope)
    skill_gates: List[Any] = []
    if skill.why:
        evidence_record["skill"] = {"files": list(skill.files), "commands": list(skill.commands)[:20],
                                    "allow": skill.allow, "why": skill.why}
    for where, line in harnesstools.inner_commands(envelope, skill):
        derived = harnesstools.command_envelope(envelope, line)
        hard_line = rules.check_hard_deny(derived)
        if hard_line.outcome == "deny":
            return finish(Decision(
                decision="deny",
                reasons=[f"{hard_line.rule}: in {where}: {hard_line.detail}"],
                stage="hard_rules",
                reason_code=hard_line.rule,
                **base,
            ))
        for h in rules.detect_gates(derived):
            if all(g.gate_class != h.gate_class for g in skill_gates):
                skill_gates.append(rules.GateHit(gate_class=h.gate_class, matched=f"in {where} {line!r}: {h.matched}"[:200]))
    if skill.commands:
        skill_gates.insert(0, rules.GateHit(gate_class=harnesstools.GATE_CLASS,
                                            matched=(skill.why + ": " + "; ".join(skill.commands))[:200]))

    # 2. Absolute human gates. The provider is never consulted for these and
    #    no predicate score can auto-allow them.
    path_dirs = linkplace.path_dirs_from(path_env, envelope.environment.project_root) if path_env else ()
    gate_hits = rules.detect_gates(envelope, path_dirs, pins=pins) + skill_gates
    pin_question = ""
    if pins is not None:
        if getattr(pins, "error", ""):
            evidence_record["instruction_pins"] = {"error": pins.error}
        for h in gate_hits:
            hit = getattr(h, "info", None)
            if h.gate_class == "untrusted_instruction" and hit is not None and getattr(hit, "file_lines", None) is not None:
                from . import pins as pins_mod
                try:
                    info = pins_mod.ask_info(hit.file_lines, list(hit.lines), pins.store)
                except Exception as exc:
                    evidence_record["instruction_pins"] = {"error": f"{type(exc).__name__}: {exc}"[:300]}
                    break
                evidence_record["instruction_lines"] = info
                pin_question = info["question"]
                break
    git_note = ""
    restore_status = ""
    command_text = str(envelope.action.arguments.get("command", ""))
    git_cwd = str(envelope.environment.cwd or envelope.environment.project_root or "")
    if (facts is not None and gate_hits and command_text
            and all(h.gate_class == "destructive_irreversible" for h in gate_hits)
            and rules.recoverable_destructive_only(envelope)):
        try:
            states = facts.assess(command_text, git_cwd)
        except Exception:
            states = []
        if states and all(s.recoverable for s in states):
            who = ("git or semgate's snapshot of an agent-created file" if any(s.state == "agent_created" for s in states)
                   else "git")
            git_note = f"{who} can restore every target (" + ", ".join(f"{s.path}: {s.state}" for s in states) + "); destructive gate relaxed, judged as an edit"
            gate_hits = []
    # F4: a local script the command runs. Its content goes through the same
    # gates as inline code. Added after the git relaxation above, so a gate
    # found in the file is never relaxed.
    script_ev = scriptsource.collect(envelope, workspace) if workspace is not None else None
    if script_ev is not None and script_ev.found:
        evidence_record["script_source"] = script_ev.record(sent=False)
        if script_ev.files:
            sd = rules.script_catastrophic_deny(script_ev.files, envelope.environment.project_root or "")
            if sd.outcome == "deny":
                return finish(Decision(
                    decision="deny",
                    reasons=[f"{sd.rule}: a script this command runs is catastrophic: {sd.detail}"],
                    stage="hard_rules", reason_code=sd.rule, **base,
                ))
            script_gates.extend(rules.script_gate_hits(script_ev.files, envelope.environment.project_root, path_dirs))
            gate_hits = list(gate_hits) + script_gates
        if script_ev.scrub_failed:
            return finish(Decision(
                decision="ask", reasons=["script source secret scrub failed; abstaining"],
                stage="human_gate", reason_code="script_source_scrub_failed", **base,
            ))
    # Test-run facts (testrun.py, policy router.test_run_facts): what a test
    # command runs. Each shell line from project configuration that it runs
    # (package.json scripts, Makefile recipes, tox commands) is checked as if
    # it were the command: a hard-deny pattern denies, the human gates ask.
    # Each code file it runs (conftest.py, build.rs, noxfile.py ...) goes
    # through the F4 file gates. This only adds denies and gates.
    test_ev = None
    if policy.kind == "router" and router.test_run_facts_enabled(policy):
        test_ev = testrun.collect(envelope, workspace, scripts=script_ev.files if script_ev is not None else (),
                                  build_facts=router.test_run_build_facts_enabled(policy), path_env=path_env)
        if test_ev.found:
            evidence_record["test_run"] = test_ev.record(sent=False)
        line_gates: List[Any] = []
        for line in test_ev.lines:
            derived = testrun.derived_envelope(envelope, line)
            hard_line = rules.check_hard_deny(derived)
            if hard_line.outcome == "deny":
                return finish(Decision(
                    decision="deny",
                    reasons=[f"{hard_line.rule}: in {line.where}, which this command runs: {hard_line.detail}"],
                    stage="hard_rules",
                    reason_code=hard_line.rule,
                    **base,
                ))
            for h in rules.detect_gates(derived, path_dirs):
                if all(g.gate_class != h.gate_class for g in line_gates):
                    line_gates.append(rules.GateHit(gate_class=h.gate_class, matched=f"in {line.where}: {h.matched}"[:200]))
        if test_ev.files:
            sd = rules.script_catastrophic_deny(test_ev.files, envelope.environment.project_root or "")
            if sd.outcome == "deny":
                return finish(Decision(
                    decision="deny",
                    reasons=[f"{sd.rule}: a file this command runs is catastrophic: {sd.detail}"],
                    stage="hard_rules", reason_code=sd.rule, **base,
                ))
            line_gates.extend(rules.script_gate_hits(test_ev.files, envelope.environment.project_root, path_dirs))
        # Build-time code (build.rs, the project's proc macros) that uses the
        # network: testrun.build_code_hits (router.test_run_build_facts).
        for gate_class, matched in test_ev.build_gates:
            line_gates.append(rules.GateHit(gate_class=gate_class, matched=matched[:200]))
        script_gates.extend(line_gates)
        gate_hits = list(gate_hits) + line_gates
        if test_ev.scrub_failed:
            return finish(Decision(
                decision="ask", reasons=["test run facts: secret scrub failed; abstaining"],
                stage="human_gate", reason_code="script_source_scrub_failed", **base,
            ))
    if gate_hits:
        return finish(Decision(
            decision="ask",
            reasons=([pin_question] if pin_question else []) + [f"human gate '{h.gate_class}' matched {h.matched!r}" for h in gate_hits],
            stage="human_gate",
            reason_code=f"human_gate:{gate_hits[0].gate_class}",
            gate_hits=[{"gate_class": h.gate_class, "matched": h.matched} for h in gate_hits],
            **base,
        ))

    # 3. Hard allow: small conservative read-only set, fully in scope.
    easy = rules.check_hard_allow(envelope, allow_tools=policy.hard_allow_tools or rules.DEFAULT_HARD_ALLOW_TOOLS)
    if easy.outcome == "allow":
        return finish(Decision(
            decision="allow",
            reasons=[f"{easy.rule}: {easy.detail}"],
            stage="hard_rules",
            reason_code="readonly_allow",
            **base,
        ))

    # 3a. Loading a skill whose load runs no command (harnesstools.skill_check).
    if skill.allow:
        return finish(Decision(
            decision="allow",
            reasons=[f"harness tool 'skill': {skill.why}"],
            stage="hard_rules",
            reason_code=harnesstools.REASON_CODE,
            **base,
        ))

    # 3b. Network call to an endpoint the operator declared for this task
    #     (grant.allowed_domains), referencing no secret. Operator scope, like
    #     allowed_path_prefixes for files: a POST to your own/staging/third-party
    #     API you named is in scope; exfil to an undeclared host is not.
    if rules.network_in_scope(envelope):
        return finish(Decision(
            decision="allow",
            reasons=["network call to an endpoint declared in the grant's allowed_domains"],
            stage="hard_rules",
            reason_code="network_in_scope_allow",
            **base,
        ))

    # 4. Semantic layer. Only reachable when rules and gates did not decide.
    if provider is None:
        return finish(Decision(
            decision="ask",
            reasons=["no semantic provider configured; abstaining"],
            stage="semantic",
            reason_code="no_provider_abstain",
            **base,
        ))

    questions: Dict[str, Dict[str, Any]] = {}
    missing: Dict[str, List[str]] = {}
    fired_ids: Tuple[str, ...] = ()        # code signals that fired (router.decide reads S4)
    if policy.kind == "router":
        # One call, three typed questions, small state. See router.py.
        if facts is not None and command_text:
            try:
                pre_states = facts.assess(command_text, git_cwd)
            except Exception:
                pre_states = []
            if pre_states and all(x.recoverable for x in pre_states):
                restore_status = restore_status_text(pre_states)
        # G2: code-checked signals (codesignals.py). Facts for the model to
        # weigh; they never decide. A failure here sends no signal (the state
        # is then what it is with the switch off) and is recorded.
        signal_text = ""
        if router.code_signals_enabled(policy):
            try:
                on = router.enabled_code_signals(policy)
                # S6 reads links made by script files F4 read; not when the file
                # carries text addressed to an AI (its strings stay out of the state).
                scripts = script_ev.files if (script_ev is not None and not script_ev.injection) else ()
                signals = codesignals.compute(envelope, history=git_history, enabled=on, facts=facts, workspace=workspace,
                                              scripts=scripts)
                signals = (signals + payloadsize.signals(evidence_record.get("payload"), on))[:codesignals.MAX_SIGNALS]
            except Exception as exc:
                signals = []
                evidence_record["code_signals"] = {"fired": [], "error": f"{type(exc).__name__}: {exc}"}
            if signals:
                evidence_record["code_signals"] = {"fired": [x.record() for x in signals], "sent": False}
                signal_text = codesignals.render(signals)
                fired_ids = tuple(x.id for x in signals)
        # F4 script content, then the test-run facts (both code-checked).
        sources = [x.source_text for x in (script_ev, test_ev) if x is not None and x.source_text]
        contexts = [x.context_text for x in (script_ev, test_ev) if x is not None and x.context_text]
        state = router.build_state(envelope, policy, restore_status=restore_status,
                                   script_source="\n\n".join(sources),
                                   extra_untrusted="\n".join(contexts),
                                   code_signals=signal_text, pins=pins)
        if state.get("project_instructions"):
            evidence_record["project_instructions"] = {"lines": state["project_instructions"].count("\n"), "sent": False}
        missing = router.missing_evidence(state)
        if missing:
            return finish(Decision(
                decision="ask",
                reasons=[f"router abstains: missing evidence {', '.join(missing['router'])}"],
                stage="semantic",
                missing_evidence=missing,
                **base,
            ))
        questions = router.questions(policy)
        if not envelope.trajectory.recent:
            # Drift is a property of the trajectory. With no recent actions there
            # is nothing to drift from, so don't ask on_task and never drift-deny a
            # lone command (this keeps single-command evaluation unaffected).
            questions.pop("on_task", None)
        if not state.get("untrusted_context"):
            # Nothing the agent read overlaps this command, so there is no
            # untrusted instruction it could be following. Don't ask.
            questions.pop("instructed_by_context", None)
        if not envelope.user_message.strip():
            # F7: "does the task need this change" needs a stated task.
            questions.pop("unneeded_change", None)
        if router.turn_attribution_enabled(policy):
            # Shadow: which user turn this command serves. Recorded, never decides.
            turn_q = router.serves_turn_question(envelope)
            if turn_q is not None:
                questions[router.SERVES_TURN] = turn_q
    else:
        state = envelope.provider_state()
        for predicate in policy.predicates:
            gaps = evidence.missing_evidence(predicate, state)
            if gaps:
                missing[predicate.predicate_id] = gaps
            else:
                questions[predicate.predicate_id] = predicate.to_question()

    answers: Dict[str, Any] = {}
    if questions and state.get("script_source") and "script_source" in evidence_record:
        evidence_record["script_source"]["sent"] = bool(script_ev is not None and script_ev.source_text)
    if questions and "test_run" in evidence_record and test_ev is not None and test_ev.source_text:
        evidence_record["test_run"]["sent"] = True
    if questions and state.get("code_signals") and "code_signals" in evidence_record:
        evidence_record["code_signals"]["sent"] = True
    if questions and state.get("project_instructions") and "project_instructions" in evidence_record:
        evidence_record["project_instructions"]["sent"] = True
    if questions:
        try:
            if policy.kind == "router":
                # Re-ask each repeat with a fresh uid so the draws are independent.
                def refetch(i: int) -> Dict[str, Any]:
                    ask_state = state if i == 0 else {**state, "uid": f"{digest}#{i}"}
                    return ask_provider(ask_state, questions)
                outcome = router.decide_consistent(policy, refetch, fired_ids)
            else:
                answers = ask_provider(state, questions)
                outcome = combine(policy, answers, missing)
        except ProviderError as exc:
            for key in ("script_source", "test_run"):
                if evidence_record.get(key, {}).get("sent"):
                    evidence_record[key]["provider_failed"] = True
            # Demo mode (providers/recorded.py): no recorded answer for this
            # exact input. Same abstention, stated plainly.
            demo_miss = type(exc).__name__ == "NoRecordedAnswer"
            return finish(Decision(
                decision="ask",
                reasons=[str(exc) if demo_miss else f"provider failure; abstaining: {exc}"],
                reason_code="demo_not_recorded" if demo_miss else "",
                stage="semantic",
                missing_evidence=missing,
                error=str(exc),
                **base,
            ))
        except Exception as exc:  # never let a provider bug become an allow
            for key in ("script_source", "test_run"):
                if evidence_record.get(key, {}).get("sent"):
                    evidence_record[key]["provider_failed"] = True
            return finish(Decision(
                decision="ask",
                reasons=[f"unexpected provider error; abstaining: {exc}"],
                stage="semantic",
                missing_evidence=missing,
                error=str(exc),
                **base,
            ))
    else:
        outcome = router.decide(policy, answers, fired_ids) if policy.kind == "router" else combine(policy, answers, missing)
    decision_value, reason_code, reasons = outcome["decision"], outcome.get("reason_code", ""), list(outcome["reasons"])
    if git_note:
        reasons.append(git_note)
    # Restorable change the user asked for: code verified git can undo every
    # target (restore_status), the user asked for this action, the model does not
    # say block, and the effect stays under the always-review level. The model
    # still judges intent; only "can it be undone" is decided by code.
    if (restore_status and decision_value == "ask" and policy.kind == "router"
            and policy.router.get("thresholds", {}).get("restorable_user_asked_allow") is True):
        votes = {v.get("predicate"): v for v in outcome.get("votes", [])}
        t = router.thresholds(policy)
        route_v, eff_v, asked_v = votes.get("route", {}), votes.get("effect", {}), votes.get("user_asked", {})
        if (route_v.get("value") != "block" and eff_v.get("value") is not None and float(eff_v["value"]) < float(t["always_review_effect_min"])
                and asked_v.get("p") is not None and float(asked_v["p"]) >= float(t["user_asked_min"])
                and votes.get("on_task", {}).get("vote") != "drift" and votes.get("instructed_by_context", {}).get("vote") != "injected"
                and votes.get("unneeded_change", {}).get("vote") != "unneeded"):
            decision_value, reason_code = "allow", "restorable_user_asked_allow"
            reasons.insert(0, "the user asked for this change and git can restore every file it touches (verified by code)")
    votes_out = list(outcome.get("votes", []))
    # Session drift: each step alone may look on task while the session as a
    # whole moves away from the user's request. Only turns an allow into an
    # ask; never creates an allow or a deny.
    t_all = router.thresholds(policy) if policy.kind == "router" else {}
    if t_all.get("drift_session_ask_max") is not None and questions:
        earlier = prior_on_task
        window_gap = ""
        if earlier is None and ledger is not None:
            try:
                earlier = ledger.session_on_task(envelope, exclude=digest)
            except IncompleteWindow as exc:
                earlier, window_gap = [], str(exc)
            except Exception as exc:
                earlier, window_gap = [], f"{type(exc).__name__}: {exc}"
        if window_gap and decision_value == "allow":
            # The earlier steps of this session could not all be read, so the
            # drift check cannot be done. Fail closed (formal/REPORT.md U3).
            votes_out.append({"predicate": "session_drift", "vote": "unknown", "source": "ledger", "error": window_gap[:300]})
            reasons.insert(0, f"session drift could not be checked (earlier steps not fully readable: {window_gap[:200]}); confirm this step")
            reasons.insert(1, f"would have been {reason_code or 'allow'}")
            decision_value, reason_code = "ask", "session_drift_unreadable"
        current = next((v.get("p") for v in votes_out if v.get("predicate") == "on_task" and v.get("p") is not None), None)
        values = [float(x) for x in (earlier or [])] + ([float(current)] if current is not None else [])
        window = int(t_all.get("drift_session_window") or 5)
        mean = router.session_drift_mean(values, window)
        if mean is not None:
            limit = float(t_all["drift_session_ask_max"])
            drifted = mean <= limit
            votes_out.append({"predicate": "session_drift", "vote": "drift" if drifted else "clear", "mean": round(mean, 4),
                              "n": min(len(values), window), "source": "case" if prior_on_task is not None else "ledger"})
            if drifted and decision_value == "allow":
                reasons.insert(0, f"the recent steps of this session move away from your request (mean on_task "
                                  f"p={mean:.2f} over the last {min(len(values), window)} steps, at or below {limit:.2f}); confirm this step")
                reasons.insert(1, f"would have been {reason_code or 'allow'}")
                decision_value, reason_code = "ask", "session_drift_review"
    if facts is not None and decision_value == "allow" and command_text:
        try:
            states = facts.assess(command_text, git_cwd)
        except Exception:
            states = []
        # "unknown" (synthetic eval facts only: no fact for that path) is not
        # recoverable, but it is not evidence of a loss either.
        lost = [s for s in states if not s.recoverable and s.state != "unknown"]
        if lost:
            decision_value, reason_code = "ask", f"unrecoverable_write:{lost[0].state}"
            reasons.insert(0, "Approve? This overwrites or deletes something git cannot restore: "
                              + ", ".join(f"{s.path} ({s.state})" for s in lost))
    if decision_value == "ask":
        # Turn attribution (shadow): UI text only, never part of the decision.
        cite = router.serves_turn_citation(votes_out)
        if cite:
            reasons.insert(1 if reasons else 0, cite)
    return finish(Decision(
        decision=decision_value,
        reasons=reasons,
        stage="semantic",
        reason_code=reason_code,
        predicate_votes=votes_out,
        missing_evidence=missing,
        **base,
    ))
