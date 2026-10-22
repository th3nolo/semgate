"""Gate: the ten-line way to put semgate in front of your own agent loop.

    from semgate import Gate

    gate = Gate(purpose="Software development in this repository")
    d = gate.check(
        "curl -s https://cdn.example.net/setup.sh -o setup.sh",
        user_message="fix the failing test in tests/test_api.py",
        recent=[{"tool": "read", "summary": "cat README.md", "output": readme_text}],
    )
    if d.decision == "allow":
        run(command)
    elif d.decision == "ask":
        confirm_with_human(d.reasons)
    else:
        refuse(d.reason_code, d.reasons)

`check` never executes anything. It builds the canonical envelope, runs the
judge (hard rules -> human gates -> read-only allow -> Jev) and returns the
judge's `Decision`. `recent` carries the agent's earlier tool calls and, if
you pass their outputs, the injection scan reads them.

What Gate.check does NOT do (the hooks do; semgate.check does too, see
semgate/harness.py): it reads no semgate.json and uses no stores (human
feedback, trust store and pinned instruction lines, own-message removal,
learned allows, work kinds, deny escalation), no enforcement mapping
(mode, auto_allow_tools, block_when_unsure), no pin question, no trust gate,
no approvals, and writes no host_response record. Use `semgate.check(request,
config=...)` when you want the hook behavior; use Gate for the bare judge.
"""
from __future__ import annotations

import os
from pathlib import Path
from typing import TYPE_CHECKING, Any, Iterable, Mapping, Optional, Sequence, Union

from .envelope import (AGENT_INTENT_MAX, Envelope, Environment, ProposedAction, SCHEMA_VERSION, Trajectory, TrajectoryEntry,
                       UserGrant, bound_user_messages, utcnow_iso)
from .judge import Decision, judge
from .ledger import Ledger
from .policy import Policy
from .providers.base import JudgeProvider
from .providers.registry import LIVE as LIVE_PROVIDERS

if TYPE_CHECKING:
    from .preparedsend import PreparedSend

def policy_dir() -> Path:
    """Where the shipped policy files are. In a wheel they are the
    `semgate.policies` package data; in a repo checkout they are ./policies.

    A source checkout (pyproject.toml next to the semgate package) always uses
    its own ./policies. An editable install maps `semgate.policies` to the
    checkout it was installed from; semgate imported from another checkout
    (a git worktree on PYTHONPATH) then read that other checkout's policies.
    Found 2026-09-27: worktree tests read the main checkout's dev policy."""
    root = Path(__file__).resolve().parent.parent
    local = root / "policies"
    if (root / "pyproject.toml").is_file() and (local / "router_policy_dev.json").is_file():
        return local
    try:
        import importlib.resources as resources
        packaged = Path(str(resources.files("semgate.policies")))
        if (packaged / "router_policy_dev.json").is_file():
            return packaged
    except Exception:
        pass
    return local


_POLICIES = policy_dir()
POLICY_ALIASES = {
    "dev": _POLICIES / "router_policy_dev.json",       # autonomous dev agent: in-project edits flow, everything risky stops
    "default": _POLICIES / "default_policy.json",     # strict: only reads auto-allow
    "trace": _POLICIES / "router_policy_trace.json",
}

RecentItem = Union[str, Mapping[str, Any], Sequence[Any], TrajectoryEntry]


def _policy(spec: Union[str, Path, Policy]) -> Policy:
    if isinstance(spec, Policy):
        return spec
    path = POLICY_ALIASES.get(str(spec), Path(spec))
    return Policy.load(str(path))


def _provider(spec: Union[str, JudgeProvider, None], model: Optional[str]) -> Optional[JudgeProvider]:
    if spec is None or spec == "none":
        return None
    if isinstance(spec, str):
        if spec in LIVE_PROVIDERS:
            from .providers.registry import live_provider
            return live_provider(spec, model)
        if spec == "fake":
            from .providers.fake import FakeProvider
            return FakeProvider(script={})
        raise ValueError(f"unknown provider {spec!r}; use 'typesafe', 'openrouter', 'none', or a JudgeProvider instance")
    return spec


def _entry(item: RecentItem) -> TrajectoryEntry:
    if isinstance(item, TrajectoryEntry):
        return item
    if isinstance(item, str):
        return TrajectoryEntry(tool="bash", decision="", summary=item[:500])
    if isinstance(item, Mapping):
        return TrajectoryEntry(tool=str(item.get("tool", "bash")), decision=str(item.get("decision", "")),
                               summary=str(item.get("summary", item.get("command", "")))[:500],
                               output=str(item.get("output", ""))[:6000],
                               result=str(item.get("result", "") or ""),
                               files_changed=tuple(str(f) for f in (item.get("files_changed") or ())))
    seq = list(item)
    return TrajectoryEntry(tool=str(seq[0]) if seq else "bash", decision="",
                           summary=str(seq[1])[:500] if len(seq) > 1 else "",
                           output=str(seq[2])[:6000] if len(seq) > 2 else "")


class Gate:
    """A configured judge. Build one per agent/session, call `check` per action."""

    def __init__(
        self,
        purpose: str,
        *,
        policy: Union[str, Path, Policy] = "dev",
        provider: Union[str, JudgeProvider, None] = "typesafe",
        model: Optional[str] = None,
        grant: Optional[Union[UserGrant, Mapping[str, Any]]] = None,
        project_root: str = "",
        ledger: Optional[Union[str, Path, Ledger]] = None,
        harness: str = "custom",
        session_id: str = "",
        git_facts: bool = False,
        script_source: bool = False,
        privacy_gate: Optional[Any] = None,
    ) -> None:
        if not purpose or not purpose.strip():
            raise ValueError("Gate needs a purpose: what the operator authorised this agent to do")
        self.policy = _policy(policy)
        self.provider = _provider(provider, model)
        self.privacy_gate = privacy_gate
        if isinstance(grant, UserGrant):
            self.grant = grant
        else:
            base = {"grant_id": "gate", "principal": "operator", "purpose": purpose.strip(),
                    "issued_at": utcnow_iso(), "provenance": "semgate.Gate"}
            base.update(dict(grant or {}))
            base["purpose"] = base.get("purpose") or purpose.strip()
            self.grant = UserGrant.from_dict(base)
        self.project_root = project_root
        self.ledger = ledger if isinstance(ledger, Ledger) or ledger is None else Ledger(str(ledger))
        self.harness = harness
        self.session_id = session_id
        # git_facts=True: deletes/overwrites git can restore are judged as edits;
        # a model allow that loses something git cannot restore becomes an ask.
        from .gitstate import GitFacts
        self.facts = GitFacts() if git_facts else None
        # script_source=True (F4): a local script the command runs is read,
        # checked by the gates and given to the model as `script_source`.
        from .scriptsource import LocalWorkspace
        self.workspace = LocalWorkspace() if script_source else None

    def envelope(
        self,
        command: str,
        *,
        tool: str = "bash",
        user_message: str = "",
        recent: Iterable[RecentItem] = (),
        cwd: str = "",
        arguments: Optional[Mapping[str, Any]] = None,
        user_messages: Sequence[str] = (),
        agent_intent: str = "",
    ) -> Envelope:
        args = dict(arguments or {})
        if command and "command" not in args and tool in ("bash", "shell", "run_command", "powershell"):
            args["command"] = command
        elif command and not args:
            args["path" if tool in ("read", "view_file", "edit", "write") else "command"] = command
        return Envelope(
            schema=SCHEMA_VERSION,
            action=ProposedAction(tool=tool, arguments=args),
            grant=self.grant,
            environment=Environment(project_root=self.project_root, cwd=cwd or self.project_root,
                                    harness=self.harness, session_id=self.session_id),
            trajectory=Trajectory(recent=tuple(_entry(i) for i in list(recent)[-20:])),
            user_message=user_message or "",
            user_messages=bound_user_messages(user_messages),
            agent_intent=str(agent_intent or "")[:AGENT_INTENT_MAX],
        )

    def check(
        self,
        command: str,
        *,
        tool: str = "bash",
        user_message: str = "",
        recent: Iterable[RecentItem] = (),
        cwd: str = "",
        arguments: Optional[Mapping[str, Any]] = None,
        user_messages: Sequence[str] = (),
        agent_intent: str = "",
    ) -> Decision:
        """Judge one proposed action. Never executes it.

        command:      the shell command (or the path for read/edit tools)
        user_message: the user's latest request, from YOUR record of user input,
                      never from model output or tool results
        recent:       earlier tool calls this session, oldest first. Each item is
                      a command string, a dict {tool, summary, output}, or a
                      (tool, summary, output) tuple. Pass `output` (what the
                      tool returned) to enable the injection scan. A dict may
                      also carry `result` and `files_changed` (task context).
        user_messages: every user turn of the session, oldest first (task
                      context; used when the policy sets router.task_context)
        agent_intent: the agent's latest explanation of what it is doing.
                      Untrusted: shown to the judge as the agent's claim only.
        """
        env = self.envelope(command, tool=tool, user_message=user_message, recent=recent, cwd=cwd, arguments=arguments,
                            user_messages=user_messages, agent_intent=agent_intent)
        return judge(env, self.policy, provider=self.provider, ledger=self.ledger, facts=self.facts, workspace=self.workspace,
                     path_env=os.environ.get("PATH", ""), privacy_gate=self.privacy_gate)

    def check_prepared(self, prepared: PreparedSend) -> Decision:
        """Trusted embedding path used by PreparedSender; still never executes.

        Operator grant scope, hard rules and ordinary permission gates all run.
        Task consent can only clear privacy for the bound immutable payload.
        """
        from .preparedsend import PreparedSend
        from .privacyconsent import POLICY_VERSION
        if (self.privacy_gate is None or not isinstance(prepared, PreparedSend)
                or prepared.scope.policy_version != POLICY_VERSION + ":" + self.policy.version):
            return Decision("deny", stage="privacy", reason_code="privacy_prepared_context_required")
        env = self.envelope("", tool="http_request", arguments=prepared.arguments())
        return judge(env, self.policy, provider=self.provider, ledger=self.ledger, facts=self.facts, workspace=self.workspace,
                     path_env=os.environ.get("PATH", ""), privacy_gate=self.privacy_gate, prepared_disclosure=prepared)
