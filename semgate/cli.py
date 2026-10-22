"""semgate CLI: judge one envelope, replay a fixture set, inspect the ledger."""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from .adapters import opencode as opencode_adapter
from .envelope import Envelope
from .judge import judge
from .ledger import Ledger
from .policy import Policy
from .providers.fake import FakeProvider
from .providers.registry import LIVE as LIVE_PROVIDERS
from .replay import replay
from .eval.runner import evaluate_cases, load_cases

from .gate import policy_dir

DEFAULT_POLICY = str(policy_dir() / "default_policy.json")
MODEL_HELP = ("model id for the live provider (default: jev-latest for typesafe, typesafe/jev-1.13 for openrouter; "
              "results compare only for the same model snapshot)")


def _load_policy(args) -> Policy:
    return Policy.load(args.policy)


def _cmd_judge(args) -> int:
    policy = _load_policy(args)
    raw = json.loads(sys.stdin.read() if args.stdin else Path(args.envelope).read_text(encoding="utf-8"))

    if args.adapter == "opencode":
        grant = opencode_adapter.grant_from_config(raw.get("grant") or {})
        envelope = opencode_adapter.envelope_from_permission_event(
            raw.get("event") or {},
            grant=grant,
            directory=raw.get("cwd") or "",
        )
    else:
        # accept both a bare envelope and a replay trace fixture that wraps one
        envelope = Envelope.from_dict(raw.get("envelope") if isinstance(raw.get("envelope"), dict) else raw)

    if args.evaluated_at:
        object.__setattr__(envelope, "evaluated_at", args.evaluated_at)

    provider = None
    if args.provider == "fake":
        provider = FakeProvider(script=json.loads(args.fake_answers) if args.fake_answers else None, fail=args.provider_fail)
    elif args.provider in LIVE_PROVIDERS:
        from .providers.registry import live_provider
        provider = live_provider(args.provider, args.model)

    ledger = Ledger(args.ledger) if args.ledger else None
    decision = judge(envelope, policy, provider=provider, ledger=ledger)
    json.dump(decision.to_dict(), sys.stdout, indent=2, sort_keys=True)
    sys.stdout.write("\n")
    return 0


def _cmd_replay(args) -> int:
    policy = _load_policy(args)
    trace_dir = Path(args.traces)
    trace_paths = sorted(str(p) for p in trace_dir.glob("*.json"))
    ledger = Ledger(args.ledger) if args.ledger else None
    report = replay(trace_paths, policy, ledger=ledger)
    json.dump(report, sys.stdout, indent=2, sort_keys=True)
    sys.stdout.write("\n")
    return 0



def _cmd_eval(args) -> int:
    policy = _load_policy(args)
    from .eval import chat_approval, exposure_intent, trust_pin
    exposure = exposure_intent.is_exposure_cases(args.cases)
    chat = not exposure and chat_approval.is_chat_approval_cases(args.cases)
    trustpin = not exposure and not chat and trust_pin.is_trust_pin_cases(args.cases)
    cases = (exposure_intent.load_cases(args.cases) if exposure else
             chat_approval.load_cases(args.cases) if chat else
             trust_pin.load_cases(args.cases) if trustpin else load_cases(args.cases))
    provider = counter = None
    if args.provider in LIVE_PROVIDERS:
        from .eval.runner import JudgeCallCounter
        from .providers.registry import live_provider
        provider = counter = JudgeCallCounter(live_provider(args.provider, args.model))
    if chat:
        # Approval by chat reply (semgate-chat-approval-case/1): code checks
        # and the question user_approved_blocked_action, not a PreToolUse decision.
        report = chat_approval.evaluate(cases, policy, provider=provider, scripted=args.provider == "scripted")
    elif trustpin:
        # The agent's `semgate trust` requests and semgate's question about
        # instruction-file lines (semgate-trust-pin-case/1).
        report = trust_pin.evaluate(cases, policy, provider=provider, scripted=args.provider == "scripted")
    elif exposure:
        # Secret exposure intent cases (semgate-exposure-case/1): the post-tool
        # question user_shared_secret, not a PreToolUse decision.
        report = exposure_intent.evaluate(cases, policy, provider=provider, scripted=args.provider == "scripted")
    else:
        report = evaluate_cases(cases, policy, provider=provider, scripted=args.provider == "scripted")
    from .eval.runner import validity_problems
    judge_calls = counter.counts() if counter is not None else None
    if judge_calls is not None:
        report["judge_calls"] = judge_calls
    problems = validity_problems(report, judge_calls)
    if problems:
        report["invalid_run"] = problems
    output = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if args.output:
        Path(args.output).write_text(output, encoding="utf-8")
    else:
        sys.stdout.write(output)
    if problems:
        # Exit 3: the run does not measure the model (e.g. a provider outage
        # made every semantic case an ask). --allow-provider-errors keeps the
        # other exit codes for a run where that is expected.
        for why in problems:
            print(f"INVALID RUN: {why}.", file=sys.stderr)
        if not args.allow_provider_errors:
            print("semgate eval: exit 3 (this run does not measure the model; "
                  "--allow-provider-errors accepts it)", file=sys.stderr)
            return 3
        print("semgate eval: --allow-provider-errors given; continuing with the normal exit code", file=sys.stderr)
    if exposure:
        return 2 if (report["secrets_missing"] or report["state_leaks"]) else 0
    if chat:
        return 2 if (report["code_path_failures"] or report["judge_not_asked"] or report["state_leaks"]) else 0
    if trustpin:
        return 2 if (report["code_path_failures"] or report["judge_not_asked"] or report["state_leaks"]
                     or report["metrics"]["lines_wrong"]) else 0
    return 2 if report["boundary_violations"] else 0

def _cmd_ledger(args) -> int:
    ledger = Ledger(args.ledger)
    if args.ledger_command == "override":
        ledger.record_override(args.judgment_id, args.reviewer, args.verdict, args.note or "")
    elif args.ledger_command == "outcome":
        ledger.record_outcome(args.judgment_id, args.outcome, args.detail or "")
    elif args.ledger_command == "list":
        for record in ledger.records():
            json.dump(record, sys.stdout, sort_keys=True)
            sys.stdout.write("\n")
    return 0


FEEDBACK_HOW = ("  Pass the semgate.json your hook uses:  semgate feedback {d} \"<command>\" --config <path to semgate.json>\n"
                "  or the store itself:                  semgate feedback {d} \"<command>\" --store <path to feedback.jsonl> "
                "[--ledger <path to ledger.jsonl>]\n"
                "  `semgate doctor` lists the installed hooks and the config each one uses.")
LEGACY_FEEDBACK_DIR = os.path.join(".antigravity", "semgate")


class _FbSource:
    """One place `semgate feedback` can write: a config (its ledger and
    feedback store), or a store given with --store."""

    def __init__(self, label: str, config: dict, store: str, ledger: str):
        self.label, self.config, self.store, self.ledger = label, config, store, ledger


def _source_of(config: dict, label: str, ledger_override: str = "") -> "_FbSource":
    from . import storepaths
    from .antigravity_hook import feedback_path
    store = feedback_path(config)                     # "" when the config's feedback is off
    ledger = ledger_override or storepaths.ledger_file(config)
    return _FbSource(label, config, os.path.abspath(store) if store else "", os.path.abspath(os.path.expanduser(ledger)))


def _project_plugin_configs(project_dir: str) -> list:
    """(host display name, plugin copy, config path) of semgate plugin copies
    inside the project: <folder>/.opencode/plugin(s)/semgate.js and
    <folder>/.pi/extensions/semgate.ts, for the folder and its git top folder.
    The installed hooks list (hosts.installed) has only user-level copies."""
    from .hosts import ADAPTERS
    from .trust import project_of
    from . import codestamp
    dirs = []
    for d in (project_dir, project_of(project_dir)):
        if d and os.path.normcase(os.path.abspath(d)) not in [os.path.normcase(os.path.abspath(x)) for x in dirs]:
            dirs.append(d)
    rels = {"opencode": (os.path.join(".opencode", "plugins", "semgate.js"), os.path.join(".opencode", "plugin", "semgate.js")),
            "pi": (os.path.join(".pi", "extensions", "semgate.ts"),)}
    out = []
    for host, names in rels.items():
        adapter = ADAPTERS.get(host)
        if adapter is None:
            continue
        for d in dirs:
            for rel in names:
                copy = Path(d) / rel
                try:
                    text = copy.read_text(encoding="utf-8", errors="replace") if copy.is_file() else ""
                except OSError:
                    continue
                if not text or not codestamp.is_semgate_copy(text):
                    continue
                cfg = adapter.wiring(text)[1]
                if cfg:
                    out.append((adapter.display, str(copy), cfg))
    return out


def _feedback_sources(args, project_dir: str) -> list:
    """Where this `semgate feedback` may write: --config, --store, else every
    installed hook's config, every semgate plugin copy in the project, and,
    only when none of these exists, the old agy folder .antigravity/semgate
    in the current folder (when it exists). [] when there is nothing."""
    from . import storepaths
    if args.config:
        path = os.path.abspath(os.path.expanduser(args.config))
        config = storepaths.load(args.config, storepaths.guess_host(args.config))
        return [_source_of(config, f"config {path} (given with --config)", args.ledger)]
    if args.store:
        store = os.path.abspath(os.path.expanduser(args.store))
        ledger = os.path.abspath(os.path.expanduser(args.ledger)) if args.ledger else str(Path(store).with_name("ledger.jsonl"))
        return [_FbSource(f"store {store} (given with --store)", {}, store, ledger)]
    from .hosts.base import HostEnv
    from .hosts.installed import installed_configs
    out, seen = [], set()
    for c in installed_configs(HostEnv.current(run_binaries=False)):
        seen.add(os.path.normcase(os.path.realpath(c.path)))
        out.append(_source_of(c.config, f"config {c.path} (from the installed {c.hosts_text()} "
                                        f"hook{'s' if len(c.hosts) > 1 else ''})", args.ledger))
    for display, copy, cfg in _project_plugin_configs(project_dir):
        path = os.path.expanduser(cfg)
        key = os.path.normcase(os.path.realpath(path))
        if key in seen or not os.path.isabs(path) or not os.path.isfile(path):
            continue
        seen.add(key)
        try:
            config = storepaths.load(path, "opencode" if display == "OpenCode" else "pi")
        except (OSError, ValueError, UnicodeDecodeError):
            continue
        out.append(_source_of(config, f"config {os.path.abspath(path)} (from the {display} plugin copy {copy})", args.ledger))
    if not out and os.path.isdir(LEGACY_FEEDBACK_DIR):
        folder = os.path.abspath(LEGACY_FEEDBACK_DIR)
        store = os.path.join(folder, "feedback.jsonl")
        ledger = os.path.abspath(os.path.expanduser(args.ledger)) if args.ledger else os.path.join(folder, "ledger.jsonl")
        out.append(_FbSource(f"the old agy store in this folder {folder} (no installed hook was found)", {}, store, ledger))
    return out


def _ts_key(ts: str) -> float:
    from .feedback import _epoch
    return _epoch(ts) or 0.0


def _feedback_deny(args, sources: list, hits: list, how: str) -> int:
    """`semgate feedback deny`: into the store of the config whose ledger has
    the newest step with this command; with no such step, the only config;
    with several and none, exit 2 (a deny must not go to a store that the
    hook of this project does not read)."""
    from .feedback import FeedbackStore, norm_root, ttl_hours_from
    if hits:
        src, why = hits[0][1], f"its ledger has the newest step with this command ({hits[0][0]['ts']})"
    elif len(sources) == 1:
        src, why = sources[0], "it is the only config found; its ledger has no step with this command yet"
    else:
        print("not recorded: several configs are installed and no ledger shows this command; choose one with --config:",
              file=sys.stderr)
        for s in sources:
            print(f"  {s.label}", file=sys.stderr)
        print(how, file=sys.stderr)
        return 2
    _print_source(src)
    print(f"  chosen because {why}")
    if not src.store:
        print("not recorded: feedback is off in this config (feedback.enabled is not true), so no hook reads a deny.",
              file=sys.stderr)
        return 2
    ttl = args.ttl_hours
    fb = FeedbackStore(src.store, max_ttl_hours=max(ttl or 0, ttl_hours_from(src.config)))
    project = norm_root(args.project) if args.project else ""
    rec = fb.record("deny", args.tool or "bash", {"command": args.command}, reviewer="operator", note=args.note,
                    session_id=args.session or "", project_root=project, ttl_hours=ttl)
    scope = [f"session {args.session}" if args.session else "every session",
             f"project {project}" if project else "every project"]
    print(f"recorded: deny {rec['tool']} `{args.command}` for {', '.join(scope)}"
          + (f", until {rec['expires_at']}" if rec.get("expires_at") else ", no expiry") + ".")
    return 0


def _print_source(src: "_FbSource", stream=None) -> None:
    stream = stream or sys.stdout
    print(f"using {src.label}", file=stream)
    print(f"  feedback store  {src.store or '(feedback is off in this config: no hook reads approvals)'}", file=stream)
    print(f"  ledger          {src.ledger}", file=stream)


def _cmd_feedback(args) -> int:
    """Record a human decision. An `allow` is bound to one session and one
    project and expires (see feedback.py); it is refused (exit 2) when no
    ledger shows an asked/blocked step with this exact command. The approval
    goes into the feedback store that belongs to the ledger where the block
    was found, so the hook that blocked it reads it. There is no fallback to
    a store under the current folder that no hook reads (the old
    .antigravity/semgate/feedback.jsonl), except where that folder exists
    and no installed hook is found; the output always names the store."""
    from .feedback import FeedbackStore, blocked_candidates, norm_root, ttl_hours_from
    from .filelock import LockTimeout
    for var in ("SEMGATE_FEEDBACK_FILE", "SEMGATE_LEDGER_FILE"):
        if os.environ.get(var, "").strip():
            print(f"ignored: {var} is no longer read; use {'--store' if 'FEEDBACK' in var else '--ledger'}", file=sys.stderr)
    if not args.show_config and (not args.decision or args.command is None):
        print("semgate feedback: decision (allow|deny) and command are required (or use --show-config)", file=sys.stderr)
        return 2
    project_dir = args.project or os.getcwd()
    sources = _feedback_sources(args, project_dir)
    how = FEEDBACK_HOW.format(d=args.decision or "allow")
    if not sources:
        print("not recorded: no installed semgate hook was found, and no --config or --store was given.\n" + how,
              file=sys.stderr)
        return 2
    if args.show_config:
        if len(sources) > 1:
            print(f"{len(sources)} configs; an approval goes to the one whose ledger shows the block:")
        for src in sources:
            _print_source(src)
        print("Nothing was written (--show-config).")
        return 0
    if not args.decision or args.command is None:
        print("semgate feedback: decision (allow|deny) and command are required (or use --show-config)", file=sys.stderr)
        return 2
    tool = args.tool or ""
    try:
        # Every ledger: the newest step with exactly this command in this
        # project decides the config (6.3 of docs/project-profiles-design.md).
        hits = []
        for src in sources:
            for c in blocked_candidates(src.ledger, args.command, project_dir=project_dir, tool=tool,
                                        session_id=args.session or "", any_decision=args.decision == "deny"):
                hits.append((c, src))
        hits.sort(key=lambda h: _ts_key(h[0]["ts"]), reverse=True)
        if args.decision == "deny":
            return _feedback_deny(args, sources, hits, how)
        found = [c for c, s in hits if s is hits[0][1]] if hits else []
        if not hits:
            where = f"session {args.session}" if args.session else f"project {norm_root(project_dir)}"
            print(f"not recorded: no asked or blocked step with exactly this command in {where}. Ledgers searched:",
                  file=sys.stderr)
            for src in sources:
                print(f"  {src.ledger}  ({src.label})", file=sys.stderr)
            print("  The command must match the blocked one character for character. Run this from the project directory,\n"
                  "  or pass --project <dir>, --session <id>, --config <path> or --ledger <path>.", file=sys.stderr)
            return 2
        pick, src = hits[0]
        _print_source(src)
        if not src.store:
            print(f"not recorded: feedback is off in this config (feedback.enabled is not true), so no hook reads an "
                  f"approval.", file=sys.stderr)
            return 2
        if pick["stage"] == "hard_rules" and pick["decision"] == "deny":
            print(f"not recorded: `{args.command}` is hard-denied (a fixed rule); an approval cannot override it.", file=sys.stderr)
            return 2
        if pick["stage"] == "privacy":
            print("not recorded: this step needs separate privacy inspection or consent; ordinary feedback cannot grant it.",
                  file=sys.stderr)
            return 2
        config = src.config
        ttl = args.ttl_hours if args.ttl_hours is not None else ttl_hours_from(config)
        fb = FeedbackStore(src.store, max_ttl_hours=max(ttl or 0, ttl_hours_from(config)))
        rec = fb.record("allow", pick["tool"], {"command": args.command}, reviewer="operator", note=args.note,
                        session_id=pick["session_id"], project_root=pick["project_root"], ttl_hours=ttl,
                        bound_to={"judgment_id": pick["judgment_id"], "asked_at": pick["ts"]})
    except LockTimeout as exc:
        print(f"not recorded: {exc}. Try again.", file=sys.stderr)
        return 3
    except ValueError as exc:
        print(f"not recorded: {exc}", file=sys.stderr)
        return 2
    print(f"approved: {rec['tool']} `{args.command}`")
    print(f"  session  {rec['session_id']}  (last {pick['decision']} at {pick['ts']})")
    print(f"  project  {rec['project_root']}")
    print(f"  expires  {rec['expires_at']}")
    others = sorted({c["session_id"] for c in found[1:] if c["session_id"] != pick["session_id"]})
    if others:
        print(f"  not for the other sessions that were asked the same command: {', '.join(others)} (use --session <id>)")
    print("Other sessions, projects and commands are not affected.")
    return 0


def _cmd_harness_init(args) -> int:
    from . import adminguard
    from .harness import write_config
    kept = [os.path.join(args.dir, n) for n in ("semgate.json", "grant.json", "check.token", "approve.token")]
    weakening = ([f"--force replaces the files in {args.dir} (config, grant and both tokens)."]
                 if args.force and any(os.path.exists(p) for p in kept) else [])
    code = adminguard.guard("harness init", weakening)
    if code:
        return code
    try:
        # main() turns --provider none into None (for `judge`); the config needs the name.
        written = write_config(args.dir, args.purpose, provider=args.provider or "none", mode=args.mode, project=args.project,
                               policy=args.policy, days=args.days, force=args.force)
    except (OSError, ValueError) as exc:
        print(f"semgate harness init: {exc}", file=sys.stderr)
        return 2
    for name, path in written.items():
        print(f"{name:14} {path}")
    cfg = written["config"].replace(" (kept)", "")
    folder = os.path.dirname(cfg)
    print()
    print("Next:")
    print(f"  semgate serve --http --config {cfg} \\")
    print(f"      --token-file {os.path.join(folder, 'check.token')} --approve-token-file {os.path.join(folder, 'approve.token')}")
    print("  The agent side (your harness) uses check.token for POST /v1/check.")
    print("  Only the human side (the code that receives a person's yes/no) may use approve.token for POST /v1/approve.")
    print("  Keep this folder out of any workspace the agent can read.")
    return 0


def _cmd_telemetry(args) -> int:
    from . import telemetry
    extra = list(args.redact_literal or [])
    if not args.no_auto_redact:
        extra += telemetry.default_extra_redactions()
    records = telemetry.load_ledger_records(args.ledger)
    clean = list(telemetry.export(records, extra=extra))
    if args.out:
        with open(args.out, "w", encoding="utf-8") as handle:
            for rec in clean:
                handle.write(json.dumps(rec, sort_keys=True) + "\n")
        print(f"wrote {len(clean)} clean telemetry records to {args.out}", file=sys.stderr)
    else:
        for rec in clean:
            json.dump(rec, sys.stdout, sort_keys=True)
            sys.stdout.write("\n")
    if args.summary:
        report = telemetry.summarize(clean)
        text = json.dumps(report, indent=2, sort_keys=True) + "\n"
        if args.summary_out:
            Path(args.summary_out).write_text(text, encoding="utf-8")
            print(f"wrote summary to {args.summary_out}", file=sys.stderr)
        else:
            sys.stderr.write(text)
    return 0


def _cmd_telemetry_send(args) -> int:
    from . import telemetry
    extra = list(args.redact_literal or [])
    if not args.no_auto_redact:
        extra += telemetry.default_extra_redactions()
    records = list(telemetry.load_ledger_records(args.infile)) if args.infile else \
        list(telemetry.export(telemetry.load_ledger_records(args.ledger), extra=extra))
    if not records:
        print("nothing to send: no clean records found", file=sys.stderr)
        return 0

    # Independent leak gate: refuse to send if anything still looks like real
    # personal data or a secret. This runs even when reading a pre-exported file.
    leaks = telemetry.scan_records(records, extra)
    if leaks:
        print(f"REFUSING TO SEND: found {len(leaks)} possible leak(s):", file=sys.stderr)
        for idx, issue in leaks[:20]:
            print(f"  record {idx}: {issue}", file=sys.stderr)
        print("Fix the export (add --redact-literal for names/hosts) and try again.", file=sys.stderr)
        return 2

    payload = telemetry.build_payload(records, semgate_version=_semgate_version(),
                                      install_id=args.install_id or None,
                                      sent_day=_today())
    endpoint = args.endpoint or os.environ.get("SEMGATE_TELEMETRY_ENDPOINT", "")
    if not args.confirm or not endpoint:
        # Dry run: show exactly what would be sent. Nothing leaves the machine.
        where = endpoint or "(no endpoint set)"
        print(f"DRY RUN — would POST {len(records)} clean records to {where}", file=sys.stderr)
        print(f"leak scan: clean ({len(records)} records checked)", file=sys.stderr)
        json.dump(payload, sys.stdout, indent=2, sort_keys=True)
        sys.stdout.write("\n")
        if endpoint and not args.confirm:
            print("Add --confirm to actually send.", file=sys.stderr)
        return 0

    status, body = telemetry.post_json(endpoint, payload)
    print(f"sent {len(records)} records to {endpoint}: HTTP {status} {body[:200]}", file=sys.stderr)
    return 0 if 200 <= status < 300 else 1


def _semgate_version() -> str:
    try:
        from . import __version__  # type: ignore
        return str(__version__)
    except Exception:
        return ""


def _today() -> str:
    from datetime import datetime, timezone
    return datetime.now(timezone.utc).strftime("%Y-%m-%d")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="semgate", description="Semantic auto mode for coding agents. We judge. The host acts.")
    parser.add_argument("-V", "--version", action="version", version=f"semgate {_semgate_version()}")
    sub = parser.add_subparsers(dest="command", required=True)

    p_judge = sub.add_parser("judge", help="Judge one envelope (decision only, never executes)")
    p_judge.add_argument("--envelope", help="Path to an envelope JSON file")
    p_judge.add_argument("--stdin", action="store_true", help="Read the envelope JSON from stdin")
    p_judge.add_argument("--adapter", default="raw", choices=["raw", "opencode"])
    p_judge.add_argument("--policy", default=DEFAULT_POLICY)
    p_judge.add_argument("--provider", default="fake", choices=["fake", *LIVE_PROVIDERS, "none"])
    p_judge.add_argument("--model", default=None, help=MODEL_HELP)
    p_judge.add_argument("--fake-answers", default="", help="JSON map of predicate_id -> probability for the fake provider")
    p_judge.add_argument("--provider-fail", action="store_true", help="Force the fake provider to fail (test the abstention path)")
    p_judge.add_argument("--ledger", default="", help="Append the judgment to this JSONL ledger")
    p_judge.add_argument("--evaluated-at", default="", help="Override evaluation time (ISO 8601, for replay/tests)")
    p_judge.set_defaults(func=_cmd_judge)

    p_replay = sub.add_parser("replay", help="Run the simulation over a fixture directory")
    p_replay.add_argument("--traces", required=True, help="Directory of trace fixtures (*.json)")
    p_replay.add_argument("--policy", default=DEFAULT_POLICY)
    p_replay.add_argument("--ledger", default="", help="Optional ledger to record replay judgments")
    p_replay.set_defaults(func=_cmd_replay)

    p_eval = sub.add_parser("eval", help="Run harness-agnostic tri-state benchmark cases")
    p_eval.add_argument("--cases", action="append", required=True, help="Case JSON/JSONL file or directory; repeatable")
    p_eval.add_argument("--policy", default=DEFAULT_POLICY)
    p_eval.add_argument("--provider", choices=["scripted", *LIVE_PROVIDERS, "none"], default="scripted",
                        help="scripted = each case's fake answers; typesafe = Jev via TYPESAFE_API_KEY; "
                             "openrouter = Jev via OPENROUTER_API_KEY; none = deterministic layers only")
    p_eval.add_argument("--model", default=None, help=MODEL_HELP)
    p_eval.add_argument("--output", default="", help="Write replayable JSON report to this path")
    p_eval.add_argument("--allow-provider-errors", action="store_true",
                        help="with a live provider, do not exit 3 when some cases got no model answer "
                             "or the judge answered 0 cases (the report still lists why in invalid_run)")
    p_eval.set_defaults(func=_cmd_eval)

    p_ledger = sub.add_parser("ledger", help="Inspect or amend the ledger")
    p_ledger.add_argument("ledger_command", choices=["list", "override", "outcome"])
    p_ledger.add_argument("--ledger", required=True)
    p_ledger.add_argument("--judgment-id", default="")
    p_ledger.add_argument("--reviewer", default="")
    p_ledger.add_argument("--verdict", default="")
    p_ledger.add_argument("--note", default="")
    p_ledger.add_argument("--outcome", default="")
    p_ledger.add_argument("--detail", default="")
    p_ledger.set_defaults(func=_cmd_ledger)

    p_fb = sub.add_parser("feedback", help="Record a human decision (allow/deny) for an exact command",
                          description="allow: approve one exact command for ONE session in ONE project, for a limited time "
                                      "(default 4 h). The session is the most recent one in this project whose ledger shows "
                                      "the command was asked or blocked. deny: block the command (every session and project "
                                      "unless --session/--project are given). Without --config and --store: the configs of "
                                      "the installed semgate hooks and of the semgate plugin copies in this project; the "
                                      "approval goes to the config whose ledger shows the block, and the output names it. "
                                      "No installed hook and no --config/--store: exit 2. The project is the current "
                                      "directory (or --project).")
    p_fb.add_argument("decision", nargs="?", choices=["allow", "deny"])
    p_fb.add_argument("command", nargs="?", help="The exact command that was blocked or should be blocked")
    p_fb.add_argument("--tool", default="", help="Tool name (allow: taken from the ledger; deny: default bash)")
    p_fb.add_argument("--store", default="", help="Feedback JSONL store (default: the feedback.feedback_file of the config "
                                                  "whose ledger shows the block)")
    p_fb.add_argument("--ledger", default="", help="Ledger to find the session in (default: each config's ledger_file; "
                                                   "with --store: ledger.jsonl next to the store)")
    p_fb.add_argument("--config", default="", help="semgate.json of the hook: store, ledger and feedback.approval_ttl_hours. "
                                                   "Default (without --config and --store): the config the installed semgate "
                                                   "hooks pass (~/.gemini/config/hooks.json, ~/.claude/settings.json, "
                                                   "~/.factory/hooks.json, the OpenCode and Pi plugins, plugin copies in "
                                                   "this project); the ledger with the block decides which one")
    p_fb.add_argument("--show-config", action="store_true", help="Print the config, feedback store and ledger that would be "
                                                                 "used, then exit without writing")
    p_fb.add_argument("--session", default="", help="Bind to this session id instead of the most recent one")
    p_fb.add_argument("--project", default="", help="Project directory (default: the current directory)")
    p_fb.add_argument("--ttl-hours", type=float, default=None, help="Expiry in hours (allow default 4, or feedback.approval_ttl_hours)")
    p_fb.add_argument("--note", default="")
    p_fb.set_defaults(func=_cmd_feedback)

    p_tel = sub.add_parser("telemetry", help="Export a clean, shareable telemetry file from a ledger (no personal data, secrets stripped)")
    p_tel.add_argument("--ledger", required=True, help="Ledger JSONL to read")
    p_tel.add_argument("--out", default="", help="Write clean telemetry JSONL here (default: stdout)")
    p_tel.add_argument("--summary", action="store_true", help="Also produce an aggregate report")
    p_tel.add_argument("--summary-out", default="", help="Write the summary here (default: stderr)")
    p_tel.add_argument("--redact-literal", action="append", help="An extra literal string to strip (name, company, host); repeatable")
    p_tel.add_argument("--no-auto-redact", action="store_true", help="Do not auto-strip the local OS username and home leaf")
    p_tel.set_defaults(func=_cmd_telemetry)

    p_send = sub.add_parser("telemetry-send", help="Send clean telemetry to an endpoint (human-run, dry-run by default, refuses on any leak)")
    src = p_send.add_mutually_exclusive_group(required=True)
    src.add_argument("--ledger", help="Ledger JSONL to export and send")
    src.add_argument("--infile", help="A pre-exported clean JSONL file to send")
    p_send.add_argument("--endpoint", default="", help="HTTPS endpoint (or set SEMGATE_TELEMETRY_ENDPOINT)")
    p_send.add_argument("--confirm", action="store_true", help="Actually send; without it this is a dry run that only prints the payload")
    p_send.add_argument("--install-id", default="", help="Optional anonymous id for dedup (a random UUID you generate once)")
    p_send.add_argument("--redact-literal", action="append", help="Extra literal to strip and forbid; repeatable")
    p_send.add_argument("--no-auto-redact", action="store_true", help="Do not auto-strip the local OS username and home leaf")
    p_send.set_defaults(func=_cmd_telemetry_send)

    p_serve = sub.add_parser("serve", add_help=False,
                             help="Long-running judge: --stdio (OpenCode/Pi plugins) or --http (any harness: POST /v1/check)")
    p_serve.add_argument("serve_args", nargs=argparse.REMAINDER)   # handled before parsing (see the top of main)

    p_agent = sub.add_parser("agent", add_help=False,
                             help="Codex with Semgate-owned tools: offline development and prepared uploads")
    p_agent.add_argument("agent_args", nargs=argparse.REMAINDER)   # own parser in codexrunner.main

    p_h = sub.add_parser("harness", help="Set up semgate for your own harness (Python API or semgate serve --http)")
    h_sub = p_h.add_subparsers(dest="harness_command", required=True)
    p_hi = h_sub.add_parser("init", help="Write semgate.json, grant.json, check.token and approve.token")
    p_hi.add_argument("--purpose", required=True, help="what the operator authorises the agent to do")
    p_hi.add_argument("--dir", default=os.path.join(os.path.expanduser("~"), ".semgate", "http"),
                      help="where the files go (default ~/.semgate/http, outside any workspace)")
    p_hi.add_argument("--provider", choices=[*LIVE_PROVIDERS, "none", "recorded"], default="typesafe")
    # enforce only; `--mode shadow` is the hidden developer switch (docs/development.md).
    p_hi.add_argument("--mode", choices=["enforce", "shadow"], default="enforce", help=argparse.SUPPRESS)
    p_hi.add_argument("--project", default="", help="optional project folder; becomes the grant's allowed_path_prefixes")
    p_hi.add_argument("--policy", default="dev", help="'dev', 'default' or a policy file path")
    p_hi.add_argument("--days", type=int, default=30, help="grant validity in days")
    p_hi.add_argument("--force", action="store_true", help="overwrite existing files")
    p_hi.set_defaults(func=_cmd_harness_init)

    from .trust import add_parser as _add_trust
    _add_trust(sub)
    from .demo import add_parser as _add_demo
    _add_demo(sub)

    from .init_antigravity import add_parser as _add_init
    _add_init(sub)
    from .report import add_parser as _add_report
    _add_report(sub)
    from .doctor import add_parser as _add_doctor
    _add_doctor(sub)
    from .privacyconsent_cli import add_parser as _add_consent
    _add_consent(sub)

    return parser


def parse_args(argv):
    """The parsed arguments of `semgate <argv>` (not `serve`), as main() uses
    them. Test harnesses that call an admin command in-process with
    guard=False (scripts/live_*.py) parse their arguments here."""
    parser = build_parser()
    args = parser.parse_args(list(argv))
    if args.command == "judge" and not args.stdin and not args.envelope:
        parser.error("judge needs --envelope or --stdin")
    if getattr(args, "provider", None) == "none":
        args.provider = None  # type: ignore[assignment]
    return args


def main(argv=None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if argv[:1] == ["serve"]:           # its own parser (serve.main): --stdio | --http and their options
        from .serve import main as serve_main
        return serve_main(argv[1:])
    if argv[:1] == ["agent"]:
        from .codexrunner import main as agent_main
        return agent_main(argv[1:])
    args = parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
