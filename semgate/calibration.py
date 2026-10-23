"""`semgate report --calibration`: how each question's answer relates to what
the human did when semgate asked. Report only: it never writes a policy.

Input (all local, read-only):
  - the ledger: judgments (decision, stage, predicate_votes, ts) and the
    human answers recorded there (`outcome` records from
    `semgate ledger outcome`, `override` records);
  - optionally the feedback store (`semgate feedback allow|deny <command>`),
    joined to a judgment by the same action key the judge uses, the first
    feedback at or after the judgment;
  - optionally the history store (record_outcomes: true): a pending ask whose
    step then ran without error = approved; a pending ask that never ran
    while a later step of the same conversation exists = rejected.

Only semantic `ask` judgments with a known human answer are used (an ask is
the one decision where a person said yes or no). Per question (route.run,
route.block, effect, user_asked, on_task, instructed_by_context, executes,
shadow questions, session_drift, serves_turn.none, ...):

  - time split: samples sorted by time, the older half is `tune`, the newer
    half is `validate` (the newer half is never used to pick anything);
  - direction and AUC: whether approved asks had higher or lower values, and
    the probability that a random approved ask has a higher value than a
    random rejected one (0.5 = no relation);
  - bins: approval rate per value bin, tune and validate side by side;
  - a suggested threshold range: on the tune half, the cuts where the asks on
    the approved side have an approval rate at or above `target` with at
    least `min_n` samples; the lowest-coverage-loss cut is checked on the
    validate half. A range with too little data says so.

Nothing is sent anywhere. Real ledgers stay local; tests use synthetic data.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional, Tuple

from .envelope import parse_ts

APPROVED = frozenset({"approved", "approve", "allow", "allowed", "ran", "executed", "accepted", "yes", "human_approved"})
REJECTED = frozenset({"rejected", "reject", "deny", "denied", "blocked", "not_run", "declined", "no", "human_blocked"})
SCORE_QUESTIONS = frozenset({"effect", "executes"})
DEFAULT_TARGET = 0.9
DEFAULT_MIN_N = 5


def _read(path: str) -> List[Dict[str, Any]]:
    p = Path(path) if path else None
    if p is None or not p.is_file():
        return []
    out = []
    for line in p.read_text(encoding="utf-8", errors="ignore").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            rec = json.loads(line)
        except ValueError:
            continue
        if isinstance(rec, dict):
            out.append(rec)
    return out


def _epoch(value: Any) -> Optional[float]:
    dt = parse_ts(str(value)) if value else None
    return dt.timestamp() if dt is not None else None


def _label(text: Any) -> Optional[bool]:
    t = str(text or "").strip().lower()
    if t in APPROVED:
        return True
    if t in REJECTED:
        return False
    return None


def features(votes: Iterable[Mapping[str, Any]]) -> Dict[str, float]:
    """One number per question from the stored votes."""
    out: Dict[str, float] = {}
    for v in votes or []:
        q = str(v.get("predicate") or "")
        if not q or v.get("vote") == "abstain":
            continue
        probs = v.get("probabilities") or {}
        if q == "route":
            for label in ("run", "review", "block"):
                if isinstance(probs.get(label), (int, float)):
                    out[f"route.{label}"] = float(probs[label])
        elif q == "serves_turn":
            if isinstance(probs.get("none"), (int, float)):
                out["serves_turn.none"] = float(probs["none"])
        elif isinstance(v.get("p"), (int, float)):
            out[q] = float(v["p"])
        elif isinstance(v.get("mean"), (int, float)):
            out[q] = float(v["mean"])
        elif isinstance(v.get("value"), (int, float)) and not isinstance(v.get("value"), bool):
            out[q] = float(v["value"])
    return out


def _feedback_matches(judgment: Mapping[str, Any], feedback: Mapping[str, Any], action_key: Optional[str]) -> bool:
    """An explicit judgment/occurrence binding takes priority over an action key."""
    binding = feedback.get("bound_to")
    if binding is not None:
        return (isinstance(binding, Mapping) and bool(binding.get("judgment_id"))
                and binding.get("judgment_id") == judgment.get("judgment_id")
                and bool(binding.get("asked_at")) and binding.get("asked_at") == judgment.get("ts"))
    # Private commands cannot be reconstructed from minimized text. Legacy
    # unbound feedback retains the old action-key join only for plain records.
    return not judgment.get("privacy_minimized") and feedback.get("action_key") == action_key


def collect(ledger_path: str, history_path: str = "", feedback_path: str = "") -> List[Dict[str, Any]]:
    """Samples: {ts, judgment_id, reason_code, features, approved, source}."""
    from .feedback import _key as feedback_key
    ledger = _read(ledger_path)
    judgments = [r for r in ledger if r.get("record_type") == "judgment"
                 and (r.get("decision") or {}).get("decision") == "ask" and (r.get("decision") or {}).get("stage") == "semantic"]
    answers: Dict[str, Tuple[bool, str]] = {}
    for r in ledger:                      # later records win
        if r.get("record_type") == "outcome":
            lab = _label(r.get("outcome"))
            if lab is not None:
                answers[str(r.get("judgment_id"))] = (lab, "outcome")
        elif r.get("record_type") == "override":
            lab = _label(r.get("verdict"))
            if lab is not None:
                answers[str(r.get("judgment_id"))] = (lab, "override")
    feedback = [r for r in _read(feedback_path) if r.get("record_type") == "feedback"]
    history = _read(history_path)
    ran = {str(r.get("judgment_id")) for r in history if r.get("record_type") == "executed" and not r.get("error") and r.get("judgment_id")}
    pending = [r for r in history if r.get("record_type") == "pending"]
    by_conv: Dict[str, List[int]] = {}
    for pos, r in enumerate(pending):
        by_conv.setdefault(str(r.get("conversation_id")), []).append(pos)
    history_answer: Dict[str, bool] = {}
    for pos, r in enumerate(pending):
        jid = str(r.get("judgment_id") or "")
        if not jid or r.get("decision") != "ask":
            continue
        if jid in ran:
            history_answer[jid] = True
        elif any(p > pos and pending[p].get("step_idx") != r.get("step_idx") for p in by_conv[str(r.get("conversation_id"))]):
            history_answer.setdefault(jid, False)     # the agent went on to another step: this ask was not approved
    samples: List[Dict[str, Any]] = []
    for j in judgments:
        jid = str(j.get("judgment_id"))
        ts = _epoch(j.get("ts"))
        label: Optional[bool] = None
        source = ""
        if jid in answers:
            label, source = answers[jid]
        else:
            env = j.get("envelope") or {}
            action = env.get("action") or {}
            key = None if j.get("privacy_minimized") else feedback_key(str(action.get("tool", "")), action.get("arguments") or {})
            after = [f for f in feedback if _feedback_matches(j, f, key) and (ts is None or (_epoch(f.get("ts")) or 0) >= ts)]
            if after:
                label, source = str(after[0].get("decision")) == "allow", "feedback"
            elif jid in history_answer:
                label, source = history_answer[jid], "history"
        if label is None:
            continue
        d = j.get("decision") or {}
        samples.append({"ts": ts if ts is not None else 0.0, "judgment_id": jid, "reason_code": d.get("reason_code", ""),
                        "features": features(d.get("predicate_votes") or []), "approved": label, "source": source})
    samples.sort(key=lambda s: s["ts"])
    return samples


def auc(pairs: List[Tuple[float, bool]]) -> Optional[float]:
    """P(value of a random approved sample > value of a random rejected one), ties 0.5."""
    pos = [x for x, a in pairs if a]
    neg = [x for x, a in pairs if not a]
    if not pos or not neg:
        return None
    wins = sum(1.0 if p > n else 0.5 if p == n else 0.0 for p in pos for n in neg)
    return wins / (len(pos) * len(neg))


def _rate(pairs: List[Tuple[float, bool]]) -> Optional[float]:
    return (sum(1 for _, a in pairs if a) / len(pairs)) if pairs else None


def _bins(question: str) -> List[Tuple[float, float]]:
    if question in SCORE_QUESTIONS:
        return [(i * 0.5, (i + 1) * 0.5) for i in range(7)]
    return [(i / 10, (i + 1) / 10) for i in range(10)]


def _in_bin(x: float, lo: float, hi: float, last: bool) -> bool:
    return lo <= x < hi or (last and x == hi)


def analyze(samples: List[Dict[str, Any]], target: float = DEFAULT_TARGET, min_n: int = DEFAULT_MIN_N) -> Dict[str, Any]:
    half = len(samples) // 2
    tune, validate = samples[:half], samples[half:]
    questions = sorted({q for s in samples for q in s["features"]})
    out: Dict[str, Any] = {}
    for q in questions:
        t = [(s["features"][q], s["approved"]) for s in tune if q in s["features"]]
        v = [(s["features"][q], s["approved"]) for s in validate if q in s["features"]]
        a_t, a_v = auc(t), auc(v)
        direction = "unknown" if a_t is None or a_t == 0.5 else ("higher_means_approved" if a_t > 0.5 else "lower_means_approved")
        bins = []
        edges = _bins(q)
        for i, (lo, hi) in enumerate(edges):
            last = i == len(edges) - 1
            bt = [p for p in t if _in_bin(p[0], lo, hi, last)]
            bv = [p for p in v if _in_bin(p[0], lo, hi, last)]
            if bt or bv:
                bins.append({"range": [lo, hi], "tune_n": len(bt), "tune_approved": sum(1 for _, a in bt if a),
                             "validate_n": len(bv), "validate_approved": sum(1 for _, a in bv if a)})
        suggestion: Dict[str, Any] = {"status": "not enough data"}
        if direction != "unknown":
            higher = direction == "higher_means_approved"
            passing = []
            for c in sorted({x for x, _ in t}):
                side = [p for p in t if (p[0] >= c if higher else p[0] <= c)]
                if len(side) >= min_n and (_rate(side) or 0.0) >= target:
                    passing.append((c, len(side), _rate(side)))
            if passing:
                best = min(passing, key=lambda x: x[0]) if higher else max(passing, key=lambda x: x[0])
                vside = [p for p in v if (p[0] >= best[0] if higher else p[0] <= best[0])]
                suggestion = {
                    "status": "ok",
                    "side": f"value {'>=' if higher else '<='} cut",
                    "cut_range_tune": [min(c for c, _, _ in passing), max(c for c, _, _ in passing)],
                    "cut": best[0], "tune_n": best[1], "tune_approval": round(best[2], 3),
                    "validate_n": len(vside), "validate_approval": None if not vside else round(_rate(vside), 3),
                }
            else:
                suggestion = {"status": f"no cut reaches approval {target:.2f} with at least {min_n} tune samples"}
        out[q] = {"tune_n": len(t), "validate_n": len(v),
                  "tune_approval": None if not t else round(_rate(t), 3),
                  "validate_approval": None if not v else round(_rate(v), 3),
                  "auc_tune": None if a_t is None else round(a_t, 3), "auc_validate": None if a_v is None else round(a_v, 3),
                  "direction": direction, "bins": bins, "suggestion": suggestion}
    return {"samples": len(samples), "tune": len(tune), "validate": len(validate), "target": target, "min_n": min_n,
            "sources": {src: sum(1 for s in samples if s["source"] == src) for src in sorted({s["source"] for s in samples})},
            "questions": out,
            "note": "report only: no policy is written; thresholds change only by an owner edit to a policy file"}


def build(ledger_path: str, history_path: str = "", feedback_path: str = "", target: float = DEFAULT_TARGET,
          min_n: int = DEFAULT_MIN_N) -> Dict[str, Any]:
    return analyze(collect(ledger_path, history_path, feedback_path), target=target, min_n=min_n)


def render(rep: Mapping[str, Any]) -> str:
    lines = [f"Calibration: {rep['samples']} answered asks (tune = older {rep['tune']}, validate = newer {rep['validate']}); "
             f"sources {rep['sources']}; target approval {rep['target']:.2f}, min {rep['min_n']} samples", ""]
    if not rep["samples"]:
        lines.append("no answered asks yet: record outcomes (semgate ledger outcome, semgate feedback, or record_outcomes: true)")
    for q, r in rep["questions"].items():
        lines.append(f"{q}: tune n={r['tune_n']} approved {r['tune_approval']}, validate n={r['validate_n']} approved "
                     f"{r['validate_approval']}; AUC tune {r['auc_tune']} validate {r['auc_validate']}; {r['direction']}")
        for b in r["bins"]:
            lo, hi = b["range"]
            lines.append(f"    [{lo:.2f}, {hi:.2f}]  tune {b['tune_approved']}/{b['tune_n']}  validate {b['validate_approved']}/{b['validate_n']}")
        s = r["suggestion"]
        if s.get("status") == "ok":
            lines.append(f"    suggested: {s['side']} with cut in {s['cut_range_tune']} (tune); at cut {s['cut']}: tune "
                         f"{s['tune_approval']} of {s['tune_n']}, validate {s['validate_approval']} of {s['validate_n']}")
        else:
            lines.append(f"    suggested: {s.get('status')}")
    lines += ["", rep["note"]]
    return "\n".join(lines)
