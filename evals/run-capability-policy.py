"""Offline runner for the capability-policy eval set. No network, no model, no paid calls.

Scores the exact capability matcher (semgate/capabilities.py) against the
frozen corpus: each case pairs a fully instantiated proposal with a synthetic
owner grant and the expectation (match only for the base case). Reports the
confusion counts, false allows by counterfactual kind, unnecessary asks, and
coverage by primitive, at the one operating point that matters for this
layer: zero false allows.

Exit 0 when the corpus scores clean (0 false allows, 0 unnecessary asks),
exit 2 otherwise, matching the boundary-violation convention of `semgate eval`.
The matcher never sees case labels; expectations are scored after the fact.
Grants come from case data and are fixtures, never runtime policy.
"""
from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from semgate.capabilities import matches_capability  # noqa: E402

REPORT_SCHEMA = "semgate-capability-policy-report/1"
PUBLIC = ROOT / "fixtures" / "eval" / "capability-policy.jsonl"


def _now(case: Dict[str, Any]) -> datetime:
    return datetime.fromisoformat(str(case["now"]).replace("Z", "+00:00"))


def score_cases(cases: List[Dict[str, Any]]) -> Dict[str, Any]:
    rows = []
    for c in cases:
        matched = matches_capability(c["proposal"], c["capability"], now=_now(c))
        rows.append({"case_id": c["case_id"], "family": c["family"], "primitive": c["primitive"],
                     "counterfactual": c["counterfactual"], "expected": c["expected"], "matched": matched})
    false_allows = [r for r in rows if r["expected"] == "no_match" and r["matched"]]
    unneeded_asks = [r for r in rows if r["expected"] == "match" and not r["matched"]]
    base = [r for r in rows if r["counterfactual"] == "base"]

    def _by(key: str, rows_) -> Dict[str, int]:
        out: Dict[str, int] = {}
        for r in rows_:
            out[r[key]] = out.get(r[key], 0) + 1
        return dict(sorted(out.items()))

    return {
        "schema": REPORT_SCHEMA,
        "cases": len(rows),
        "families": len({r["family"] for r in rows}),
        "base_cases": len(base),
        "matched": sum(1 for r in rows if r["matched"]),
        "confusion": {
            "allow_correct": sum(1 for r in base if r["matched"]),
            "false_allows": len(false_allows),
            "unnecessary_asks": len(unneeded_asks),
            "no_match_correct": sum(1 for r in rows if r["expected"] == "no_match" and not r["matched"]),
        },
        "false_allows_by_counterfactual": _by("counterfactual", false_allows),
        "false_allows_by_primitive": _by("primitive", false_allows),
        "unnecessary_ask_cases": [r["case_id"] for r in unneeded_asks],
        "false_allow_cases": [r["case_id"] for r in false_allows],
        "coverage": {
            "by_primitive": _by("primitive", rows),
            "by_counterfactual": _by("counterfactual", rows),
        },
        "operating_point": {
            "benign_auto_allow": (sum(1 for r in base if r["matched"]) / len(base)) if base else 0.0,
            "false_allows": len(false_allows),
            "rule_shape": "exact action + exact target + exact scope + trusted owner provenance + validity window + not revoked",
            "wildcards_or_categories_allowed": False,
            "labels_used_to_construct_grants": False,
        },
    }


def load(path: Path) -> List[Dict[str, Any]]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--cases", default=str(PUBLIC), help="JSONL corpus (default: the committed public file)")
    ap.add_argument("--output", help="write the report JSON here (default: stdout)")
    args = ap.parse_args(argv)
    report = score_cases(load(Path(args.cases)))
    text = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if args.output:
        Path(args.output).write_text(text, encoding="utf-8")
    else:
        print(text, end="")
    bad = report["confusion"]["false_allows"] or report["confusion"]["unnecessary_asks"]
    return 2 if bad else 0


if __name__ == "__main__":
    raise SystemExit(main())
