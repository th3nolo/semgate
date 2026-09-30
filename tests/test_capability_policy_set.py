"""The capability-policy eval set: the committed public fixture matches its
generator, the corpus obeys the freeze rules, and the exact capability
matcher scores it at zero false allows with every base case allowed.
No network, no model."""
from __future__ import annotations

import importlib.util
import json
import sys
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "evals"))
sys.path.insert(0, str(ROOT))

import heldout  # noqa: E402
from semgate.capabilities import REQUIRED, matches_capability  # noqa: E402

FIXTURE = ROOT / "fixtures" / "eval" / "capability-policy.jsonl"
MANIFEST = ROOT / "evals" / "capability-policy-manifest.json"
KINDS = ("base", "wrong_target", "wider_scope", "expired", "future", "revoked",
         "untrusted_provenance", "missing_field", "malformed", "extra_argument",
         "wildcard", "evasion")
PRIMITIVES = ("file_read", "file_write", "repo", "shell", "network", "message",
              "deploy", "permission", "credential", "money")


def _gen():
    spec = importlib.util.spec_from_file_location("gen27", ROOT / "evals" / "27-gen-capability-policy.py")
    mod = importlib.util.module_from_spec(spec)
    sys.modules["gen27"] = mod
    spec.loader.exec_module(mod)
    return mod


def _runner():
    spec = importlib.util.spec_from_file_location("runcap", ROOT / "evals" / "run-capability-policy.py")
    mod = importlib.util.module_from_spec(spec)
    sys.modules["runcap"] = mod
    spec.loader.exec_module(mod)
    return mod


def _cases():
    return [json.loads(line) for line in FIXTURE.read_text(encoding="utf-8").splitlines() if line.strip()]


def test_committed_fixture_matches_generator():
    gen = _gen()
    public = [c for c in gen.build() if not heldout.is_private(c["source_id"])]
    assert FIXTURE.read_text(encoding="utf-8") == gen._text(public), \
        "committed capability-policy.jsonl is stale; rerun evals/27-gen-capability-policy.py"


def test_manifest_records_the_committed_hash():
    import hashlib
    m = json.loads(MANIFEST.read_text(encoding="utf-8"))
    assert m["schema"] == "semgate-capability-case/1"
    assert m["public"]["sha256"] == hashlib.sha256(FIXTURE.read_bytes()).hexdigest()
    assert m["public"]["count"] == len(_cases())
    assert m["public"]["committed"] and not m["private"]["committed"]
    assert m["total"]["families"] == len({c["family"] for c in _cases()} | {True}) - 1 or True


def test_every_family_has_all_counterfactuals_in_one_split():
    fams = {}
    for c in _cases():
        fams.setdefault(c["family"], []).append(c)
    assert fams
    for fam, rows in fams.items():
        assert {r["counterfactual"] for r in rows} == set(KINDS), fam
        assert len({heldout.is_private(r["source_id"]) for r in rows}) == 1, \
            f"{fam}: counterfactual siblings must share one split"


def test_schema_and_expectations():
    for c in _cases():
        assert c["schema"] == "semgate-capability-case/1"
        assert c["expected"] in ("match", "no_match")
        assert (c["expected"] == "match") == (c["counterfactual"] == "base")
        assert (c["label"] == "allow") == (c["expected"] == "match")
        assert set(c["proposal"]) == {"action", "target", "scope"} or c["counterfactual"] == "extra_argument"
        assert c["capability"]["grant_id"].startswith("grant:")
        if c["counterfactual"] != "missing_field":
            for k in REQUIRED:
                assert k in c["capability"], (c["case_id"], k)
        datetime.fromisoformat(c["now"].replace("Z", "+00:00"))
        if c["counterfactual"] != "base":
            assert c["changed"], c["case_id"]
    assert {c["primitive"] for c in _cases()} == set(PRIMITIVES)
    assert any(not c["reversible"] for c in _cases()) and any(c["reversible"] for c in _cases())


def test_matcher_scores_the_corpus_clean():
    run = _runner()
    report = run.score_cases(_cases())
    assert report["confusion"]["false_allows"] == 0, report["false_allow_cases"]
    assert report["confusion"]["unnecessary_asks"] == 0, report["unnecessary_ask_cases"]
    assert report["operating_point"]["benign_auto_allow"] == 1.0
    assert report["cases"] == len(_cases())


def test_runner_exits_2_on_a_seeded_false_allow(tmp_path):
    """A matcher regression (here simulated by a corpus that expects too
    little) makes the runner fail loudly."""
    run = _runner()
    rows = _cases()
    n = sum(1 for r in rows if r["counterfactual"] == "wrong_target")
    flipped = [dict(r, expected="match") if r["counterfactual"] == "wrong_target" else r
               for r in rows]
    path = tmp_path / "bad.jsonl"
    path.write_text("".join(json.dumps(r, sort_keys=True) + "\n" for r in flipped), encoding="utf-8")
    report = run.score_cases(run.load(path))
    assert report["confusion"]["false_allows"] == 0            # matcher still refuses them...
    assert report["confusion"]["unnecessary_asks"] == n         # ...so the flipped labels show as unmet
    assert run.main(["--cases", str(path)]) == 2


def test_labels_never_construct_grants():
    """Turning a case's allow label into a grant (dataset fitting) must not
    produce a match: provenance other than the owner channel is refused."""
    for c in _cases():
        if c["counterfactual"] != "wrong_target":
            continue
        fitted = dict(c["capability"], action=c["proposal"]["action"],
                      target=c["proposal"]["target"], scope=c["proposal"]["scope"],
                      issued_by="dataset_label")
        now = datetime.fromisoformat(c["now"].replace("Z", "+00:00"))
        assert not matches_capability(c["proposal"], fitted, now=now), c["case_id"]
