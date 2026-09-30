# Capability-policy dataset

Measures the exact known-benign capability layer (`semgate/capabilities.py`):
an action may auto-allow only when it is an exact action + target + scope
match of a predeclared grant that came from the trusted owner channel, is
inside its validity window, and is not revoked. Everything else falls through
to the rest of the pipeline (never an auto-allow, never a deny from this
layer). This set exists because the frozen benchmark carries no trusted,
predeclared exact capabilities, so it cannot measure the layer
(`evals/3-known-benign-policy-layer.py`).

## Shape

- `fixtures/eval/capability-policy.jsonl`: the committed public corpus
  (936 cases, 78 families). `evals/private/capability-policy.jsonl` is the
  git-ignored held-out split (144 cases, 12 families).
- One family is one realistic granted action across ten primitives: file
  reads/writes, repository operations, shell commands, network requests,
  message sends, deploys, permission changes, credential access, and
  money-bearing actions; reversible and irreversible effects.
- Each family has the same twelve cases: an exact in-scope `base` plus the
  counterfactuals `wrong_target`, `wider_scope`, `expired`, `future`,
  `revoked`, `untrusted_provenance`, `missing_field`, `malformed`,
  `extra_argument`, `wildcard`, and a primitive-specific `evasion`
  (non-canonical path, subdomain, reordered argv, lookalike handle, ...).
  Only `base` may match.
- The split is by family id (`int(sha256(source_id), 16) % 5 == 0`), so all
  twelve siblings of a family stay in one split and cannot leak across it.

## Threat model

The layer exists to auto-clear work the owner already authorized exactly,
without a model call. Its failure mode is a false allow: a near-miss action
(wrong target, wider scope, a grant that is expired, future, revoked,
forged by a tool output or an agent claim, malformed, wildcarded, or a
same-effect spelling) slipping through as "the granted action". Every
counterfactual family targets one of those slips. The matcher is
deterministic and total: malformed input never matches.

Grants in this set are synthetic fixtures with trusted-owner provenance in
the schema. Dataset labels measure outcomes; they never create
authorization, and nothing in this directory is loaded as runtime policy
(`policies/known-benign-capabilities.json` stays empty until an owner
declares real grants).

## Running

```
python evals/run-capability-policy.py                 # public corpus, report on stdout, exit 2 on any false allow
python evals/27-gen-capability-policy.py --check      # committed file matches the generator
```

No model, no key, no paid calls.

## Freeze and append-only rules

- The corpus is frozen once first scored. Corrections and new families are
  appended as a new dataset revision with an audit note in the manifest;
  never edit a published case in place.
- The generator is deterministic (fixed decision time
  `2026-09-29T12:00:00Z`); regeneration must reproduce the committed file
  byte for byte (`tests/test_capability_policy_set.py`).
- Never tune the matcher, thresholds, or rules on the held-out split.

## Limitations

- Synthetic: the families are realistic but authored, not captured traffic.
  Real-world coverage depends on owners declaring real grants.
- The matcher assumes canonical identifiers on both sides. Canonicalization
  of proposals (path normalization, argv parsing, URL forms) happens before
  this layer and is measured separately (roadmap suite 4); the `evasion`
  cases here only assert that non-canonical input does not exact-match.
- This measures the capability overlay only, not the full gate: a `no_match`
  case may still be allowed or denied downstream by hard rules, the human
  gate, or the judge.
- The `future` and `revoked` counterfactuals exercise `not_before` /
  `revoked_at`, optional grant fields the matcher gained with this dataset;
  older grants without them behave exactly as before.
