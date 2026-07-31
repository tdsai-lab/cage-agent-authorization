# generators/

Action-indexed, witness-explicit analytic layer (the paper's specification (§12–16, 19, 21); MVP fixed at `d = 1`).

## Implemented

- **`oracle.py`** — the analytic **action-indexed** safety oracle `Safe(z, a)`. Rules looked up by
  `(domain, tool_id, candidate_action, categorical_context)`; scalar-threshold + affine families;
  exact margins. Implements the §19 API returning **witnesses**:
  `safe`, `discrete_reachable_unsafe`, `continuous_reachable_unsafe`, `joint_reachable_unsafe`,
  `category`. Source of truth — never a learned model.
- **`verify_interaction_type.py`** — witness-explicit A/B/C/D/R classifier. A **C** verdict requires
  an auditable same-state joint-gap witness (`pre_continuous_margin < 0 ≤ post_continuous_margin`).
  `falsification_cross_check` only tries to *disprove* an R verdict; never assigns a category.
- **`test_oracle.py`** — unit tests (10/10): threshold/affine C & R, **action-indexed reversal**
  (same `z`, different `a`, different `Safe`), `valid_range` not clipping the adversary, `|D_1|=8`,
  witness margins pre<0≤post, falsification cannot override the analytic oracle.
- **`generate.py`** — sweeps numeric/categorical grids, calls `category(z, a, d=1, eps)`, accepts
  each point with its exact label, stores the C witness, and self-audits (0 invariant violations).
  Writes `../data/<domain>.jsonl` + `../data/all.jsonl`.
- **`threshold_sensitivity.py`** — C non-empty for 455/455 threshold pairs; action-indexed oracle
  reproduces the analytic C-interval `[0.40, 0.50)`.

See also `../cert/certificate_oracles.py` for the deterministic certificate sanity table
(disc-only / cont-only / naive-composition / hybrid-oracle), which exhibits the non-composition
failure on C and non-vacuous hybrid safety on R — analytically, before any model exists.

## Run

```bash
python test_oracle.py  # 10/10
python generate.py  # writes ../data/*.jsonl, audits C witnesses
python threshold_sensitivity.py  # C robustness
python ../cert/certificate_oracles.py  # key C/R certificate table
```

## Not yet implemented (next, the ML/research phase)

Classifier baselines (`../models/`), empirical mixed attacks, randomized-smoothing certificate
baselines vs the **deterministic** ones already here, and hybrid randomized smoothing on
`h_θ(z, a)` (`../cert/`). The smoothed object is action-indexed `h_θ(z, a)`, not `h_θ(z)`.
