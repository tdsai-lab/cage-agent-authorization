# EXP_LIP_VS_RS — deterministic Lipschitz gate vs the smoothing certificate

A deterministic 1-Lipschitz backend for the learned post-tool-return authorization gate, compared
against the project's randomized-smoothing certificate **on the same model**, to decompose why
smoothing recovers only ~4–12% of robust-safe utility at the strict operating point (ε=0.10).

## What it answers

At ε=0.10, τ=0.90, M∈{1500,2000}, does a deterministic 1-Lipschitz gate recover substantially more of
the **exact** robust-safe set than smoothing? Primary metric `cert_recovery_vs_exact = R_allow =
#{R_exact allowed}/#R_exact`. The deficit is split into finite-MC tax, smoothing-transition tax, and
genuine learned-margin deficiency.

## Model

`models/orthogonium_adapter.py` — `LipGate`: a scalar signed-margin gate (safe ⟺ h_θ>0), 1-Lipschitz
w.r.t. its input (Orthogonium `OrthoLinear` + `MaxMin` + `UnitNormLinear`; no BatchNorm/Dropout/
unconstrained Linear; claimed L=1, empirically checked). The `FeatureEncoder` is used WITHOUT numeric
standardization, so 1-Lipschitz-in-input = 1-Lipschitz in the raw ε-ball, and the smoothing and
deterministic certificates share one encoding.

## Certificates (both on the same LipGate)

- **Deterministic margin** (`certify_lip`): `allow ⟺ min_{s'∈N_d(s)} h_θ(s',x,a) > L·ε` (exact
  discrete enumeration of `_states`; continuous handled by the Lipschitz bound). Strict `>`.
- **Smoothing** (`certify_smooth` → `smoothed_gate.certify`): the project Gaussian-RS / Clopper–Pearson
  / Cohen certificate, run on the LipGate via `LipSmoothWrapper`.

Baselines: OPA exact oracle (`category==R`, `exact_oracle_status=exact`), uncertified LipGate
(pointwise), MLP + smoothing (the existing Track-C gate), naive marginal.

## Run

```bash
./run_quick.sh  # finance, ε∈{0.03,0.10}, M∈{1500,2000} — sanity (~1-2 min on GPU)
./run_full.sh  # finance/sre/ops, ε∈{0.03,0.10}, M∈{1500,2000,10000}
```

Outputs in `results/`: `tables/L1_operating_points.csv` (R/C/U allow + cost per backend),
`L2_recovery_decomposition.csv`, `L3_cost.csv`, `L4_delta_epsilon_geometry.csv`,
`figures/c_prevalence_vs_min_delta_epsilon.pdf`, `snippets/lip_backend_snippet.tex`,
`diagnostics/lipgate_*.json` (claimed + empirical Lipschitz).

### PLAN_2 P4 defensive cleanup (`scripts/soundness_suite.py`, `scripts/tighten_lcert.py`)

```bash
python scripts/multiseed_variance.py  # L5 — 5-seed mean±std (Task F)
python scripts/soundness_suite.py --studies G1,G2,G3,G4  # L7–L10 (Task G: MC / FWER / σ×τ×ε / base-gate)
python scripts/k100_regime.py --k-list 10,50,100,150  # L6 — fidelity-k (Task G5)
python scripts/tighten_lcert.py  # L11 — certified LOCAL Lipschitz bound (Task H)
```

Result: **soundness invariant, only utility moves** — `cert_false_allow=0` across every Monte-Carlo
budget, FWER confidence, (σ,τ,ε) operating point, and base gate (L7–L10); the global `L_cert=1` is tight
and the certified LOCAL bound `‖∇_cont h‖≈0.98` shows no removable L-slack (L11), so the deterministic
deficit is pure learned-margin. Tables L5–L11 are tracked; `soundness_suite_summary.json` carries the
invariant. Test: `tests/test_p4_soundness.py`.

## Scope / honesty

- `policy_provenance = authored_provenance_conditioned_rego` — C-witnesses arise under **authored**
  provenance-conditioned Rego evaluated by OPA (not "spontaneously under an executable engine").
- The deterministic certificate certifies the **learned Lipschitz gate**; oracle false-allows
  (`cert_false_allow`) are empirical measurements against the executable policy, NOT a proof of the OPA
  policy itself. If `cert_false_allow>0` with high recovery, that is an oracle-mismatch danger case,
  reported as such.
- The clean tax decomposition uses smoothing vs deterministic **on the same LipGate**; MLP smoothing is
  cross-model context only.
- Smoothing is retained as the model-agnostic backend for non-Lipschitz / black-box gates.
