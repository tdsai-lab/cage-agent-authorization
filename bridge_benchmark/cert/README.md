# cert/ — certificates for the safety gate (PLAN3 §§8–13, PLAN4)

## The certificate: `enumerate_discrete_gaussian_rs`

For the MVP threat model the discrete budget is an exact finite adversarial set. We therefore certify
the discrete channel by **enumeration**, and apply randomized smoothing only to the continuous
numerical channel. Discrete randomized smoothing is left for settings where the discrete budget is
too large to enumerate or where a principled semantic discrete kernel exists (see
the paper's certificate-choice discussion).

The main (and only) certificate is **`enumerate_discrete_gaussian_rs`**:
- exact enumeration over valid `d=1` discrete swaps (`\mathcal D^{valid}_{1,a}`, action-valid only);
- Gaussian randomized smoothing over the numeric fields (noise centered at the clean `x_2`, δ=0);
- Clopper–Pearson lower bound `p̲_{s'}` per discrete state;
- Cohen radius penalty `ℓ_{s'}(ε)=Φ(Φ⁻¹(p̲_{s'}) − ε/σ)` applied once;
- **allow iff the worst-state lower bound `min_{s'} ℓ_{s'}(ε) ≥ τ`**.

This is **not** full hybrid Neyman–Pearson product smoothing, and discrete smoothing is **not** a
required next step.

## Files
- **`certificate_oracles.py`** — DETERMINISTIC, model-free certificate sanity table (Table 4):
  discrete-only / continuous-only / naive-composition / exact-hybrid **oracle** certificates. Shows
  naive composition falsely certifies safe on C, and the exact hybrid certifies safe non-vacuously on
  R. This table is model-free and stays in the paper.
- **`smoothed_gate.py`** — enumerative Gaussian randomized-smoothing certificate for the LEARNED gate
  over `B_{1,ε}` (PLAN3 §9). For each reachable discrete state `s ∈ D_1` (restricted to action-valid
  swaps): `p_s` via Monte-Carlo, Clopper–Pearson lower bound `p̲_s`, Cohen bound
  `ℓ_s(ε)=Φ(Φ⁻¹(p̲_s) − ε/σ)`. Hybrid lower bound `p̲_hyb = min_s ℓ_s(ε)`; **allow iff `p̲_hyb ≥ τ`**.
  Also exposes the discrete-only / continuous-only / naive variants for comparison.
- **`evaluate_certificates.py`** — orchestrator producing Tables 1–5 and per-record certificates
  (`out/certificates.jsonl`, PLAN3 §11). Bounded runtime via subsampling.
- **`audit_smoothed_gate.py`** — correctness audit (PLAN4 §4): action-valid states only, p_s at δ=0,
  ε-penalty applied once, lower bound in [0,1], C/U allow = 0, R allow > 0, false allow = 0.
- **`ablate_smoothed_gate.py`** — σ/τ/n_mc ablation (PLAN4 §5) → `out/ablation_smoothed_gate.{csv,md}`.
- **`r_margin_diagnostics.py`** — why R points certify or not (PLAN4 §6) → `out/r_margin_diagnostics.csv`.

## Run
```bash
python certificate_oracles.py  # Table 4 (model-free)
python evaluate_certificates.py --sigma 0.10 --epsilon 0.10 --tau 0.95 --n-mc 5000 --alpha 0.001
python audit_smoothed_gate.py  # 8-property audit
python ablate_smoothed_gate.py  # sigma/tau/n_mc grid
python r_margin_diagnostics.py  # R margin vs certificate bound
```

## Key tuning (PLAN3 §16 / PLAN4 §5, the non-vacuity risk)
σ and ε are in RAW numeric units (same space as the oracle threat set). A point certifies roughly iff
its nearest-discrete-state margin `m ≳ ε + σ·Φ⁻¹(τ)` (corroborated by `r_margin_diagnostics.py`).
Across the whole ablation grid **certified_false_allow = C_allow = U_allow = 0**; only R_allow varies.
Stable recommended setting: **σ≈0.075–0.10, τ=0.95, n_mc=5000**.

## Result (σ=0.10, ε=0.10, τ=0.95, n_mc=5000)
```
certificate_type  : enumerate_discrete_gaussian_rs
certified FALSE allow  : 0.000  <- SOUND (up to confidence 1-alpha)
certified allow by cat : A=0  B=0  C=0  R>0 (non-vacuous)  U=0
```
The certificate **refuses C and U** (and the near-boundary A/B) and **allows a non-vacuous fraction of
R** robust-interior points — sound and non-vacuous. This is the MVP certificate; the discrete channel
is certified by exact enumeration, not smoothing. A full hybrid Neyman–Pearson product certificate is
possible future work (it would only *tighten* the conservative min-over-states bound), **not** a
required next step.
