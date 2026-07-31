# EXP-OPA-FULL — full authored-policy robustness/utility sweep with REAL OPA labels

Labels and the A/B/C/R/U category of every typed return come from the **OPA engine** (v1.17.1, `opa eval`), not the analytic generator (`policy_provenance = authored_rego`). The certified post-return gate is certified per record over B_{1,ε} with a **family-wise** Clopper–Pearson level (`alpha_branch = alpha_FWER / num_branches`).

Sweep: domains=['finance', 'sre', 'ops'], backends=['smoothing', 'lipschitz'], seeds=[0, 1, 2], epsilons=[0.05, 0.1], taus=[0.9, 0.95]; n_train=1000, n_eval=300, n_mc=1500, sigma=0.1, scheme=natural. 10800 per-example records.

## FWER accounting (logged)

`alpha_FWER = 0.001`. The family per record is the discrete neighborhood `{identity} ∪ N_1(s)`; `num_branches` ∈ [8, 8] (median 8), so per-branch Clopper–Pearson levels are `alpha_branch ∈ [1.25e-04, 1.25e-04]` (median 1.25e-04). This is the exact per-record accounting reused from `run_opa_gate.py` (Bonferroni union bound over the enumerated swaps).

## Main table — per (domain, backend, eps, tau), mean ± std across seeds

| domain | backend | eps | tau | clean_acc | C% | R% | U% | C_allow | U_allow | **R_allow** | cert_FA | naive_C | attack_FA | accept |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| finance | lipschitz | 0.05 | 0.9 | 0.837±0.004 | 0.056±0.008 | 0.442±0.010 | 0.346±0.007 | 0.000±0.000 | 0.000±0.000 | **0.441±0.058** | 0.000±0.000 | 1.000±0.000 | 0.298±0.037 | ✅ |
| finance | lipschitz | 0.05 | 0.95 | 0.837±0.004 | 0.056±0.008 | 0.442±0.010 | 0.346±0.007 | 0.000±0.000 | 0.000±0.000 | **0.441±0.058** | 0.000±0.000 | 1.000±0.000 | 0.298±0.037 | ✅ |
| finance | lipschitz | 0.1 | 0.9 | 0.837±0.004 | 0.120±0.012 | 0.341±0.006 | 0.346±0.007 | 0.000±0.000 | 0.000±0.000 | **0.360±0.095** | 0.000±0.000 | 1.000±0.000 | 0.381±0.029 | ✅ |
| finance | lipschitz | 0.1 | 0.95 | 0.837±0.004 | 0.120±0.012 | 0.341±0.006 | 0.346±0.007 | 0.000±0.000 | 0.000±0.000 | **0.360±0.095** | 0.000±0.000 | 1.000±0.000 | 0.381±0.029 | ✅ |
| finance | smoothing | 0.05 | 0.9 | 0.995±0.007 | 0.056±0.008 | 0.442±0.010 | 0.346±0.007 | 0.000±0.000 | 0.000±0.000 | **0.354±0.032** | 0.000±0.000 | 1.000±0.000 | 0.378±0.028 | ✅ |
| finance | smoothing | 0.05 | 0.95 | 0.995±0.007 | 0.056±0.008 | 0.442±0.010 | 0.346±0.007 | 0.000±0.000 | 0.000±0.000 | **0.123±0.030** | 0.000±0.000 | 1.000±0.000 | 0.378±0.028 | ✅ |
| finance | smoothing | 0.1 | 0.9 | 0.995±0.007 | 0.120±0.012 | 0.341±0.006 | 0.346±0.007 | 0.000±0.000 | 0.000±0.000 | **0.068±0.020** | 0.000±0.000 | 1.000±0.000 | 0.474±0.022 | ✅ |
| finance | smoothing | 0.1 | 0.95 | 0.995±0.007 | 0.120±0.012 | 0.341±0.006 | 0.346±0.007 | 0.000±0.000 | 0.000±0.000 | **0.000±0.000** | 0.000±0.000 | 1.000±0.000 | 0.474±0.022 | ⚠️ |
| ops | lipschitz | 0.05 | 0.9 | 0.844±0.009 | 0.056±0.008 | 0.442±0.010 | 0.346±0.007 | 0.000±0.000 | 0.000±0.000 | **0.466±0.067** | 0.000±0.000 | 1.000±0.000 | 0.298±0.042 | ✅ |
| ops | lipschitz | 0.05 | 0.95 | 0.844±0.009 | 0.056±0.008 | 0.442±0.010 | 0.346±0.007 | 0.000±0.000 | 0.000±0.000 | **0.466±0.067** | 0.000±0.000 | 1.000±0.000 | 0.298±0.042 | ✅ |
| ops | lipschitz | 0.1 | 0.9 | 0.844±0.009 | 0.120±0.012 | 0.341±0.006 | 0.346±0.007 | 0.000±0.000 | 0.000±0.000 | **0.393±0.094** | 0.000±0.000 | 1.000±0.000 | 0.381±0.035 | ✅ |
| ops | lipschitz | 0.1 | 0.95 | 0.844±0.009 | 0.120±0.012 | 0.341±0.006 | 0.346±0.007 | 0.000±0.000 | 0.000±0.000 | **0.393±0.094** | 0.000±0.000 | 1.000±0.000 | 0.381±0.035 | ✅ |
| ops | smoothing | 0.05 | 0.9 | 0.991±0.012 | 0.056±0.008 | 0.442±0.010 | 0.346±0.007 | 0.000±0.000 | 0.000±0.000 | **0.359±0.013** | 0.000±0.000 | 1.000±0.000 | 0.376±0.035 | ✅ |
| ops | smoothing | 0.05 | 0.95 | 0.991±0.012 | 0.056±0.008 | 0.442±0.010 | 0.346±0.007 | 0.000±0.000 | 0.000±0.000 | **0.140±0.040** | 0.000±0.000 | 1.000±0.000 | 0.376±0.035 | ✅ |
| ops | smoothing | 0.1 | 0.9 | 0.991±0.012 | 0.120±0.012 | 0.341±0.006 | 0.346±0.007 | 0.000±0.000 | 0.000±0.000 | **0.071±0.018** | 0.000±0.000 | 1.000±0.000 | 0.472±0.028 | ✅ |
| ops | smoothing | 0.1 | 0.95 | 0.991±0.012 | 0.120±0.012 | 0.341±0.006 | 0.346±0.007 | 0.000±0.000 | 0.000±0.000 | **0.000±0.000** | 0.000±0.000 | 1.000±0.000 | 0.472±0.028 | ⚠️ |
| sre | lipschitz | 0.05 | 0.9 | 0.864±0.011 | 0.056±0.008 | 0.442±0.010 | 0.346±0.007 | 0.000±0.000 | 0.000±0.000 | **0.506±0.070** | 0.000±0.000 | 1.000±0.000 | 0.320±0.041 | ✅ |
| sre | lipschitz | 0.05 | 0.95 | 0.864±0.011 | 0.056±0.008 | 0.442±0.010 | 0.346±0.007 | 0.000±0.000 | 0.000±0.000 | **0.506±0.070** | 0.000±0.000 | 1.000±0.000 | 0.320±0.041 | ✅ |
| sre | lipschitz | 0.1 | 0.9 | 0.864±0.011 | 0.120±0.012 | 0.341±0.006 | 0.346±0.007 | 0.000±0.000 | 0.000±0.000 | **0.400±0.093** | 0.000±0.000 | 1.000±0.000 | 0.406±0.030 | ✅ |
| sre | lipschitz | 0.1 | 0.95 | 0.864±0.011 | 0.120±0.012 | 0.341±0.006 | 0.346±0.007 | 0.000±0.000 | 0.000±0.000 | **0.400±0.093** | 0.000±0.000 | 1.000±0.000 | 0.406±0.030 | ✅ |
| sre | smoothing | 0.05 | 0.9 | 0.997±0.002 | 0.056±0.008 | 0.442±0.010 | 0.346±0.007 | 0.000±0.000 | 0.000±0.000 | **0.353±0.036** | 0.000±0.000 | 1.000±0.000 | 0.378±0.019 | ✅ |
| sre | smoothing | 0.05 | 0.95 | 0.997±0.002 | 0.056±0.008 | 0.442±0.010 | 0.346±0.007 | 0.000±0.000 | 0.000±0.000 | **0.127±0.049** | 0.000±0.000 | 1.000±0.000 | 0.378±0.019 | ✅ |
| sre | smoothing | 0.1 | 0.9 | 0.997±0.002 | 0.120±0.012 | 0.341±0.006 | 0.346±0.007 | 0.000±0.000 | 0.000±0.000 | **0.045±0.022** | 0.000±0.000 | 1.000±0.000 | 0.474±0.013 | ✅ |
| sre | smoothing | 0.1 | 0.95 | 0.997±0.002 | 0.120±0.012 | 0.341±0.006 | 0.346±0.007 | 0.000±0.000 | 0.000±0.000 | **0.000±0.000** | 0.000±0.000 | 1.000±0.000 | 0.474±0.013 | ⚠️ |

## Acceptance target (C_allow=U_allow=cert_false_allow=0, R_allow>0)

**3/24 cells flagged** (reported, not hidden):

- finance/smoothing eps=0.1 tau=0.95: R_allow=0.0 (vacuous: ε/σ or τ too strict for this geometry)
- ops/smoothing eps=0.1 tau=0.95: R_allow=0.0 (vacuous: ε/σ or τ too strict for this geometry)
- sre/smoothing eps=0.1 tau=0.95: R_allow=0.0 (vacuous: ε/σ or τ too strict for this geometry)

Diagnosis note: a vacuous `R_allow=0` is a *utility* (not soundness) failure — it means the strict operating point (large ε/σ or τ) leaves no certifiable robust band for this policy geometry; soundness (`cert_false_allow=0`) is preserved. `C_allow>0`/`U_allow>0`/`cert_false_allow>0` would be soundness failures (none expected; if seen, check learned-gate fidelity, MC budget, or an OPA-label mismatch).

**Reading.** Utility (`R_allow`) decreases as ε grows toward σ and as τ tightens (see `utility_curve_epsilon.csv` / `utility_curve_tau.csv`); soundness (`C_allow=U_allow=cert_false_allow=0`) is invariant. The smoothing backend is a black-box certificate (any `predict_proba` gate); the deterministic 1-Lipschitz backend is sampling-free and can recover more R utility in this low-dimensional OPA setting. `naive_C_falseallow≈1` is a definitional sanity check (C passes each marginal but fails jointly); `attack_false_allow` is the uncertified learned point-gate's in-budget exploit rate that the certificate closes.

