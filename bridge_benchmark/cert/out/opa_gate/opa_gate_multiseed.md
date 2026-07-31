# OPA-gate experiment — multi-seed (mean ± std over seeds)

Full mode, seeds = [0, 1, 2, 3, 4] (5 per domain). Labels + A/B/C/R/U from the OPA engine (v1.17.1); `policy_provenance = authored_rego` (authored Rego evaluated by OPA — a **controlled policy-as-code** oracle, **not** a third-party / external-policy bundle). Family-wise Clopper–Pearson confidence.

| domain | n_eval | **C-prevalence** | **R_allow** (ε=0.10) | **cert_false_allow** | C_allow | U_allow |
| --- | --- | --- | --- | --- | --- | --- |
| finance | 400 | **0.112 ± 0.007** | **0.067 ± 0.010** | **0.000 ± 0.000** | 0.000 ± 0.000 | 0.000 ± 0.000 |
| sre | 400 | **0.107 ± 0.016** | **0.073 ± 0.018** | **0.000 ± 0.000** | 0.000 ± 0.000 | 0.000 ± 0.000 |
| ops | 400 | **0.122 ± 0.011** | **0.065 ± 0.017** | **0.000 ± 0.000** | 0.000 ± 0.000 | 0.000 ± 0.000 |

## R_allow vs epsilon (mean ± std over seeds)

| domain | ε=0.03 | ε=0.05 | ε=0.1 |
| --- | --- | --- | --- |
| finance | 0.601 ± 0.024 | 0.473 ± 0.020 | 0.067 ± 0.010 |
| sre | 0.574 ± 0.034 | 0.462 ± 0.032 | 0.073 ± 0.018 |
| ops | 0.578 ± 0.021 | 0.438 ± 0.019 | 0.065 ± 0.017 |

**Reading.** Across seeds, C-witnesses arise spontaneously under the OPA oracle at stable nontrivial prevalence; the certified gate's soundness metrics (`C_allow`, `U_allow`, `cert_false_allow`) are 0 with ~0 variance, and `R_allow` is a stable (if conservative) trade-off that recovers as ε shrinks. **Scope:** authored_rego is controlled policy-as-code evidence — it reduces the analytic-generator-artifact risk but is **not** external-policy validation (which would require a vendored third-party Rego/Gatekeeper bundle).

