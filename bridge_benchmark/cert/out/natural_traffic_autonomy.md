# S50 (M2 / R3) — natural-traffic autonomy accounting

R_allow is CONDITIONAL on the robust-safe set R; here it is restated as UNCONDITIONAL certified-autonomy on natural traffic (`Pr[R]·R_allow`), with the implied human-review volume and the natural hazard prevalence Pr[C] the gate must catch. ε=0.1, δ=0.08.

| setting | rung/backend | Pr[R] | Pr[C] hazard | R_allow (cond.) | uncond. certified-allow | human-review volume |
|---|---|---|---|---|---|---|
| IEEE-CIS (real fraud risk) | exact (rung 1) | 0.568 | 0.033 | 1.000 | **0.568** | 0.432 |
| NAB (real EC2/RDS CPU) | Lipschitz (rung 2) | 0.461 | 0.109 | 1.000 | **0.461** | 0.539 |
| NAB (real EC2/RDS CPU) | RS (rung 2, ablation) | 0.461 | 0.109 | 1.000 | **0.461** | 0.539 |
| NAB (real EC2/RDS CPU) | exact (rung 1) | 0.461 | 0.109 | 1.000 | **0.461** | 0.539 |
| REG psd2_low_value (PSD2/AML) | smoothed (rung 2) | 0.258 | 0.098 | 0.338 | **0.087** | 0.913 |
| REG psd2_tra (PSD2/AML) | smoothed (rung 2) | 0.102 | 0.080 | 0.195 | **0.020** | 0.980 |
| REG aml_ctr (PSD2/AML) | smoothed (rung 2) | 0.273 | 0.065 | 0.338 | **0.092** | 0.908 |
| OPA Track-C finance (policy-as-code) | Lipschitz (rung 2) | 0.341 | 0.120 | 0.360 | **0.123** | 0.877 |
| OPA Track-C ops (policy-as-code) | Lipschitz (rung 2) | 0.341 | 0.120 | 0.393 | **0.134** | 0.866 |
| OPA Track-C sre (policy-as-code) | Lipschitz (rung 2) | 0.341 | 0.120 | 0.400 | **0.136** | 0.864 |

**§6.4 takeaway sentence.** On natural traffic the exact rung-1 certificate autonomously clears 57% (IEEE-CIS) to 46% (NAB) of decisions with a certificate, routing the rest to human review — so a 'low' conditional R_allow still corresponds to a substantial, auditable autonomy volume, not near-total abstention.
