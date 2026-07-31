# EXP-B1 — δ-sensitivity of C prevalence (min(δ,ε) law on real data)

W3, , . ieee_cis_policy.analytic_category, nab_policy.analytic_category (analytic taxonomy only). ε=0.1, seeds=[0, 1, 2].

**Conditionality.** Prevalence UNDER a provenance-conditioned threshold gap δ, tracking min(δ,ε) — NOT deployed prevalence. Natural sampling on the real gate pool; the C rate scales with the boundary density × min(δ,ε).

### ieee_cis (θ_base=0.488808)

| δ | min(δ,ε) | Pr(A) | Pr(B) | **Pr(C)** | Pr(R) | Pr(U) | exact cert FA |
|--:|--:|--:|--:|--:|--:|--:|--:|
| 0.02 | 0.02 | 0.008321 | 0.118179 | **0.011267±0.006654** | 0.568422 | 0.293812 | 0.0 |
| 0.05 | 0.05 | 0.019762 | 0.107276 | **0.02217±0.013441** | 0.568422 | 0.282371 | 0.0 |
| 0.08 | 0.08 | 0.029388 | 0.096018 | **0.033428±0.020249** | 0.568422 | 0.272745 | 0.0 |
| 0.15 | 0.1 | 0.043282 | 0.088971 | **0.040474±0.024299** | 0.568422 | 0.25885 | 0.0 |
| 0.3 | 0.1 | 0.079296 | 0.088971 | **0.040474±0.024299** | 0.568422 | 0.222838 | 0.0 |

Law check: monotone→ε **True**, saturation span above ε **0.0**, corr(Pr(C), min(δ,ε)) **1.0**, tracks_law **True**; exact cert_false_allow max **0.0**.

### nab (θ_base=0.33343)

| δ | min(δ,ε) | Pr(A) | Pr(B) | **Pr(C)** | Pr(R) | Pr(U) | exact cert FA |
|--:|--:|--:|--:|--:|--:|--:|--:|
| 0.02 | 0.02 | 0.037016 | 0.237505 | **0.001599±0.000196** | 0.460905 | 0.262975 | 0.0 |
| 0.05 | 0.05 | 0.061046 | 0.227283 | **0.011821±0.00224** | 0.460905 | 0.238945 | 0.0 |
| 0.08 | 0.08 | 0.077756 | 0.129986 | **0.109118±0.020079** | 0.460905 | 0.222235 | 0.0 |
| 0.15 | 0.1 | 0.131058 | 0.04829 | **0.190814±0.036006** | 0.460905 | 0.168933 | 0.0 |
| 0.3 | 0.1 | 0.153307 | 0.04829 | **0.190814±0.036006** | 0.460905 | 0.146684 | 0.0 |

Law check: monotone→ε **True**, saturation span above ε **0.0**, corr(Pr(C), min(δ,ε)) **0.9564**, tracks_law **True**; exact cert_false_allow max **0.0**.

**Verdict.** VERIFIED PREDICTION: Pr(C) tracks min(δ,ε) on both real datasets (monotone to δ=ε, saturates above) and the exact certificate stays sound (cert_false_allow=0) at every δ → the C rate is a δ-parameterised prediction of Theorem 1, not a single-δ artifact.
