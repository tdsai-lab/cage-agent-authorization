# M5 — Prop. 3 boundary-mass check on real clipped/quantized marginals

Empirical mass within 1e-6 of every certificate boundary of the signed margin g_t = value − θ_t, on the REAL IEEE-CIS and NAB natural gate pools (ε=0.1, δ=0.08, 3 seeds). Both oracles use CLOSED inequalities (unsafe ⟺ m ≥ 0), so any boundary record is BLOCKED — positive mass costs abstention, never a false-allow.

- ieee_cis: 885809 record-evaluations over 3 seeds
- nab: 87556 record-evaluations over 3 seeds

| dataset | boundary | on-boundary k/N | mass fraction | soundness side |
|---|---|---|---|---|
| ieee_cis | clean_boundary (g_self=0) | 0/885809 | 0.00e+00 | blocked (unsafe-closed) — abstention only, never false-allow |
| ieee_cis | continuous_flip (g_self=-eps) | 7/885809 | 7.90e-06 | blocked (unsafe-closed) — abstention only, never false-allow |
| ieee_cis | joint_neighbor_clean (g_nbr=0) | 1/885809 | 1.13e-06 | blocked (unsafe-closed) — abstention only, never false-allow |
| ieee_cis | joint_neighbor_flip (g_nbr=-eps) | 3/885809 | 3.39e-06 | blocked (unsafe-closed) — abstention only, never false-allow |
| ieee_cis | value_clip_lo (value=0) | 0/885809 | 0.00e+00 | blocked (unsafe-closed) — abstention only, never false-allow |
| ieee_cis | value_clip_hi (value=1) | 0/885809 | 0.00e+00 | blocked (unsafe-closed) — abstention only, never false-allow |
| ieee_cis | theta_clip_lo (theta=0.05) | 0/885809 | 0.00e+00 | blocked (unsafe-closed) — abstention only, never false-allow |
| ieee_cis | theta_clip_hi (theta=0.95) | 0/885809 | 0.00e+00 | blocked (unsafe-closed) — abstention only, never false-allow |
| nab | clean_boundary (g_self=0) | 0/87556 | 0.00e+00 | blocked (unsafe-closed) — abstention only, never false-allow |
| nab | continuous_flip (g_self=-eps) | 1/87556 | 1.14e-05 | blocked (unsafe-closed) — abstention only, never false-allow |
| nab | joint_neighbor_clean (g_nbr=0) | 3/87556 | 3.43e-05 | blocked (unsafe-closed) — abstention only, never false-allow |
| nab | joint_neighbor_flip (g_nbr=-eps) | 0/87556 | 0.00e+00 | blocked (unsafe-closed) — abstention only, never false-allow |
| nab | value_clip_lo (value=0) | 0/87556 | 0.00e+00 | blocked (unsafe-closed) — abstention only, never false-allow |
| nab | value_clip_hi (value=1) | 643/87556 | 7.34e-03 | blocked (unsafe-closed) — abstention only, never false-allow |
| nab | theta_clip_lo (theta=0.05) | 0/87556 | 0.00e+00 | blocked (unsafe-closed) — abstention only, never false-allow |
| nab | theta_clip_hi (theta=0.95) | 0/87556 | 0.00e+00 | blocked (unsafe-closed) — abstention only, never false-allow |

**Verdict.** Non-zero boundary mass detected: ieee_cis/continuous_flip (g_self=-eps) = 7/885809; ieee_cis/joint_neighbor_clean (g_nbr=0) = 1/885809; ieee_cis/joint_neighbor_flip (g_nbr=-eps) = 3/885809; nab/continuous_flip (g_self=-eps) = 1/87556; nab/joint_neighbor_clean (g_nbr=0) = 3/87556; nab/value_clip_hi (value=1) = 643/87556. Prop. 3's Pr[m=ε]=0 assumption does NOT hold exactly on these quantized/clipped marginals → state the proposition with the conservative closed inequality (unsafe ⟺ m ≥ 0). Soundness is unaffected because the closed form already blocks these records; the only effect is a measured amount of extra abstention.
