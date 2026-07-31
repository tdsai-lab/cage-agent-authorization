# TM2 adaptive attack on the learned gate; certified-gate defense

Adversary knows g_theta, B_{1,eps}, tau, Safe and searches for z* in B_{1,eps}(z) that is truly unsafe yet allowed. **The learned gate has false allows; the certified gate removes them while staying non-vacuous on R.** Node-level robustness of the post-return gate only (not end-to-end agent robustness).

n=20000 records/domain, n_attack=200/category, eps=0.1, sigma=0.1, tau=0.9, n_mc=1500, seed=0. Deterministic d=1 enumeration + numeric ring search. Certificate = enumerate_discrete_gaussian_rs (no discrete smoothing).

## Per-domain summary (category = ALL)

| domain | learned_adaptive_false_allow | certified_adaptive_false_allow | naive_C_falseallow | C_allow | R_allow | U_allow | cert_false_allow |
| --- | --- | --- | --- | --- | --- | --- | --- |
| finance_compliance | 0.0167 | 0.0 | 1.0 | 0.0 | 0.495 | 0.0 | 0.0 |
| sre_monitoring | 0.15 | 0.0 | 1.0 | 0.0 | 0.28 | 0.0 | 0.0 |
| ops_security | 0.0433 | 0.0 | 1.0 | 0.0 | 0.23 | 0.0 | 0.0 |

## Per-(domain, category) breakdown

| domain | category | n | learned_adaptive_false_allow | certified_adaptive_false_allow | naive_C_falseallow | C_allow | R_allow | U_allow | cert_false_allow |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| finance_compliance | C | 200 | 0.005 | 0.0 | 1.0 |  |  |  | 0.0 |
| finance_compliance | R | 200 | 0.0 | 0.0 |  |  |  |  | 0.0 |
| finance_compliance | U | 200 | 0.045 | 0.0 |  |  |  |  | 0.0 |
| sre_monitoring | C | 200 | 0.12 | 0.0 | 1.0 |  |  |  | 0.0 |
| sre_monitoring | R | 200 | 0.0 | 0.0 |  |  |  |  | 0.0 |
| sre_monitoring | U | 200 | 0.33 | 0.0 |  |  |  |  | 0.0 |
| ops_security | C | 200 | 0.035 | 0.0 | 1.0 |  |  |  | 0.0 |
| ops_security | R | 200 | 0.0 | 0.0 |  |  |  |  | 0.0 |
| ops_security | U | 200 | 0.095 | 0.0 |  |  |  |  | 0.0 |

**Expected pattern:** learned_adaptive_false_allow > 0; naive_C_falseallow high on C; certified_adaptive_false_allow = 0; R_allow > 0; C_allow = U_allow = cert_false_allow = 0.

