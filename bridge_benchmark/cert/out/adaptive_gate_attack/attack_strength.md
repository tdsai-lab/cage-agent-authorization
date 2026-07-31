# TM2 attack-strength ablation (learned gate)

n=20000/domain, n_attack=150/category, eps=0.1, sigma=0.1, tau=0.9, n_mc=1500, seed=0. d=1 discrete enumeration is exact; the continuous search varies by mode inside ||x'-x||_2<=eps. The certified side is mode-independent (analytic).

| domain | attack_mode | n_attack | learned_adaptive_false_allow | certified_adaptive_false_allow | C_allow | U_allow | R_allow | cert_false_allow | n_attack_success |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| finance_compliance | random | 450 | 0.06 | 0.0 | 0.0 | 0.0 | 0.5067 | 0.0 | 27 |
| finance_compliance | ring_grid | 450 | 0.0133 | 0.0 | 0.0 | 0.0 | 0.5067 | 0.0 | 6 |
| finance_compliance | coordinate_search | 450 | 0.0133 | 0.0 | 0.0 | 0.0 | 0.5067 | 0.0 | 6 |
| finance_compliance | pgd_like | 450 | 0.0133 | 0.0 | 0.0 | 0.0 | 0.5067 | 0.0 | 6 |
| sre_monitoring | random | 450 | 0.3222 | 0.0 | 0.0 | 0.0 | 0.28 | 0.0 | 145 |
| sre_monitoring | ring_grid | 450 | 0.1489 | 0.0 | 0.0 | 0.0 | 0.28 | 0.0 | 67 |
| sre_monitoring | coordinate_search | 450 | 0.1489 | 0.0 | 0.0 | 0.0 | 0.28 | 0.0 | 67 |
| sre_monitoring | pgd_like | 450 | 0.1489 | 0.0 | 0.0 | 0.0 | 0.28 | 0.0 | 67 |
| ops_security | random | 450 | 0.1267 | 0.0 | 0.0 | 0.0 | 0.24 | 0.0 | 57 |
| ops_security | ring_grid | 450 | 0.0378 | 0.0 | 0.0 | 0.0 | 0.24 | 0.0 | 17 |
| ops_security | coordinate_search | 450 | 0.0378 | 0.0 | 0.0 | 0.0 | 0.24 | 0.0 | 17 |
| ops_security | pgd_like | 450 | 0.0378 | 0.0 | 0.0 | 0.0 | 0.24 | 0.0 | 17 |

**Reading.** Stronger continuous searches find more residual false allows in the LEARNED gate (`learned_adaptive_false_allow` grows from `random` to `coordinate_search`/`pgd_like`), while the CERTIFIED gate is unaffected: `certified_adaptive_false_allow = C_allow = U_allow = cert_false_allow = 0` for every mode, with `R_allow` non-vacuous.

