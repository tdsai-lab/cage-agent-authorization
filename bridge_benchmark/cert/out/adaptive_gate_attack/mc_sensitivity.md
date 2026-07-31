# TM2 Monte-Carlo sensitivity (n_mc x seed)

n=8000/domain, n_attack=60/category, eps=0.1, sigma=0.1, tau=0.9, seeds=[0, 1, 2]. The certificate is statistical; soundness metrics stay 0 across MC budgets and seeds, while R_allow (utility) varies, especially at low n_mc.

## Per (domain, n_mc, seed)

| domain | n_mc | seed | certified_adaptive_false_allow | cert_false_allow | C_allow | U_allow | R_allow |
| --- | --- | --- | --- | --- | --- | --- | --- |
| finance_compliance | 500 | 0 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| finance_compliance | 500 | 1 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| finance_compliance | 500 | 2 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| finance_compliance | 1500 | 0 | 0.0 | 0.0 | 0.0 | 0.0 | 0.4167 |
| finance_compliance | 1500 | 1 | 0.0 | 0.0 | 0.0 | 0.0 | 0.4667 |
| finance_compliance | 1500 | 2 | 0.0 | 0.0 | 0.0 | 0.0 | 0.5667 |
| finance_compliance | 5000 | 0 | 0.0 | 0.0 | 0.0 | 0.0 | 0.5333 |
| finance_compliance | 5000 | 1 | 0.0 | 0.0 | 0.0 | 0.0 | 0.5 |
| finance_compliance | 5000 | 2 | 0.0 | 0.0 | 0.0 | 0.0 | 0.6333 |
| sre_monitoring | 500 | 0 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| sre_monitoring | 500 | 1 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| sre_monitoring | 500 | 2 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| sre_monitoring | 1500 | 0 | 0.0 | 0.0 | 0.0 | 0.0 | 0.2333 |
| sre_monitoring | 1500 | 1 | 0.0 | 0.0 | 0.0 | 0.0 | 0.2 |
| sre_monitoring | 1500 | 2 | 0.0 | 0.0 | 0.0 | 0.0 | 0.2667 |
| sre_monitoring | 5000 | 0 | 0.0 | 0.0 | 0.0 | 0.0 | 0.2667 |
| sre_monitoring | 5000 | 1 | 0.0 | 0.0 | 0.0 | 0.0 | 0.2333 |
| sre_monitoring | 5000 | 2 | 0.0 | 0.0 | 0.0 | 0.0 | 0.3333 |
| ops_security | 500 | 0 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| ops_security | 500 | 1 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| ops_security | 500 | 2 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| ops_security | 1500 | 0 | 0.0 | 0.0 | 0.0 | 0.0 | 0.3333 |
| ops_security | 1500 | 1 | 0.0 | 0.0 | 0.0 | 0.0 | 0.3 |
| ops_security | 1500 | 2 | 0.0 | 0.0 | 0.0 | 0.0 | 0.25 |
| ops_security | 5000 | 0 | 0.0 | 0.0 | 0.0 | 0.0 | 0.3667 |
| ops_security | 5000 | 1 | 0.0 | 0.0 | 0.0 | 0.0 | 0.3167 |
| ops_security | 5000 | 2 | 0.0 | 0.0 | 0.0 | 0.0 | 0.3667 |

## R_allow mean ± std over seeds

| domain | n_mc | mean_R_allow | std_R_allow |
| --- | --- | --- | --- |
| finance_compliance | 500 | 0.0000 | 0.0000 |
| finance_compliance | 1500 | 0.4834 | 0.0624 |
| finance_compliance | 5000 | 0.5555 | 0.0566 |
| ops_security | 500 | 0.0000 | 0.0000 |
| ops_security | 1500 | 0.2944 | 0.0342 |
| ops_security | 5000 | 0.3500 | 0.0236 |
| sre_monitoring | 500 | 0.0000 | 0.0000 |
| sre_monitoring | 1500 | 0.2333 | 0.0272 |
| sre_monitoring | 5000 | 0.2778 | 0.0416 |

**Reading.** `certified_adaptive_false_allow = cert_false_allow = C_allow = U_allow = 0` across every (n_mc, seed) — soundness is stable. `R_allow` varies (larger and noisier at low n_mc), reflecting the finite-sample confidence procedure; we do not claim finite-MC perfection beyond the Clopper–Pearson bound actually used.

