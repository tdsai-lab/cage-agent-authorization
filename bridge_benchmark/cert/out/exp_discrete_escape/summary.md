# T1-2 — Discrete escape rate (symmetric twin of the freshness/continuous escape)

Params: eps=0.1, n=4000, seeds=[0, 1, 2], sigma=0.1, tau=0.9, alpha_FWER=0.001.


## (1) Leave-one-fault-out escape from the declared neighborhood N_d^{-M} x B_eps

For each held-out mechanism M, N_d is built from the OTHER discrete mechanisms; M-faults are injected and we measure Pr[realized z' not in N_d^{-M} x B_eps].

| mechanism | channel | substrate | n | escape_rate (mean +/- std) |
|---|---|---|---:|---:|
| wrong_provenance_binding | discrete | ieee_cis | 4000 | 0.000 +/- 0.000 |
| wrong_policy_pack | discrete | ieee_cis | 4000 | 0.000 +/- 0.000 |
| toctou_env_label | discrete | ieee_cis | 4000 | 0.000 +/- 0.000 |
| schema_skew | continuous(x2) | ieee_cis | 4000 | 0.811 +/- 0.004 |
| cache_key_collision | continuous(x2) | ieee_cis | 4000 | 0.982 +/- 0.002 |
| wrong_provenance_binding | discrete | financial_compliance | 4000 | 0.000 +/- 0.000 |
| wrong_policy_pack | discrete | financial_compliance | 4000 | 0.000 +/- 0.000 |
| toctou_env_label | discrete | financial_compliance | 4000 | 0.000 +/- 0.000 |
| schema_skew | continuous(x2) | financial_compliance | 4000 | 0.861 +/- 0.004 |
| cache_key_collision | continuous(x2) | financial_compliance | 4000 | 1.000 +/- 0.000 |
| wrong_provenance_binding | discrete | sre_monitoring | 4000 | 0.000 +/- 0.000 |
| wrong_policy_pack | discrete | sre_monitoring | 4000 | 0.000 +/- 0.000 |
| toctou_env_label | discrete | sre_monitoring | 4000 | 0.000 +/- 0.000 |
| schema_skew | continuous(x2) | sre_monitoring | 4000 | 0.865 +/- 0.003 |
| cache_key_collision | continuous(x2) | sre_monitoring | 4000 | 0.999 +/- 0.001 |

## (2) Over-declaration cost: R_allow vs |N_d| (K inert branches added)

| K | num_branches | alpha_branch | R_allow (mean +/- std) |
|---:|---:|---:|---:|
| 0 | 3 | 3.33e-04 | 0.172 +/- 0.030 |
| 1 | 4 | 2.50e-04 | 0.109 +/- 0.006 |
| 2 | 5 | 2.00e-04 | 0.051 +/- 0.010 |
| 4 | 7 | 1.43e-04 | 0.012 +/- 0.003 |
| 8 | 11 | 9.09e-05 | 0.002 +/- 0.001 |

**Read.** Provenance/policy/TOCTOU held-out escape ~ 0: their discrete edges are redundantly covered by the remaining mechanisms' vocab, so removing one still lands the realized state inside N_d -> the declared neighborhood is COMPLETE for the discrete mechanisms. schema_skew and cache_key_collision escape with nonzero rate: they move x2 past eps (they have no discrete footprint), i.e. they are the OUT-of-budget tail already scoped to the validation layer (#16) — the result CONFIRMS the scoping. Widening N_d to absorb them is not free: part (2) shows R_allow decreasing monotonically in |N_d| (more min-over-states branches + smaller family-wise alpha_branch). The budget is measured, the escape is measured — now on BOTH channels (continuous EXP2-A + this discrete one).

