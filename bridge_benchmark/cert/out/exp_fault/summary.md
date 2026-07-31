# EXP-FAULT — mechanistic fault-injection / budget calibration

Budget under test: **B_{1,0.1}** (d <= 1 atomic discrete swap AND ||x2 - x2'||_2 <= 0.1). Per-fault records in `per_fault.jsonl`; multi-seed mean+/-std below (1 seed(s), n=400 faults/seed/fault). Oracle labels via generators/oracle.py on the oracle-aware substrates (financial_compliance, ieee_cis, sre_monitoring).

## Drift granularity (d) and continuous radius (eps)

| substrate | fault | class | Pr[d=0] | Pr[d=1] | Pr[d>=2] | eps p50 | eps p90 | eps p95 | frac in B_1,0.1 |
|---|---|---|---:|---:|---:|---:|---:|---:|---:|
| financial_compliance | toctou_env_label | discrete | 0.000 | 1.000 | 0.000 | 0.000 | 0.000 | 0.000 | 1.000 |
| financial_compliance | wrong_policy_pack | discrete | 0.000 | 1.000 | 0.000 | 0.000 | 0.000 | 0.000 | 1.000 |
| financial_compliance | wrong_provenance_binding | discrete | 0.000 | 1.000 | 0.000 | 0.000 | 0.000 | 0.000 | 1.000 |
| financial_compliance | cache_key_collision | out_of_budget | 1.000 | 0.000 | 0.000 | 0.783 | 1.107 | 1.177 | 0.000 |
| financial_compliance | normalization_skew | in_budget | 1.000 | 0.000 | 0.000 | 0.049 | 0.097 | 0.111 | 0.915 |
| financial_compliance | numeric_jitter | in_budget | 1.000 | 0.000 | 0.000 | 0.051 | 0.080 | 0.089 | 0.988 |
| financial_compliance | schema_skew | out_of_budget | 1.000 | 0.000 | 0.000 | 0.444 | 0.909 | 1.021 | 0.130 |
| financial_compliance | stale_cache | freshness_removable | 1.000 | 0.000 | 0.000 | 0.227 | 0.331 | 0.378 | 0.030 |
| ieee_cis | toctou_env_label | discrete | 0.000 | 1.000 | 0.000 | 0.000 | 0.000 | 0.000 | 1.000 |
| ieee_cis | wrong_policy_pack | discrete | 0.000 | 1.000 | 0.000 | 0.000 | 0.000 | 0.000 | 1.000 |
| ieee_cis | wrong_provenance_binding | discrete | 0.000 | 1.000 | 0.000 | 0.000 | 0.000 | 0.000 | 1.000 |
| ieee_cis | cache_key_collision | out_of_budget | 1.000 | 0.000 | 0.000 | 0.635 | 1.040 | 1.132 | 0.005 |
| ieee_cis | normalization_skew | in_budget | 1.000 | 0.000 | 0.000 | 0.041 | 0.079 | 0.094 | 0.968 |
| ieee_cis | numeric_jitter | in_budget | 1.000 | 0.000 | 0.000 | 0.045 | 0.066 | 0.073 | 0.998 |
| ieee_cis | schema_skew | out_of_budget | 1.000 | 0.000 | 0.000 | 0.566 | 1.013 | 1.135 | 0.177 |
| ieee_cis | stale_cache | freshness_removable | 1.000 | 0.000 | 0.000 | 0.043 | 0.243 | 0.405 | 0.667 |
| sre_monitoring | toctou_env_label | discrete | 0.000 | 1.000 | 0.000 | 0.000 | 0.000 | 0.000 | 1.000 |
| sre_monitoring | wrong_policy_pack | discrete | 0.000 | 1.000 | 0.000 | 0.000 | 0.000 | 0.000 | 1.000 |
| sre_monitoring | wrong_provenance_binding | discrete | 0.000 | 1.000 | 0.000 | 0.000 | 0.000 | 0.000 | 1.000 |
| sre_monitoring | cache_key_collision | out_of_budget | 1.000 | 0.000 | 0.000 | 0.785 | 1.063 | 1.162 | 0.000 |
| sre_monitoring | normalization_skew | in_budget | 1.000 | 0.000 | 0.000 | 0.049 | 0.092 | 0.107 | 0.927 |
| sre_monitoring | numeric_jitter | in_budget | 1.000 | 0.000 | 0.000 | 0.051 | 0.081 | 0.090 | 0.988 |
| sre_monitoring | schema_skew | out_of_budget | 1.000 | 0.000 | 0.000 | 0.412 | 0.957 | 1.125 | 0.122 |
| sre_monitoring | stale_cache | freshness_removable | 1.000 | 0.000 | 0.000 | 0.225 | 0.358 | 0.404 | 0.028 |

## Oracle category transitions (oracle-aware substrates)

| substrate | fault | Pr[Safe!=Safe'] | Pr[Safe->Unsafe] | Pr[R->C] | Pr[C->U] | Pr[R->U] |
|---|---|---:|---:|---:|---:|---:|
| financial_compliance | toctou_env_label | 0.030 | 0.010 | 0.005 | 0.000 | 0.000 |
| financial_compliance | wrong_policy_pack | 0.025 | 0.010 | 0.015 | 0.000 | 0.000 |
| financial_compliance | wrong_provenance_binding | 0.323 | 0.150 | 0.010 | 0.000 | 0.000 |
| financial_compliance | cache_key_collision | 0.380 | 0.193 | 0.013 | 0.020 | 0.072 |
| financial_compliance | normalization_skew | 0.048 | 0.028 | 0.015 | 0.000 | 0.000 |
| financial_compliance | numeric_jitter | 0.020 | 0.013 | 0.013 | 0.000 | 0.000 |
| financial_compliance | schema_skew | 0.185 | 0.075 | 0.018 | 0.018 | 0.015 |
| financial_compliance | stale_cache | 0.133 | 0.055 | 0.033 | 0.000 | 0.000 |
| ieee_cis | toctou_env_label | 0.000 | 0.000 | 0.000 | 0.000 | 0.000 |
| ieee_cis | wrong_policy_pack | 0.000 | 0.000 | 0.000 | 0.000 | 0.000 |
| ieee_cis | wrong_provenance_binding | 0.212 | 0.182 | 0.000 | 0.000 | 0.000 |
| ieee_cis | cache_key_collision | 0.325 | 0.155 | 0.040 | 0.035 | 0.050 |
| ieee_cis | normalization_skew | 0.022 | 0.020 | 0.010 | 0.000 | 0.000 |
| ieee_cis | numeric_jitter | 0.015 | 0.015 | 0.000 | 0.000 | 0.000 |
| ieee_cis | schema_skew | 0.087 | 0.052 | 0.005 | 0.018 | 0.013 |
| ieee_cis | stale_cache | 0.025 | 0.015 | 0.007 | 0.000 | 0.003 |
| sre_monitoring | toctou_env_label | 0.058 | 0.033 | 0.015 | 0.000 | 0.000 |
| sre_monitoring | wrong_policy_pack | 0.025 | 0.005 | 0.003 | 0.000 | 0.000 |
| sre_monitoring | wrong_provenance_binding | 0.417 | 0.225 | 0.010 | 0.000 | 0.000 |
| sre_monitoring | cache_key_collision | 0.375 | 0.160 | 0.005 | 0.020 | 0.018 |
| sre_monitoring | normalization_skew | 0.030 | 0.018 | 0.005 | 0.000 | 0.000 |
| sre_monitoring | numeric_jitter | 0.033 | 0.015 | 0.005 | 0.000 | 0.000 |
| sre_monitoring | schema_skew | 0.203 | 0.125 | 0.013 | 0.010 | 0.000 |
| sre_monitoring | stale_cache | 0.122 | 0.062 | 0.018 | 0.005 | 0.003 |

## In-budget vs out-of-budget

**Discrete granularity.** Every single discrete fault (wrong_provenance_binding, wrong_policy_pack, toctou_env_label) changes exactly one atom: Pr[d=1]=1, eps=0, and Pr[d>=2]=0. d=1 is therefore the *atomic single-fault granularity* — d>=2 requires two compounded faults, not a single mechanism. This is measured, not asserted.

**In-budget continuous.** After integrity+freshness validation the residual continuous faults are sensor/re-read jitter and normalizer skew (normalization_skew, numeric_jitter); a large fraction of these land within eps=0.1 (see `frac in B_1,0.1`). These are exactly the faults the certificate covers.

**Freshness-removable.** stale_cache (same-surface staleness) sits partly within eps=0.1 under integrity-only validation; a freshness/TTL check removes its tail (#17/derive_epsilon `integrity_plus_freshness` regime). It is in-budget once a freshness SLA is declared.

**Out-of-budget (NOT covered).** cache_key_collision, schema_skew are honestly reported as the out-of-budget tail: schema-skew is a column transposition and cache-key-collision is a wrong-entity serve (arbitrary endpoint fabrication). The certificate does **not** cover arbitrary endpoint fabrication; these are the faults a validation stage (schema-version / key-integrity check) must catch, and #17/derive_epsilon removes them from the residual eps.
