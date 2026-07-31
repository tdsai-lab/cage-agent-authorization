# PLAN.md #17 — per-domain empirical continuous budget eps_emp (residual after validation)

Discrete budget is `d=1` for all pipelines (every atomic fault is exactly d=1, Pr[d>=2]=0; measured in #16). `eps_emp` = a high quantile of the pooled residual continuous drift that SURVIVES the validation stack.

| pipeline | regime | residual continuous faults | eps p90 | **eps p95** | eps p99 | frac<=0.10 |
|---|---|---|---:|---:|---:|---:|
| fraud_risk | none | cache_key_collision+normalization_skew+numeric_jitter+schema_skew+stale_cache | 0.330 | **0.652** | 1.024 | 0.780 |
| fraud_risk | integrity | normalization_skew+numeric_jitter+stale_cache | 0.114 | **0.193** | 0.460 | 0.878 |
| fraud_risk | integrity_plus_freshness | normalization_skew+numeric_jitter | 0.070 | **0.078** | 0.099 | 0.990 |
| finance_compliance | none | cache_key_collision+normalization_skew+numeric_jitter+schema_skew+stale_cache | 0.399 | **0.692** | 1.084 | 0.580 |
| finance_compliance | integrity | normalization_skew+numeric_jitter+stale_cache | 0.276 | **0.322** | 0.403 | 0.637 |
| finance_compliance | integrity_plus_freshness | normalization_skew+numeric_jitter | 0.083 | **0.093** | 0.114 | 0.967 |
| alerting_monitoring | none | cache_key_collision+normalization_skew+numeric_jitter+schema_skew+stale_cache | 0.407 | **0.742** | 1.095 | 0.575 |
| alerting_monitoring | integrity | normalization_skew+numeric_jitter+stale_cache | 0.276 | **0.323** | 0.424 | 0.634 |
| alerting_monitoring | integrity_plus_freshness | normalization_skew+numeric_jitter | 0.084 | **0.095** | 0.118 | 0.965 |

**Reads.** Under **integrity+freshness** validation the residual is sensor/re-read jitter + normalizer skew, whose p95 ~ 0.09-0.10 -> **eps=0.10 is well-calibrated**. Under **integrity only** (no freshness check) same-surface staleness survives and the p95 grows (driven by stale reads) -> the realistic radius is larger, which is exactly what #20 re-sweeps. The discrete budget stays d=1 throughout. Per-validation-stage eps shrink is #19.
