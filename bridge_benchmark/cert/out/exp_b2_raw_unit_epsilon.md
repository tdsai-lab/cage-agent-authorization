# EXP-B2 — raw-unit ε audit

Q6. Normalized ε=0.1 → raw units, at quantiles [0.5, 0.95, 0.99]. Pure post-processing of the Appendix-D normalization; no model/gate/LLM. Log-normalized fields (amount, distance) have an ε-move that GROWS with the operating point (log compression); linear/clip fields (CPU%, C/D/V means) have a constant ε-move = ε·cap.

**Headline.** A normalized ε=0.1 step in amount_norm is ~$70.8353 at the median TransactionAmt, ~$452.8166 at p95, and ~$556.6901 at p99 (~7.9× the median) — the log scaling makes ε a SMALL dollar move on typical transactions and a several-hundred-dollar swing only in the heavy tail (where the norm saturates at the p99 cap, so the move is downward). 'Small numerical corruption' is accurate for the bulk; the honest caveat is the tail, where per-field ε (EXP-A6) is the mitigation.

### ieee_cis

caps: {'amount_cap': 1104.0, 'dist_cap': 2111.0, 'c_cap': 107.2579, 'd_cap': 436.3333, 'v_cap': 1.1}

| field | unit | anchor q | raw value | norm value | raw move (±ε) | interval width | kind |
|---|---|--:|--:|--:|--:|--:|---|
| amount_norm (TransactionAmt) | USD | 0.5 | 68.769 | 0.6058 | +70.8353/−35.1491 | 105.9844 | log |
| amount_norm (TransactionAmt) | USD | 0.95 | 445.0 | 0.8705 | +452.8166/−224.6912 | 677.5078 | log |
| amount_norm (TransactionAmt) | USD | 0.99 | 1104.0 | 1.0 | +-0.0/−556.6901 | 556.6901 | log |
| dist1_norm | dist-units | 0.5 | 8.0 | 0.287 | +10.3514/−4.8143 | 15.1656 | log |
| dist1_norm | dist-units | 0.95 | 846.0 | 0.8806 | +974.1797/−453.0746 | 1427.2543 | log |
| dist1_norm | dist-units | 0.99 | 2040.0 | 0.9955 | +71.0/−1091.7653 | 1162.7653 | log |
| dist2_norm | dist-units | 0.5 | 37.0 | 0.4752 | +43.7058/−20.3268 | 64.0327 | log |
| dist2_norm | dist-units | 0.95 | 1001.0 | 0.9026 | +1110.0/−535.9867 | 1645.9867 | log |
| dist2_norm | dist-units | 0.99 | 2367.48 | 1.0 | +-256.48/−1386.2244 | 1129.7444 | log |
| c_mean_norm | C-agg | 0.5 | 0.9286 | 0.0087 | +10.7258/−10.7258 | 21.4516 | linear |
| c_mean_norm | C-agg | 0.95 | 16.2857 | 0.1518 | +10.7258/−10.7258 | 21.4516 | linear |
| c_mean_norm | C-agg | 0.99 | 107.2579 | 1.0 | +10.7258/−10.7258 | 21.4516 | linear |
| risk_score | probability (dimensionless) | None | None | None | +0.1/−0.1 | 0.2 | identity |

### nab

| field | unit | anchor q | raw value | norm value | raw move (±ε) | interval width | kind |
|---|---|--:|--:|--:|--:|--:|---|
| cpu_util_norm | CPU % | 0.5 | 29.836 | 0.2984 | +10.0/−10.0 | 20.0 | linear |
| cpu_util_norm | CPU % | 0.95 | 92.8805 | 0.9288 | +10.0/−10.0 | 20.0 | linear |
| cpu_util_norm | CPU % | 0.99 | 99.342 | 0.9934 | +10.0/−10.0 | 20.0 | linear |
| delta_norm | CPU %/step | None | None | None | +20.0/−20.0 | 40.0 | linear-span |

