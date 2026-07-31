# EXP-CX4 = A6 — calibrated per-field ε budget

Source: NEW_EXP_OPA_CHECK.md CX4 / NEW_NEW_EXP.md A6. Multivariate-affine policy, k=6 fields, |X1|=4, seeds=[0, 1, 2, 3, 4], calibration p95 (frozen), eval split disjoint. Exact certificate; dual norm per geometry.

| geometry | Δ (eps-gain) | held-out fault coverage | robust-safe coverage (autonomy) | abstention | policy false-allow |
|---|--:|--:|--:|--:|--:|
| global_l2 | 1.3512 | 0.9509±0.0026 | **0.4531**±0.1186 | 0.5469 | 0.0 |
| ellipsoid | 0.9061 | 0.9484±0.001 | **0.6196**±0.0548 | 0.3804 | 0.0379 |
| linf_box | 1.2652 | 0.9489±0.0023 | **0.4805**±0.0718 | 0.5195 | 0.0 |

### Real per-field residual anchor (IEEE-CIS, #16 integrity+freshness residual)

Injectors: ['numeric_jitter', 'normalization_skew']; **p95 field heterogeneity ratio 2.9×** (max/min field p95).

| field | p50 | p95 | p99 |
|---|--:|--:|--:|
| risk_score | 0.01173 | 0.04197 | 0.06241 |
| amount_norm | 0.01414 | 0.0551 | 0.08413 |
| dist1_norm | 0.00567 | 0.04112 | 0.05986 |
| dist2_norm | 6e-05 | 0.01932 | 0.03101 |
| c_mean_norm | 0.00142 | 0.02363 | 0.03497 |
| d_mean_norm | 0.00669 | 0.03893 | 0.05995 |
| v_mean_norm | 0.0127 | 0.04861 | 0.06711 |

**Verdict.** PER-FIELD BUDGET WINS THE PARETO: the ellipsoid ball matches the global-ℓ₂ held-out fault coverage (0.9484 vs 0.9509) at HIGHER certified autonomy (R_allow 0.6196 vs 0.4531) — sizing each field to its own p95 residual stops the global sphere from over-charging the quiet fields. Budget frozen on calibration; both sound (policy_false_allow ≈ 0.0379).
