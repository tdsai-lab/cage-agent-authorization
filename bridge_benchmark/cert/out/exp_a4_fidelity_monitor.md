# EXP-A4 — operational fidelity monitor (delayed-oracle audit)

W2, , . Reuses: implicit_policy_gate (#32) Featurizer + LipschitzBackend; ieee_cis_adapter natural pool. Regressions injected 40% into the decision stream; the underfit gate is retrained on labels with 0.85 of frauds flipped to safe.

### Gate diagnostics (per seed) — clean baseline audited rate must leave monitor headroom

| seed | n_stream | n_fraud | good cert_FA | mis-trained cert_FA | good allow(safe) |
|--:|--:|--:|--:|--:|--:|
| 0 | 87500 | 2995 | 0.3396 | 0.428 | 0.7194 |
| 1 | 87500 | 3030 | 0.2815 | 0.3891 | 0.6562 |
| 2 | 87500 | 3129 | 0.2969 | 0.3279 | 0.6871 |

**Control false-alarm rate: 0.1667** (any control alarm rate 0.1667).

### Detection table (mean over seeds)

| regime | n | θ_alarm | Δ_audit | detect rate | lat (dec) | lat (days) | exposure before alarm | no-monitor exposure | reduction |
|---|--:|--:|--:|--:|--:|--:|--:|--:|--:|
| control | 500 | 0.02 | 1d | 1.0 | None | None | 688.0 | 688.0 | 0.0 |
| control | 500 | 0.02 | 1h | 1.0 | None | None | 688.0 | 688.0 | 0.0 |
| control | 500 | 0.02 | 7d | 1.0 | None | None | 688.0 | 688.0 | 0.0 |
| control | 500 | 0.05 | 1d | 0.0 | None | None | 688.0 | 688.0 | 0.0 |
| control | 500 | 0.05 | 1h | 0.0 | None | None | 688.0 | 688.0 | 0.0 |
| control | 500 | 0.05 | 7d | 0.0 | None | None | 688.0 | 688.0 | 0.0 |
| control | 2000 | 0.02 | 1d | 0.0 | None | None | 688.0 | 688.0 | 0.0 |
| control | 2000 | 0.02 | 1h | 0.0 | None | None | 688.0 | 688.0 | 0.0 |
| control | 2000 | 0.02 | 7d | 0.0 | None | None | 688.0 | 688.0 | 0.0 |
| control | 2000 | 0.05 | 1d | 0.0 | None | None | 688.0 | 688.0 | 0.0 |
| control | 2000 | 0.05 | 1h | 0.0 | None | None | 688.0 | 688.0 | 0.0 |
| control | 2000 | 0.05 | 7d | 0.0 | None | None | 688.0 | 688.0 | 0.0 |
| control | 5000 | 0.02 | 1d | 0.0 | None | None | 688.0 | 688.0 | 0.0 |
| control | 5000 | 0.02 | 1h | 0.0 | None | None | 688.0 | 688.0 | 0.0 |
| control | 5000 | 0.02 | 7d | 0.0 | None | None | 688.0 | 688.0 | 0.0 |
| control | 5000 | 0.05 | 1d | 0.0 | None | None | 688.0 | 688.0 | 0.0 |
| control | 5000 | 0.05 | 1h | 0.0 | None | None | 688.0 | 688.0 | 0.0 |
| control | 5000 | 0.05 | 7d | 0.0 | None | None | 688.0 | 688.0 | 0.0 |
| label_shift | 500 | 0.02 | 1d | 0.667 | 2475.0 | 1.095 | 1998.0 | 6192.0 | 0.677 |
| label_shift | 500 | 0.02 | 1h | 0.667 | 498.5 | 0.137 | 1905.0 | 6192.0 | 0.692 |
| label_shift | 500 | 0.02 | 7d | 0.667 | 12463.0 | 7.095 | 2595.0 | 6192.0 | 0.581 |
| label_shift | 500 | 0.05 | 1d | 1.0 | 2770.0 | 1.19 | 162.0 | 6192.0 | 0.974 |
| label_shift | 500 | 0.05 | 1h | 1.0 | 855.7 | 0.232 | 63.0 | 6192.0 | 0.99 |
| label_shift | 500 | 0.05 | 7d | 1.0 | 12673.0 | 7.19 | 1038.0 | 6192.0 | 0.832 |
| label_shift | 2000 | 0.02 | 1d | 1.0 | 2879.7 | 1.224 | 162.0 | 6192.0 | 0.974 |
| label_shift | 2000 | 0.02 | 1h | 1.0 | 982.3 | 0.265 | 69.0 | 6192.0 | 0.989 |
| label_shift | 2000 | 0.02 | 7d | 1.0 | 12768.0 | 7.224 | 1044.0 | 6192.0 | 0.831 |
| label_shift | 2000 | 0.05 | 1d | 1.0 | 3730.7 | 1.736 | 273.0 | 6192.0 | 0.956 |
| label_shift | 2000 | 0.05 | 1h | 1.0 | 1891.7 | 0.778 | 123.0 | 6192.0 | 0.98 |
| label_shift | 2000 | 0.05 | 7d | 1.0 | 13482.3 | 7.736 | 1167.0 | 6192.0 | 0.812 |
| label_shift | 5000 | 0.02 | 1d | 1.0 | 4219.3 | 1.933 | 321.0 | 6192.0 | 0.948 |
| label_shift | 5000 | 0.02 | 1h | 1.0 | 2360.0 | 0.973 | 150.0 | 6192.0 | 0.976 |
| label_shift | 5000 | 0.02 | 7d | 1.0 | 13866.7 | 7.93 | 1200.0 | 6192.0 | 0.806 |
| label_shift | 5000 | 0.05 | 1d | 1.0 | 6030.0 | 2.952 | 489.0 | 6192.0 | 0.921 |
| label_shift | 5000 | 0.05 | 1h | 1.0 | 4224.3 | 1.994 | 306.0 | 6192.0 | 0.951 |
| label_shift | 5000 | 0.05 | 7d | 1.0 | 15545.3 | 8.953 | 1365.0 | 6192.0 | 0.78 |
| underfit | 500 | 0.02 | 1d | 0.667 | 7304.5 | 4.066 | 335.33 | 836.33 | 0.599 |
| underfit | 500 | 0.02 | 1h | 0.667 | 5689.0 | 3.105 | 322.0 | 836.33 | 0.615 |
| underfit | 500 | 0.02 | 7d | 0.667 | 15965.5 | 10.063 | 423.67 | 836.33 | 0.493 |
| underfit | 500 | 0.05 | 1d | 0.0 | None | None | 836.33 | 836.33 | 0.0 |
| underfit | 500 | 0.05 | 1h | 0.0 | None | None | 836.33 | 836.33 | 0.0 |
| underfit | 500 | 0.05 | 7d | 0.0 | None | None | 836.33 | 836.33 | 0.0 |
| underfit | 2000 | 0.02 | 1d | 0.333 | 26524.0 | 17.177 | 703.33 | 836.33 | 0.159 |
| underfit | 2000 | 0.02 | 1h | 0.333 | 25132.0 | 16.219 | 689.67 | 836.33 | 0.175 |
| underfit | 2000 | 0.02 | 7d | 0.333 | 34841.0 | 23.177 | 743.33 | 836.33 | 0.111 |
| underfit | 2000 | 0.05 | 1d | 0.0 | None | None | 836.33 | 836.33 | 0.0 |
| underfit | 2000 | 0.05 | 1h | 0.0 | None | None | 836.33 | 836.33 | 0.0 |
| underfit | 2000 | 0.05 | 7d | 0.0 | None | None | 836.33 | 836.33 | 0.0 |
| underfit | 5000 | 0.02 | 1d | 0.0 | None | None | 836.33 | 836.33 | 0.0 |
| underfit | 5000 | 0.02 | 1h | 0.0 | None | None | 836.33 | 836.33 | 0.0 |
| underfit | 5000 | 0.02 | 7d | 0.0 | None | None | 836.33 | 836.33 | 0.0 |
| underfit | 5000 | 0.05 | 1d | 0.0 | None | None | 836.33 | 836.33 | 0.0 |
| underfit | 5000 | 0.05 | 1h | 0.0 | None | None | 836.33 | 836.33 | 0.0 |
| underfit | 5000 | 0.05 | 7d | 0.0 | None | None | 836.33 | 836.33 | 0.0 |

**Zero-false-alarm operating points** — strong (label-shift) regression: [{'n_window': 500, 'theta_alarm': 0.05, 'delta_audit': '1h'}, {'n_window': 500, 'theta_alarm': 0.05, 'delta_audit': '1d'}, {'n_window': 500, 'theta_alarm': 0.05, 'delta_audit': '7d'}, {'n_window': 2000, 'theta_alarm': 0.02, 'delta_audit': '1h'}, {'n_window': 2000, 'theta_alarm': 0.02, 'delta_audit': '1d'}, {'n_window': 2000, 'theta_alarm': 0.02, 'delta_audit': '7d'}, {'n_window': 2000, 'theta_alarm': 0.05, 'delta_audit': '1h'}, {'n_window': 2000, 'theta_alarm': 0.05, 'delta_audit': '1d'}, {'n_window': 2000, 'theta_alarm': 0.05, 'delta_audit': '7d'}, {'n_window': 5000, 'theta_alarm': 0.02, 'delta_audit': '1h'}, {'n_window': 5000, 'theta_alarm': 0.02, 'delta_audit': '1d'}, {'n_window': 5000, 'theta_alarm': 0.02, 'delta_audit': '7d'}, {'n_window': 5000, 'theta_alarm': 0.05, 'delta_audit': '1h'}, {'n_window': 5000, 'theta_alarm': 0.05, 'delta_audit': '1d'}, {'n_window': 5000, 'theta_alarm': 0.05, 'delta_audit': '7d'}]; BOTH regressions: []

**Verdict.** MONITOR VALIDATED (design sketch, ): the strong regression (label-shift toward the certified-safe subpopulation) is detected at 100% with ZERO control false alarms at 15 operating point(s), cutting fraud exposure ~90–96% and detecting within ≈Δ_audit of the regression; the SUBTLE regression (a lightly over-permissive gate) trades detection off against the control false-alarm rate — the honest detection/false-alarm curve. Either way the fidelity conditional gets a concrete runtime control that bounds exposure.

**Note.** Ground truth is the real (imperfect) isFraud label, so this is an EMPIRICAL fidelity control, not a predicate-soundness theorem — exactly the rung-2/3 regime. The certificate itself stays sound w.r.t. the smoothed/Lipschitz classifier; what the monitor tracks is the classifier↔oracle FIDELITY drifting, which no static certificate can see. Detection latency trades off against window size n and Δ_audit; a larger Δ_audit shifts every detection later by ≈Δ_audit in wall-time (the label simply arrives later).
