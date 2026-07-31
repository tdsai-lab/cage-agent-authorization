# IDEA #4 — the certifiable interface is a low-dim policy state, not raw high-dim returns

ε=0.1, σ=0.1, τ=0.85, n_mc=600. Safety depends on `k_active` fields; the return carries `k_raw` fields (the rest are nuisance). Four gates differ only in what part of x₂ they may use; all certified by the SAME smoothed certificate, scored against the true oracle.

## k_active=5, k_raw=20 (K=20, n_cert=120, L1-selected=8)

| gate | fields | fidelity | **cert_false_allow** | R_allow | abstention |
|---|---:|---:|---:|---:|---:|
| dense | 20 | 0.9333 | **0.0** | 0.3793 | 0.9083 |
| noise_trained | 20 | 0.975 | **0.0** | 0.4483 | 0.8917 |
| bottleneck | 8 | 0.95 | **0.0** | 0.5517 | 0.8667 |
| oracle_proj | 5 | 0.975 | **0.0** | 0.4828 | 0.8833 |

## k_active=5, k_raw=50 (K=20, n_cert=120, L1-selected=19)

| gate | fields | fidelity | **cert_false_allow** | R_allow | abstention |
|---|---:|---:|---:|---:|---:|
| dense | 50 | 0.85 | **0.0** | 0.3939 | 0.8917 |
| noise_trained | 50 | 0.95 | **0.0** | 0.6667 | 0.8167 |
| bottleneck | 19 | 0.9167 | **0.0** | 0.5455 | 0.85 |
| oracle_proj | 5 | 0.9917 | **0.0** | 0.6061 | 0.8333 |

## k_active=5, k_raw=100 (K=20, n_cert=120, L1-selected=25)

| gate | fields | fidelity | **cert_false_allow** | R_allow | abstention |
|---|---:|---:|---:|---:|---:|
| dense | 100 | 0.7417 | **0.0167** | 0.2812 | 0.9083 |
| noise_trained | 100 | 0.8667 | **0.0** | 0.6562 | 0.825 |
| bottleneck | 25 | 0.9417 | **0.0** | 0.4688 | 0.875 |
| oracle_proj | 5 | 0.9833 | **0.0** | 0.4375 | 0.8833 |

**Reads.** As `k_raw` grows with `k_active` fixed, the **dense** MLP on raw x₂ loses fidelity and its smoothed certificate starts to false-allow (cert_false_allow ↑) — it cannot cleanly learn to ignore the nuisance dimensions from finite data. Restricting the gate to a low-dim policy state — exactly (**oracle_proj**) or estimated from data (**bottleneck** via L1) — restores **cert_false_allow → 0** while keeping **R_allow > 0** (non-vacuous). Noise-training helps but does not fully close the gap. The certifiable interface is therefore a typed, low-dimensional policy state h(x₂), not raw high-dimensional tool-return logs: the recommendation is projection, not smoothing the raw space.
