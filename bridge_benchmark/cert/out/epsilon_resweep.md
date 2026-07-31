# PLAN.md #20 — certificate metrics re-swept over the derived empirical eps (#17)

`sigma=0.10` fixed (deployed value), `tau=0.80`. `naive_C_falseallow` must stay 1.0 (non-composition) and `cert_false_allow` must stay 0.0 (soundness) at every eps; `R_allow` is the utility curve. Regime annotations map each eps to its #17 validation stack.

| domain | eps | regime | C% | naive_C_FA | **cert_FA** | C_allow | **R_allow** | U_allow | clean_acc |
|---|---:|---|---:|---:|---:|---:|---:|---:|---:|
| finance | 0.05 | integrity+freshness | 4.9 | 1.0 | **0.0** | 0.0 | **0.625** | 0.0 | 0.995 |
| finance | 0.1 | integrity+freshness | 8.7 | 1.0 | **0.0** | 0.0 | **0.625** | 0.0 | 0.9956 |
| finance | 0.2 | integrity (real/IEEE) | 15.2 | 1.0 | **0.0** | 0.0 | **0.0** | 0.0 | 0.9944 |
| finance | 0.35 | integrity (synthetic) | 19.3 | 1.0 | **0.0** | 0.0 | **0.0** | 0.0 | 0.995 |
| monitoring | 0.05 | integrity+freshness | 4.8 | 1.0 | **0.0** | 0.0 | **0.325** | 0.0 | 0.9875 |
| monitoring | 0.1 | integrity+freshness | 7.6 | 1.0 | **0.0** | 0.0 | **0.325** | 0.0 | 0.9887 |
| monitoring | 0.2 | integrity (real/IEEE) | 10.1 | 1.0 | **0.0** | 0.0 | **0.0** | 0.0 | 0.9875 |
| monitoring | 0.35 | integrity (synthetic) | 9.8 | 1.0 | **0.0** | 0.0 | **0.0** | 0.0 | 0.9881 |

**Reads.** The non-composition failure (`naive_C_FA`=1.0) and certificate soundness (`cert_FA`=0.0) hold at EVERY empirical eps -> the result is not an artifact of eps=0.10. `R_allow` is healthy at the calibrated operating point (eps~0.05-0.10, the integrity+freshness regime) and trades down as the radius grows without freshness validation -> validating staleness (#19) preserves utility.
