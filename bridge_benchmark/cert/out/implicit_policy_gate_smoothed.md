# PLAN.md #32 — gate on a really-implicit policy (real IEEE-CIS isFraud, no predicate)

Implicit policy: `approve-safe <=> not fraud`, ground truth = held-out **real** `isFraud` label (imperfect, owned honestly). No executable predicate. Certificate backend: **smoothed** (Gaussian randomized smoothing, Monte-Carlo).

- gate quality vs held-out fraud label: AUC **0.7191**, acc 0.959
- **(i) exact / marginal certificate**: UNDEFINED (no executable predicate to enumerate B_{1,eps})
- **(ii) certificate non-vacuity** (truly-safe txns certified-allowed): **0.4033** (point-gate allow 0.9867)
- **(iii) robustness on truly-unsafe (fraud) txns** — false-allow (n=68 held-out frauds):

| gate | safe-allow rate | fraud false-allow (clean) | fraud false-allow (ATTACKED) |
|---|---:|---:|---:|
| point (thr=0.5) | 0.9867 | 0.8088 | **0.9706** |
| point (matched thr=0.9993) | 0.4033 | 0.1176 | **0.4853** |
| **certified** | 0.4033 | — | **0.0441** |

**Reads.** With no executable predicate the exact/marginal certificate baselines are unavailable by construction; the smoothed certificate over the learned gate is the only sound robustness statement and it is non-vacuous. The **matched-threshold** point gate is tuned to the SAME safe-allow rate as the certificate, isolating robustness from conservatism: even there, a B_{1,eps} attack drives the point gate's fraud false-allow far above the certified gate's near-zero rate -> the certificate buys REAL robustness, not just a stricter threshold. Ground truth is the imperfect held-out fraud label, so this is an empirical robustness result, not a predicate-soundness theorem.
