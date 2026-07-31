# PLAN.md #32 — gate on a really-implicit policy (real IEEE-CIS isFraud, no predicate)

Implicit policy: `approve-safe <=> not fraud`, ground truth = held-out **real** `isFraud` label (imperfect, owned honestly). **No executable predicate**, so the exact and marginal certificate baselines are UNDEFINED by construction (they need a predicate to enumerate which points of B_{1,eps} are unsafe). The only sound robustness statement is a certificate over the LEARNED gate.

- gate quality vs held-out fraud label: AUC ~**0.7275** (the implicit policy is learnable but noisy)
- **(i) exact / marginal certificate**: UNDEFINED (no executable predicate to enumerate B_{1,eps})

**(ii)+(iii) Two certificate backends on the SAME gate** (the EXP_LIP tradeoff, here in the implicit-policy regime). `cert_false_allow` and the **matched-threshold** point gate (same safe-allow rate, isolating robustness from conservatism) on held-out frauds:

| backend | sampling | cert allow (safe) | **cert FA (fraud)** | point matched FA clean | point matched FA **ATTACKED** |
|---|---|---:|---:|---:|---:|
| lipschitz | none (deterministic) | 0.7217 | **0.4118** | 0.4412 | **0.4706** |
| smoothed | MC n=1000 | 0.4033 | **0.0441** | 0.1176 | **0.4853** |

**Reads.** With no predicate the exact/marginal baselines do not exist; a certificate over the learned gate is the only sound option, and it is non-vacuous. Under a B_{1,eps} attack the matched-threshold point gate's fraud false-allow rises well above the certified gate's -> the certificate buys REAL robustness, not just a stricter threshold. The **deterministic 1-Lipschitz** certificate needs NO sampling (stable at low n, no tau/n_mc knife-edge); the **smoothing** certificate is more conservative and gives a cleaner fraud separation on this weak (AUC~0.72) signal -- the same lip-vs-smoothing tradeoff as EXP_LIP. Ground truth is the imperfect held-out fraud label, so this is an empirical robustness result, not a predicate-soundness theorem.
