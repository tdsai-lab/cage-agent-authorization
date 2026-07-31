# T2-9 — Abstention-DoS: attacking the price of soundness

The certified gate trades a **false-allow** attack surface for an **availability / abstention** one. Prop-4 soundness holds (cert_false_allow=0), but an adversary that *selects* boundary-seeking inputs (analytic margin |m|~0) can INFLATE the abstention rate delivered to the human circuit -> an alert-fatigue DoS. Soundness is invariant; availability is the new axis; a mitigation bounds it.

Pool: real IEEE-CIS balanced set; policy theta_base=0.488808, delta=0.08, eps=0.1. Certified gate = EXACT analytic certificate (allow iff analytic R).

## 1. Attack — abstention inflation under adversarial input selection

| strength | abstain_benign | abstain_adv | **inflation** | cfa_benign | cfa_adv |
|---:|---:|---:|---:|---:|---:|
| 0.25 | 0.405±0.003 | 0.552±0.007 | **1.36±0.01** | 0.000 | 0.000 |
| 0.5 | 0.405±0.003 | 0.698±0.006 | **1.72±0.01** | 0.000 | 0.000 |
| 0.75 | 0.405±0.003 | 0.843±0.003 | **2.08±0.01** | 0.000 | 0.000 |
| 1.0 | 0.405±0.003 | 0.989±0.001 | **2.44±0.02** | 0.000 | 0.000 |

At the strongest attack (strength=1.0): abstain 0.401 (benign) -> 0.990 (adv), inflation **2.47x**.

## 2. Soundness invariant

cert_false_allow over ALL conditions (benign, adversarial, every mitigation) = **0.0000**. The attack costs availability, never safety.

## 3. Mitigations + cost

| mitigation | param | abstain_adv_after | inflation_after | cost | cfa |
|---|---|---:|---:|---|---:|
| rate_limit | budget_frac=0.5 | 0.500 | 1.25 | dropped_frac=0.490 | 0.000 |
| rate_limit | budget_frac=0.3 | 0.300 | 0.75 | dropped_frac=0.690 | 0.000 |
| rate_limit | budget_frac=0.15 | 0.150 | 0.37 | dropped_frac=0.840 | 0.000 |
| adaptive_eps | eps=0.1 | 0.990 | 2.47 | residual_exposure_vs_full_eps=0.0000 | 0.000 |
| adaptive_eps | eps=0.08 | 0.966 | 2.41 | residual_exposure_vs_full_eps=0.0239 | 0.000 |
| adaptive_eps | eps=0.06 | 0.932 | 2.32 | residual_exposure_vs_full_eps=0.0582 | 0.000 |
| adaptive_eps | eps=0.04 | 0.849 | 2.12 | residual_exposure_vs_full_eps=0.1408 | 0.000 |
| adaptive_eps | eps=0.02 | 0.748 | 1.86 | residual_exposure_vs_full_eps=0.2418 | 0.000 |

**Reads.** (rate_limit) a per-source abstention budget caps the human-circuit load an adversarial source can inflict -> bounds the inflation, cost = dropped/queued adversarial volume, NO safety cost. (adaptive_eps) shrinking the certified radius reclaims boundary records into R (lower abstention) at the price of a *residual exposure* to attacks between eps' and the full declared radius -- the abstention-vs-robustness-radius trade. cert_false_allow stays 0 w.r.t. the advertised radius throughout.
