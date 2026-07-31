# PLAN_2 P3 — real kind + Kyverno harness with an externally-inspectable side effect

Cluster **kind cage-p3**, admission **Kyverno v1.13**. Policy: `replicas <= cap(tier); tier from a separate ConfigMap via context.apiCall (TOCTOU)`. Fault: stale tier-registry serves lax(cap 10) while true tier is strict(cap 3) — wrong_provenance_binding. Tier caps {'strict': 3, 'lax': 10}. The 6-replica witness is safe under lax (cap 10) and unsafe under strict (cap 3); the verdict flips purely on the provenance binding `s` (a d=1 swap), the request bytes unchanged.

| arm | replicas | served tier | admitted | **real side effect** |
|---|---:|---|:--:|:--:|
| deployed_admission | 6 | lax | yes | **YES** |
| certified_gate | 6 | lax | no | none |
| oracle_true_tier | 6 | strict | no | none |
| certified_gate (safe, non-vacuity) | 2 | lax | yes | **YES** |

certified-gate overhead ≈ **0.25 µs/decision**.

**Reads.** On a REAL cluster with REAL Kyverno admission, the `wrong_provenance_binding` fault makes the deployed admission control read a **stale** tier (lax) and **admit** a workload that the true tier (strict) forbids — a committed, `kubectl get`-inspectable side effect. The **certified rung-1 gate blocks it** (side effect = none) because it enumerates the tier neighbourhood `N_1(s_served)` — which contains the true `strict` — and tests every branch at the ε-shifted cap instead of trusting the served binding; the `strict` branch fails. The **oracle** (fresh registry) denies too, confirming the gate matches ground truth. On a genuinely-safe workload the gate still deploys (non-vacuous). This lifts #29's in-process result to a real cluster + real controller + real side effect. (The LLM proposer is orthogonal and certified separately, Experiment F.)
