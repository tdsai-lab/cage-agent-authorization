# System soundness decomposition (theory glue for EXP 2)

This frames the validation-stack adversary (`validation_stack_adversary.py`, NEW_EXPS EXP 2). It is the
½-page argument that turns EXP 2 from "another attack" into *the measurement of the only remaining term in
system soundness*.

## Statement

Let the certified gate be **sound for its declared budget** `B_{d,ε}`: for any typed return `z` it
authorizes and any realized corruption `z' ∈ B_{d,ε}(z)`, the action stays policy-safe. (This is the
theorem the exact / RS / Lipschitz backends satisfy — measured here as `cert_false_allow = 0`.)

A **system false allow** is the event that the deployed system executes a policy-unsafe action that the
gate authorized. It decomposes by whether the realized corruption stayed inside the declared budget:

```
system-sound  ⟺  gate-sound  ∧  (realized corruption ⊆ B_{d,ε})

P[system false allow]
  ≤  P[gate false allow | corruption ∈ budget]  +  P[corruption ∉ budget]
  =  0 (gate soundness)  +  budget-escape rate
  =  budget-escape rate.
```

The first term is **0** by the gate-soundness theorem. Therefore

```
system_false_allow  =  budget-escape rate,
```

and EXP 2 is a **direct measurement of the only non-zero term**. The gate does not claim to defend the
validation stack; it claims soundness *conditional on a declared stack*, and EXP 2 measures how strong that
stack must be for the conditional to hold in deployment.

## The two non-zero sources of budget escape (the two parts of EXP 2)

1. **Freshness escape (EXP 2-A).** The realized continuous corruption is risk-score *staleness*: a cache
  serves the entity's score from Δt ago. We measure the real same-entity drift `|score(t) − score(t−Δt)|`
  on real IEEE-CIS over real `TransactionDT`. When the p95 drift exceeds the declared `ε`, a realized
  point can land outside `B_{1,ε}` and cross `θ` — a budget escape. `ε_emp@p95(Δt)` vs the declared `ε`
  line is exactly the conditional's failure boundary: **the certificate is valid only under a freshness
  SLA `Δt ≤ Δt*`**, where `Δt*` is the crossing. Below it the deployment must tighten the SLA or widen
  the declared `ε` (trading utility). `cert_false_allow` stays 0 throughout — only `system_false_allow`
  (the escape term) moves, exactly as the decomposition predicts.

2. **Constructor escape (EXP 2-B).** The discrete binding is corrupted *at the z-constructor*, before the
  typed interface. The realized true binding is not in `N_d(s_observed)` at all — it is outside `B_{d,ε}`
  by construction. The gate certifies its (wrong) neighborhood soundly and still admits the action. This
  is **not a defended surface**; it is the **TCB boundary**: the guarantee holds within the typed
  interface and stops at the extractor. `false_allow` vs the flip probability `p` delimits exactly where
  the guarantee ends.

## What this buys the paper

The honest reading of a sound certificate is not "the system cannot be exploited" but "the system cannot be
exploited *through the typed interface within the declared budget*." EXP 2 makes both qualifiers
*measured rather than asserted*: the freshness SLA `Δt*` is a number on real data, and the constructor is
named as the TCB boundary with its own measured curve. That is the credibility move an adversarial reviewer
asks for — "what happens when the adversary attacks the validation stack?" — answered with a measurement,
not a hand-wave.
