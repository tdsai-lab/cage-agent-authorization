# Negative control — arbitrary endpoint lies are OUTSIDE the certified budget (Part D)

- IEEE-CIS real-data records; true-unsafe states (risk_score above the per-tool threshold). The endpoint fabricates a safe-looking return by lowering `risk_score` by `fabrication_gap`. ε=0.1, σ=0.1, τ=0.9, n_mc=2000. n=120 true-unsafe examples.

`inside_certified_budget` = is the fabrication within ε of the true state; `certified_claim_applicable` = fraction of fakes that lie within B_{1,ε}(z_true) (so the certificate around z_true would cover them); `unsafe_if_endpoint_lies` = fraction the gate allows that are OUTSIDE the certified budget (the certificate makes no claim about these).

| fabrication_gap | n | mean_distance_to_true_state | inside_certified_budget | gate_allow_on_fake | certified_claim_applicable | unsafe_if_endpoint_lies |
| --- | --- | --- | --- | --- | --- | --- |
| 0.05 | 120 | 0.05 | True | 0.0 | 1.0 | 0.0 |
| 0.1 | 120 | 0.1 | True | 0.0 | 1.0 | 0.0 |
| 0.2 | 120 | 0.2 | False | 0.0 | 0.0 | 0.0 |
| 0.4 | 120 | 0.4 | False | 0.2833 | 0.0 | 0.2833 |
| 0.8 | 120 | 0.6777 | False | 1.0 | 0.0 | 1.0 |

**Conclusion.**

- The gate is **not an endpoint-truthfulness verifier**. It certifies authorization stability under bounded typed corruption around the *observed* return.
- For small fabrications (`fabrication_gap ≤ ε`) the lie is inside B_{1,ε}(z_true): the certificate's robustness guarantee around the true state still bites, and a sound gate trained near the boundary tends to refuse.
- For large fabrications (`fabrication_gap ≫ ε`) the fake is far outside the budget; the certificate makes **no claim** (`certified_claim_applicable → 0`) and the gate allows the fabricated safe return. If the endpoint fabricates an arbitrary false return outside B_{1,ε}, provenance / capability / trust infrastructure is needed UPSTREAM — this is outside the node-level certificate's scope.

