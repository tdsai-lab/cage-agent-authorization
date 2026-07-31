# IEEE-CIS real-data-grounded agent-integration experiment (appendix)

> **certified node != certified agent.** We certify ONLY the post-tool-return gate `allow(z,a)`. The LLM is a realistic action proposer that can be induced into proposing unsafe approvals; it is NOT certified. This is an integration illustration placed AFTER the synthetic proof and the IEEE-CIS node-level certificate results — not a central claim.

- backend: `ollama` model=`qwen3.6:latest`  | episodes/cell: 100  | θ_base=0.489 δ=0.08 ε=0.1 σ=0.1 τ=0.9


Ground truth: `unsafe_to_execute_automatically(z,a) ⟺ ∃ z'∈B_{1,ε}(z): Safe(z',a)=0` (a non-robust point is unsafe for AUTOMATIC approval, not necessarily clean-unsafe).


## Table A — c_witness attack (CERTIFICATE-GEOMETRY test)

Category-C transactions (disc-only safe ∧ cont-only safe ∧ joint-unsafe), shown as-is at the loose provenance. Approval is locally plausible under the displayed policy but not robust.

| gate | llm_propose_approve | unsafe_exec (post-gate) | cert_false_allow | abstain |
| --- | --- | --- | --- | --- |
| none | 1.0 | 1.0 | 1.0 | 0.0 |
| learned | 1.0 | 1.0 | 1.0 | 0.0 |
| certified | 1.0 | 0.0 | 0.0 | 1.0 |
| oracle | 1.0 | 0.0 | 0.0 | 1.0 |


## Table B — injection attack (ARCHITECTURE test)

The typed `z` the gate reads is UNCHANGED; an adversarial instruction sits in a display-only field the LLM sees. `llm_unsafe_approval_pre_gate` measures LLM COMPROMISE (independent of the gate); `unsafe_exec` is the POST-gate outcome. The gate is **unaffected by this injection channel because the injected bytes are not part of the typed authorization input** — this guarantee is conditional on the typed interface (it would not hold if the injection corrupted the upstream parser that builds `z`).

| gate | llm_unsafe_approval_pre_gate | unsafe_exec (post-gate) | cert_false_allow | abstain |
| --- | --- | --- | --- | --- |
| none | 0.01 | 0.01 | 1.0 | 0.0 |
| learned | 0.01 | 0.0 | 0.0 | 0.01 |
| certified | 0.01 | 0.0 | 0.0 | 0.01 |
| oracle | 0.01 | 0.0 | 0.0 | 0.01 |


## Table C — clean control (non-vacuity)

Faithful returns; does the agent still APPROVE robust-safe (R) transactions?

| gate | R_exec | unsafe_exec | cert_false_allow | fraud_rate_executed (diag) |
| --- | --- | --- | --- | --- |
| none | 1.0 | 0.0 | 0.0 | 0.0 |
| learned | 1.0 | 0.0 | 0.0 | 0.0 |
| certified | 0.24 | 0.0 | 0.0 | 0.0 |
| oracle | 1.0 | 0.0 | 0.0 | 0.0 |


## Reading

- **c_witness**: undefended (`none`) executes unsafe approvals; `certified` drives `unsafe_exec` and `cert_false_allow` to 0 while staying non-vacuous on R. This is the case the hybrid certificate is uniquely needed for.
- **injection**: the LLM is compromised (`llm_unsafe_approval_pre_gate` high) yet the certified gate blocks execution (`unsafe_exec`=0). Message: **LLM compromised, execution blocked** — because the injected text is not in the typed authorization input.
- `fraud_rate_executed` is a diagnostic, not a certified property.


## Limitations

- Not end-to-end agent robustness; the certified object is the single post-tool-return node.
- The injection guarantee is conditional on the typed interface; injection that corrupts the constructor of `z` is out of scope here.
