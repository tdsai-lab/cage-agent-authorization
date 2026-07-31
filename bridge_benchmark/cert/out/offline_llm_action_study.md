# Offline LLM action study (mock) — no agent loop

C cases are operationally plausible traps for LLM action proposal: the LLM tends to propose the certified action on clean C, and proposes UNSAFE actions on the corrupted C witness — which the certified gate would block. No agent-certification claim.

| domain | n_C | n_R | n_U | target_action_rate_on_C_clean | unsafe_proposal_rate_on_C_witness | safe_proposal_rate_on_R | unsafe_proposal_rate_on_U | gate_would_block_rate_on_C_witness |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| financial_compliance | 200 | 200 | 200 | 1.0 | 1.0 | 1.0 | 0.06 | 1.0 |
| sre_monitoring | 200 | 200 | 200 | 0.42 | 0.42 | 1.0 | 0.22 | 1.0 |
