# Mandatory-gate / bypass ablation (scope clarification)

The certificate is sound only for actions ROUTED THROUGH the gate. `bypass_rate` = fraction of privileged proposals that execute directly, skipping the gate. With the mandatory gate (bypass 0) unsafe execution is 0; bypassing reintroduces unsafe execution.

| domain | bypass_rate | n | n_privileged_proposals | effective_bypass_rate | unsafe_exec_with_mandatory_gate | unsafe_exec_with_bypass |
| --- | --- | --- | --- | --- | --- | --- |
| finance | 0.0 | 480 | 471 | 0.0 | 0.0 | 0.0 |
| finance | 0.1 | 480 | 471 | 0.0849 | 0.0 | 0.0271 |
| finance | 0.25 | 480 | 471 | 0.2251 | 0.0 | 0.0708 |
| finance | 0.5 | 480 | 471 | 0.4374 | 0.0 | 0.1375 |
| finance | 1.0 | 480 | 471 | 1.0 | 0.0 | 0.3146 |
| sre | 0.0 | 480 | 471 | 0.0 | 0.0 | 0.0 |
| sre | 0.1 | 480 | 471 | 0.087 | 0.0 | 0.0312 |
| sre | 0.25 | 480 | 471 | 0.2335 | 0.0 | 0.0813 |
| sre | 0.5 | 480 | 471 | 0.4989 | 0.0 | 0.1479 |
| sre | 1.0 | 480 | 471 | 1.0 | 0.0 | 0.3146 |

**Reading.** The certificate is sound for actions routed through the gate; it does NOT cover actions that bypass the certified interface. The system-level antecedent — all consequential actions pass through the post-return gate — is explicit, not assumed.

