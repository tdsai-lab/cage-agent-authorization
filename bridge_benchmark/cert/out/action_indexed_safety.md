# Action-indexed safety — the certified object is Safe(z, a), not Safe(z)

For a fixed typed return z we evaluate several candidate actions. The privileged action carries a policy rule; escalation/notification/etc. are conservative fallbacks that are always policy-safe. `action_dependence_rate` = fraction of z where the actions disagree on safety. n=20000/domain, eps=0.1, seed=0.

| domain | n | n_actions | action_dependence_rate | same_z_different_action_rate | gate_decision_variation_over_actions | privileged_unsafe_rate |
| --- | --- | --- | --- | --- | --- | --- |
| finance_compliance | 20000 | 4 | 0.3405 | 0.3405 | 0.1135 | 0.3405 |
| sre_monitoring | 20000 | 4 | 0.3157 | 0.3157 | 0.1052 | 0.3157 |
| ops_security | 20000 | 4 | 0.3296 | 0.3296 | 0.1098 | 0.3296 |

**Reading.** The same returned object can be safe for escalation or notification but unsafe for approval, deletion, or suppression. Therefore the certified object must be Allow(z, a), not Allow(z): the gate is action-indexed, not a generic anomaly detector over z.

