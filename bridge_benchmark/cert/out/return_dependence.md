# TM1 return-dependence — Safe(z,a) depends on the returned object z

`rho_matched = Pr[Safe(z0,a) != Safe(z1,a) | z0,z1 share domain/action/schema family]`. All rates are on the analytic oracle (no learned model, no agent loop). `eps` is unused for the discrete labels here (clean Safe), reported for provenance.

Settings: n=20000 records/domain, n_pairs=10000, eps=0.1, seed=0.

| domain | n_records | safe_rate | rho_matched | rho_same_tool | rho_tool_swap_same_x1 | rho_same_categorical_context | pre_return_majority_error | n_pairs |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| finance_compliance | 20000 | 0.6595 | 0.4557 | 0.3745 | 0.4668 | 0.4535 | 0.3405 | 10000 |
| sre_monitoring | 20000 | 0.6843 | 0.4253 | 0.4006 | 0.4395 | 0.4228 | 0.3157 | 10000 |
| ops_security | 20000 | 0.6704 | 0.4401 | 0.3816 | 0.4639 | 0.4332 | 0.3296 | 10000 |

**Reading.** A nonzero matched return-dependence rate means authorization cannot be reduced to a pre-execution tool-call permission. The returned object z is a necessary input to the safety predicate Safe(z,a). `pre_return_majority_error` is the irreducible error of any pre-return policy that sees only the domain/action and not the return: it must predict a single label for all returns of that tool-call, so it is wrong on the minority class.

