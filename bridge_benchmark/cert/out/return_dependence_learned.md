# TM1b learned pre-return vs post-return baseline

A PRE-return predictor sees only pre-execution info (domain/action/tool id); it must NOT see the returned x1/x2 (risk, amount, severity, confidence). A POST-return predictor sees the full typed return z=(t,x1,x2). Both predict the oracle label Safe(z,a) (HistGradientBoosting). n=20000/domain, eps=0.1, seed=0.

| domain | n | majority_error | pre_return_error | pre_return_auc | post_return_error | post_return_auc | rho_matched |
| --- | --- | --- | --- | --- | --- | --- | --- |
| finance_compliance | 20000 | 0.3406 | 0.2773 | 0.7501 | 0.0035 | 0.9999 | 0.4557 |
| sre_monitoring | 20000 | 0.3158 | 0.3158 | 0.6691 | 0.007 | 0.9998 | 0.4253 |
| ops_security | 20000 | 0.3297 | 0.3297 | 0.7029 | 0.005 | 0.9999 | 0.4401 |

**Reading.** `pre_return_error` stays close to `majority_error` (the provenance alone barely predicts safety), while `post_return_error` is much lower and `post_return_auc` much higher. A pre-execution permission layer cannot decide the downstream authorization predicate because Safe(z,a) depends on the returned object z.

