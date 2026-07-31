# T1-3 — Operational triage: low R_allow reframed as a certified-autonomy tier

**Reframe.** Deployment is TRIAGE, not allow-or-nothing. The gate auto-executes the certified tranche; everything else routes to the *existing* human-review circuit. `R_allow` is therefore the **certified-autonomy fraction** (volume of robust-safe traffic that runs with a formal B_{1,eps} contract), NOT an abstention rate. Purely analytic on the existing IEEE-CIS gate/cert machinery (`implicit_policy_gate.py` reused verbatim).

## Backend: lipschitz

Held-out mixed traffic: n=3000 (68 fraud). eps=0.1, sigma=0.1, tau=0.9.

| operating point | gate | auto-approved (autonomy) | in-budget fraud in tranche | in-budget fraud false-allow (of fraud) | human-review load |
|---|---|---:|---:|---:|---:|
| **certified autonomy (default margin=0)** | certified_lipschitz | **0.71** | **0.0131** | **0.4118** | 0.29 |
| volume-matched point | point | 0.71 | 0.0147 | **0.4598** | 0.29 |
| certified autonomy (strict-0 frontier) | certified_lipschitz | 0.084 | 0.0 | 0.0 | 0.916 |
| high-volume point (~80%) | point | 0.8 | 0.0162 | **0.5712** | 0.2 |

- Certified gate at its default operating point: **71% of traffic runs fully autonomously with a formal robust-safe contract; 29% keeps the existing human circuit.** In-budget adversarial fraud false-allow in that tranche = **0.4118**.
- At the SAME autonomy volume the point gate lets the adversary land **0.46** of the fraud population into the auto tranche under the in-budget attack (== implicit_policy_gate's `point_matched_false_allow_attacked`) -> same oversight saved, no contract, so the adversary reaches it in B_{1,eps}.
- A strict-0 frontier tier (8% volume) gives literally 0 in-budget fraud; a high-volume ~80% point gate leaks **0.57** of fraud under attack.
- Per-seed strict-0-frontier max in-budget fraud (seeds [0, 1, 2]): [0.0, 0.0, 0.0].

## Backend: smoothed

Held-out mixed traffic: n=3000 (68 fraud). eps=0.1, sigma=0.1, tau=0.9.

| operating point | gate | auto-approved (autonomy) | in-budget fraud in tranche | in-budget fraud false-allow (of fraud) | human-review load |
|---|---|---:|---:|---:|---:|
| **certified autonomy (default tau=0.90)** | certified_smoothed | **0.3707** | **0.0027** | **0.0441** | 0.6293 |
| volume-matched point | point | 0.3707 | 0.0207 | **0.5323** | 0.6293 |
| certified autonomy (strict-0 frontier) | certified_smoothed | 0.0 | 0.0 | 0.0 | 1.0 |
| high-volume point (~80%) | point | 0.8 | 0.0263 | **0.9265** | 0.2 |

- Certified gate at its default operating point: **37% of traffic runs fully autonomously with a formal robust-safe contract; 63% keeps the existing human circuit.** In-budget adversarial fraud false-allow in that tranche = **0.0441**.
- At the SAME autonomy volume the point gate lets the adversary land **0.53** of the fraud population into the auto tranche under the in-budget attack (== implicit_policy_gate's `point_matched_false_allow_attacked`) -> same oversight saved, no contract, so the adversary reaches it in B_{1,eps}.
- A strict-0 frontier tier (0% volume) gives literally 0 in-budget fraud; a high-volume ~80% point gate leaks **0.93** of fraud under attack.
- Per-seed strict-0-frontier max in-budget fraud (seeds [0, 1, 2]): [0.0, 0.0, 0.0].

**Interpretation.** R_allow is NOT '80% abstention'; it is the fraction that clears autonomously under a formal budget contract. At the certified gate's operating volume the in-budget adversarial fraud false-allow is ~0, while a point gate matched to the SAME volume (or run at higher autonomy) re-admits a large fraction of fraud under the in-budget attack. The remaining traffic keeps the current human process, so the certificate ADDS a quantified low-/zero-fraud autonomy tier on top of the status quo rather than replacing it — oversight economics, not abstention.

**Limitations.** Analytic, node-level, on existing runs. Ground truth is the imperfect held-out real `isFraud` label (empirical robustness, not a predicate-soundness theorem). The certified gate's in-budget fraud is 0 w.r.t. the smoothed/Lipschitz robustness statement over B_{1,eps}, not w.r.t. an out-of-budget adversary.
