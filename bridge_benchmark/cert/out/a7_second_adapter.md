# A7 — second independent adapter (k8s cost admission) reproduces the taxonomy

Adapter #2: **k8s Deployment manifest → (tier, cost-score) → real Kyverno admission** — a continuous `cost ≤ θ(tier)` idiom (θ_strict=0.5, θ_loose=0.8, ε=0.1), genuinely independent of the IEEE-CIS/Marble adapter (different domain, format, engine).

- taxonomy over cost: U=39 A=61 B=0 **C=20** R=80 (C-band cost∈[0.4, 0.5])
- **engine↔analytic agreement 1.0** over 18 real Kyverno admission checks (disagreements: 0)
- **real-Kyverno Category-C witnesses: 6** — non-composition holds on the engine: **True**

| cost | clean(loose) | swap(strict) | +ε(loose) | **joint(strict,+ε)** | cat |
|---:|:--:|:--:|:--:|:--:|:--:|
| 0.401 | admit | admit | admit | **DENY** | C |
| 0.4206 | admit | admit | admit | **DENY** | C |
| 0.4402 | admit | admit | admit | **DENY** | C |
| 0.4598 | admit | admit | admit | **DENY** | C |
| 0.4794 | admit | admit | admit | **DENY** | C |
| 0.499 | admit | admit | admit | **DENY** | C |

**Reads.** A **second, independent real adapter** (k8s manifest → real Kyverno admission, continuous `cost ≤ θ(tier)`) reproduces the full A/B/C/R/U taxonomy and the **non-composition** witness: real Kyverno **admits every single-channel move (clean, provenance swap, +ε) but DENIES the joint** — so a naive marginal certificate that certifies each channel would false-allow. The engine's admission verdict matches the analytic oracle (agreement reported). This de-risks that the phenomenon is an artifact of the IEEE-CIS/Marble adapter: it appears on a different domain, format and engine.
