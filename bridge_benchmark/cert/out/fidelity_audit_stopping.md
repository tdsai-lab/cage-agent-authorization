# M4 = R7 — anytime-valid fidelity-audit stopping rule (S26 upgrade)

Method: **alpha-spending union-bounded Clopper-Pearson confidence sequence (anytime-valid); establish-then-halt stopping rule**, α=0.05, tolerance = baseline + 0.03 (floor 0.05), Δ_audit=1d, subtle corrupt_frac=0.15 / severe corrupt_frac=0.6, checkpoints N0=50×1.4, seeds=[0, 1, 2].

| regime | guarantee established | halt rate | mean halt latency (audits) | clean guarantee p̄ | final p̄ | baseline |
|---|--:|--:|--:|--:|--:|--:|
| control | 1.0 | 0.0 | None | 0.02114 | 0.01914 | 0.01897 |
| subtle | 1.0 | 0.0 | None | 0.02114 | 0.01924 | 0.01897 |
| severe | 1.0 | 0.0 | None | 0.02114 | 0.01965 | 0.01897 |

### Per-seed detail

| seed | regime | n audited | baseline | p* | est@N | halted | halt N | latency | anytime p̄(final) | fixed-N p̄ | clean guarantee p̄ |
|--:|---|--:|--:|--:|--:|:--:|--:|--:|--:|--:|--:|
| 0 | control | 154024 | 0.01949 | 0.05 | 527 | N | None | None | 0.01968 | 0.01893 | 0.02166 |
| 0 | subtle | 153654 | 0.01949 | 0.05 | 527 | N | None | None | 0.01977 | 0.01901 | 0.02166 |
| 0 | severe | 149868 | 0.01949 | 0.05 | 527 | N | None | None | 0.01988 | 0.01911 | 0.02166 |
| 1 | control | 144644 | 0.01868 | 0.05 | 1033 | N | None | None | 0.0187 | 0.01794 | 0.02085 |
| 1 | subtle | 143299 | 0.01868 | 0.05 | 1033 | N | None | None | 0.0186 | 0.01783 | 0.02085 |
| 1 | severe | 148644 | 0.01868 | 0.05 | 1033 | N | None | None | 0.01948 | 0.01872 | 0.02085 |
| 2 | control | 145770 | 0.01873 | 0.05 | 1033 | N | None | None | 0.01905 | 0.01828 | 0.02091 |
| 2 | subtle | 146351 | 0.01873 | 0.05 | 1033 | N | None | None | 0.01934 | 0.01857 | 0.02091 |
| 2 | severe | 151363 | 0.01873 | 0.05 | 1033 | N | None | None | 0.0196 | 0.01884 | 0.02091 |

### Non-vacuity demonstration (deterministic, no-GPU)

Semi-synthetic audited stream: 20000 audits at true rate 0.02 then 20000 at 0.12 (p*=0.05). The establish-then-halt rule fires: guarantee established at N=737, **HALT at N=29881** (p̄=0.05831), latency **9881 audits** after the regression — confirming the stopping rule is non-vacuous.

**Verdict.** FINITE-AUDIT DEPLOYMENT GUARANTEE for rungs 2–3: a rigorous anytime-valid CI + stopping rule. On the real S26 stream the lifetime guarantee 'audited false-allow ≤ p̄(N) at ≥95%, ∀N' establishes early (N≈500–1000) at p̄≤0.02114 and NEVER halts — even under the SEVERE injected over-permissive gate (corrupt_frac=0.6), because the robustness-certified allow-set is largely insensitive to gate label-corruption (cumulative p̄ stays 0.01965≪p*=0.049). So the deployment guarantee is robust and autonomy correctly continues; the machinery is NON-VACUOUS — on a semi-synthetic stream whose true rate crosses p* the rule HALTS at N=29881 (latency 9881 audits). Local change-detection remains A4's complementary windowed monitor.

_Ground truth is the imperfect held-out isFraud label, so the bounded quantity is the EMPIRICAL audited false-allow rate (the rung-2/3 fidelity regime), not a predicate-soundness theorem — the certificate itself keeps cert_false_allow=0 w.r.t. the smoothed/Lipschitz gate; this bounds the gate↔oracle fidelity gap with a finite-sample guarantee._
