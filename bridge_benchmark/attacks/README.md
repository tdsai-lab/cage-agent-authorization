# attacks/ — empirical mixed discrete–continuous attack (PLAN3 §7)

`mixed_attack.py` attacks the learned gate `s_θ(z, a)` over the MVP threat set `B_{1,ε}`:
exact enumeration of the `d=1` discrete states (restricted to provenance swaps that have a rule for
the candidate action) × a deterministic numeric search (polar/ring grid; `k` is small) inside the
L2 `ε`-ball.

Headline metric (conditioned on truly-unsafe clean points):
```
robust_false_allow = P[ ∃ z' ∈ B_{1,ε}(z) : s_θ(z',a)=allow | Safe(z,a)=unsafe ]
```
Also reported: clean false-allow, and — over Category C — the fraction where the **uncertified** gate
allows a TRULY-unsafe joint-reachable point (`attack_reaches_true_unsafe_allow`).

## Run
```bash
python mixed_attack.py  # full (slow: ~1 min, retrains models)
```
For the bounded subsampled version, use `cert/evaluate_certificates.py` (Table 3).

## Result (Table 3)
The mixed attack inflates false-allow dramatically (e.g. `joint_mlp` clean 0.00 → robust ~1.0) and
makes the uncertified gate allow truly-unsafe joint-reachable points on ~40–50% of C cases. This is
the motivation for the certified wrapper in `../cert/` — robustness is **not** a property of the
accurate clean classifier; it must be certified.
