#!/usr/bin/env python3
"""
mixed_attack.py — empirical mixed discrete-continuous attack on the learned gate h_theta(z, a).

For each record we enumerate ALL d=1 discrete states (exact, finite) and search the continuous channel
inside the L2 eps-ball (deterministic polar/ring grid; k is small, per SPEC sec.16/PLAN2 step 13). We
attack the SAFE side of the decision: the attacker tries to make the gate output ``allow`` (safe).

Headline metric (SPEC; conditioned on truly-unsafe clean points):

    robust_false_allow = P[ exists z' in B_{1,eps}(z) : h_theta(z', a) = allow | Safe(z, a) = 0 ]

We also report the certificate-relevant danger over Category C: clean-safe points where a joint
perturbation reaches a TRULY-unsafe state (oracle) that the gate STILL allows -> a real false allow
that a sound certificate must refuse.
"""
from __future__ import annotations

import math
import sys
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "generators"))
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "models"))

from oracle import discrete_swaps, get_rule, safe as oracle_safe, _x1  # noqa: E402
from baselines import train_all  # noqa: E402


def _ring_offsets(k, eps, n_radii=4, n_ang=16):
    """Deterministic offsets covering the L2 eps-ball. k=2 -> polar grid; k>2 -> coordinate +/- rings."""
    radii = [eps * (i + 1) / n_radii for i in range(n_radii)]
    offs = [[0.0] * k]
    if k == 2:
        for r in radii:
            for j in range(n_ang):
                th = 2 * math.pi * j / n_ang
                offs.append([r * math.cos(th), r * math.sin(th)])
    else:
        for r in radii:
            for c in range(k):
                for s in (+1.0, -1.0):
                    v = [0.0] * k
                    v[c] = s * r
                    offs.append(v)
    return offs


def _states(rt, rec, d=1):
    dc = rt["domains"][rec["domain"]]
    a = rec["candidate_action"]
    x1 = _x1(rec)
    yield rec["tool_id"], dict(x1), 0
    for t2, x12, r in discrete_swaps(dc, rec["tool_id"], x1, d):
        if get_rule(dc, t2, a, x12) is not None:  # threat model: only action-valid provenance swaps
            yield t2, x12, r


def attack_allows(model, rt, rec, eps, thr=0.5, d=1):
    """Return (clean_allow, attacked_allow): does the gate allow the clean point / anywhere in B?"""
    a = rec["candidate_action"]
    nf = rt["domains"][rec["domain"]]["numeric_fields"]
    base = rec["numeric_fields"]
    k = len(nf)
    offs = _ring_offsets(k, eps)

    clean_allow = model.allow_point(rec["domain"], rec["tool_id"], a, _x1(rec), base, thr)
    attacked_allow = False
    for tool, x1, _r in _states(rt, rec, d):
        for off in offs:
            num = {f: float(base[f]) + off[i] for i, f in enumerate(nf)}
            if model.allow_point(rec["domain"], tool, a, x1, num, thr):
                attacked_allow = True
                break
        if attacked_allow:
            break
    return clean_allow, attacked_allow


def attack_reaches_true_unsafe_allow(model, rt, rec, eps, thr=0.5, d=1):
    """For a clean-safe record: does some z' in B that is TRULY unsafe (oracle) get allowed by the gate?
    This is the dangerous false allow a sound certificate must refuse."""
    a = rec["candidate_action"]
    nf = rt["domains"][rec["domain"]]["numeric_fields"]
    base = rec["numeric_fields"]
    offs = _ring_offsets(len(nf), eps)
    for tool, x1, _r in _states(rt, rec, d):
        for off in offs:
            num = {f: float(base[f]) + off[i] for i, f in enumerate(nf)}
            z = {"domain": rec["domain"], "tool_id": tool, "candidate_action": a,
                 "categorical_fields": x1, "numeric_fields": num}
            if not oracle_safe(z, a, rt) and model.allow_point(rec["domain"], tool, a, x1, num, thr):
                return True
    return False


def run(eps=0.10):
    models, (train, val, test), rt = train_all()
    unsafe = [r for r in test if r["y"] == 0]
    cpts = [r for r in test if r["category"] == "C"]

    print(f"eps={eps}  test unsafe pts={len(unsafe)}  test C pts={len(cpts)}\n")
    hdr = f"{'model':<22} {'cleanFalseAllow':>15} {'robustFalseAllow':>17} {'C: gate allows true-unsafe':>28}"
    print(hdr); print("-" * len(hdr))
    rows = {}
    for name, m in models.items():
        if m.is_oracle:
            continue
        clean_fa = np.mean([m.allow_point(r["domain"], r["tool_id"], r["candidate_action"], _x1(r),
                                          r["numeric_fields"]) for r in unsafe]) if unsafe else 0.0
        robust = np.mean([attack_allows(m, rt, r, eps)[1] for r in unsafe]) if unsafe else 0.0
        c_true_unsafe_allow = (np.mean([attack_reaches_true_unsafe_allow(m, rt, r, eps) for r in cpts])
                               if cpts else 0.0)
        rows[name] = {"clean_false_allow": float(clean_fa), "robust_false_allow": float(robust),
                      "C_gate_allows_true_unsafe": float(c_true_unsafe_allow)}
        print(f"{name:<22} {clean_fa:>15.3f} {robust:>17.3f} {c_true_unsafe_allow:>28.3f}")
    print("\nRead: the mixed attack inflates false-allow vs clean; on C, an UNCERTIFIED gate allows")
    print("      truly-unsafe joint-reachable points -> motivates the hybrid certificate (cert/).")
    return rows


if __name__ == "__main__":
    run()
