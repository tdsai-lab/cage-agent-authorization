#!/usr/bin/env python3
"""
audit_smoothed_gate.py — correctness audit of the enumerate-discrete + Gaussian-RS certificate
(PLAN4 sec.4). Verifies the structural and behavioural properties the certificate must satisfy.

Checks:
  1. Every certified record uses only ACTION-VALID discrete states.
  2. No invalid tool/action pair is queried.
  3. p_s is estimated at the CLEAN x2 (delta = 0), not an adversarially shifted x2.
  4. The RS epsilon penalty is applied EXACTLY ONCE.
  5. lower_bound_probability is always in [0, 1].
  6. C records have certified allow = 0.
  7. U records have certified allow = 0.
  8. R records have a nonzero certified allow rate.
"""
from __future__ import annotations

import argparse
import sys
import warnings
from pathlib import Path

import numpy as np
from scipy.stats import norm

warnings.filterwarnings("ignore")
for p in ("../generators", "../models", "../attacks", "."):
    sys.path.insert(0, str((Path(__file__).resolve().parent / p).resolve()))

from oracle import get_rule, _x1  # noqa: E402
from baselines import train_all, train_certified_gate  # noqa: E402
from smoothed_gate import (certify, per_state_bounds, smoothed_p_safe, cohen_lower, _states)  # noqa: E402


def _sub(test, cat, n):
    return [r for r in test if r["category"] == cat][:n]


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--sigma", type=float, default=0.10)
    ap.add_argument("--epsilon", "--eps", dest="eps", type=float, default=0.10)
    ap.add_argument("--tau", type=float, default=0.95)
    ap.add_argument("--n-mc", type=int, default=2000)
    ap.add_argument("--alpha", type=float, default=1e-3)
    ap.add_argument("--n", type=int, default=40, help="records per category")
    args = ap.parse_args()

    models, (train, val, test), rt = train_all()
    gate = train_certified_gate(train, rt, sigma=args.sigma, n_aug=6)
    recs = sum((_sub(test, c, args.n) for c in "ABCRU"), [])

    invalid_states = 0
    out_of_range = 0
    penalty_mismatch = 0
    delta0_violation = 0
    certs = []

    for r in recs:
        # (1,2) action-valid states only
        a = r["candidate_action"]
        dc = rt["domains"][r["domain"]]
        for tool, x1 in _states(rt, r):
            if get_rule(dc, tool, a, x1) is None:
                invalid_states += 1

        c = certify(gate, rt, r, sigma=args.sigma, eps=args.eps, tau=args.tau,
                    n_mc=args.n_mc, alpha=args.alpha)
        certs.append((r, c))

        # (5) lower bound in [0,1]
        lb = c["lower_bound_probability"]
        if not (0.0 - 1e-9 <= lb <= 1.0 + 1e-9):
            out_of_range += 1

        # (4) epsilon penalty applied exactly once: recompute min_s Phi(Phi^-1(p_lb_s) - eps/sigma)
        # from the SAME seeded per-state p_lb and compare to the reported lower bound.
        ps = per_state_bounds(gate, rt, r, args.sigma, args.n_mc, args.alpha, seed=0)
        recomputed_once = min(cohen_lower(s["p_lb"], args.eps, args.sigma) for s in ps)
        if abs(recomputed_once - lb) > 1e-3:
            penalty_mismatch += 1
        # a hypothetical DOUBLE penalty would be strictly smaller; confirm reported != double
        double = min(cohen_lower(s["p_lb"], 2 * args.eps, args.sigma) for s in ps)
        if args.eps > 0 and abs(double - lb) < 1e-9 and abs(double - recomputed_once) > 1e-6:
            penalty_mismatch += 1

    # (3) p_s estimated at delta=0: with sigma -> 0 the smoothed estimate must equal the gate's
    #     CLEAN prediction at x2 (noise is centered at x2, no adversarial shift).
    rng = np.random.default_rng(0)
    for r in recs[:30]:
        tool, x1 = next(_states(rt, r))  # identity state
        k, n = smoothed_p_safe(gate, rt, r["domain"], tool, r["candidate_action"], x1,
                               r["numeric_fields"], sigma=1e-9, n_mc=64, rng=rng)
        p_tiny = k / n
        clean = gate.proba_safe_point(r["domain"], r["tool_id"], r["candidate_action"], _x1(r),
                                      r["numeric_fields"]) >= 0.5
        if round(p_tiny) != int(clean):
            delta0_violation += 1

    # category allow rates + certified false allow
    def rate(cat):
        xs = [c for r, c in certs if r["category"] == cat]
        return float(np.mean([c["allow"] for c in xs])) if xs else float("nan")

    allowed = [(r, c) for r, c in certs if c["allow"]]
    # truly unsafe in B_{1,eps} (oracle joint-reachable) OR clean-unsafe -> a false allow
    from oracle import joint_reachable_unsafe
    false_allow = sum(1 for r, c in allowed
                      if r["y"] == 0 or joint_reachable_unsafe(r, r["candidate_action"], rt, 1, args.eps)["reachable"])
    cfa = false_allow / max(1, len(allowed))

    print(f"records audited            : {len(recs)}")
    print(f"invalid discrete states    : {invalid_states}        (expect 0)")
    print(f"out-of-range lower bounds   : {out_of_range}        (expect 0)")
    print(f"eps-penalty mismatches      : {penalty_mismatch}        (expect 0  -> applied exactly once)")
    print(f"delta=0 estimation viol.    : {delta0_violation}        (expect 0  -> p_s centered at clean x2)")
    print(f"C allow rate                : {rate('C'):.3f}    (expect 0)")
    print(f"U allow rate                : {rate('U'):.3f}    (expect 0)")
    print(f"R allow rate                : {rate('R'):.3f}    (expect > 0)")
    print(f"A allow rate                : {rate('A'):.3f}")
    print(f"B allow rate                : {rate('B'):.3f}")
    print(f"certified false allow rate  : {cfa:.3f}    (expect 0)")

    ok = (invalid_states == 0 and out_of_range == 0 and penalty_mismatch == 0
          and delta0_violation == 0 and rate("C") == 0.0 and rate("U") == 0.0
          and rate("R") > 0.0 and cfa == 0.0)
    print("\nAUDIT:", "PASS" if ok else "FAIL")
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
