#!/usr/bin/env python3
"""
r_margin_diagnostics.py — explain why some R (robust-interior) records certify and others do not
(PLAN4 sec.6).

For each R record we compute the analytic ORACLE robust margin: the smallest continuous L2 distance
from x2 to an unsafe boundary over the valid d=1 discrete states,

    nearest_oracle_margin = min_{s' in D_valid_1}  |m_{s'}(x2)| / scale_{s'},

(all states are safe for an R point, so this is the easiest-to-flip / nearest boundary), and compare
it to the certificate lower bound. Expected: larger robust margin -> larger certificate lower bound.

Output: out/r_margin_diagnostics.csv  (+ printed summary).
"""
from __future__ import annotations

import argparse
import csv
import sys
import warnings
from pathlib import Path

import numpy as np

warnings.filterwarnings("ignore")
for p in ("../generators", "../models", "."):
    sys.path.insert(0, str((Path(__file__).resolve().parent / p).resolve()))

from oracle import get_rule, margin_and_scale, _x1  # noqa: E402
from baselines import train_all, train_certified_gate  # noqa: E402
from smoothed_gate import certify, _states  # noqa: E402

OUT = Path(__file__).resolve().parent / "out"


def nearest_oracle_margin(rt, rec):
    """min over valid discrete states of the L2 distance from x2 to that state's unsafe boundary."""
    dc = rt["domains"][rec["domain"]]
    a = rec["candidate_action"]
    nf = dc["numeric_fields"]
    best, worst_state = float("inf"), None
    for tool, x1 in _states(rt, rec):
        rule = get_rule(dc, tool, a, x1)
        m, scale = margin_and_scale(rule, x1, rec["numeric_fields"], nf)
        dist = abs(m) / scale if scale > 0 else float("inf")  # safe point: distance to boundary
        if dist < best:
            best, worst_state = dist, tool
    return best, worst_state


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--sigma", type=float, default=0.10)
    ap.add_argument("--epsilon", "--eps", dest="eps", type=float, default=0.10)
    ap.add_argument("--tau", type=float, default=0.95)
    ap.add_argument("--n-mc", type=int, default=2000)
    ap.add_argument("--alpha", type=float, default=1e-3)
    ap.add_argument("--n", type=int, default=150, help="max R records")
    args = ap.parse_args()

    models, (train, val, test), rt = train_all()
    gate = train_certified_gate(train, rt, sigma=args.sigma, n_aug=6)
    R = [r for r in test if r["category"] == "R"][:args.n]

    rows = []
    for r in R:
        margin, worst_oracle = nearest_oracle_margin(rt, r)
        c = certify(gate, rt, r, sigma=args.sigma, eps=args.eps, tau=args.tau,
                    n_mc=args.n_mc, alpha=args.alpha)
        rows.append({
            "record_id": r["id"], "domain": r["domain"], "candidate_action": r["candidate_action"],
            "epsilon": args.eps, "sigma": args.sigma, "tau": args.tau,
            "lower_bound_probability": c["lower_bound_probability"], "allow": int(c["allow"]),
            "nearest_oracle_margin": round(margin, 4),
            "worst_discrete_state": c["worst_discrete_state"]["tool_id"],
            "worst_oracle_state": worst_oracle,
        })

    OUT.mkdir(exist_ok=True)
    with open(OUT / "r_margin_diagnostics.csv", "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        w.writeheader()
        w.writerows(rows)

    allowed = [r for r in rows if r["allow"]]
    refused = [r for r in rows if not r["allow"]]
    corr = float(np.corrcoef([r["nearest_oracle_margin"] for r in rows],
                             [r["lower_bound_probability"] for r in rows])[0, 1]) if len(rows) > 2 else float("nan")
    print(f"R records                 : {len(rows)}")
    print(f"R allowed                 : {len(allowed)}")
    print(f"R refused                 : {len(refused)}")
    print(f"mean margin allowed R      : {np.mean([r['nearest_oracle_margin'] for r in allowed]):.4f}"
          if allowed else "mean margin allowed R      : n/a")
    print(f"mean margin refused R      : {np.mean([r['nearest_oracle_margin'] for r in refused]):.4f}"
          if refused else "mean margin refused R      : n/a")
    print(f"corr(margin, lower_bound)  : {corr:.3f}   (expect > 0: larger margin -> larger bound)")
    print(f"wrote -> {OUT/'r_margin_diagnostics.csv'}")


if __name__ == "__main__":
    main()
