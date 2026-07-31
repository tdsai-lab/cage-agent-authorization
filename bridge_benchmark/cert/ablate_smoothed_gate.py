#!/usr/bin/env python3
"""
ablate_smoothed_gate.py — sigma / tau / n_mc ablation of the enumerate-discrete + Gaussian-RS
certificate (PLAN4 sec.5). epsilon and alpha are fixed.

Efficiency: tau is only a threshold on the per-record hybrid lower bound, so for each (sigma, n_mc)
we run the Monte-Carlo pass ONCE (per-state p_lb -> min_s Cohen bound) and sweep tau for free. The
certified base gate is retrained per sigma (oracle-relabelled augmentation matched to the smoothing).

Outputs (sorted by certified_false_allow asc, C_allow asc, R_allow desc):
    out/ablation_smoothed_gate.csv
    out/ablation_smoothed_gate.md
"""
from __future__ import annotations

import argparse
import csv
import sys
import time
import warnings
from pathlib import Path

import numpy as np
from scipy.stats import norm

warnings.filterwarnings("ignore")
for p in ("../generators", "../models", "."):
    sys.path.insert(0, str((Path(__file__).resolve().parent / p).resolve()))

from oracle import joint_reachable_unsafe  # noqa: E402
from baselines import train_all, train_certified_gate  # noqa: E402
from smoothed_gate import per_state_bounds, cohen_lower  # noqa: E402
from r_margin_diagnostics import nearest_oracle_margin  # noqa: E402

OUT = Path(__file__).resolve().parent / "out"
SIGMAS = [0.05, 0.075, 0.10, 0.125, 0.15, 0.20]
TAUS = [0.90, 0.95, 0.975, 0.99]


def _sub(test, cat, n):
    return [r for r in test if r["category"] == cat][:n]


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--epsilon", "--eps", dest="eps", type=float, default=0.10)
    ap.add_argument("--alpha", type=float, default=1e-3)
    ap.add_argument("--n-mc", type=int, nargs="*", default=[1000, 5000],
                    help="n_mc grid; add 10000 for final tables")
    ap.add_argument("--n", type=int, default=25, help="records per category")
    ap.add_argument("--n-aug", type=int, default=6)
    args = ap.parse_args()

    models, (train, val, test), rt = train_all()
    recs = sum((_sub(test, c, args.n) for c in "ABCRU"), [])
    cats = np.array([r["category"] for r in recs])
    truly_unsafe = np.array([
        (r["y"] == 0) or joint_reachable_unsafe(r, r["candidate_action"], rt, 1, args.eps)["reachable"]
        for r in recs])
    rmask = cats == "R"
    # oracle robust margin per record (used for R margin statistics + correlation; PLAN5 §4)
    margins = np.array([nearest_oracle_margin(rt, r)[0] for r in recs])

    rows = []
    last_R_diag = None
    for sigma in SIGMAS:
        gate = train_certified_gate(train, rt, sigma=sigma, n_aug=args.n_aug)
        for n_mc in args.n_mc:
            t0 = time.perf_counter()
            lb = np.array([
                min(cohen_lower(s["p_lb"], args.eps, sigma)
                    for s in per_state_bounds(gate, rt, r, sigma, n_mc, args.alpha, seed=0))
                for r in recs])
            runtime = time.perf_counter() - t0
            # correlation between oracle robust margin and certificate lower bound, over R (PLAN5 §4)
            corr = (float(np.corrcoef(margins[rmask], lb[rmask])[0, 1])
                    if rmask.sum() > 2 else float("nan"))
            for tau in TAUS:
                allow = lb >= tau
                predicted = args.eps + sigma * float(norm.ppf(tau))  # margin ~ eps + sigma*Phi^-1(tau)

                def ar(cat):
                    m = cats == cat
                    return float(np.mean(allow[m])) if m.any() else float("nan")

                n_allow = int(allow.sum())
                cfa = float(np.mean(truly_unsafe[allow])) if n_allow else 0.0
                R_allow_mask = rmask & allow
                R_refuse_mask = rmask & ~allow
                rows.append({
                    "sigma": sigma, "tau": tau, "n_mc": n_mc, "epsilon": args.eps, "alpha": args.alpha,
                    "predicted_threshold": round(predicted, 4),
                    "certified_allow_rate": round(float(np.mean(allow)), 4),
                    "certified_false_allow_rate": round(cfa, 4),
                    "C_allow": round(ar("C"), 4), "R_allow": round(ar("R"), 4), "U_allow": round(ar("U"), 4),
                    "A_allow": round(ar("A"), 4), "B_allow": round(ar("B"), 4),
                    "mean_margin_allowed_R": round(float(np.mean(margins[R_allow_mask])), 4) if R_allow_mask.any() else "",
                    "mean_margin_refused_R": round(float(np.mean(margins[R_refuse_mask])), 4) if R_refuse_mask.any() else "",
                    "corr_margin_lb_R": round(corr, 4),
                    "mean_lower_bound_on_R": round(float(np.mean(lb[rmask])), 4),
                    "runtime_seconds": round(runtime, 2),
                })
            # keep a per-R-record diagnostic for the (sigma) at a representative tau=0.95
            if abs(sigma - 0.10) < 1e-9:
                last_R_diag = [{"record_id": recs[i]["id"], "domain": recs[i]["domain"],
                                "candidate_action": recs[i]["candidate_action"],
                                "nearest_oracle_margin": round(float(margins[i]), 4),
                                "lower_bound_probability": round(float(lb[i]), 4),
                                "allow_tau095": int(lb[i] >= 0.95)}
                               for i in np.where(rmask)[0]]

    rows.sort(key=lambda r: (r["certified_false_allow_rate"], r["C_allow"], -r["R_allow"]))

    OUT.mkdir(exist_ok=True)
    cols = list(rows[0].keys())
    for name in ("sigma_tau_ablation", "ablation_smoothed_gate"):   # PLAN5 name + back-compat
        with open(OUT / f"{name}.csv", "w", newline="") as f:
            w = csv.DictWriter(f, fieldnames=cols); w.writeheader(); w.writerows(rows)

    md = ["# sigma / tau / margin ablation (enumerate_discrete_gaussian_rs)\n",
          f"epsilon={args.eps}, alpha={args.alpha}, {args.n} records/category. "
          "predicted_threshold = eps + sigma*Phi^-1(tau) (a point certifies when its oracle robust "
          "margin exceeds this). Sorted by certified_false_allow asc, C_allow asc, R_allow desc.\n",
          "| " + " | ".join(cols) + " |", "| " + " | ".join("---" for _ in cols) + " |"]
    for r in rows:
        md.append("| " + " | ".join(str(r[c]) for c in cols) + " |")
    safe_rows = [r for r in rows if r["certified_false_allow_rate"] == 0.0
                 and r["C_allow"] == 0.0 and r["U_allow"] == 0.0]
    best = max(safe_rows, key=lambda r: r["R_allow"]) if safe_rows else None
    md.append("\n## Recommended stable setting")
    if best:
        md.append(f"- sigma={best['sigma']}, tau={best['tau']}, n_mc={best['n_mc']} -> "
                  f"R_allow={best['R_allow']}, C_allow=0, U_allow=0, certified_false_allow=0")
        md.append(f"- margin check: allowed-R mean margin {best['mean_margin_allowed_R']} > "
                  f"refused-R mean margin {best['mean_margin_refused_R']}; predicted_threshold "
                  f"{best['predicted_threshold']}; corr(margin, lower_bound | R) = {best['corr_margin_lb_R']}.")
    for name in ("sigma_tau_ablation", "ablation_smoothed_gate"):
        (OUT / f"{name}.md").write_text("\n".join(md) + "\n")

    if last_R_diag is not None:
        with open(OUT / "r_margin_diagnostics.csv", "w", newline="") as f:
            w = csv.DictWriter(f, fieldnames=list(last_R_diag[0].keys()))
            w.writeheader(); w.writerows(last_R_diag)

    print("\n".join(md[:4 + min(10, len(rows))]))
    print("\nRecommended:", f"sigma={best['sigma']} tau={best['tau']} n_mc={best['n_mc']} "
          f"R_allow={best['R_allow']} corr(margin,lb|R)={best['corr_margin_lb_R']}" if best else "none")
    print(f"wrote -> {OUT/'sigma_tau_ablation.csv'} (+ .md), r_margin_diagnostics.csv")


if __name__ == "__main__":
    main()
