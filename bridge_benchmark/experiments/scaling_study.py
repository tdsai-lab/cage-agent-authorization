#!/usr/bin/env python3
"""
scaling_study.py — controlled scaling experiment for the typed gate + certificate (no LLM).

Varies the tool vocabulary K, the numeric dimension k, and the categorical complexity |X1|, keeping
d=1, and runs the SAME pipeline (oracle labels -> small gate -> empirical attack -> enumerate-discrete
+ Gaussian-RS certificate). Demonstrates, at scale:
  * Category C exists systematically (not hand-crafted);
  * R_allow stays non-vacuous;
  * marginal / naive certificates fail reproducibly (naive_C_falseallow ~ 1, attack_false_allow high),
    while the hybrid enumerate certificate keeps C_allow = 0 and cert_false_allow = 0.

Writes out/scaling_results.csv and out/scaling_results.md.
"""
from __future__ import annotations

import argparse
import csv
import sys
import warnings
from pathlib import Path

warnings.filterwarnings("ignore")
sys.path.insert(0, str(Path(__file__).resolve().parent))
from synthetic_tools import make_rule_table, sample_records  # noqa: E402
from harness import run_setting, to_md, SCALING_COLS  # noqa: E402

OUT = Path(__file__).resolve().parents[1] / "cert" / "out"


def settings(full=False):
    """(label, K, k, x1) sweeps. Shared anchor K=8,k=5,|X1|=4 appears once."""
    s = []
    Ks = [4, 8, 16, 32]
    ks = [2, 5, 10, 20, 50]
    x1s = [2, 4, 8]
    for K in Ks:
        s.append((f"K-sweep K={K}", K, 5, 4))
    for k in ks:
        s.append((f"k-sweep k={k}", 8, k, 4))
    for x in x1s:
        s.append((f"X1-sweep |X1|={x}", 8, 5, x))
    if full:
        for K in Ks:
            for k in ks:
                s.append((f"grid K={K} k={k}", K, k, 4))
    # dedupe by (K,k,x1)
    seen, out = set(), []
    for lbl, K, k, x in s:
        key = (K, k, x)
        if key not in seen:
            seen.add(key); out.append((lbl, K, k, x))
    return out


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--n", type=int, default=8000, help="records per setting")
    ap.add_argument("--sigma", type=float, default=0.10)
    ap.add_argument("--tau", type=float, default=0.90)
    ap.add_argument("--eps", type=float, default=0.10)
    ap.add_argument("--n-mc", type=int, default=2000)
    ap.add_argument("--n-cert", type=int, default=40)
    ap.add_argument("--n-attack", type=int, default=60)
    ap.add_argument("--n-aug", type=int, default=8)
    ap.add_argument("--full", action="store_true", help="add the full K x k grid")
    ap.add_argument("--seed", type=int, default=1)
    args = ap.parse_args()

    rows = []
    for lbl, K, k, x1 in settings(args.full):
        rt = make_rule_table(K=K, k=k, x1_size=x1, seed=args.seed)
        recs = sample_records(rt, args.n, eps=args.eps, seed=args.seed)
        row = run_setting(rt, recs, eps=args.eps, sigma=args.sigma, tau=args.tau, n_mc=args.n_mc,
                          n_cert=args.n_cert, n_attack=args.n_attack, n_aug=args.n_aug,
                          train_cap=min(args.n, 16000), seed=args.seed, label=lbl)
        rows.append(row)
        print(f"{lbl:18s} K={K:2d} k={k:2d} |X1|={x1} | C%={row['C_pct']:4.1f} R%={row['R_pct']:4.1f} "
              f"| cleanAcc={row['clean_acc']:.3f} attackFA={row['attack_false_allow']:.2f} "
              f"naiveC={row['naive_C_falseallow']:.2f} | C_allow={row['C_allow']:.2f} "
              f"R_allow={row['R_allow']:.2f} U_allow={row['U_allow']:.2f} cFA={row['cert_false_allow']:.2f} "
              f"| {row['runtime_seconds']:.0f}s")

    OUT.mkdir(parents=True, exist_ok=True)
    with open(OUT / "scaling_results.csv", "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=SCALING_COLS)
        w.writeheader()
        w.writerows([{c: r.get(c, "") for c in SCALING_COLS} for r in rows])
    note = (f"sigma={args.sigma}, tau={args.tau}, eps={args.eps}, n_mc={args.n_mc}, "
            f"{args.n} records/setting. d=1. Certificate = enumerate_discrete_gaussian_rs.")
    (OUT / "scaling_results.md").write_text(to_md(rows, SCALING_COLS, "Scaling study", note))

    # invariants that must hold across the whole grid
    bad_C = [r["label"] for r in rows if r["C_allow"] not in (0, 0.0)]
    bad_fa = [r["label"] for r in rows if r["cert_false_allow"] not in (0, 0.0)]
    vac = [r["label"] for r in rows if r["R_allow"] in (0, 0.0)]
    print(f"\nC_allow>0 in: {bad_C or 'NONE'}")
    print(f"cert_false_allow>0 in: {bad_fa or 'NONE'}")
    print(f"R_allow==0 (vacuous) in: {vac or 'NONE'}")
    print(f"wrote -> {OUT/'scaling_results.csv'} and .md")


if __name__ == "__main__":
    main()
