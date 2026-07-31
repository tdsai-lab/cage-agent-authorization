#!/usr/bin/env python3
"""
dimension_validity.py — regime-of-validity sweep over the continuous dimension k (PLAN5 §3).

The important scaling axis at d=1 is k (the number of numeric fields), not K. We sweep
k ∈ {2, 5, 10, 20, 50, 100} with K fixed, d=1, ε=0.10, training the same small tabular gate, and ask:
does the certificate's non-vacuity (R_allow) survive as the continuous dimension grows? This
quantifies how far the "tool returns are low-dimensional" assumption holds. Either outcome is useful:
survival up to k=50/100 is a strong result; degradation defines the regime of validity.

Output: out/dimension_validity.csv and .md.
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
from harness import run_setting  # noqa: E402

OUT = Path(__file__).resolve().parents[1] / "cert" / "out"
KS = [2, 5, 10, 20, 50, 100]
COLS = ["k", "K", "n_records", "C_pct", "R_pct", "U_pct", "clean_acc", "attack_false_allow",
        "C_allow", "R_allow", "U_allow", "cert_false_allow", "runtime_seconds"]


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--K", type=int, default=8)
    ap.add_argument("--n", type=int, default=6000)
    ap.add_argument("--eps", type=float, default=0.10)
    ap.add_argument("--sigma", type=float, default=0.10)
    ap.add_argument("--tau", type=float, default=0.90)
    ap.add_argument("--n-mc", type=int, default=1500)
    ap.add_argument("--n-cert", type=int, default=40)
    ap.add_argument("--n-attack", type=int, default=50)
    ap.add_argument("--ks", type=int, nargs="*", default=KS)
    ap.add_argument("--seed", type=int, default=1)
    args = ap.parse_args()

    rows = []
    for k in args.ks:
        rt = make_rule_table(K=args.K, k=k, x1_size=4, seed=args.seed)
        recs = sample_records(rt, args.n, eps=args.eps, seed=args.seed)
        row = run_setting(rt, recs, eps=args.eps, sigma=args.sigma, tau=args.tau, n_mc=args.n_mc,
                          n_cert=args.n_cert, n_attack=args.n_attack, n_aug=8,
                          train_cap=min(args.n, 16000), seed=args.seed, label=f"k={k}")
        rows.append({c: row.get(c if c != "k" else "k", k) for c in COLS} | {"k": k})
        print(f"k={k:3d} | C%={row['C_pct']:4.1f} R%={row['R_pct']:4.1f} | cleanAcc={row['clean_acc']:.3f} "
              f"attackFA={row['attack_false_allow']:.2f} | C_allow={row['C_allow']:.2f} "
              f"R_allow={row['R_allow']:.2f} U_allow={row['U_allow']:.2f} cFA={row['cert_false_allow']:.2f} "
              f"| {row['runtime_seconds']:.0f}s")

    OUT.mkdir(parents=True, exist_ok=True)
    with open(OUT / "dimension_validity.csv", "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=COLS); w.writeheader(); w.writerows(rows)
    md = ["# Dimension validity — certificate non-vacuity vs continuous dimension k\n",
          f"K={args.K}, d=1, eps={args.eps}, sigma={args.sigma}, tau={args.tau}, n_mc={args.n_mc}, "
          f"n={args.n}/k.\n",
          "| " + " | ".join(COLS) + " |", "| " + " | ".join("---" for _ in COLS) + " |"]
    for r in rows:
        md.append("| " + " | ".join(str(r[c]) for c in COLS) + " |")
    rmin = min(r["R_allow"] for r in rows); rmax = max(r["R_allow"] for r in rows)
    md.append(f"\n**Regime of validity:** R_allow ∈ [{rmin:.2f}, {rmax:.2f}] across k∈{args.ks}; "
              f"C_allow max={max(r['C_allow'] for r in rows):.2f}, "
              f"cert_false_allow max={max(r['cert_false_allow'] for r in rows):.2f} (sound at every k). "
              "Soundness is dimension-independent; non-vacuity is what k stresses.")
    (OUT / "dimension_validity.md").write_text("\n".join(md) + "\n")
    print(f"\nwrote -> {OUT/'dimension_validity.csv'} and .md")


if __name__ == "__main__":
    main()
