#!/usr/bin/env python3
"""measure_runtime.py — Table L3. Per-example certificate latency (mean/p50/p95) for each backend on
the authored-Rego setting, with repeats. Measures the OPA exact oracle, MLP smoothing (M∈{1500,2000,
10000}), and the deterministic LipGate certificate separately."""
from __future__ import annotations

import argparse
import csv
import statistics
import sys
import time
import warnings
from pathlib import Path

warnings.filterwarnings("ignore")
_EXP = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_EXP / "models"))
sys.path.insert(0, str(_EXP.parents[1] / "experiments" / "opa_gate"))
import lip_gate as LG  # noqa: E402
from run_opa_gate import train_gate_opa  # noqa: E402
from smoothed_gate import certify as smooth_certify  # noqa: E402


def _pct(xs, q):
    xs = sorted(xs)
    return xs[min(len(xs) - 1, int(round(q * (len(xs) - 1))))] if xs else float("nan")


def time_backend(fn, recs, repeats):
    lat = []
    for _ in range(repeats):
        for r in recs:
            t0 = time.perf_counter(); fn(r); lat.append((time.perf_counter() - t0) * 1e3)
    return {"mean_ms": round(statistics.fmean(lat), 4), "p50_ms": round(_pct(lat, 0.5), 4),
            "p95_ms": round(_pct(lat, 0.95), 4)}


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--domain", default="finance")
    ap.add_argument("--eps", type=float, default=0.10)
    ap.add_argument("--n", type=int, default=60)
    ap.add_argument("--repeats", type=int, default=3)
    ap.add_argument("--mc-list", default="1500,2000,10000")
    ap.add_argument("--sigma", type=float, default=0.10)
    ap.add_argument("--tau", type=float, default=0.90)
    ap.add_argument("--alpha", type=float, default=0.001)
    ap.add_argument("--seed", type=int, default=0)
    args = ap.parse_args()
    TAB = _EXP / "results" / "tables"; TAB.mkdir(parents=True, exist_ok=True)
    mc_list = [int(x) for x in args.mc_list.split(",") if x.strip()]

    orc = LG.OpaOracle(args.domain)
    enc = LG.make_encoder(orc.rt)
    train = LG.sample_records(args.domain, 1200, seed=args.seed)
    recs = LG.sample_records(args.domain, args.n, seed=args.seed + 5)
    lip = LG.train_lipgate(orc, enc, train, variant="robust-aug", seed=args.seed)
    mlp = train_gate_opa(orc, train, args.sigma, n_aug=4, seed=args.seed)
    cats, _ = LG.exact_categories(orc, recs, args.eps)

    rows = []
    rows.append({"backend": "opa_exact_oracle", "n_mc": 0,
                 **time_backend(lambda r: orc.categorize([r], args.eps), recs, args.repeats)})
    for m in mc_list:
        rows.append({"backend": "mlp_smoothing", "n_mc": m,
                     **time_backend(lambda r, m=m: smooth_certify(mlp, orc.rt, r, sigma=args.sigma,
                                    eps=args.eps, tau=args.tau, n_mc=m, alpha=args.alpha),
                                    recs, args.repeats)})
    rows.append({"backend": "lipgate_deterministic", "n_mc": 0,
                 **time_backend(lambda r: LG.certify_lip(lip, enc, orc.rt, r, args.eps), recs, args.repeats)})

    base = next(r["mean_ms"] for r in rows if r["backend"] == "lipgate_deterministic")
    for r in rows:
        r["epsilon"] = args.eps
        r["relative_cost"] = round(r["mean_ms"] / base, 2) if base else float("nan")
    cols = ["backend", "epsilon", "n_mc", "mean_ms", "p50_ms", "p95_ms", "relative_cost"]
    with open(TAB / "L3_cost.csv", "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=cols, extrasaction="ignore"); w.writeheader(); w.writerows(rows)
    for r in rows:
        print(f"  {r['backend']:24s} M={r['n_mc']:>5} mean={r['mean_ms']}ms p95={r['p95_ms']}ms "
              f"rel={r['relative_cost']}x")
    print(f"\nwrote -> {TAB/'L3_cost.csv'}")


if __name__ == "__main__":
    main()
