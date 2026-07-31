#!/usr/bin/env python3
"""
multiseed_variance.py — Table L5: mean ± std over seeds for the HEADLINE backend numbers, so the
deterministic-LipGate recovery (and the suspicious ops ordering det > MLP-smoothing@10k) is reported
with variance rather than a single seed. Mirrors the OPA multi-seed table.

For each (domain, ε) and seed, train LipGate (robust-aug) + the project MLP on distinct draws, then
evaluate on a category-balanced subset:
    lipgate_deterministic | lipgate_smoothing(M) | mlp_smoothing(M=2000) | mlp_smoothing(M=10000)
and aggregate R_allow (= cert_recovery_vs_exact), cert_false_allow, C_allow, U_allow across seeds.
"""
from __future__ import annotations

import argparse
import csv
import random
import sys
import warnings
from collections import defaultdict
from pathlib import Path

import numpy as np

warnings.filterwarnings("ignore")
_EXP = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_EXP / "models"))
sys.path.insert(0, str(_EXP.parents[1] / "experiments" / "opa_gate"))
import lip_gate as LG  # noqa: E402
from run_opa_gate import train_gate_opa  # noqa: E402
from smoothed_gate import certify as smooth_certify  # noqa: E402

TAB = _EXP / "results" / "tables"


def _balanced(cats, recs, per_cat, seed):
    rng = random.Random(seed)
    by = defaultdict(list)
    for c, r in zip(cats, recs):
        by[c["category"]].append((c, r))
    out = []
    for cat in ("R", "C", "U"):
        xs = by[cat]; rng.shuffle(xs); out += xs[:per_cat]
    return out


def _rates(sub, allow_fn):
    by = {k: [0, 0] for k in "RCU"}
    cfa = [0, 0]
    for c, r in sub:
        a = bool(allow_fn(r))
        if c["category"] in by:
            by[c["category"]][1] += 1; by[c["category"]][0] += int(a)
        if a:
            cfa[1] += 1; cfa[0] += int(c["truly_unsafe_reachable"])

    def rt(b):
        return b[0] / b[1] if b[1] else float("nan")
    return rt(by["R"]), rt(by["C"]), rt(by["U"]), (cfa[0] / cfa[1] if cfa[1] else 0.0)


def run(domains, seeds, eps_list, mc_high, per_cat, n_train, n_eval, sigma, tau, alpha):
    # per (domain, eps, backend) -> list of (R, C, U, cfa) across seeds
    acc = defaultdict(list)
    for s in seeds:
        for di, domain in enumerate(domains):
            seed = 100 * s + di
            orc = LG.OpaOracle(domain)
            enc = LG.make_encoder(orc.rt)
            train = LG.sample_records(domain, n_train, seed=seed)
            ev = LG.sample_records(domain, n_eval, seed=seed + 1)
            lip = LG.train_lipgate(orc, enc, train, variant="robust-aug", seed=seed)
            wrap = LG.LipSmoothWrapper(lip, enc, orc.rt)
            mlp = train_gate_opa(orc, train, sigma, n_aug=4, seed=seed)
            for eps in eps_list:
                cats, _ = LG.exact_categories(orc, ev, eps)
                sub = _balanced(cats, ev, per_cat, seed)
                backends = {
                    "lipgate_deterministic": lambda r, eps=eps: LG.certify_lip(lip, enc, orc.rt, r, eps)["allow"],
                    f"lipgate_smoothing_M{mc_high}": lambda r, eps=eps: LG.certify_smooth(
                        wrap, orc.rt, r, sigma, eps, tau, mc_high, alpha)["allow"],
                    "mlp_smoothing_M2000": lambda r, eps=eps: smooth_certify(
                        mlp, orc.rt, r, sigma=sigma, eps=eps, tau=tau, n_mc=2000, alpha=alpha)["allow"],
                    f"mlp_smoothing_M{mc_high}": lambda r, eps=eps: smooth_certify(
                        mlp, orc.rt, r, sigma=sigma, eps=eps, tau=tau, n_mc=mc_high, alpha=alpha)["allow"],
                }
                for bk, fn in backends.items():
                    acc[(domain, eps, bk)].append(_rates(sub, fn))
            print(f"  seed={s} {domain} done")
    return acc


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--domains", default="finance,sre,ops")
    ap.add_argument("--seeds", default="0,1,2,3,4")
    ap.add_argument("--eps-list", default="0.03,0.10")
    ap.add_argument("--mc-high", type=int, default=10000)
    ap.add_argument("--per-cat", type=int, default=60)
    ap.add_argument("--n-train", type=int, default=1500)
    ap.add_argument("--n-eval", type=int, default=400)
    ap.add_argument("--sigma", type=float, default=0.10)
    ap.add_argument("--tau", type=float, default=0.90)
    ap.add_argument("--alpha", type=float, default=0.001)
    args = ap.parse_args()
    TAB.mkdir(parents=True, exist_ok=True)
    seeds = [int(x) for x in args.seeds.split(",") if x.strip()]
    eps_list = [float(x) for x in args.eps_list.split(",") if x.strip()]
    domains = [d.strip() for d in args.domains.split(",") if d.strip()]

    acc = run(domains, seeds, eps_list, args.mc_high, args.per_cat, args.n_train, args.n_eval,
              args.sigma, args.tau, args.alpha)
    rows = []
    for (domain, eps, bk), vals in acc.items():
        arr = np.array(vals, dtype=float)        # columns R,C,U,cfa
        rows.append({"domain": domain, "epsilon": eps, "backend": bk, "n_seeds": len(vals),
                     "R_allow_mean": round(float(np.nanmean(arr[:, 0])), 4),
                     "R_allow_std": round(float(np.nanstd(arr[:, 0])), 4),
                     "C_allow_mean": round(float(np.nanmean(arr[:, 1])), 4),
                     "U_allow_mean": round(float(np.nanmean(arr[:, 2])), 4),
                     "cert_false_allow_mean": round(float(np.nanmean(arr[:, 3])), 4),
                     "cert_false_allow_max": round(float(np.nanmax(arr[:, 3])), 4)})
    order = {"lipgate_deterministic": 0}
    rows.sort(key=lambda r: (r["domain"], float(r["epsilon"]), order.get(r["backend"], 9), r["backend"]))
    cols = ["domain", "epsilon", "backend", "n_seeds", "R_allow_mean", "R_allow_std",
            "C_allow_mean", "U_allow_mean", "cert_false_allow_mean", "cert_false_allow_max"]
    with open(TAB / "L5_multiseed_variance.csv", "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=cols, extrasaction="ignore"); w.writeheader(); w.writerows(rows)

    for r in rows:
        print(f"  {r['domain']:8s} eps={r['epsilon']} {r['backend']:24s} "
              f"R_allow={r['R_allow_mean']}±{r['R_allow_std']} cfa_max={r['cert_false_allow_max']}")
    # headline ordering check on ops @ eps=0.10
    def get(domain, eps, bk):
        return next((r for r in rows if r["domain"] == domain and float(r["epsilon"]) == eps
                     and r["backend"] == bk), None)
    for domain in domains:
        det = get(domain, 0.10, "lipgate_deterministic")
        mlp = get(domain, 0.10, f"mlp_smoothing_M{args.mc_high}")
        if det and mlp:
            gap = det["R_allow_mean"] - mlp["R_allow_mean"]
            pooled = (det["R_allow_std"] ** 2 + mlp["R_allow_std"] ** 2) ** 0.5
            verdict = ("det > MLP@%d beyond ±std" % args.mc_high if gap > pooled else
                       "within ±std (not separated)")
            print(f"[ordering @eps=0.10 {domain}] det={det['R_allow_mean']}±{det['R_allow_std']} "
                  f"vs mlp@{args.mc_high}={mlp['R_allow_mean']}±{mlp['R_allow_std']} -> {verdict}")
    print(f"\nwrote -> {TAB/'L5_multiseed_variance.csv'}")


if __name__ == "__main__":
    main()
