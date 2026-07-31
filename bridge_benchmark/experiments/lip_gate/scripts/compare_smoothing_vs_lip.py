#!/usr/bin/env python3
"""
compare_smoothing_vs_lip.py — EXP_LIP_VS_RS main run (Table L1 + raw recovery for L2/L3).

For each authored-Rego domain and ε, evaluate every backend on a category-balanced eval set and report
recovery of the EXACT robust-safe set (R_allow == cert_recovery_vs_exact), C_allow, U_allow, empirical
oracle cert_false_allow, and per-example cost:

    exact oracle | uncertified LipGate | MLP+smoothing (M∈{1500,2000,10000}) |
    LipGate+smoothing (M∈{2000,10000}) | LipGate+deterministic | naive marginal

The clean smoothing-tax isolation is LipGate+smoothing vs LipGate+deterministic (same model).
policy_provenance = authored_provenance_conditioned_rego. The deterministic certificate certifies the
LEARNED gate; oracle false-allows are empirical measurements against the executable policy.
"""
from __future__ import annotations

import argparse
import csv
import json
import random
import sys
import time
import warnings
from collections import Counter
from pathlib import Path

import numpy as np

warnings.filterwarnings("ignore")
_HERE = Path(__file__).resolve().parent
_EXP = _HERE.parent
sys.path.insert(0, str(_EXP / "models"))
sys.path.insert(0, str(_EXP.parents[1] / "experiments" / "opa_gate"))
import lip_gate as LG  # noqa: E402
from run_opa_gate import train_gate_opa  # noqa: E402  (reuse the project MLP gate)
from smoothed_gate import certify as smooth_certify  # noqa: E402

TAB = _EXP / "results" / "tables"
DIAG = _EXP / "results" / "diagnostics"
PROV = LG.PROVENANCE


def balanced(cats, recs, per_cat, seed):
    rng = random.Random(seed)
    by = {}
    for c, r in zip(cats, recs):
        by.setdefault(c["category"], []).append((c, r))
    out = []
    for cat in ("R", "C", "U", "A", "B"):
        xs = by.get(cat, [])
        rng.shuffle(xs)
        out += xs[:per_cat]
    return out


def _metrics(rows):
    """rows: list of (category, allow, truly_unsafe). -> R/C/U allow + cert_false_allow."""
    by = {k: [0, 0] for k in "RCU"}
    cfa = [0, 0]
    for cat, allow, unsafe in rows:
        if cat in by:
            by[cat][1] += 1; by[cat][0] += int(allow)
        if allow:
            cfa[1] += 1; cfa[0] += int(unsafe)

    def r(b):
        return round(b[0] / b[1], 4) if b[1] else float("nan")
    return r(by["R"]), r(by["C"]), r(by["U"]), (round(cfa[0] / cfa[1], 4) if cfa[1] else 0.0)


def run_domain(domain, n_train, n_eval, per_cat, eps_list, mc_list, sigma, tau, alpha, variant, seed):
    orc = LG.OpaOracle(domain)
    enc = LG.make_encoder(orc.rt)                       # raw (identity) numeric encoding
    train = LG.sample_records(domain, n_train, seed=seed)
    ev = LG.sample_records(domain, n_eval, seed=seed + 1)

    lip = LG.train_lipgate(orc, enc, train, variant=variant, seed=seed)
    wrap = LG.LipSmoothWrapper(lip, enc, orc.rt)
    mlp = train_gate_opa(orc, train, sigma, n_aug=4, seed=seed)   # project MLP (standardized enc)
    dim = enc.matrix(ev[:1]).shape[1]
    emp_L = LG.empirical_lipschitz(lip, dim, device=LG.DEVICE)

    rows_L1, raw = [], {}
    for eps in eps_list:
        cats, status = LG.exact_categories(orc, ev, eps)
        sub = balanced(cats, ev, per_cat, seed)
        unsafe = {id(r): c["truly_unsafe_reachable"] for c, r in sub}
        cat_of = {id(r): c["category"] for c, r in sub}

        def add(backend, n_mc, allow_fn):
            t0 = time.perf_counter()
            rows = [(cat_of[id(r)], bool(allow_fn(r)), unsafe[id(r)]) for c, r in sub]
            ms = (time.perf_counter() - t0) * 1e3 / max(1, len(sub))
            R, C, U, cfa = _metrics(rows)
            rows_L1.append({"domain": domain, "epsilon": eps, "backend": backend, "n_mc": n_mc,
                            "R_allow": R, "C_allow": C, "U_allow": U, "cert_false_allow": cfa,
                            "cost_ms": round(ms, 4), "policy_provenance": PROV,
                            "exact_oracle_status": status, "lipgate_variant": variant,
                            "empirical_lipschitz": round(emp_L, 4)})
            raw[(backend, n_mc)] = R
            print(f"  {domain} eps={eps} {backend:24s} M={n_mc:>5} | R={R} C={C} U={U} cfa={cfa} {ms:.3f}ms")

        # exact oracle (allow iff category R)
        add("exact_oracle", 0, lambda r: cat_of[id(r)] == "R")
        # uncertified learned LipGate (pointwise margin > 0)
        add("uncertified_lipgate", 0, lambda r: LG.lip_pointwise_allow(lip, enc, r))
        # MLP + smoothing
        for m in mc_list:
            add("mlp_smoothing", m,
                lambda r, m=m: smooth_certify(mlp, orc.rt, r, sigma=sigma, eps=eps, tau=tau,
                                              n_mc=m, alpha=alpha)["allow"])
        # LipGate + smoothing (same model)
        for m in [x for x in mc_list if x in (2000, 10000)]:
            add("lipgate_smoothing", m,
                lambda r, m=m: LG.certify_smooth(wrap, orc.rt, r, sigma, eps, tau, m, alpha)["allow"])
        # LipGate + deterministic (same model)
        add("lipgate_deterministic", 0, lambda r: LG.certify_lip(lip, enc, orc.rt, r, eps)["allow"])
        # naive marginal composition (sanity): clean-safe AND no single-channel flip
        def naive(r):
            c = next(cc for cc, rr in sub if id(rr) == id(r))
            return c["clean_safe"] and not c["disc_flip"] and not c["cont_flip"]
        add("naive_marginal", 0, naive)
        raw_store[(domain, eps)] = dict(raw)
    return rows_L1


raw_store = {}


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--domains", default="finance,sre,ops")
    ap.add_argument("--n-train", type=int, default=1500)
    ap.add_argument("--n-eval", type=int, default=400)
    ap.add_argument("--per-cat", type=int, default=80)
    ap.add_argument("--eps-list", default="0.03,0.10")
    ap.add_argument("--mc-list", default="1500,2000,10000")
    ap.add_argument("--sigma", type=float, default=0.10)
    ap.add_argument("--tau", type=float, default=0.90)
    ap.add_argument("--alpha", type=float, default=0.001)
    ap.add_argument("--variant", default="robust-aug", choices=["small", "medium", "robust-aug"])
    ap.add_argument("--seed", type=int, default=0)
    args = ap.parse_args()
    TAB.mkdir(parents=True, exist_ok=True); DIAG.mkdir(parents=True, exist_ok=True)
    eps_list = [float(x) for x in args.eps_list.split(",") if x.strip()]
    mc_list = [int(x) for x in args.mc_list.split(",") if x.strip()]
    domains = [d.strip() for d in args.domains.split(",") if d.strip()]

    all_rows = []
    for d in domains:
        print(f"[{d}] training (variant={args.variant}, device={LG.DEVICE})...")
        all_rows += run_domain(d, args.n_train, args.n_eval, args.per_cat, eps_list, mc_list,
                               args.sigma, args.tau, args.alpha, args.variant, args.seed)

    cols = ["domain", "epsilon", "backend", "n_mc", "R_allow", "C_allow", "U_allow",
            "cert_false_allow", "cost_ms", "exact_oracle_status", "policy_provenance",
            "lipgate_variant", "empirical_lipschitz"]
    with open(TAB / "L1_operating_points.csv", "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=cols, extrasaction="ignore"); w.writeheader(); w.writerows(all_rows)
    # raw recovery for decomposition/runtime (keyed by domain|eps -> {backend|n_mc: R})
    raw_out = {f"{d}|{e}": {f"{b}|{m}": v for (b, m), v in raw.items()}
               for (d, e), raw in raw_store.items()}
    (TAB / "_raw_recovery.json").write_text(json.dumps(raw_out, indent=2) + "\n")
    print(f"\nwrote -> {TAB/'L1_operating_points.csv'} ; _raw_recovery.json ({len(all_rows)} rows)")


if __name__ == "__main__":
    main()
