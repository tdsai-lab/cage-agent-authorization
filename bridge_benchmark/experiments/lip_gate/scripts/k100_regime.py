#!/usr/bin/env python3
"""
k100_regime.py — FOLLOWUP (2): regime-of-validity stress (PLAN5 F.7 / H.2) on the LipGate.

The smoothed MLP gate degrades at k=100 (dimension_validity: clean acc ~0.92, cert_false_allow ~0.23 —
the regime edge / H.2). We rerun the SAME k stress on the deterministic 1-Lipschitz backend to see
whether the Lipschitz gate extends the regime of validity (bonus) or degrades too (documents H.2 as
model-class-independent). Synthetic typed-tool setting (`synthetic_tools.make_rule_table(k)`), analytic
oracle; reuses the LipGate training + deterministic certificate + the project smoothed gate.

policy_provenance = authored_provenance_conditioned_rego is NOT claimed here (this is the synthetic
controlled family); rows are labelled `synthetic_dimension_study`.
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
_BB = _EXP.parents[1]
for p in ("generators", "models", "cert", "experiments"):
    sys.path.insert(0, str(_BB / p))
sys.path.insert(0, str(_EXP / "models"))

from oracle import safe as oracle_safe, category as oracle_category  # noqa: E402
from synthetic_tools import make_rule_table, sample_records, DOMAIN  # noqa: E402
from baselines import train_certified_gate  # noqa: E402
from smoothed_gate import certify as smooth_certify  # noqa: E402
import lip_gate as LG  # noqa: E402

TAB = _EXP / "results" / "tables"


class SyntheticOracle:
    """OpaOracle-compatible interface backed by the analytic oracle (so lip_gate works unchanged)."""

    def __init__(self, rt):
        self.domain = DOMAIN
        self.rt = rt
        self.dc = rt["domains"][DOMAIN]
        self.rego = None

    def safe_records(self, records):
        return [bool(oracle_safe(r, r["candidate_action"], self.rt)) for r in records]

    def categorize(self, records, eps):
        out = []
        for r in records:
            res = oracle_category(r, r["candidate_action"], self.rt, d=1, eps=eps)
            cat = res["category"][0]
            out.append({"category": cat, "clean_safe": bool(res["clean_safe"]),
                        "truly_unsafe_reachable": cat != "R",
                        "disc_flip": bool(res["discrete_only_unsafe"]),
                        "cont_flip": bool(res["continuous_only_unsafe"]),
                        "joint_flip": bool(res["joint_unsafe"]),
                        "is_D": bool(res.get("is_multivariate_joint"))})
        return out


def _balanced(cats, recs, per_cat, seed):
    rng = random.Random(seed)
    by = defaultdict(list)
    for c, r in zip(cats, recs):
        by[c["category"]].append((c, r))
    out = []
    for cat in ("R", "C", "U"):
        xs = by[cat]; rng.shuffle(xs); out += xs[:per_cat]
    return out


def run_k(k, K, x1_size, n_train, n_eval, per_cat, eps, sigma, tau, n_mc, alpha, seed):
    rt = make_rule_table(K=K, k=k, x1_size=x1_size, seed=seed)
    orc = SyntheticOracle(rt)
    enc = LG.make_encoder(rt)
    train = sample_records(rt, n_train, eps=eps, seed=seed)
    ev = sample_records(rt, n_eval, eps=eps, seed=seed + 1)
    lip = LG.train_lipgate(orc, enc, train, variant="robust-aug", seed=seed)
    mlp = train_certified_gate(train, rt, sigma=sigma, n_aug=6, seed=seed)

    cats = orc.categorize(ev, eps)
    sub = _balanced(cats, ev, per_cat, seed)
    # clean accuracy of each gate's pointwise decision vs the oracle clean label
    lip_acc = np.mean([int(LG.lip_pointwise_allow(lip, enc, r) == bool(oracle_safe(r, r["candidate_action"], rt)))
                       for _c, r in sub])
    mlp_acc = np.mean([int(mlp.allow_point(DOMAIN, r["tool_id"], r["candidate_action"], r["categorical_fields"],
                                           r["numeric_fields"]) == bool(oracle_safe(r, r["candidate_action"], rt)))
                       for _c, r in sub])

    def metrics(allow_fn):
        by = {q: [0, 0] for q in "RCU"}; cfa = [0, 0]
        for c, r in sub:
            a = bool(allow_fn(r))
            if c["category"] in by:
                by[c["category"]][1] += 1; by[c["category"]][0] += int(a)
            if a:
                cfa[1] += 1; cfa[0] += int(c["truly_unsafe_reachable"])

        def rt_(b):
            return round(b[0] / b[1], 4) if b[1] else float("nan")
        return rt_(by["R"]), rt_(by["C"]), rt_(by["U"]), (round(cfa[0] / cfa[1], 4) if cfa[1] else 0.0)

    lip_R, lip_C, lip_U, lip_cfa = metrics(lambda r: LG.certify_lip(lip, enc, rt, r, eps)["allow"])
    mlp_R, mlp_C, mlp_U, mlp_cfa = metrics(
        lambda r: smooth_certify(mlp, rt, r, sigma=sigma, eps=eps, tau=tau, n_mc=n_mc, alpha=alpha)["allow"])
    return [
        {"setting": "synthetic_dimension_study", "k": k, "backend": "lipgate_deterministic",
         "clean_acc": round(float(lip_acc), 4), "R_allow": lip_R, "C_allow": lip_C, "U_allow": lip_U,
         "cert_false_allow": lip_cfa},
        {"setting": "synthetic_dimension_study", "k": k, "backend": "mlp_smoothing",
         "clean_acc": round(float(mlp_acc), 4), "R_allow": mlp_R, "C_allow": mlp_C, "U_allow": mlp_U,
         "cert_false_allow": mlp_cfa},
    ]


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--k-list", default="10,50,100")
    ap.add_argument("--K", type=int, default=8)
    ap.add_argument("--x1-size", type=int, default=4)
    ap.add_argument("--n-train", type=int, default=12000)
    ap.add_argument("--n-eval", type=int, default=2000)
    ap.add_argument("--per-cat", type=int, default=80)
    ap.add_argument("--eps", type=float, default=0.10)
    ap.add_argument("--sigma", type=float, default=0.10)
    ap.add_argument("--tau", type=float, default=0.90)
    ap.add_argument("--n-mc", type=int, default=2000)
    ap.add_argument("--alpha", type=float, default=0.001)
    ap.add_argument("--seed", type=int, default=0)
    args = ap.parse_args()
    TAB.mkdir(parents=True, exist_ok=True)
    rows = []
    for k in [int(x) for x in args.k_list.split(",") if x.strip()]:
        print(f"[k={k}] training + certifying ...")
        rs = run_k(k, args.K, args.x1_size, args.n_train, args.n_eval, args.per_cat, args.eps,
                   args.sigma, args.tau, args.n_mc, args.alpha, args.seed)
        rows += rs
        for r in rs:
            print(f"  k={k} {r['backend']:24s} clean_acc={r['clean_acc']} R_allow={r['R_allow']} "
                  f"C_allow={r['C_allow']} U_allow={r['U_allow']} cert_false_allow={r['cert_false_allow']}")
    cols = ["setting", "k", "backend", "clean_acc", "R_allow", "C_allow", "U_allow", "cert_false_allow"]
    with open(TAB / "L6_k100_regime.csv", "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=cols, extrasaction="ignore"); w.writeheader(); w.writerows(rows)
    print(f"\nwrote -> {TAB/'L6_k100_regime.csv'}")


if __name__ == "__main__":
    main()
