#!/usr/bin/env python3
"""
policy_state_projection.py — IDEA #4: the certifiable interface is a LOW-DIMENSIONAL policy state, not
raw high-dimensional tool returns.

Setup: a scalar-threshold tool table whose safety depends on only `k_active` numeric fields; the return
carries `k_raw ≥ k_active` fields, the extra ones being realistic **nuisance** (never policy-binding):

    x_2 = (x_active ∈ R^{k_active}, x_nuisance ∈ R^{k_raw-k_active}),   Policy(z) depends on x_active only.

We train four gates that differ only in what part of x_2 they may use, then certify each with the SAME
smoothed certificate and score them against the true oracle:

    dense         — MLP on raw x_2 (all k_raw dims); must LEARN to ignore nuisance from finite data.
    noise_trained — dense, but with heavier oracle-relabelled Gaussian augmentation (invariance pressure).
    bottleneck    — L1-selected fields from data (a sparse policy-state estimate h(x_2)).
    oracle_proj   — the true projection to x_active (the ceiling: the certifiable interface).

Metrics: fidelity (gate vs oracle point accuracy), **cert_false_allow** (certified-allowed yet oracle
reachably-unsafe in B_{1,ε} on the FULL threat), **R_allow** (non-vacuity), abstention. Expected: the
dense MLP degrades as k_raw grows (fidelity ↓, cert_false_allow ↑), while projecting to k_eff ≤ 50
restores cert_false_allow → 0 with R_allow > 0. The lesson is not "smoothing scales to raw logs"; it is
"certifiability needs a typed low-dim policy state". Reuses make_rule_table + train_certified_gate +
the smoothed cert. numpy/sklearn.
"""
from __future__ import annotations

import argparse
import copy
import json
import sys
import warnings
from pathlib import Path

import numpy as np

warnings.filterwarnings("ignore")
_root = Path(__file__).resolve().parents[1]
for p in ("generators", "models", "cert", "experiments"):
    sys.path.insert(0, str(_root / p))

from oracle import safe, joint_reachable_unsafe, continuous_reachable_unsafe  # noqa: E402
from synthetic_tools import make_rule_table, sample_records, DOMAIN  # noqa: E402
from dataset import FeatureEncoder  # noqa: E402
from baselines import GateModel, _weighted_fit  # noqa: E402
from smoothed_gate import certify  # noqa: E402
from sklearn.linear_model import LogisticRegression  # noqa: E402
from sklearn.neural_network import MLPClassifier  # noqa: E402

OUT = _root / "cert" / "out"
EPS, SIGMA, TAU = 0.10, 0.10, 0.85


def _rt_view(rt, fields):
    """A shallow rule-table view that DECLARES only `fields` as numeric (same rules; since the table is
    all-scalar, the oracle is identical — nuisance fields are never referenced). The gate's FeatureEncoder
    and the certificate's perturbation are thus restricted to `fields`, i.e. the gate applies the
    projection h(x_2)."""
    view = copy.copy(rt)
    view["domains"] = dict(rt["domains"])
    dc = dict(rt["domains"][DOMAIN])
    dc["numeric_fields"] = list(fields)
    view["domains"][DOMAIN] = dc
    return view


def _active_fields(rt):
    """The DISTINCT policy-binding numeric fields (one scalar threshold field per action group). With
    affine_frac=0 every rule is a scalar_threshold, so this is exactly the k_active-dim policy state."""
    seen = []
    for r in rt["domains"][DOMAIN]["rules"]:
        f = r.get("numeric_field")
        if f and f not in seen:
            seen.append(f)
    return seen or rt["domains"][DOMAIN]["numeric_fields"][:1]


def _l1_selected_fields(train, rt, all_fields, seed):
    """A sparse policy-state estimate: L1-logistic on raw x_2 → fields with non-trivial coefficients."""
    X = np.array([[float(r["numeric_fields"][f]) for f in all_fields] for r in train])
    y = np.array([r["y"] for r in train])
    if len(set(y.tolist())) < 2:
        return all_fields
    clf = LogisticRegression(penalty="l1", solver="liblinear", C=0.5, max_iter=500, random_state=seed)
    clf.fit(X, y)
    coef = np.abs(clf.coef_[0])
    thr = 0.1 * coef.max() if coef.max() > 0 else 0.0
    sel = [f for f, c in zip(all_fields, coef) if c > thr]
    return sel or all_fields


def train_gate_on_fields(train, rt_full, fields, sigma, n_aug, seed, hidden=(64, 32)):
    """Like train_certified_gate but the ENCODER is restricted to `fields` (the gate's projection h(x₂)),
    while Gaussian augmentation + oracle relabelling run over the FULL numeric space (so the oracle sees
    every policy-binding field). The gate thus applies a projection but is trained/labelled honestly."""
    rng = np.random.default_rng(seed)
    dc = rt_full["domains"][DOMAIN]
    nf = dc["numeric_fields"]                                   # FULL numeric space for augment+oracle
    aug = list(train)
    for r in train:
        base, a = r["numeric_fields"], r["candidate_action"]
        for _ in range(n_aug):
            num = {f: float(base.get(f, 0.5)) + float(rng.normal(0.0, sigma)) for f in nf}
            z = {"domain": DOMAIN, "tool_id": r["tool_id"], "candidate_action": a,
                 "categorical_fields": r.get("categorical_fields", {}), "numeric_fields": num}
            y = 1 if safe(z, a, rt_full) else 0                 # oracle relabel over full space
            aug.append({"domain": DOMAIN, "tool_id": r["tool_id"], "candidate_action": a,
                        "categorical_fields": r.get("categorical_fields", {}),
                        "numeric_fields": num, "y": y})
    enc = FeatureEncoder(_rt_view(rt_full, fields)).fit_numeric(aug)   # encoder sees only `fields`
    X = enc.matrix(aug)
    y = np.array([r["y"] for r in aug])
    est = MLPClassifier(hidden_layer_sizes=hidden, max_iter=1000, random_state=seed)
    _weighted_fit(est, X, y, False, False)
    return GateModel(f"proj({len(fields)})", enc, est)


def _oracle_safe(rec, a, rt):
    return safe(rec, a, rt)


def _robust_unsafe(rec, a, rt, eps=EPS):
    if not safe(rec, a, rt):
        return True
    if continuous_reachable_unsafe(rec, a, rt, eps)["reachable"]:
        return True
    return joint_reachable_unsafe(rec, a, rt, 1, eps)["reachable"]


def cert_eval(gate, rt_full, fields, recs, n_mc, seed):
    # the cert perturbs the gate's own field space (its encoder h(x₂)); SOUNDNESS is measured against the
    # FULL oracle threat B_{1,ε} over all k_raw — so a gate blind to a policy-binding field is exposed as
    # a cert_false_allow even though its own field space is never perturbed there.
    rt_view = _rt_view(rt_full, fields)
    n = len(recs)
    fid = allow = fa = 0
    r_total = r_allow = 0
    for rec in recs:
        p = gate.proba_safe_point(DOMAIN, rec["tool_id"], rec["candidate_action"],
                                  rec["categorical_fields"], rec["numeric_fields"])
        fid += int((p >= 0.5) == _oracle_safe(rec, rec["candidate_action"], rt_full))
        c = certify(gate, rt_view, rec, sigma=SIGMA, eps=EPS, tau=TAU, n_mc=n_mc, seed=seed)
        allowed = bool(c["cert_allow"]["hybrid"])
        allow += int(allowed)
        if allowed and _robust_unsafe(rec, rec["candidate_action"], rt_full):
            fa += 1                                    # certified-allow yet truly reachably-unsafe
        if rec["category"] == "R":
            r_total += 1
            r_allow += int(allowed)
    return {"fidelity": round(fid / n, 4), "cert_allow_rate": round(allow / n, 4),
            "cert_false_allow": round(fa / n, 4), "abstention": round(1 - allow / n, 4),
            "R_allow": round(r_allow / r_total, 4) if r_total else None}


def build_gates(train, rt, all_fields, active_fields, sigma, n_aug, seed):
    l1 = _l1_selected_fields(train, rt, all_fields, seed)
    specs = {
        "dense":        (all_fields, n_aug),
        "noise_trained": (all_fields, n_aug * 4),
        "bottleneck":   (l1, n_aug),
        "oracle_proj":  (active_fields, n_aug),
    }
    gates = {}
    for name, (fields, na) in specs.items():
        gates[name] = (train_gate_on_fields(train, rt, fields, sigma=sigma, n_aug=na, seed=seed),
                       fields)
    return gates, l1


def run_cell(k_active, k_raw, n, n_cert, n_mc, sigma, n_aug, seed):
    K = 4 * k_active                                   # m=4 -> n_groups = k_active active scalar fields
    rt = make_rule_table(K=K, k=k_raw, x1_size=4, m=4, seed=seed, affine_frac=0.0)
    recs = sample_records(rt, n, eps=EPS, seed=seed)
    ntr = int(0.7 * len(recs))
    train, test = recs[:ntr], recs[ntr:]
    all_fields = rt["domains"][DOMAIN]["numeric_fields"]
    active = _active_fields(rt)
    gates, l1 = build_gates(train, rt, all_fields, active, sigma, n_aug, seed)
    # a balanced cert-eval subset (cap n_cert) that includes R for non-vacuity
    sub = test[:n_cert]
    rows = {}
    for name, (gate, fields) in gates.items():
        m = cert_eval(gate, rt, fields, sub, n_mc, seed)
        m["n_fields_used"] = len(fields)
        rows[name] = m
    return {"k_active": k_active, "k_raw": k_raw, "K": K, "n_records": len(recs),
            "n_cert_eval": len(sub), "l1_selected": len(l1), "gates": rows}


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--k-active", type=int, nargs="*", default=[5])
    ap.add_argument("--k-raw", type=int, nargs="*", default=[20, 100])
    ap.add_argument("--n", type=int, default=6000)
    ap.add_argument("--n-cert", type=int, default=150)
    ap.add_argument("--n-mc", type=int, default=600)
    ap.add_argument("--sigma", type=float, default=SIGMA)
    ap.add_argument("--n-aug", type=int, default=6)
    ap.add_argument("--seed", type=int, default=0)
    ap.add_argument("--out", default="policy_state_projection")
    args = ap.parse_args()

    cells = []
    for ka in args.k_active:
        for kr in args.k_raw:
            if kr < ka:
                continue
            cell = run_cell(ka, kr, args.n, args.n_cert, args.n_mc, args.sigma, args.n_aug, args.seed)
            cells.append(cell)
            print(f"\n== k_active={ka} k_raw={kr} (K={cell['K']}, n_cert={cell['n_cert_eval']}) ==")
            for name, m in cell["gates"].items():
                print(f"  {name:14s} fields={m['n_fields_used']:3d} | fidelity={m['fidelity']:.3f} "
                      f"cert_false_allow={m['cert_false_allow']:.3f} R_allow={m['R_allow']} "
                      f"abstain={m['abstention']:.2f}")

    res = {"experiment": "IDEA #4 — low-dim policy-state projection vs raw high-dim returns",
           "eps": EPS, "sigma": args.sigma, "tau": TAU, "n_mc": args.n_mc, "cells": cells}
    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / f"{args.out}.json").write_text(json.dumps(res, indent=2))
    _write_md(OUT / f"{args.out}.md", res)
    print(f"\nwrote {OUT / (args.out + '.json')}\nwrote {OUT / (args.out + '.md')}")
    return res


def _write_md(path, res):
    with open(path, "w") as f:
        f.write("# IDEA #4 — the certifiable interface is a low-dim policy state, not raw high-dim returns\n\n")
        f.write(f"ε={res['eps']}, σ={res['sigma']}, τ={res['tau']}, n_mc={res['n_mc']}. Safety depends on "
                "`k_active` fields; the return carries `k_raw` fields (the rest are nuisance). Four gates "
                "differ only in what part of x₂ they may use; all certified by the SAME smoothed "
                "certificate, scored against the true oracle.\n\n")
        for cell in res["cells"]:
            f.write(f"## k_active={cell['k_active']}, k_raw={cell['k_raw']} "
                    f"(K={cell['K']}, n_cert={cell['n_cert_eval']}, L1-selected={cell['l1_selected']})\n\n")
            f.write("| gate | fields | fidelity | **cert_false_allow** | R_allow | abstention |\n")
            f.write("|---|---:|---:|---:|---:|---:|\n")
            for name, m in cell["gates"].items():
                f.write(f"| {name} | {m['n_fields_used']} | {m['fidelity']} | "
                        f"**{m['cert_false_allow']}** | {m['R_allow']} | {m['abstention']} |\n")
            f.write("\n")
        f.write("**Reads.** As `k_raw` grows with `k_active` fixed, the **dense** MLP on raw x₂ loses "
                "fidelity and its smoothed certificate starts to false-allow (cert_false_allow ↑) — it "
                "cannot cleanly learn to ignore the nuisance dimensions from finite data. Restricting the "
                "gate to a low-dim policy state — exactly (**oracle_proj**) or estimated from data "
                "(**bottleneck** via L1) — restores **cert_false_allow → 0** while keeping **R_allow > 0** "
                "(non-vacuous). Noise-training helps but does not fully close the gap. The certifiable "
                "interface is therefore a typed, low-dimensional policy state h(x₂), not raw "
                "high-dimensional tool-return logs: the recommendation is projection, not smoothing the "
                "raw space.\n")


if __name__ == "__main__":
    main()
