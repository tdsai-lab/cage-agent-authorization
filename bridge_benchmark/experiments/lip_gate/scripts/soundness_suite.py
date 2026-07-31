#!/usr/bin/env python3
"""
soundness_suite.py — PLAN_2 P4 Task G: the consolidated soundness/utility suite for the smoothing
certificate, on the executable OPA finance policy (the sound, well-fit regime). The contribution P4
locks is "**soundness is invariant; only utility (R_allow) moves**": across every Monte-Carlo budget,
every FWER confidence, every (σ,τ,ε) operating point, and every base-gate architecture, the certified
false-allow stays 0, while R_allow (recovery of the exactly-robust-safe set) shifts predictably.

Four studies + a fidelity-k pointer (G5 is `k100_regime.py`, run separately with k∈{50,100,150}):
  G1  MC saturation   R_allow(M),  M ∈ {500,1k,2k,5k,10k,20k}   — pins the finite-MC tax → plateau.
  G2  confidence      α_FWER ∈ {1e-2,1e-3,1e-4}                  — Bonferroni is mild; soundness invariant.
  G3  soundness grid  σ×τ×ε                                      — cert_false_allow=0 everywhere; R moves.
  G4  base-gate sweep {MLP, GBT, logistic, LipGate}             — procedure not architecture; best fit.

All studies share one finance OpaOracle, one category-balanced eval subset, and the project certificate
`smoothed_gate.certify` (LipGate via `LipSmoothWrapper`). cert_false_allow is the EMPIRICAL false-allow vs
the executable policy (truly_unsafe_reachable among certified-allowed) — soundness w.r.t. the smoothed
gate is a theorem; this measures it against the oracle. Rows → results/tables/L7–L10 + cert/out mirror.
"""
from __future__ import annotations

import argparse
import csv
import json
import random
import sys
import warnings
from collections import defaultdict
from pathlib import Path

import numpy as np

warnings.filterwarnings("ignore")
_EXP = Path(__file__).resolve().parent.parent
_BB = _EXP.parents[1]
sys.path.insert(0, str(_EXP / "models"))
sys.path.insert(0, str(_BB / "models"))
sys.path.insert(0, str(_BB / "experiments" / "opa_gate"))
sys.path.insert(0, str(_BB / "cert"))

import lip_gate as LG  # noqa: E402
from baselines import GateModel, _weighted_fit  # noqa: E402
from dataset import FeatureEncoder  # noqa: E402
from smoothed_gate import certify as smooth_certify  # noqa: E402
from sklearn.ensemble import HistGradientBoostingClassifier  # noqa: E402
from sklearn.linear_model import LogisticRegression  # noqa: E402
from sklearn.neural_network import MLPClassifier  # noqa: E402

TAB = _EXP / "results" / "tables"
MIRROR = _BB / "cert" / "out"


# --------------------------------------------------------------------------- #
# shared: OPA-relabelled Gaussian augmentation + a GateModel for an arbitrary sklearn estimator
# (generalizes run_opa_gate.train_gate_opa, which hard-codes the MLP).
# --------------------------------------------------------------------------- #
def _augment_opa(orc, train, sigma, n_aug, seed):
    rng = np.random.default_rng(seed)
    nf = orc.dc["numeric_fields"]
    aug = []
    for r in train:
        aug.append({**r})
        base = r["numeric_fields"]
        for _ in range(n_aug):
            num = {f: float(base[f]) + float(rng.normal(0.0, sigma)) for f in nf}
            aug.append({"domain": orc.domain, "tool_id": r["tool_id"],
                        "candidate_action": r["candidate_action"],
                        "categorical_fields": r["categorical_fields"], "numeric_fields": num})
    labels = orc.safe_records(aug)                          # one batched OPA call (never a clean label)
    for r, y in zip(aug, labels):
        r["y"] = 1 if y else 0
    return aug


_GATE_FACTORIES = {
    "mlp": lambda seed: (MLPClassifier(hidden_layer_sizes=(64, 32), max_iter=1000, random_state=seed),
                         False, False),
    "gbt": lambda seed: (HistGradientBoostingClassifier(max_iter=300, random_state=seed), False, True),
    "logistic": lambda seed: (LogisticRegression(max_iter=2000, class_weight="balanced"), True, False),
}


def train_opa_gate(orc, train, sigma, n_aug, seed, kind="mlp"):
    aug = _augment_opa(orc, train, sigma, n_aug, seed)
    enc = FeatureEncoder(orc.rt).fit_numeric(aug)
    X, y = enc.matrix(aug), np.array([r["y"] for r in aug])
    est, cw, sw = _GATE_FACTORIES[kind](seed)
    _weighted_fit(est, X, y, cw, sw)
    return GateModel(f"opa_{kind}(sigma={sigma})", enc, est, rule_table=orc.rt)


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
    """(R_allow, C_allow, U_allow, cert_false_allow) over a balanced subset."""
    by = {k: [0, 0] for k in "RCU"}
    cfa = [0, 0]
    for c, r in sub:
        a = bool(allow_fn(r))
        if c["category"] in by:
            by[c["category"]][1] += 1; by[c["category"]][0] += int(a)
        if a:
            cfa[1] += 1; cfa[0] += int(c["truly_unsafe_reachable"])

    def rt(b):
        return round(b[0] / b[1], 4) if b[1] else float("nan")
    return rt(by["R"]), rt(by["C"]), rt(by["U"]), (round(cfa[0] / cfa[1], 4) if cfa[1] else 0.0)


# --------------------------------------------------------------------------- #
# G1 — MC saturation curve R_allow(M)
# --------------------------------------------------------------------------- #
def study_mc(orc, gate, sub, mlist, sigma, eps, tau, alpha):
    rows = []
    for M in mlist:
        R, C, U, cfa = _rates(sub, lambda r: smooth_certify(
            gate, orc.rt, r, sigma=sigma, eps=eps, tau=tau, n_mc=M, alpha=alpha)["allow"])
        rows.append({"study": "G1_mc_saturation", "n_mc": M, "sigma": sigma, "eps": eps, "tau": tau,
                     "alpha": alpha, "R_allow": R, "C_allow": C, "U_allow": U, "cert_false_allow": cfa})
        print(f"  [G1] M={M:6d}  R_allow={R}  cert_false_allow={cfa}")
    return rows


# --------------------------------------------------------------------------- #
# G2 — confidence (FWER) sensitivity
# --------------------------------------------------------------------------- #
def study_alpha(orc, gate, sub, alphas, sigma, eps, tau, n_mc):
    rows = []
    for a in alphas:
        R, C, U, cfa = _rates(sub, lambda r: smooth_certify(
            gate, orc.rt, r, sigma=sigma, eps=eps, tau=tau, n_mc=n_mc, alpha=a)["allow"])
        rows.append({"study": "G2_confidence", "alpha": a, "confidence": round(1 - a, 4), "sigma": sigma,
                     "eps": eps, "tau": tau, "n_mc": n_mc, "R_allow": R, "C_allow": C, "U_allow": U,
                     "cert_false_allow": cfa})
        print(f"  [G2] alpha={a:<7g} conf={1-a:.4f}  R_allow={R}  cert_false_allow={cfa}")
    return rows


# --------------------------------------------------------------------------- #
# G3 — soundness heatmap over σ × τ × ε
# --------------------------------------------------------------------------- #
def study_grid(orc, train, sub_recs_for_retrain, sigmas, taus, epses, n_mc, alpha, n_aug, seed,
               eval_recs):
    """For each σ we retrain the gate at that smoothing level (σ is a training+certify parameter), then
    sweep τ×ε on the certificate. cert_false_allow must be 0 across the whole grid; only R_allow moves."""
    rows = []
    for sigma in sigmas:
        gate = train_opa_gate(orc, train, sigma, n_aug, seed, kind="mlp")
        cats = orc.categorize(eval_recs, max(epses))     # categories computed at the widest eps (superset)
        for eps in epses:
            cats_e = orc.categorize(eval_recs, eps)
            sub = _balanced(cats_e, eval_recs, len(sub_recs_for_retrain), seed)
            for tau in taus:
                R, C, U, cfa = _rates(sub, lambda r: smooth_certify(
                    gate, orc.rt, r, sigma=sigma, eps=eps, tau=tau, n_mc=n_mc, alpha=alpha)["allow"])
                rows.append({"study": "G3_soundness_grid", "sigma": sigma, "tau": tau, "eps": eps,
                             "n_mc": n_mc, "alpha": alpha, "R_allow": R, "C_allow": C, "U_allow": U,
                             "cert_false_allow": cfa})
                print(f"  [G3] sigma={sigma} tau={tau} eps={eps}  R_allow={R}  cfa={cfa}")
    return rows


# --------------------------------------------------------------------------- #
# G4 — base-gate architecture sweep {MLP, GBT, logistic, LipGate}
# --------------------------------------------------------------------------- #
def study_base_gates(orc, enc_lip, train, eval_recs, per_cat, sigma, eps, tau, n_mc, alpha, n_aug, seed):
    cats = orc.categorize(eval_recs, eps)
    sub = _balanced(cats, eval_recs, per_cat, seed)
    rows = []
    # sklearn base gates (smoothed)
    for kind in ("mlp", "gbt", "logistic"):
        gate = train_opa_gate(orc, train, sigma, n_aug, seed, kind=kind)
        acc = np.mean([int(gate.allow_point(orc.domain, r["tool_id"], r["candidate_action"],
                                            r["categorical_fields"], r["numeric_fields"])
                          == bool(orc.safe_records([r])[0])) for _c, r in sub])
        R, C, U, cfa = _rates(sub, lambda r: smooth_certify(
            gate, orc.rt, r, sigma=sigma, eps=eps, tau=tau, n_mc=n_mc, alpha=alpha)["allow"])
        rows.append({"study": "G4_base_gate", "base_gate": kind, "backend": "smoothing",
                     "clean_acc": round(float(acc), 4), "R_allow": R, "C_allow": C, "U_allow": U,
                     "cert_false_allow": cfa})
        print(f"  [G4] {kind:9s} smoothing   clean_acc={acc:.4f} R_allow={R} cfa={cfa}")
    # LipGate: smoothing AND deterministic on the same model
    lip = LG.train_lipgate(orc, enc_lip, train, variant="robust-aug", seed=seed)
    wrap = LG.LipSmoothWrapper(lip, enc_lip, orc.rt)
    lip_acc = np.mean([int(LG.lip_pointwise_allow(lip, enc_lip, r) == bool(orc.safe_records([r])[0]))
                       for _c, r in sub])
    R, C, U, cfa = _rates(sub, lambda r: smooth_certify(
        wrap, orc.rt, r, sigma=sigma, eps=eps, tau=tau, n_mc=n_mc, alpha=alpha)["allow"])
    rows.append({"study": "G4_base_gate", "base_gate": "lipgate", "backend": "smoothing",
                 "clean_acc": round(float(lip_acc), 4), "R_allow": R, "C_allow": C, "U_allow": U,
                 "cert_false_allow": cfa})
    print(f"  [G4] lipgate   smoothing   clean_acc={lip_acc:.4f} R_allow={R} cfa={cfa}")
    Rd, Cd, Ud, cfad = _rates(sub, lambda r: LG.certify_lip(lip, enc_lip, orc.rt, r, eps)["allow"])
    rows.append({"study": "G4_base_gate", "base_gate": "lipgate", "backend": "deterministic",
                 "clean_acc": round(float(lip_acc), 4), "R_allow": Rd, "C_allow": Cd, "U_allow": Ud,
                 "cert_false_allow": cfad})
    print(f"  [G4] lipgate   determ.     clean_acc={lip_acc:.4f} R_allow={Rd} cfa={cfad}")
    return rows


# --------------------------------------------------------------------------- #
def _write(rows, name, cols):
    TAB.mkdir(parents=True, exist_ok=True); MIRROR.mkdir(parents=True, exist_ok=True)
    for d in (TAB, MIRROR):
        with open(d / f"{name}.csv", "w", newline="") as f:
            w = csv.DictWriter(f, fieldnames=cols, extrasaction="ignore")
            w.writeheader(); w.writerows(rows)


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--domain", default="finance")
    ap.add_argument("--n-train", type=int, default=1500)
    ap.add_argument("--n-eval", type=int, default=700)
    ap.add_argument("--per-cat", type=int, default=60)
    ap.add_argument("--sigma", type=float, default=0.10)
    ap.add_argument("--eps", type=float, default=0.10)
    ap.add_argument("--tau", type=float, default=0.90)
    ap.add_argument("--alpha", type=float, default=0.001)
    ap.add_argument("--n-aug", type=int, default=4)
    ap.add_argument("--seed", type=int, default=0)
    ap.add_argument("--mc-list", default="500,1000,2000,5000,10000,20000")
    ap.add_argument("--alpha-list", default="0.01,0.001,0.0001")
    ap.add_argument("--sigma-grid", default="0.075,0.10,0.15")
    ap.add_argument("--tau-grid", default="0.90,0.95")
    ap.add_argument("--eps-grid", default="0.03,0.10")
    ap.add_argument("--studies", default="G1,G2,G3,G4")
    args = ap.parse_args()

    studies = {s.strip() for s in args.studies.split(",") if s.strip()}
    orc = LG.OpaOracle(args.domain)
    enc_lip = LG.make_encoder(orc.rt)
    train = LG.sample_records(args.domain, args.n_train, seed=args.seed)
    ev = LG.sample_records(args.domain, args.n_eval, seed=args.seed + 1)
    cats = orc.categorize(ev, args.eps)
    sub = _balanced(cats, ev, args.per_cat, args.seed)
    print(f"[setup] domain={args.domain} eval={len(ev)} balanced_subset={len(sub)} "
          f"(per_cat≤{args.per_cat})  sigma={args.sigma} eps={args.eps} tau={args.tau}")

    all_rows = {}
    if "G1" in studies or "G2" in studies or "G4" in studies:
        gate = train_opa_gate(orc, train, args.sigma, args.n_aug, args.seed, kind="mlp")

    if "G1" in studies:
        print("[G1] MC saturation R_allow(M) ...")
        mlist = [int(x) for x in args.mc_list.split(",") if x.strip()]
        rows = study_mc(orc, gate, sub, mlist, args.sigma, args.eps, args.tau, args.alpha)
        _write(rows, "L7_mc_saturation",
               ["study", "n_mc", "sigma", "eps", "tau", "alpha", "R_allow", "C_allow", "U_allow",
                "cert_false_allow"])
        all_rows["G1"] = rows

    if "G2" in studies:
        print("[G2] confidence (FWER) sensitivity ...")
        alphas = [float(x) for x in args.alpha_list.split(",") if x.strip()]
        rows = study_alpha(orc, gate, sub, alphas, args.sigma, args.eps, args.tau, 2000)
        _write(rows, "L8_confidence_sensitivity",
               ["study", "alpha", "confidence", "sigma", "eps", "tau", "n_mc", "R_allow", "C_allow",
                "U_allow", "cert_false_allow"])
        all_rows["G2"] = rows

    if "G3" in studies:
        print("[G3] soundness grid sigma x tau x eps ...")
        sigmas = [float(x) for x in args.sigma_grid.split(",") if x.strip()]
        taus = [float(x) for x in args.tau_grid.split(",") if x.strip()]
        epses = [float(x) for x in args.eps_grid.split(",") if x.strip()]
        rows = study_grid(orc, train, list(range(args.per_cat)), sigmas, taus, epses, 2000,
                          args.alpha, args.n_aug, args.seed, ev)
        _write(rows, "L9_soundness_grid",
               ["study", "sigma", "tau", "eps", "n_mc", "alpha", "R_allow", "C_allow", "U_allow",
                "cert_false_allow"])
        all_rows["G3"] = rows

    if "G4" in studies:
        print("[G4] base-gate architecture sweep ...")
        rows = study_base_gates(orc, enc_lip, train, ev, args.per_cat, args.sigma, args.eps, args.tau,
                                2000, args.alpha, args.n_aug, args.seed)
        _write(rows, "L10_base_gate_sweep",
               ["study", "base_gate", "backend", "clean_acc", "R_allow", "C_allow", "U_allow",
                "cert_false_allow"])
        all_rows["G4"] = rows

    # invariant check across every row of every study: cert_false_allow == 0
    flat = [r for rs in all_rows.values() for r in rs]
    max_cfa = max((r["cert_false_allow"] for r in flat), default=0.0)
    r_moves = len({r["R_allow"] for r in flat}) > 1
    summary = {"domain": args.domain, "n_rows": len(flat), "studies": sorted(all_rows),
               "max_cert_false_allow": max_cfa, "soundness_invariant_holds": max_cfa == 0.0,
               "R_allow_varies": bool(r_moves),
               "claim": "soundness invariant (cert_false_allow=0 across all M, alpha, (sigma,tau,eps), "
                        "and base gates); only utility R_allow moves."}
    (TAB / "soundness_suite_summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    (MIRROR / "soundness_suite_summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    print(f"\n[summary] rows={len(flat)} max_cert_false_allow={max_cfa} "
          f"soundness_invariant={'PASS' if max_cfa == 0.0 else 'FAIL'} R_allow_varies={r_moves}")
    print(f"wrote -> {TAB} (L7–L10 + soundness_suite_summary.json) + mirror {MIRROR}")
    return summary


if __name__ == "__main__":
    main()
