#!/usr/bin/env python3
"""
neighbor_head_to_head.py — NEW_EXPS EXP 1: isolate the point-vs-neighborhood axis (Axe 1).

One table over the REAL IEEE-CIS executable OPA policy `risk_score < θ(provenance)` (every label from the
OPA 1.17.1 engine, not the analytic oracle). The 2×2 of {point, neighborhood} × {implicit-learned,
explicit-exact}, plus a no-gate baseline:

  row                       cell                     evaluates
  no_gate                   baseline                 always allow
  learned_point  (g_θ)      implicit × point         MLP at the observed clean point only
  verified_point_predicate  explicit × point  ◄NEW   the SAME Rego via the SAME `opa eval`, at the single
                                                     observed point only (NO N_d enumeration, NO ε-ball)
  exact_rung1               explicit × neighborhood  the SAME Rego, enumerate N_1(s) + ε-shift per branch
  certified_rs / _lip       implicit × neighborhood  learned gate + smoothing / Lipschitz over B_{1,ε}

Adversary: B_{1,0.10} realized by the #16 TOCTOU/provenance fault (loose↔strict swap; for continuous-only
witnesses the +ε staleness move). The witness denominator is the CANONICAL Prop-4 set — computed ONCE from
the OPA oracle, gate-independent, the SAME denominator for every row (comparability):

  W = {clean-safe} ∩ {m(z,a) ≤ ε} = {clean-safe} ∖ R      (operationally: Safe(observed)=1 ∧ category∈{A,B,C})

i.e. the clean-safe slice that Prop 4 forces ANY sound gate to refuse. This is deliberately NOT P[execute|C]:
the head-to-head has no marginal-composition row, so a C-only denominator would be unmotivated here (C is
defined by its relation to the marginal checks — that contrast lives in Q4's naive_C_falseallow and the
engine-verified non-composition anchor #9b/B2, a separate experiment). `attack_false_allow` = fraction of W
the gate allows at the observed point — for W every in-budget worst case is unsafe by construction, so the
adversary realizes it ⇒ allowing the observed point is a false allow. (|W|/total is a boundary-sampled rate,
NOT a natural deployed prevalence — label it as such, same caveat as the 800-witness C set.)

CORRECTNESS CHECKS (not targets): verified_point ≈ 1.00 on W (a witness is clean-safe by definition, and
the predicate calls the same Rego at the observed point ⇒ it allows every witness — exactness at the
observed point buys nothing); learned_point ≤ verified_point (MLP imperfection, never above 1.00);
exact_rung1 = certified_* = 0 on W; cert_false_allow = 0 for every certified row (soundness invariant).

Framing (HARD): this instantiates the EVALUATION REGIME of each gate family (heuristic point classification,
exact point predicate, neighborhood certification). It does NOT reimplement VeriGuard/AgentSpec/CaMeL.
"""
from __future__ import annotations

import argparse
import csv
import json
import sys
import warnings
from collections import Counter, defaultdict
from pathlib import Path

import numpy as np

warnings.filterwarnings("ignore")
_HERE = Path(__file__).resolve().parent
_BB = _HERE.parent
sys.path.insert(0, str(_HERE))
sys.path.insert(0, str(_HERE / "opa_gate"))

import ieee_opa_gate as G  # noqa: E402
from ieee_cis_opa_cwitness import load_records, categorize_via_opa  # noqa: E402

OUT = _BB / "cert" / "out"
ROWS = ["no_gate", "learned_point", "verified_point_predicate", "exact_rung1",
        "certified_rs", "certified_lip"]
CELL = {"no_gate": "baseline", "learned_point": "implicit × point",
        "verified_point_predicate": "explicit × point (NEW)", "exact_rung1": "explicit × neighborhood",
        "certified_rs": "implicit × neighborhood", "certified_lip": "implicit × neighborhood"}


def _verified_point(records):
    """explicit × point: the SAME Rego via the SAME opa eval, evaluated ONLY at the observed point."""
    return G.opa_safe([G._case(r["tool_id"], r["x2"]) for r in records])


def run_seed(records, n_train, n_eval, eps, sigma, tau, n_mc, alpha, seed):
    rng = np.random.default_rng(seed)
    idx = rng.permutation(len(records))
    train = [records[i] for i in idx[:n_train]]
    ev = [records[i] for i in idx[n_train:n_train + n_eval]]

    cats = categorize_via_opa(ev, eps)                              # OPA: category + clean_safe (rung-1)
    vpoint = _verified_point(ev)                                    # explicit × point (standalone predicate)
    # sanity: the verified point predicate must equal OPA clean_safe (same Rego, same point)
    assert all(bool(v) == bool(c["clean_safe"]) for v, c in zip(vpoint, cats)), \
        "verified_point_predicate disagrees with OPA clean_safe — eval path bug"

    xy = G.build_training_set(train, sigma=sigma, n_aug=4, seed=seed)   # OPA labels once, shared
    gate = G.train_gate(train, sigma=sigma, n_aug=4, seed=seed, xy=xy)
    lip, dev = G.train_lip_gate(train, sigma=sigma, n_aug=4, epochs=200, seed=seed, xy=xy)

    # per-record gate decisions at the observed point / over the ball
    dec = {r: [] for r in ROWS}
    for r, c, vp in zip(ev, cats, vpoint):
        t, x2 = r["tool_id"], r["x2"]
        dec["no_gate"].append(True)
        dec["learned_point"].append(gate.allow_point(t, x2))
        dec["verified_point_predicate"].append(bool(vp))
        dec["exact_rung1"].append(c["category"] == "R")            # allow iff robustly safe (nothing flips)
        dec["certified_rs"].append(G.allow_rs(gate, t, x2, sigma, eps, tau, n_mc, alpha, seed)["allow"])
        dec["certified_lip"].append(G.allow_lip(lip, dev, t, x2, eps)["allow"])

    # gate-independent denominator = the Prop-4 set {clean-safe} \ R (clean-safe ∧ some in-budget flip);
    # NOT P[execute|C] (see module docstring). Computed ONCE from the OPA oracle, identical for every row.
    W = [i for i, c in enumerate(cats) if c["clean_safe"] and c["category"] in ("A", "B", "C")]
    Rs = [i for i, c in enumerate(cats) if c["category"] == "R"]
    safe_obs = [bool(c["clean_safe"]) for c in cats]
    unsafe_in_ball = [c["category"] != "R" for c in cats]          # truly unsafe somewhere in B_{1,ε}

    out = {"n_eval": len(ev), "n_witness": len(W), "witness_prevalence": round(len(W) / len(ev), 4),
           "category_dist": dict(Counter(c["category"] for c in cats)), "rows": {}}
    for row in ROWS:
        d = dec[row]
        afa = float(np.mean([d[i] for i in W])) if W else float("nan")            # attack_false_allow over W
        acc = float(np.mean([d[i] == safe_obs[i] for i in range(len(ev))]))       # clean_acc vs OPA Safe
        rall = float(np.mean([d[i] for i in Rs])) if Rs else float("nan")         # Rallow (utility)
        allowed = [i for i in range(len(ev)) if d[i]]
        cfa = (float(np.mean([unsafe_in_ball[i] for i in allowed])) if allowed else 0.0)  # cert_false_allow
        out["rows"][row] = {"attack_false_allow": afa, "clean_acc": acc, "Rallow": rall,
                            "cert_false_allow": cfa}
    return out


def aggregate(seed_results):
    agg = {}
    for row in ROWS:
        cols = defaultdict(list)
        for sr in seed_results:
            for k, v in sr["rows"][row].items():
                cols[k].append(v)
        agg[row] = {k: (round(float(np.nanmean(v)), 4), round(float(np.nanstd(v)), 4))
                    for k, v in cols.items()}
    n_w = [sr["n_witness"] for sr in seed_results]
    n_e = [sr["n_eval"] for sr in seed_results]
    return agg, n_w, n_e


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--n-records", type=int, default=10000)
    ap.add_argument("--n-train", type=int, default=1500)
    ap.add_argument("--n-eval", type=int, default=2000)
    ap.add_argument("--eps", type=float, default=0.10)
    ap.add_argument("--sigma", type=float, default=0.10)
    ap.add_argument("--tau", type=float, default=0.90)
    ap.add_argument("--n-mc", type=int, default=2000)
    ap.add_argument("--alpha", type=float, default=1e-3)
    ap.add_argument("--seeds", default="0,1,2,3,4")
    args = ap.parse_args()
    seeds = [int(s) for s in args.seeds.split(",") if s.strip()]

    records = load_records(n=args.n_records)
    seed_results = []
    for s in seeds:
        r = run_seed(records, args.n_train, args.n_eval, args.eps, args.sigma, args.tau,
                     args.n_mc, args.alpha, s)
        seed_results.append(r)
        print(f"  seed={s}: witnesses={r['n_witness']}/{r['n_eval']} "
              f"({r['witness_prevalence']}) cats={r['category_dist']}")
        for row in ROWS:
            m = r["rows"][row]
            print(f"     {row:26s} afa={m['attack_false_allow']:.3f} acc={m['clean_acc']:.3f} "
                  f"Rallow={m['Rallow']:.3f} cfa={m['cert_false_allow']:.3f}")

    agg, n_w, n_e = aggregate(seed_results)
    # correctness invariants. The HARD soundness invariant (afa=0, cert_false_allow=0) is asserted for the
    # rows whose soundness is a THEOREM on this executable policy: exact rung-1 (exact enumeration) and
    # certified_rs (Gaussian RS, sound over B_{1,ε}). certified_lip's soundness is EMPIRICAL against the
    # learned Lipschitz gate (cf. #32 / lip_gate H.2): on the AUC-limited real-data boundary the
    # constrained gate can misfit, so a small cert_false_allow is the documented gate-fidelity danger
    # case, reported (not asserted to 0).
    vp = agg["verified_point_predicate"]["attack_false_allow"][0]
    lp = agg["learned_point"]["attack_false_allow"][0]
    SOUND = ("exact_rung1", "certified_rs")
    inv = {
        "verified_point_eq_1": abs(vp - 1.0) < 1e-6,
        "learned_le_verified": lp <= vp + 1e-9,
        "sound_rows_zero_afa": all(agg[r]["attack_false_allow"][0] == 0.0 for r in SOUND),
        "sound_rows_cert_false_allow_zero": all(agg[r]["cert_false_allow"][0] == 0.0 for r in SOUND),
        "lip_empirical_cert_false_allow": agg["certified_lip"]["cert_false_allow"][0],  # reported, not asserted
    }
    OUT.mkdir(parents=True, exist_ok=True)
    cols = ["row", "cell", "attack_false_allow_mean", "attack_false_allow_std", "clean_acc_mean",
            "clean_acc_std", "Rallow_mean", "Rallow_std", "cert_false_allow_mean"]
    table = []
    for row in ROWS:
        a = agg[row]
        table.append({"row": row, "cell": CELL[row],
                      "attack_false_allow_mean": a["attack_false_allow"][0],
                      "attack_false_allow_std": a["attack_false_allow"][1],
                      "clean_acc_mean": a["clean_acc"][0], "clean_acc_std": a["clean_acc"][1],
                      "Rallow_mean": a["Rallow"][0], "Rallow_std": a["Rallow"][1],
                      "cert_false_allow_mean": a["cert_false_allow"][0]})
    with open(OUT / "exp1_neighbor_head_to_head.csv", "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=cols); w.writeheader(); w.writerows(table)
    payload = {"config": vars(args), "n_witness_per_seed": n_w, "n_eval_per_seed": n_e,
               "witness_total": int(np.sum(n_w)), "eval_total": int(np.sum(n_e)),
               "table": table, "correctness_invariants": inv,
               "per_seed": seed_results}
    (OUT / "exp1_neighbor_head_to_head.json").write_text(json.dumps(payload, indent=2))

    print(f"\n=== EXP1 (mean±std over {len(seeds)} seeds; {int(np.sum(n_w))} witnesses "
          f"over {int(np.sum(n_e))} transactions) ===")
    print(f"{'row':26s} {'cell':26s} {'attack_FA':>12s} {'clean_acc':>10s} {'Rallow':>8s} {'cert_FA':>8s}")
    for row in ROWS:
        a = agg[row]
        print(f"{row:26s} {CELL[row]:26s} {a['attack_false_allow'][0]:.3f}±{a['attack_false_allow'][1]:.3f}  "
              f"{a['clean_acc'][0]:.3f}    {a['Rallow'][0]:.3f}   {a['cert_false_allow'][0]:.3f}")
    print(f"\ncorrectness invariants: {inv}")
    hard = ("verified_point_eq_1", "learned_le_verified", "sound_rows_zero_afa",
            "sound_rows_cert_false_allow_zero")
    if not all(inv[k] for k in hard):
        print("*** HARD INVARIANT VIOLATION — investigate before reporting ***")
    print(f"(certified_lip cert_false_allow={inv['lip_empirical_cert_false_allow']} — empirical "
          f"gate-fidelity caveat, cf. #32/lip_gate H.2; certified_rs is the sound certified row)")
    print(f"wrote -> {OUT/'exp1_neighbor_head_to_head.{csv,json}'}")
    return payload


if __name__ == "__main__":
    main()
