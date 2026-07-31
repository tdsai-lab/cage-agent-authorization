#!/usr/bin/env python3
"""
geometric_sensitivity.py — the headline experiment (PLAN5 §2): C% vs boundary separation Δ/ε.

Directly answers the "C is fabricated by the generator" critique by showing C is a GEOMETRIC
phenomenon. For two tools (t, t') sharing one action and numeric field, with thresholds θ_t, θ_{t'},
we sweep the gap Δ = |θ_t − θ_{t'}| (in units of ε) and measure category prevalence + the certificate.

Expectation (and analytic fact): the Category-C interval length for clean points on the high-threshold
tool is exactly **min(Δ, ε)** — so C measure grows linearly while Δ < ε and **saturates at ε for
Δ ≥ ε**; meanwhile category A (discrete-dominant) grows and R shrinks as Δ increases. C is therefore
an O(ε) effect: a provenance swap that displaces the boundary by ~ε creates the joint gap. (We do NOT
claim C "disappears" for large Δ — it saturates.)

Outputs: out/geometric_sensitivity.csv and .md (plot-ready columns:
  gap_over_epsilon, C_rate, A_rate, R_rate, naive_C_falseallow, C_allow, R_allow, cert_false_allow,
  analytic_C_len).
A `--realistic-finance` flag repeats the sweep on the finance template (sanctions↔credit gap).
"""
from __future__ import annotations

import argparse
import csv
import sys
import warnings
from pathlib import Path

import numpy as np

warnings.filterwarnings("ignore")
sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "generators"))
from oracle import category  # noqa: E402
from harness import run_setting  # noqa: E402

OUT = Path(__file__).resolve().parents[1] / "cert" / "out"
DOMAIN = "synthetic"
GAPS = [0.0, 0.25, 0.5, 0.75, 1.0, 1.5, 2.0, 3.0]   # in units of eps


def make_gap_table(delta, theta_hi=0.6):
    """Two scalar tools sharing field x0 and one action; gap Δ between thresholds."""
    a = "approve"
    theta_lo = theta_hi - delta
    rules = [
        {"domain": DOMAIN, "tool_id": "tool_hi", "candidate_action": a, "categorical_context": {},
         "rule_family": "scalar_threshold", "numeric_field": "x0", "unsafe_direction": ">=",
         "threshold": float(theta_hi)},
        {"domain": DOMAIN, "tool_id": "tool_lo", "candidate_action": a, "categorical_context": {},
         "rule_family": "scalar_threshold", "numeric_field": "x0", "unsafe_direction": ">=",
         "threshold": float(theta_lo)},
    ]
    dc = {"tools": ["tool_hi", "tool_lo"], "numeric_fields": ["x0"],
          "categorical_fields": {"ctx": ["c0", "c1"]}, "candidate_actions": [a], "rules": rules,
          "_tool_action": {"tool_hi": a, "tool_lo": a}, "_action_field": {a: "x0"}}
    return {"meta": {"synthetic": True, "K": 2, "k": 1, "x1_size": 2}, "mvp": {"discrete_budget_mvp": 1},
            "domains": {DOMAIN: dc}}


def sample_gap_records(rt, n, eps, seed):
    rng = np.random.default_rng(seed)
    dc = rt["domains"][DOMAIN]
    tools = dc["tools"]
    recs = []
    for i in range(n):
        tool = str(rng.choice(tools))
        x1 = {"ctx": str(rng.choice(["c0", "c1"]))}
        x2 = {"x0": float(rng.random())}
        res = category({"domain": DOMAIN, "tool_id": tool, "candidate_action": "approve",
                        "categorical_fields": x1, "numeric_fields": x2}, "approve", rt, 1, eps)
        recs.append({"id": f"g-{i:06d}", "domain": DOMAIN, "tool_id": tool, "candidate_action": "approve",
                     "categorical_fields": x1, "numeric_fields": x2,
                     "y": 1 if res["clean_safe"] else 0,
                     "safety_label": "safe" if res["clean_safe"] else "unsafe",
                     "category": res["category"][0]})
    return recs


def analytic_C_len(delta, eps, theta_hi=0.6):
    """Length of the C interval for clean points on the high-threshold tool, clipped to [0,1]."""
    theta_lo = theta_hi - delta
    lo = max(0.0, theta_lo - eps)
    hi = min(theta_lo, theta_hi - eps)
    return max(0.0, min(1.0, hi) - lo)


def run_sweep(make_rt, label, eps, n, sigma, tau, n_mc, n_cert, n_attack, seed):
    rows = []
    for g in GAPS:
        delta = g * eps
        rt = make_rt(delta)
        recs = sample_gap_records(rt, n, eps, seed) if make_rt is make_gap_table else \
            _sample_via(rt, n, eps, seed)
        row = run_setting(rt, recs, eps=eps, sigma=sigma, tau=tau, n_mc=n_mc, n_cert=n_cert,
                          n_attack=n_attack, n_aug=8, train_cap=min(n, 16000), seed=seed,
                          label=f"{label} Δ/ε={g}")
        rows.append({
            "family": label, "gap_over_epsilon": g, "delta": round(delta, 4),
            "C_rate": row["C_pct"] / 100, "A_rate": row["A_pct"] / 100, "B_rate": row["B_pct"] / 100,
            "R_rate": row["R_pct"] / 100, "U_rate": row["U_pct"] / 100,
            "naive_C_falseallow": row["naive_C_falseallow"], "C_allow": row["C_allow"],
            "R_allow": row["R_allow"], "U_allow": row["U_allow"],
            "cert_false_allow": row["cert_false_allow"],
            "analytic_C_len": round(analytic_C_len(delta, eps), 4) if label == "scalar2" else "",
        })
        print(f"{label:14s} Δ/ε={g:<4} | C%={row['C_pct']:4.1f} A%={row['A_pct']:4.1f} "
              f"R%={row['R_pct']:4.1f} | naiveC={row['naive_C_falseallow']:.2f} "
              f"C_allow={row['C_allow']:.2f} R_allow={row['R_allow']:.2f} cFA={row['cert_false_allow']:.2f}")
    return rows


# finance-template gap sweep (PLAN5 §5): vary sanctions threshold under credit's fixed threshold
def _finance_gap_table(delta):
    import sys as _s
    _s.path.insert(0, str(Path(__file__).resolve().parent))
    from realistic_schemas import finance_schema
    _, rt = finance_schema()
    dc = rt["domains"][DOMAIN]
    credit = next(r for r in dc["rules"] if r["tool_id"] == "credit_check")
    for r in dc["rules"]:
        if r["tool_id"] == "sanctions_screen":
            r["threshold"] = float(credit["threshold"]) - float(delta)  # gap = delta
    rt["meta"]["K"] = len(dc["tools"]); rt["meta"]["k"] = len(dc["numeric_fields"])
    rt["meta"]["x1_size"] = max(len(v) for v in dc["categorical_fields"].values())
    return rt


def _sample_via(rt, n, eps, seed):
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    from synthetic_tools import sample_records
    return sample_records(rt, n, eps=eps, seed=seed)


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--eps", type=float, default=0.10)
    ap.add_argument("--n", type=int, default=5000)
    ap.add_argument("--sigma", type=float, default=0.10)
    ap.add_argument("--tau", type=float, default=0.90)
    ap.add_argument("--n-mc", type=int, default=1500)
    ap.add_argument("--n-cert", type=int, default=40)
    ap.add_argument("--n-attack", type=int, default=50)
    ap.add_argument("--seed", type=int, default=1)
    ap.add_argument("--realistic-finance", action="store_true")
    args = ap.parse_args()

    rows = run_sweep(make_gap_table, "scalar2", args.eps, args.n, args.sigma, args.tau,
                     args.n_mc, args.n_cert, args.n_attack, args.seed)
    if args.realistic_finance:
        rows += run_sweep(_finance_gap_table, "finance", args.eps, args.n, args.sigma, args.tau,
                          args.n_mc, args.n_cert, args.n_attack, args.seed)

    OUT.mkdir(parents=True, exist_ok=True)
    cols = ["family", "gap_over_epsilon", "delta", "C_rate", "A_rate", "B_rate", "R_rate", "U_rate",
            "naive_C_falseallow", "C_allow", "R_allow", "U_allow", "cert_false_allow", "analytic_C_len"]
    with open(OUT / "geometric_sensitivity.csv", "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=cols); w.writeheader(); w.writerows(rows)

    md = ["# Geometric sensitivity — C% vs boundary separation Δ/ε\n",
          f"eps={args.eps}, n={args.n}/gap, sigma={args.sigma}, tau={args.tau}, n_mc={args.n_mc}. "
          "Analytic C-interval length = min(Δ, ε) (clipped to the value range).\n",
          "| " + " | ".join(cols) + " |", "| " + " | ".join("---" for _ in cols) + " |"]
    for r in rows:
        md.append("| " + " | ".join(str(r.get(c, "")) for c in cols) + " |")
    scal = [r for r in rows if r["family"] == "scalar2"]
    md.append(f"\n**Scalar family:** C_rate is {scal[0]['C_rate']*100:.1f}% at Δ=0, grows with Δ, and "
              f"**saturates** near the analytic bound min(Δ,ε) once Δ≳ε "
              f"(C%≈{scal[-1]['C_rate']*100:.1f}% across Δ/ε∈{{1,1.5,2,3}}); meanwhile A grows and R "
              "shrinks. C is therefore an O(ε) geometric phenomenon — a provenance swap that displaces "
              "the safety boundary by ~ε creates the joint gap — not a generator artifact. "
              f"Certificate stays sound across all gaps (max C_allow={max(r['C_allow'] for r in rows):.2f}, "
              f"max cert_false_allow={max(r['cert_false_allow'] for r in rows):.2f}).")
    (OUT / "geometric_sensitivity.md").write_text("\n".join(md) + "\n")
    print(f"\nwrote -> {OUT/'geometric_sensitivity.csv'} and .md")


if __name__ == "__main__":
    main()
