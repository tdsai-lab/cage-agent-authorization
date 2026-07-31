#!/usr/bin/env python3
"""
delta_sensitivity_c.py — EXP-B1 (NEW_NEW_EXP.md Priority B; , ). δ-sensitivity of C prevalence
on the two REAL datasets, to test the min(Δ,ε) prevalence law of Theorem 1.

The "natural" C rates are measured under an authored provenance-conditioned threshold gap δ≈0.08≈ε, near the
saturation of the min(Δ,ε) geometry. If a reviewer suspects the C rate is an artifact of that one δ, the
sharpest reply is to SWEEP δ and show Pr(C) TRACKS min(δ,ε): a weakness becomes a verified prediction. This
driver regenerates the analytic A/B/C/R/U taxonomy at δ ∈ {0.02,0.05,0.08,0.15,0.30}, ε=0.10 fixed, natural
sampling, 3 seeds, on:
  * IEEE-CIS  — real held-out risk_score, real loose/strict provenance, θ_base=0.488808 (real gen constant).
  * NAB       — real EC2/RDS CPU utilization, θ_base = gate-pool cpu quantile (q=0.70, as T2-7).
Analytic oracle taxonomy ONLY (no gate retraining needed for prevalence): reuses `ieee_cis_policy.
analytic_category` / `nab_policy.analytic_category` (the same scalar-threshold geometry the OPA engine
reproduces at agreement 1.0). Optional soundness check: the EXACT certificate (allow ⟺ category R) has
cert_false_allow=0 at every δ — soundness is δ-independent.

The min(δ,ε) prediction: the per-record C-interval on the policy value has length min(δ,ε) (analytic
`c_interval`), so under a fixed boundary density Pr(C) ∝ min(δ,ε): monotone in δ up to δ=ε, then SATURATED.
We report Pr(C)(δ), the normalized min(δ,ε) overlay, and the monotone+saturation check.

**Text must stay conditional** (r3): this is prevalence UNDER a provenance-conditioned threshold gap δ,
tracking min(δ,ε) — NOT deployed prevalence. numpy/pandas; real data; no LLM/GPU/network (NAB pre-downloaded).
"""
from __future__ import annotations

import argparse
import os
import json
import sys
import warnings
from pathlib import Path

import numpy as np

warnings.filterwarnings("ignore")
_HERE = Path(__file__).resolve().parent
_BB = _HERE.parent
sys.path.insert(0, str(_BB))
sys.path.insert(0, str(_BB / "realdata"))

import pandas as pd  # noqa: E402

OUT = _BB / "cert" / "out"
IEEE_RAW = os.environ.get("IEEE_CIS_DIR", "bridge_benchmark/data/raw/ieee_cis")
EPS = 0.10
IEEE_THETA_BASE = 0.488808          # real generation constant (ieee_fraud.rego / validation_stack_adversary)
NAB_THETA_QUANTILE = 0.70           # T2-7 default
DELTAS = [0.02, 0.05, 0.08, 0.15, 0.30]
CATS = ["A", "B", "C", "R", "U"]


# --------------------------------------------------------------------------- #
# IEEE-CIS natural records: (risk_score, x1, tool)
# --------------------------------------------------------------------------- #
def ieee_records(seed, max_rows=None):
    import ieee_cis_adapter as A
    import ieee_cis_policy as pol
    df = A.load_raw(IEEE_RAW, max_rows=max_rows)
    split = A.assign_split(df, seed=seed)
    edges = A._amount_band_edges(pd.to_numeric(df["TransactionAmt"], errors="coerce"))
    tr = df[split == "risk_model_train"]
    gate = df[split == "gate_pool"].copy()
    pipe, _ = A.train_risk_model(tr, edges, seed=seed)
    risk = A.predict_risk(pipe, gate, edges)
    tids = gate["TransactionID"].to_numpy()
    recs = []
    for row, r, tid in zip(gate.to_dict("records"), risk, tids):
        x1 = A.build_x1(row, edges)
        tool = pol.TOOLS[int(A._stable_unit(int(tid), seed=1234) * len(pol.TOOLS)) % len(pol.TOOLS)]
        recs.append((float(min(max(r, 0.0), 1.0)), tool, x1))
    return recs, IEEE_THETA_BASE, pol


# --------------------------------------------------------------------------- #
# NAB natural records: (cpu_util_norm, x1, tool)
# --------------------------------------------------------------------------- #
def nab_records(seed, max_rows=None):
    import nab_adapter as adp
    import nab_policy as pol
    df = adp.load_raw(max_rows=max_rows)
    split = adp.assign_split(df, seed=seed)
    gate = df[split == "gate_pool"].copy()
    cpu_norm = gate["value"].map(adp._norm_pct).to_numpy()
    theta_base = float(np.quantile(cpu_norm, NAB_THETA_QUANTILE)) if len(cpu_norm) else 0.5
    theta_base = min(0.95, max(0.05, theta_base))
    recs = []
    for row in gate.to_dict("records"):
        x1 = adp.build_x1(row)
        cpu = adp._norm_pct(row["value"])
        tool = adp.obs_base_tool(int(row["obs_id"]), seed) if "obs_id" in row else pol.TOOLS[0]
        recs.append((float(cpu), tool, x1))
    return recs, theta_base, pol


# --------------------------------------------------------------------------- #
def sweep(recs, theta_base, pol, deltas, eps):
    rows = []
    for d in deltas:
        counts = {c: 0 for c in CATS}
        exact_allowed = exact_false_allow = 0     # exact certificate: allow ⟺ R
        for val, tool, x1 in recs:
            res = pol.analytic_category(val, tool, x1, theta_base, d, eps)
            c = res["category"]
            counts[c] += 1
            if c == "R":                          # exact certificate allows exactly the robust set
                exact_allowed += 1
                if res["joint_unsafe"] or not res["clean_safe"]:
                    exact_false_allow += 1        # would be a soundness violation (must be 0)
        n = len(recs)
        rows.append({"delta": d, "n": n,
                     "pr": {c: round(counts[c] / n, 6) for c in CATS},
                     "pr_C": round(counts["C"] / n, 6),
                     "min_delta_eps": round(min(d, eps), 4),
                     "exact_cert_allow_rate": round(exact_allowed / n, 6),
                     "exact_cert_false_allow": round(exact_false_allow / max(1, exact_allowed), 6)})
    return rows


def aggregate(per_seed_rows, deltas):
    out = []
    for i, d in enumerate(deltas):
        cells = [ps[i] for ps in per_seed_rows]
        prC = [c["pr_C"] for c in cells]
        out.append({"delta": d, "min_delta_eps": cells[0]["min_delta_eps"],
                    "pr_C_mean": round(float(np.mean(prC)), 6), "pr_C_std": round(float(np.std(prC)), 6),
                    "pr_by_cat_mean": {c: round(float(np.mean([x["pr"][c] for x in cells])), 6)
                                       for c in CATS},
                    "exact_cert_false_allow_max": round(max(x["exact_cert_false_allow"] for x in cells), 6),
                    "exact_cert_allow_rate_mean": round(float(np.mean(
                        [x["exact_cert_allow_rate"] for x in cells])), 6)})
    return out


def law_check(agg, eps):
    """Test Pr(C) ~ min(δ,ε): (1) monotone non-decreasing up to δ=ε, (2) saturates for δ≥ε (relative change
    small), (3) Pearson corr of Pr(C) with min(δ,ε). Returns a dict of diagnostics."""
    prC = [a["pr_C_mean"] for a in agg]
    mde = [a["min_delta_eps"] for a in agg]
    deltas = [a["delta"] for a in agg]
    below = [(d, p) for d, p in zip(deltas, prC) if d <= eps]
    mono = all(below[i][1] <= below[i + 1][1] + 1e-9 for i in range(len(below) - 1))
    above = [p for d, p in zip(deltas, prC) if d >= eps]
    sat_span = (max(above) - min(above)) / max(1e-9, max(above)) if len(above) >= 2 else 0.0
    corr = float(np.corrcoef(prC, mde)[0, 1]) if len(set(prC)) > 1 else float("nan")
    return {"monotone_up_to_eps": bool(mono), "saturation_rel_span_above_eps": round(sat_span, 4),
            "pearson_corr_prC_vs_min_delta_eps": round(corr, 4),
            "tracks_law": bool(mono and sat_span < 0.25 and (np.isnan(corr) or corr > 0.9))}


def run(datasets, seeds, deltas, eps, max_rows, out_prefix):
    results = {}
    for ds in datasets:
        loader = ieee_records if ds == "ieee_cis" else nab_records
        per_seed = []
        theta_used = None
        for s in seeds:
            recs, theta_base, pol = loader(s, max_rows=max_rows)
            theta_used = theta_base
            per_seed.append(sweep(recs, theta_base, pol, deltas, eps))
            print(f"[{ds} seed={s}] n={len(recs)} θ_base={round(theta_base,4)} "
                  f"Pr(C) over δ={[r['pr_C'] for r in per_seed[-1]]}")
        agg = aggregate(per_seed, deltas)
        law = law_check(agg, eps)
        results[ds] = {"theta_base": round(theta_used, 6), "eps": eps, "n_seeds": len(seeds),
                       "table": agg, "law_check": law,
                       "exact_cert_false_allow_max": round(
                           max(a["exact_cert_false_allow_max"] for a in agg), 6)}
        print(f"[{ds}] law: {law}  | exact cert_false_allow max = "
              f"{results[ds]['exact_cert_false_allow_max']}")

    all_track = all(r["law_check"]["tracks_law"] for r in results.values())
    all_sound = all(r["exact_cert_false_allow_max"] == 0.0 for r in results.values())
    verdict = ("VERIFIED PREDICTION: Pr(C) tracks min(δ,ε) on both real datasets (monotone to δ=ε, saturates "
               "above) and the exact certificate stays sound (cert_false_allow=0) at every δ → the C rate is "
               "a δ-parameterised prediction of Theorem 1, not a single-δ artifact." if (all_track and all_sound)
               else ("SOUND but law deviates: report the deviation and temper Theorem-1's prevalence-law claim "
                     "(soundness unaffected)." if all_sound else
                     "UNEXPECTED: exact certificate not sound at some δ — investigate (should be 0 by construction)."))
    payload = {
        "experiment": "EXP-B1 — δ-sensitivity of C prevalence (real datasets, min(δ,ε) law test)",
        "priority": "B",
        "reuses": "ieee_cis_policy.analytic_category, nab_policy.analytic_category (analytic taxonomy only)",
        "eps": eps, "deltas": deltas, "seeds": list(seeds), "results": results,
        "verdict": verdict,
        "conditionality_note": ("Prevalence UNDER a provenance-conditioned threshold gap δ, tracking min(δ,ε) "
                                "— NOT deployed prevalence. Natural sampling on the real gate pool; the C rate "
                                "scales with the boundary density × min(δ,ε)."),
    }
    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / f"{out_prefix}.json").write_text(json.dumps(payload, indent=2))
    _write_md(OUT / f"{out_prefix}.md", payload)
    _plot(results, deltas, eps, OUT / f"{out_prefix}.pdf")
    print(f"\nVERDICT: {verdict}")
    print(f"wrote -> {OUT/(out_prefix+'.json')}\nwrote -> {OUT/(out_prefix+'.md')}")
    return payload


def _write_md(path, p):
    with open(path, "w") as f:
        f.write("# EXP-B1 — δ-sensitivity of C prevalence (min(δ,ε) law on real data)\n\n")
        f.write(f"{p['reuses']}. ε={p['eps']}, "
                f"seeds={p['seeds']}.\n\n**Conditionality.** {p['conditionality_note']}\n\n")
        for ds, r in p["results"].items():
            f.write(f"### {ds} (θ_base={r['theta_base']})\n\n")
            f.write("| δ | min(δ,ε) | Pr(A) | Pr(B) | **Pr(C)** | Pr(R) | Pr(U) | exact cert FA |\n")
            f.write("|--:|--:|--:|--:|--:|--:|--:|--:|\n")
            for a in r["table"]:
                pc = a["pr_by_cat_mean"]
                f.write(f"| {a['delta']} | {a['min_delta_eps']} | {pc['A']} | {pc['B']} | "
                        f"**{a['pr_C_mean']}±{a['pr_C_std']}** | {pc['R']} | {pc['U']} | "
                        f"{a['exact_cert_false_allow_max']} |\n")
            lc = r["law_check"]
            f.write(f"\nLaw check: monotone→ε **{lc['monotone_up_to_eps']}**, saturation span above ε "
                    f"**{lc['saturation_rel_span_above_eps']}**, corr(Pr(C), min(δ,ε)) "
                    f"**{lc['pearson_corr_prC_vs_min_delta_eps']}**, tracks_law **{lc['tracks_law']}**; "
                    f"exact cert_false_allow max **{r['exact_cert_false_allow_max']}**.\n\n")
        f.write(f"**Verdict.** {p['verdict']}\n")


def _plot(results, deltas, eps, path):
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except Exception:
        return
    fig, ax = plt.subplots(figsize=(6, 4))
    for ds, r in results.items():
        prC = [a["pr_C_mean"] for a in r["table"]]
        ax.plot(deltas, prC, "o-", label=f"Pr(C) {ds}")
        # normalized min(δ,ε) overlay scaled to the dataset's peak Pr(C)
        peak = max(prC) or 1.0
        ax.plot(deltas, [min(d, eps) / eps * peak for d in deltas], "--", alpha=0.5,
                label=f"min(δ,ε) law ×{round(peak,3)}")
    ax.axvline(eps, ls=":", color="k", alpha=0.6, label=f"δ=ε={eps}")
    ax.set_xlabel("provenance threshold gap δ"); ax.set_ylabel("Pr(C)")
    ax.legend(fontsize=7); fig.tight_layout()
    fig.savefig(path); plt.close(fig)
    print(f"wrote -> {path}")


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--datasets", default="ieee_cis,nab")
    ap.add_argument("--seeds", default="0,1,2")
    ap.add_argument("--deltas", default=",".join(str(d) for d in DELTAS))
    ap.add_argument("--eps", type=float, default=EPS)
    ap.add_argument("--max-rows", type=int, default=None)
    ap.add_argument("--out", default="exp_b1_delta_sensitivity")
    a = ap.parse_args()
    ds = [x.strip() for x in a.datasets.split(",") if x.strip()]
    seeds = [int(s) for s in a.seeds.split(",") if s.strip()]
    deltas = [float(x) for x in a.deltas.split(",") if x.strip()]
    run(ds, seeds, deltas, a.eps, a.max_rows, a.out)


if __name__ == "__main__":
    main()
