#!/usr/bin/env python3
"""M2 — natural-traffic autonomy accounting (supp table S50).

Motivation: utility of a low R_allow. R_allow is a CONDITIONAL rate — the fraction of the
robust-safe set R that the certified gate authorizes. On its own it reads as low
utility. This re-aggregation restates it as UNCONDITIONAL autonomy on natural traffic:

    unconditional_certified_allow = Pr[R] · R_allow     (gate allows only within R)
    human_review_volume           = 1 − unconditional_certified_allow

per Table-5 natural-sampling setting, alongside the natural hazard prevalence Pr[C]
(the joint-corruption cases the gate must catch) — the S15 triage numbers restated on
natural traffic.

Pure re-aggregation of existing runs (no GPU/LLM/retrain):
  * IEEE-CIS / NAB natural Pr[R], Pr[C]  ← cert/out/exp_b1_delta_sensitivity.json (δ=0.08, ε=0.10)
  * NAB R_allow per backend              ← cert/out/exp_second_dataset/summary.csv
  * REG PSD2/AML natural rows            ← policy_idiom_prevalence/.../regulatory_{c_prevalence,certified_gate}.csv
  * OPA Track-C natural cells            ← cert/out/exp_opa_full/summary.json (canonical ε=0.1, τ=0.9)

Outputs (gitignored cert/out):
    cert/out/natural_traffic_autonomy.csv   (= supp table S50)
    cert/out/natural_traffic_autonomy.md
"""
from __future__ import annotations

import csv
import json
import os

HERE = os.path.dirname(os.path.abspath(__file__))
_BB = os.path.abspath(os.path.join(HERE, ".."))
OUT = os.path.join(_BB, "cert", "out")
REG = os.path.join(HERE, "policy_idiom_prevalence", "results", "tables")

DELTA = 0.08
EPS = 0.10


def _acc(setting, rung, pr_R, pr_C, R_allow, n, source):
    uncond = pr_R * R_allow
    return {
        "setting": setting,
        "rung_backend": rung,
        "n": n,
        "Pr_R_natural": round(pr_R, 4),
        "Pr_C_natural_hazard": round(pr_C, 4),
        "R_allow_conditional": round(R_allow, 4),
        "unconditional_certified_allow": round(uncond, 4),
        "human_review_volume": round(1.0 - uncond, 4),
        "source": source,
    }


def _load_csv(p):
    with open(p) as fh:
        return list(csv.DictReader(fh))


def rows_ieee_nab(rows):
    p = os.path.join(OUT, "exp_b1_delta_sensitivity.json")
    if not os.path.exists(p):
        return
    res = json.load(open(p))["results"]

    # IEEE-CIS: exact rung-1 certificate (allows exactly R => R_allow = 1.0 on natural traffic)
    ie = res.get("ieee_cis")
    if ie:
        r = next(x for x in ie["table"] if abs(x["delta"] - DELTA) < 1e-9)
        prR = r["pr_by_cat_mean"]["R"]
        prC = r["pr_by_cat_mean"]["C"]
        rows.append(_acc("IEEE-CIS (real fraud risk)", "exact (rung 1)", prR, prC, 1.0,
                         "~295k natural", "exp_b1_delta_sensitivity.json"))

    # NAB: exact / Lipschitz / RS backends (R_allow read from the second-dataset summary)
    nb = res.get("nab")
    nab_allow = {}
    sp = os.path.join(OUT, "exp_second_dataset", "summary.csv")
    if os.path.exists(sp):
        for line in open(sp):
            parts = line.strip().split(",")
            if parts and parts[0] == "R_allow_lipschitz_primary":
                nab_allow["Lipschitz (rung 2)"] = float(parts[1])
            elif parts and parts[0] == "R_allow_smoothing_ablation":
                nab_allow["RS (rung 2, ablation)"] = float(parts[1])
            elif parts and parts[0] == "R_allow_exact_ceiling":
                nab_allow["exact (rung 1)"] = float(parts[1])
    if nb:
        r = next(x for x in nb["table"] if abs(x["delta"] - DELTA) < 1e-9)
        prR = r["pr_by_cat_mean"]["R"]
        prC = r["pr_by_cat_mean"]["C"]
        for rung, allow in (nab_allow or {"exact (rung 1)": 1.0}).items():
            rows.append(_acc("NAB (real EC2/RDS CPU)", rung, prR, prC, allow,
                             "~29k natural", "exp_b1 + exp_second_dataset"))


def rows_reg(rows):
    prev_p = os.path.join(REG, "regulatory_c_prevalence.csv")
    gate_p = os.path.join(REG, "regulatory_certified_gate.csv")
    if not (os.path.exists(prev_p) and os.path.exists(gate_p)):
        return
    gate = {(g["policy_family"], g["sampling_mode"], g["epsilon"]): g for g in _load_csv(gate_p)}
    for p in _load_csv(prev_p):
        if p["sampling_mode"] != "natural" or abs(float(p["epsilon"]) - EPS) > 1e-9:
            continue
        g = gate.get((p["policy_family"], "natural", p["epsilon"]))
        if not g:
            continue
        rows.append(_acc(f"REG {p['policy_family']} (PSD2/AML)", "smoothed (rung 2)",
                         float(p["R_pct"]), float(p["C_pct"]), float(g["R_allow"]),
                         int(float(p["n"])), "regulatory_{c_prevalence,certified_gate}.csv"))


def rows_opa(rows):
    p = os.path.join(OUT, "exp_opa_full", "summary.json")
    if not os.path.exists(p):
        return
    d = json.load(open(p))
    n = d["config"]["n_eval"] * len(d["config"]["seeds"])
    for c in d["cells"]:
        if not (abs(c["eps"] - 0.1) < 1e-9 and abs(c["tau"] - 0.9) < 1e-9):
            continue
        if c["backend"] != "lipschitz":     # Lipschitz is the primary backend
            continue
        rows.append(_acc(f"OPA Track-C {c['domain']} (policy-as-code)", "Lipschitz (rung 2)",
                         c["R_rate_mean"], c["C_rate_mean"], c["R_allow_mean"], n,
                         "exp_opa_full/summary.json"))


def main():
    rows = []
    rows_ieee_nab(rows)
    rows_reg(rows)
    rows_opa(rows)

    os.makedirs(OUT, exist_ok=True)
    cols = ["setting", "rung_backend", "n", "Pr_R_natural", "Pr_C_natural_hazard",
            "R_allow_conditional", "unconditional_certified_allow",
            "human_review_volume", "source"]
    csv_p = os.path.join(OUT, "natural_traffic_autonomy.csv")
    with open(csv_p, "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=cols)
        w.writeheader()
        w.writerows(rows)

    md_p = os.path.join(OUT, "natural_traffic_autonomy.md")
    with open(md_p, "w") as fh:
        fh.write("# S50 (M2 / R3) — natural-traffic autonomy accounting\n\n")
        fh.write("R_allow is CONDITIONAL on the robust-safe set R; here it "
                 "is restated as UNCONDITIONAL certified-autonomy on natural traffic "
                 "(`Pr[R]·R_allow`), with the implied human-review volume and the natural hazard "
                 f"prevalence Pr[C] the gate must catch. ε={EPS}, δ={DELTA}.\n\n")
        fh.write("| setting | rung/backend | Pr[R] | Pr[C] hazard | R_allow (cond.) | "
                 "uncond. certified-allow | human-review volume |\n")
        fh.write("|---|---|---|---|---|---|---|\n")
        for r in rows:
            fh.write(f"| {r['setting']} | {r['rung_backend']} | {r['Pr_R_natural']:.3f} | "
                     f"{r['Pr_C_natural_hazard']:.3f} | {r['R_allow_conditional']:.3f} | "
                     f"**{r['unconditional_certified_allow']:.3f}** | "
                     f"{r['human_review_volume']:.3f} |\n")
        if rows:
            exact = [r for r in rows if "exact" in r["rung_backend"]]
            if exact:
                lo = min(exact, key=lambda r: r["unconditional_certified_allow"])
                hi = max(exact, key=lambda r: r["unconditional_certified_allow"])
                fh.write(f"\n**§6.4 takeaway sentence.** On natural traffic the exact rung-1 certificate "
                         f"autonomously clears {hi['unconditional_certified_allow']*100:.0f}% "
                         f"({hi['setting'].split(' (')[0]}) to "
                         f"{lo['unconditional_certified_allow']*100:.0f}% "
                         f"({lo['setting'].split(' (')[0]}) of decisions with a certificate, routing the "
                         f"rest to human review — so a 'low' conditional R_allow still corresponds to a "
                         f"substantial, auditable autonomy volume, not near-total abstention.\n")
    print(f"wrote {csv_p}")
    print(f"wrote {md_p}")
    for r in rows:
        print(f"  {r['setting']:42s} {r['rung_backend']:24s} "
              f"Pr[R]={r['Pr_R_natural']:.3f} uncond={r['unconditional_certified_allow']:.3f} "
              f"human_review={r['human_review_volume']:.3f}")


if __name__ == "__main__":
    main()
