#!/usr/bin/env python3
"""make_delta_epsilon_geometry.py — Table L4 + figure: closes the registered C% ∝ min(Δ,ε) geometry
check. Sweeps ε, measures C% under the OPA oracle, and bins C-witnesses by their per-record threshold
gap Δ (parsed from the authored Rego base/adj dicts) to show C concentrates where Δ ≲ ε."""
from __future__ import annotations

import argparse
import csv
import sys
import warnings
from pathlib import Path

import numpy as np

warnings.filterwarnings("ignore")
_EXP = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_EXP / "models"))
_OPA = _EXP.parents[1] / "experiments" / "opa_gate"
sys.path.insert(0, str(_OPA))
import lip_gate as LG  # noqa: E402
import methodology as M  # noqa: E402

PROV_FIELD = {"finance": "jurisdiction", "sre": "service_tier", "ops": "network"}
SIGNAL = {"finance": "risk_score", "sre": "signal", "ops": "login_risk"}


def _theta(base, adj, pf, tool, x1):
    return base.get(tool, 0.0) + adj.get(x1.get(pf), 0.0)


def _neighbors(domain, tool, x1):
    """Registered (mechanism-tagged) discrete neighbours, with the rego threshold for each."""
    return [(t2, x12) for t2, x12, _f, _m in M.registered_swaps(domain, tool, x1)]


def per_record_min_delta(domain, rego, tool, x1, _nbrs=None):
    base, adj = rego.get("base", {}), rego.get("adj", {})
    pf = PROV_FIELD[domain]
    th_self = _theta(base, adj, pf, tool, x1)
    nbrs = _nbrs if _nbrs is not None else _neighbors(domain, tool, x1)
    deltas = [abs(th_self - _theta(base, adj, pf, t2, x12)) for t2, x12 in nbrs]
    return min(deltas) if deltas else float("nan")


def analytic_category(domain, rego, r, eps, nbrs):
    """Same `field < θ(s)` semantics as the OPA authored policy, computed analytically (no OPA call)."""
    base, adj = rego.get("base", {}), rego.get("adj", {})
    pf = PROV_FIELD[domain]
    x = float(r["numeric_fields"][SIGNAL[domain]])
    th_self = _theta(base, adj, pf, r["tool_id"], r["categorical_fields"])
    th_nbrs = [_theta(base, adj, pf, t2, x12) for t2, x12 in nbrs]
    clean_safe = x < th_self
    disc = any(not (x < t) for t in th_nbrs)
    cont = not (x + eps < th_self)
    joint = any(not (x + eps < t) for t in th_nbrs)
    if not clean_safe:
        return "U"
    if disc:
        return "A"
    if cont:
        return "B"
    if joint:
        return "C"
    return "R"


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--domains", default="finance,sre,ops")
    ap.add_argument("--eps-grid", default="0.02,0.03,0.05,0.08,0.10,0.14,0.20")
    ap.add_argument("--n", type=int, default=2000)
    ap.add_argument("--seed", type=int, default=0)
    args = ap.parse_args()
    TAB = _EXP / "results" / "tables"; FIG = _EXP / "results" / "figures"
    TAB.mkdir(parents=True, exist_ok=True); FIG.mkdir(parents=True, exist_ok=True)
    eps_grid = [float(x) for x in args.eps_grid.split(",") if x.strip()]
    domains = [d.strip() for d in args.domains.split(",") if d.strip()]

    from schema import DOMAINS  # noqa: E402
    rego_path = lambda d: DOMAINS[d]["rego"]  # noqa: E731
    rows, curves = [], {}
    for domain in domains:
        rego = M.parse_rego_thresholds(Path(rego_path(domain)).read_text())
        min_delta = M.threshold_gaps(domain, Path(rego_path(domain)).read_text())["min_delta"]
        recs = LG.sample_records(domain, args.n, seed=args.seed)
        nbrs_cache = [_neighbors(domain, r["tool_id"], r["categorical_fields"]) for r in recs]
        cpct = []
        for eps in eps_grid:
            cats = [analytic_category(domain, rego, r, eps, nb) for r, nb in zip(recs, nbrs_cache)]
            n = len(cats)
            c_idx = [i for i, c in enumerate(cats) if c == "C"]
            cpct.append(len(c_idx) / n)
            # bin C-witnesses by Δ/ε
            doe = []
            for i in c_idx:
                d = per_record_min_delta(domain, rego, recs[i]["tool_id"], recs[i]["categorical_fields"],
                                         nbrs_cache[i])
                if d == d:
                    doe.append(d / eps)
            bins = {"Δ/ε<1": [], "1≤Δ/ε<2": [], "Δ/ε≥2": []}
            for v in doe:
                (bins["Δ/ε<1"] if v < 1 else bins["1≤Δ/ε<2"] if v < 2 else bins["Δ/ε≥2"]).append(v)
            for label, vals in bins.items():
                rows.append({"domain": domain, "epsilon": eps, "delta_bin": label,
                             "mean_delta_over_epsilon": round(float(np.mean(vals)), 4) if vals else "",
                             "C_percent": round(len(vals) / n, 4), "n": n,
                             "policy_min_delta": min_delta, "predicted_C_band": round(min(min_delta, eps), 4)})
        curves[domain] = (eps_grid, cpct, min_delta)

    cols = ["domain", "epsilon", "delta_bin", "mean_delta_over_epsilon", "C_percent", "n",
            "policy_min_delta", "predicted_C_band"]
    with open(TAB / "L4_delta_epsilon_geometry.csv", "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=cols, extrasaction="ignore"); w.writeheader(); w.writerows(rows)

    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
        fig, ax = plt.subplots(figsize=(6, 4))
        for domain, (xs, ys, md) in curves.items():
            ax.plot(xs, ys, marker="o", label=f"{domain} (C%)")
            ax.axvline(md, ls="--", alpha=0.4)
        ax.set_xlabel("epsilon (normalized)"); ax.set_ylabel("C-prevalence")
        ax.set_title("C% vs epsilon (dashed = policy min Δ; C-band ≈ min(Δ,ε))")
        ax.legend(); fig.tight_layout()
        fig.savefig(FIG / "c_prevalence_vs_min_delta_epsilon.pdf")
        print(f"wrote -> {FIG/'c_prevalence_vs_min_delta_epsilon.pdf'}")
    except Exception as e:
        print(f"[figure skipped: {e}]")
    print(f"wrote -> {TAB/'L4_delta_epsilon_geometry.csv'} ({len(rows)} rows)")


if __name__ == "__main__":
    main()
