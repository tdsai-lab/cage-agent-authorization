#!/usr/bin/env python3
"""M5 — boundary-mass check for Prop. 3 on clipped/quantized real marginals.

Motivation: Prop. 3 assumes the
safety boundary is measure-zero (Pr[m = ε] = 0), but real IEEE-CIS risk scores and
NAB CPU telemetry are clipped to [0,1] and quantized, and the NAB threshold θ_base is
a data QUANTILE (q=0.70) that can coincide exactly with telemetry atoms. If any
records sit exactly on a certificate boundary the equality in Prop. 3 must be replaced
by the conservative inequality.

We measure, on the real IEEE-CIS and NAB natural gate pools, the empirical mass within
1e-6 of every certificate-relevant boundary of the signed margin
    g_t(z) = value − θ_t(x1)          (Safe ⟺ value ≤ θ_t  ⟺  g_t ≤ 0)
namely:
  * clean boundary      g_self = 0        (value exactly on its own threshold)
  * continuous-flip     g_self = −ε       (value + ε exactly on its own threshold)
  * joint/neighbor      g_nbr  ∈ {0, −ε}  (a d=1 provenance swap's threshold)
plus the clip atoms value ∈ {0,1} and θ ∈ {0.05, 0.95}.

Soundness note (why this is a remark, not a bug): BOTH oracles classify the boundary
as UNSAFE (unsafe ⟺ m ≥ 0, and reachable-unsafe ⟺ m + ε ≥ 0 — closed inequalities), so
a record ON a boundary is BLOCKED. Positive boundary mass therefore only costs
abstention; it can never produce a false-allow. The measured mass tells the paper how
many real records the equality→inequality wording actually touches.

Outputs (gitignored cert/out):
    cert/out/prop3_boundary_mass.csv
    cert/out/prop3_boundary_mass.md
"""
from __future__ import annotations

import csv
import os
import sys

import numpy as np

HERE = os.path.dirname(os.path.abspath(__file__))
_BB = os.path.abspath(os.path.join(HERE, ".."))
OUT = os.path.join(_BB, "cert", "out")
for p in ("realdata", "experiments"):
    sys.path.insert(0, os.path.join(_BB, p))

EPS = 0.10
DELTA = 0.08          # headline provenance gap for the real-data settings (T2-7 / validation-stack)
TOL = 1e-6            # "on the boundary" tolerance
SEEDS = [0, 1, 2]


def _margins(recs, theta_base, pol, delta, eps):
    """Return per-record dict of the certificate-relevant quantities."""
    out = []
    for val, tool, x1 in recs:
        th_self = pol.threshold_for_tool(theta_base, tool, x1, delta)
        nbrs = pol.discrete_neighbors(tool)
        th_nbrs = [pol.threshold_for_tool(theta_base, t2, x1, delta) for t2 in nbrs]
        out.append({
            "value": float(val),
            "th_self": float(th_self),
            "g_self": float(val) - float(th_self),
            "g_nbr_min": min((float(val) - t for t in th_nbrs), default=float("nan")),
            "th_nbrs": th_nbrs,
        })
    return out


def _mass(vals, target, tol=TOL):
    arr = np.asarray(vals, dtype=float)
    arr = arr[~np.isnan(arr)]
    if arr.size == 0:
        return 0, 0
    return int(np.sum(np.abs(arr - target) <= tol)), int(arr.size)


def audit_dataset(name, loader, delta=DELTA, eps=EPS, max_rows=None):
    rows = []
    # aggregate the atom counts over seeds (one θ_base per seed for NAB; fixed for IEEE)
    agg = {}
    total_n = 0
    for seed in SEEDS:
        recs, theta_base, pol = loader(seed, max_rows=max_rows)
        m = _margins(recs, theta_base, pol, delta, eps)
        total_n += len(m)
        checks = {
            "clean_boundary (g_self=0)":            [(mm["g_self"], 0.0) for mm in m],
            "continuous_flip (g_self=-eps)":        [(mm["g_self"], -eps) for mm in m],
            "joint_neighbor_clean (g_nbr=0)":       [(mm["g_nbr_min"], 0.0) for mm in m],
            "joint_neighbor_flip (g_nbr=-eps)":     [(mm["g_nbr_min"], -eps) for mm in m],
            "value_clip_lo (value=0)":              [(mm["value"], 0.0) for mm in m],
            "value_clip_hi (value=1)":              [(mm["value"], 1.0) for mm in m],
            "theta_clip_lo (theta=0.05)":           [(mm["th_self"], 0.05) for mm in m],
            "theta_clip_hi (theta=0.95)":           [(mm["th_self"], 0.95) for mm in m],
        }
        for label, pairs in checks.items():
            vals = [v for v, _ in pairs]
            tgt = pairs[0][1]
            k, _ = _mass(vals, tgt)
            a = agg.setdefault(label, [0, 0])
            a[0] += k
            a[1] += len(vals)
    for label, (k, n) in agg.items():
        rows.append({
            "dataset": name, "boundary": label,
            "on_boundary_k": k, "N": n,
            "mass_fraction": round(k / n, 8) if n else float("nan"),
            "soundness_side": "blocked (unsafe-closed) — abstention only, never false-allow",
        })
    return rows, total_n


def main():
    all_rows = []
    notes = []
    try:
        import delta_sensitivity_c as DS
    except Exception as e:  # pragma: no cover
        print(f"cannot import loaders: {e}")
        return

    for name, loader in (("ieee_cis", DS.ieee_records), ("nab", DS.nab_records)):
        try:
            rows, n = audit_dataset(name, loader)
            all_rows.extend(rows)
            notes.append(f"{name}: {n} record-evaluations over {len(SEEDS)} seeds")
        except FileNotFoundError as e:
            notes.append(f"{name}: SKIPPED (data absent: {e})")
        except Exception as e:  # pragma: no cover
            notes.append(f"{name}: ERROR {e}")

    os.makedirs(OUT, exist_ok=True)
    csv_p = os.path.join(OUT, "prop3_boundary_mass.csv")
    with open(csv_p, "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=["dataset", "boundary", "on_boundary_k",
                                           "N", "mass_fraction", "soundness_side"])
        w.writeheader()
        w.writerows(all_rows)

    md_p = os.path.join(OUT, "prop3_boundary_mass.md")
    with open(md_p, "w") as fh:
        fh.write("# M5 — Prop. 3 boundary-mass check on real clipped/quantized marginals\n\n")
        fh.write("Empirical mass within 1e-6 of every certificate boundary of "
                 f"the signed margin g_t = value − θ_t, on the REAL IEEE-CIS and NAB natural gate "
                 f"pools (ε={EPS}, δ={DELTA}, {len(SEEDS)} seeds). Both oracles use CLOSED "
                 "inequalities (unsafe ⟺ m ≥ 0), so any boundary record is BLOCKED — positive mass "
                 "costs abstention, never a false-allow.\n\n")
        for nline in notes:
            fh.write(f"- {nline}\n")
        fh.write("\n| dataset | boundary | on-boundary k/N | mass fraction | soundness side |\n")
        fh.write("|---|---|---|---|---|\n")
        for r in all_rows:
            fh.write(f"| {r['dataset']} | {r['boundary']} | {r['on_boundary_k']}/{r['N']} | "
                     f"{r['mass_fraction']:.2e} | {r['soundness_side']} |\n")
        any_mass = [r for r in all_rows if r["on_boundary_k"] > 0]
        fh.write("\n**Verdict.** ")
        if any_mass:
            fh.write("Non-zero boundary mass detected: "
                     + "; ".join(f"{r['dataset']}/{r['boundary']} = {r['on_boundary_k']}/{r['N']}"
                                 for r in any_mass)
                     + ". Prop. 3's Pr[m=ε]=0 assumption does NOT hold exactly on these "
                     "quantized/clipped marginals → state the proposition with the conservative "
                     "closed inequality (unsafe ⟺ m ≥ 0). Soundness is unaffected because the "
                     "closed form already blocks these records; the only effect is a measured amount "
                     "of extra abstention.\n")
        else:
            fh.write("Zero boundary mass at 1e-6 on both real pools: Prop. 3's measure-zero "
                     "boundary assumption holds empirically here; no wording change required "
                     "(the closed inequality is kept for safety regardless).\n")
    print(f"wrote {csv_p}")
    print(f"wrote {md_p}")
    for r in all_rows:
        if r["on_boundary_k"] > 0:
            print(f"  MASS {r['dataset']}/{r['boundary']}: {r['on_boundary_k']}/{r['N']} "
                  f"({r['mass_fraction']:.2e})")
    for nline in notes:
        print(" ", nline)


if __name__ == "__main__":
    main()
