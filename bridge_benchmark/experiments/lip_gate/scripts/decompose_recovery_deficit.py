#!/usr/bin/env python3
"""
decompose_recovery_deficit.py — Table L2. Splits the exact-recovery deficit into finite-MC tax,
smoothing-transition tax, and learned-margin deficiency, using SMOOTHING and DETERMINISTIC certificates
on the SAME LipGate (the only clean decomposition). MLP smoothing is reported as cross-model context,
NOT folded into the tax split.

Reads results/tables/_raw_recovery.json (written by compare_smoothing_vs_lip.py).
"""
from __future__ import annotations

import csv
import json
from pathlib import Path

_EXP = Path(__file__).resolve().parent.parent
TAB = _EXP / "results" / "tables"
RAW = TAB / "_raw_recovery.json"


def main():
    raw = json.loads(RAW.read_text())
    rows = []
    for key, rec in raw.items():
        domain, eps = key.split("|")

        def g(name):
            v = rec.get(name)
            return float(v) if isinstance(v, (int, float)) else (float(v) if v not in (None, "", "nan") else float("nan"))
        lip_det = g("lipgate_deterministic|0")
        lip_lowM = g("lipgate_smoothing|2000")
        lip_highM = g("lipgate_smoothing|10000")
        mlp_lowM = g("mlp_smoothing|2000")
        finite_mc_tax = lip_highM - lip_lowM
        transition_tax = lip_det - lip_highM
        margin_def = 1.0 - lip_det
        det_gain_lowM = lip_det - lip_lowM
        # validity: same-model terms should be ≥ -tol (negative => model mismatch / noise)
        tol = 0.02
        valid = all(x >= -tol for x in (finite_mc_tax, transition_tax, margin_def, det_gain_lowM)
                    if x == x)
        rows.append({"domain": domain, "epsilon": eps, "exact_recovery": 1.0,
                     "smooth_lowM_lipgate": round(lip_lowM, 4), "smooth_highM_lipgate": round(lip_highM, 4),
                     "lip_deterministic": round(lip_det, 4),
                     "finite_mc_tax": round(finite_mc_tax, 4),
                     "smoothing_transition_tax": round(transition_tax, 4),
                     "learned_margin_deficiency": round(margin_def, 4),
                     "deterministic_gain_over_lowM": round(det_gain_lowM, 4),
                     "mlp_smoothing_lowM_context": round(mlp_lowM, 4),
                     "decomposition_valid": valid})
    rows.sort(key=lambda r: (r["domain"], float(r["epsilon"])))
    cols = ["domain", "epsilon", "exact_recovery", "smooth_lowM_lipgate", "smooth_highM_lipgate",
            "lip_deterministic", "finite_mc_tax", "smoothing_transition_tax",
            "learned_margin_deficiency", "deterministic_gain_over_lowM", "mlp_smoothing_lowM_context",
            "decomposition_valid"]
    with open(TAB / "L2_recovery_decomposition.csv", "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=cols); w.writeheader(); w.writerows(rows)
    for r in rows:
        print(f"  {r['domain']} eps={r['epsilon']} | lip_det={r['lip_deterministic']} "
              f"mc_tax={r['finite_mc_tax']} trans_tax={r['smoothing_transition_tax']} "
              f"margin_def={r['learned_margin_deficiency']} det_gain={r['deterministic_gain_over_lowM']} "
              f"(valid={r['decomposition_valid']})")
    print(f"\nwrote -> {TAB/'L2_recovery_decomposition.csv'}")


if __name__ == "__main__":
    main()
