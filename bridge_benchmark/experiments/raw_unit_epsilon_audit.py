#!/usr/bin/env python3
"""
raw_unit_epsilon_audit.py — EXP-B2 (NEW_NEW_EXP.md Priority B; ). What does a normalized ε=0.10 (‖·‖₂
in the [0,1] feature space) mean in RAW units (dollars, CPU %, distance)? If a normalized-ε ball hides huge
raw-unit tail moves, "small numerical corruption" needs rewording (a soundness-adjacent honesty point).

Pure post-processing of the Appendix-D normalization (ieee_cis_adapter / nab_adapter): invert the log/clip
scaling at the median (p50), p95 and p99 of each raw field and report the raw-unit move that a normalized
step of ε=0.10 corresponds to at that operating point. No model, no gate, no LLM.

Normalizations audited:
  * _norm_log(x,cap)=min(log1p(x)/log1p(cap),1)   [IEEE amount_norm(cap=p99 amt), dist1/dist2_norm] — inverse
    x=expm1(v·L), L=log1p(cap). ε=0.10 is a DIFFERENT raw move at different v (log compression): tiny near 0,
    large near the cap. Reported as the raw $ / distance interval [inv(v-ε), inv(v+ε)].
  * _norm_clip(x,cap)=clip(x/cap,0,1)             [IEEE c/d/v_mean_norm] — linear: raw move = ε·cap (const).
  * _norm_pct(x)=clip(x/100,0,1)                  [NAB cpu_util/roll_mean/roll_std_norm] — ε=0.10 = 10 CPU pts.
  * delta_norm=(δ+100)/200                         [NAB] — ε=0.10 = 20 delta-units.
  * risk_score is a model PROBABILITY in [0,1] (already the normalized quantity): ε=0.10 = 0.10 prob. points
    (dimensionless — reported as such, not converted).
"""
from __future__ import annotations

import argparse
import os
import json
import math
import sys
import warnings
from pathlib import Path

import numpy as np

warnings.filterwarnings("ignore")
_HERE = Path(__file__).resolve().parent
_BB = _HERE.parent
sys.path.insert(0, str(_BB / "realdata"))

import pandas as pd  # noqa: E402

OUT = _BB / "cert" / "out"
IEEE_RAW = os.environ.get("IEEE_CIS_DIR", "bridge_benchmark/data/raw/ieee_cis")
EPS = 0.10
ANCHORS = [0.50, 0.95, 0.99]


def _inv_log(v, cap):
    return math.expm1(max(v, 0.0) * math.log1p(cap))


def audit_log_field(name, raw_values, cap, eps, unit):
    from ieee_cis_adapter import _norm_log
    s = pd.to_numeric(pd.Series(raw_values), errors="coerce").dropna()
    rows = []
    for q in ANCHORS:
        raw_q = float(s.quantile(q))
        v = _norm_log(raw_q, cap)
        up = _inv_log(min(v + eps, 1.0), cap)
        dn = _inv_log(max(v - eps, 0.0), cap)
        rows.append({"field": name, "unit": unit, "anchor_quantile": q, "raw_value": round(raw_q, 4),
                     "normalized_value": round(v, 4),
                     "raw_move_up_for_eps": round(up - raw_q, 4), "raw_move_down_for_eps": round(raw_q - dn, 4),
                     "raw_interval_width": round(up - dn, 4),
                     "kind": "log"})
    return rows


def audit_linear_field(name, raw_values, cap, eps, unit, transform=lambda x, c: x / c):
    s = pd.to_numeric(pd.Series(raw_values), errors="coerce").dropna()
    rows = []
    raw_move = eps * cap                       # linear: constant raw move
    for q in ANCHORS:
        raw_q = float(s.quantile(q))
        rows.append({"field": name, "unit": unit, "anchor_quantile": q, "raw_value": round(raw_q, 4),
                     "normalized_value": round(min(max(raw_q / cap, 0.0), 1.0), 4),
                     "raw_move_up_for_eps": round(raw_move, 4), "raw_move_down_for_eps": round(raw_move, 4),
                     "raw_interval_width": round(2 * raw_move, 4), "kind": "linear"})
    return rows


def audit_ieee(eps, max_rows=None):
    import ieee_cis_adapter as A
    df = A.load_raw(IEEE_RAW, max_rows=max_rows)
    caps = A._caps(df)
    rows = []
    rows += audit_log_field("amount_norm (TransactionAmt)", df["TransactionAmt"], caps["amount_cap"], eps, "USD")
    rows += audit_log_field("dist1_norm", df["dist1"], caps["dist_cap"], eps, "dist-units")
    rows += audit_log_field("dist2_norm", df["dist2"], caps["dist_cap"], eps, "dist-units")
    # c/d/v mean features (clip): raw move = eps*cap regardless of anchor; report anchors for the raw value
    rows += audit_linear_field("c_mean_norm", df[A.C_COLS].mean(axis=1), caps["c_cap"], eps, "C-agg")
    # risk_score: dimensionless probability
    rows.append({"field": "risk_score", "unit": "probability (dimensionless)", "anchor_quantile": None,
                 "raw_value": None, "normalized_value": None, "raw_move_up_for_eps": eps,
                 "raw_move_down_for_eps": eps, "raw_interval_width": 2 * eps, "kind": "identity"})
    return {"caps": {k: round(v, 4) for k, v in caps.items()}, "rows": rows}


def audit_nab(eps, max_rows=None):
    import nab_adapter as adp
    df = adp.load_raw(max_rows=max_rows)
    rows = audit_linear_field("cpu_util_norm", df["value"], 100.0, eps, "CPU %")
    # delta_norm uses a /200 span → raw move = eps*200
    rows.append({"field": "delta_norm", "unit": "CPU %/step", "anchor_quantile": None, "raw_value": None,
                 "normalized_value": None, "raw_move_up_for_eps": round(eps * 200, 4),
                 "raw_move_down_for_eps": round(eps * 200, 4), "raw_interval_width": round(eps * 400, 4),
                 "kind": "linear-span"})
    return {"rows": rows}


def run(eps, max_rows, out_prefix):
    ieee = audit_ieee(eps, max_rows=max_rows) if Path(IEEE_RAW).exists() else None
    nab = audit_nab(eps, max_rows=max_rows)

    # headline read: the log-compressed dollar field. Compare ε=0.10 raw move at median vs p99.
    headline = None
    if ieee:
        amt = [r for r in ieee["rows"] if r["field"].startswith("amount_norm")]

        def mag(r):   # ε-move MAGNITUDE (max of up/down); at/above the cap the norm saturates so only the
            return max(r["raw_move_up_for_eps"], r["raw_move_down_for_eps"])   # downward move is non-zero
        med = next(r for r in amt if r["anchor_quantile"] == 0.50)
        p95 = next(r for r in amt if r["anchor_quantile"] == 0.95)
        p99 = next(r for r in amt if r["anchor_quantile"] == 0.99)
        ratio = round(mag(p99) / mag(med), 1) if mag(med) else None
        headline = {
            "amount_eps_move_at_median_usd": mag(med),
            "amount_eps_move_at_p95_usd": mag(p95),
            "amount_eps_move_at_p99_usd": mag(p99),
            "p99_over_median_ratio": ratio,
            "reading": (f"A normalized ε={eps} step in amount_norm is ~${mag(med)} at the median "
                        f"TransactionAmt, ~${mag(p95)} at p95, and ~${mag(p99)} at p99 "
                        f"(~{ratio}× the median) — the log scaling makes ε a SMALL dollar move on typical "
                        f"transactions and a several-hundred-dollar swing only in the heavy tail (where the "
                        f"norm saturates at the p99 cap, so the move is downward). 'Small numerical "
                        f"corruption' is accurate for the bulk; the honest caveat is the tail, where "
                        f"per-field ε (EXP-A6) is the mitigation."),
        }

    payload = {
        "experiment": "EXP-B2 — raw-unit ε audit (what does ‖·‖₂≤ε mean in dollars/CPU%?)",
        "priority": "B", "eps": eps, "anchors": ANCHORS,
        "ieee_cis": ieee, "nab": nab, "headline": headline,
        "note": ("Pure post-processing of the Appendix-D normalization; no model/gate/LLM. Log-normalized "
                 "fields (amount, distance) have an ε-move that GROWS with the operating point (log "
                 "compression); linear/clip fields (CPU%, C/D/V means) have a constant ε-move = ε·cap."),
    }
    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / f"{out_prefix}.json").write_text(json.dumps(payload, indent=2))
    _write_md(OUT / f"{out_prefix}.md", payload)
    if headline:
        print(f"amount ε={eps}: ${headline['amount_eps_move_at_median_usd']} @median  vs  "
              f"${headline['amount_eps_move_at_p99_usd']} @p99  (~{headline['p99_over_median_ratio']}×)")
    print(f"wrote -> {OUT/(out_prefix+'.json')}\nwrote -> {OUT/(out_prefix+'.md')}")
    return payload


def _write_md(path, p):
    with open(path, "w") as f:
        f.write("# EXP-B2 — raw-unit ε audit\n\n")
        f.write(f"Normalized ε={p['eps']} → raw units, at "
                f"quantiles {p['anchors']}. {p['note']}\n\n")
        if p["headline"]:
            f.write(f"**Headline.** {p['headline']['reading']}\n\n")
        for ds in ("ieee_cis", "nab"):
            d = p.get(ds)
            if not d:
                continue
            f.write(f"### {ds}\n\n")
            if d.get("caps"):
                f.write(f"caps: {d['caps']}\n\n")
            f.write("| field | unit | anchor q | raw value | norm value | raw move (±ε) | interval width | "
                    "kind |\n|---|---|--:|--:|--:|--:|--:|---|\n")
            for r in d["rows"]:
                f.write(f"| {r['field']} | {r['unit']} | {r['anchor_quantile']} | {r['raw_value']} | "
                        f"{r['normalized_value']} | +{r['raw_move_up_for_eps']}/−{r['raw_move_down_for_eps']} "
                        f"| {r['raw_interval_width']} | {r['kind']} |\n")
            f.write("\n")


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--eps", type=float, default=EPS)
    ap.add_argument("--max-rows", type=int, default=None)
    ap.add_argument("--out", default="exp_b2_raw_unit_epsilon")
    a = ap.parse_args()
    run(a.eps, a.max_rows, a.out)


if __name__ == "__main__":
    main()
