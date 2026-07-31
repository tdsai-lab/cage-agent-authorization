#!/usr/bin/env python3
"""
generate.py — ToolDecisionBench record generator (analytic-oracle labelled).

Builds records ONLY after the witness-explicit oracle is in place (PLAN2 ordering). It deterministically
sweeps the numeric grid for each (domain, tool, candidate_action, categorical_context), calls the
analytic oracle ``category(z, a, d=1, eps)``, and accepts each point with its exact label. Every C
record carries the auditable ``joint_gap_witness`` (safe before the continuous move, unsafe after).

Determinism: no RNG (Date.now/Math.random are unavailable in this environment and would break
reproducibility). Numeric grids are fixed; ``--per-category`` caps how many of each category to keep.

Output: JSONL to ``bridge_benchmark/data/<domain>.jsonl`` (and a combined ``all.jsonl``), each line:

    {
      "id", "domain", "tool_id", "candidate_action",
      "categorical_fields", "numeric_fields",
      "safety_label",            # Safe(z, a) from the oracle
      "category",                # A/B/C/D/R
      "is_multivariate_joint",
      "d", "epsilon",
      "cont_margin",
      "joint_gap_witness"        # only for category C
    }
"""
from __future__ import annotations

import argparse
import json
from collections import Counter
from pathlib import Path

from oracle import load_rule_table, category, safe, _x1

EPS_DEFAULT = 0.10
DATA_DIR = Path(__file__).resolve().parents[1] / "data"


def _frange(lo: float, hi: float, step: float):
    n = int(round((hi - lo) / step))
    return [round(lo + i * step, 4) for i in range(n + 1)]


def _categorical_grid(domain_cfg: dict) -> list[dict]:
    """Small fixed set of categorical contexts (first value of each field, plus a couple variants)."""
    cats = domain_cfg["categorical_fields"]
    base = {f: vals[0] for f, vals in cats.items()}
    grid = [dict(base)]
    # add one variant per field (second value) to exercise x_1 dependence
    for f, vals in cats.items():
        if len(vals) > 1:
            v = dict(base)
            v[f] = vals[1]
            grid.append(v)
    return grid


def _numeric_grid(domain: str) -> list[dict]:
    if domain == "financial_compliance":
        return [{"risk_score": r, "amount_norm": 0.2} for r in _frange(0.0, 1.0, 0.01)]
    if domain == "system_monitoring":
        # 2-D grid (coarse) so affine boundaries and joint gaps are exercised
        out = []
        for er in _frange(0.0, 1.0, 0.05):
            for lat in _frange(0.0, 1.0, 0.05):
                out.append({"error_rate": er, "latency_norm": lat})
        return out
    raise ValueError(domain)


def generate_domain(domain: str, rule_table: dict, eps: float, per_category: int) -> list[dict]:
    dc = rule_table["domains"][domain]
    kept: list[dict] = []
    caps: Counter = Counter()
    rid = 0
    for action in dc["candidate_actions"]:
        for ctx in _categorical_grid(dc):
            for tool in dc["tools"]:
                if not any(r["tool_id"] == tool and r["candidate_action"] == action for r in dc["rules"]):
                    continue
                for num in _numeric_grid(domain):
                    z = {"domain": domain, "tool_id": tool, "candidate_action": action,
                         "categorical_fields": dict(ctx), "numeric_fields": dict(num)}
                    res = category(z, action, rule_table, d=1, eps=eps)
                    cat = res["category"]
                    key = (action, tool, cat)
                    if caps[key] >= per_category:
                        continue
                    caps[key] += 1
                    rid += 1
                    rec = {
                        "id": f"{domain[:3]}-{rid:06d}",
                        "domain": domain,
                        "tool_id": tool,
                        "candidate_action": action,
                        "categorical_fields": dict(ctx),
                        "numeric_fields": dict(num),
                        "safety_label": "safe" if res["clean_safe"] else "unsafe",
                        "category": cat,
                        "is_multivariate_joint": res["is_multivariate_joint"],
                        "d": 1,
                        "epsilon": eps,
                        "cont_margin": res["cont_margin"],
                    }
                    if cat == "C_joint_gap":
                        rec["joint_gap_witness"] = res["joint_gap_witness"]
                    kept.append(rec)
    return kept


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--domains", nargs="*", default=["financial_compliance", "system_monitoring"])
    ap.add_argument("--eps", type=float, default=EPS_DEFAULT)
    ap.add_argument("--per-category", type=int, default=40,
                    help="max records kept per (action, tool, category)")
    ap.add_argument("--out-dir", default=str(DATA_DIR))
    args = ap.parse_args()

    rt = load_rule_table()
    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    combined: list[dict] = []
    summary: dict[str, Counter] = {}
    for domain in args.domains:
        recs = generate_domain(domain, rt, args.eps, args.per_category)
        (out_dir / f"{domain}.jsonl").write_text(
            "\n".join(json.dumps(r) for r in recs) + "\n", encoding="utf-8")
        combined.extend(recs)
        summary[domain] = Counter(r["category"] for r in recs)

    (out_dir / "all.jsonl").write_text(
        "\n".join(json.dumps(r) for r in combined) + "\n", encoding="utf-8")

    # Audit: re-verify every C witness invariant on the written data.
    bad = 0
    for r in combined:
        if r["category"] == "C_joint_gap":
            w = r["joint_gap_witness"]
            if not (w["pre_continuous_margin"] < 0 <= w["post_continuous_margin"]):
                bad += 1
    print(f"Wrote {len(combined)} records to {out_dir}")
    for domain, c in summary.items():
        print(f"  {domain}: " + ", ".join(f"{k.split('_')[0]}={v}" for k, v in sorted(c.items())))
    print(f"C-witness invariant violations: {bad} (must be 0)")
    if bad:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
