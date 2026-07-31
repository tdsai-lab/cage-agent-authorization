#!/usr/bin/env python3
"""
realdata_ieee_cis.py — generate IEEE-CIS real-data-grounded typed authorization records.

Pipeline: load CSVs -> features (x1, x2) -> held-out risk model -> theta_base from gate_pool risk
quantile -> constructed provenance policy -> per-row analytic category + witness -> sampling.

The continuous channel (risk_score + real marginals) is grounded in the dataset; the authorization
policy (provenance tools, thresholds, Safe) is CONSTRUCTED. isFraud is never an authorization label.

CLI:
  python -m bridge_benchmark.experiments.realdata_ieee_cis \
    --input-dir bridge_benchmark/data/raw/ieee_cis \
    --out bridge_benchmark/data/realdata/ieee_cis_records.jsonl \
    --sampling boundary_balanced --n-records 10000 \
    --theta-quantile 0.70 --delta 0.08 --epsilon 0.10 --seed 0
"""
from __future__ import annotations

import argparse
import json
import sys
from collections import Counter, defaultdict
from pathlib import Path

import numpy as np

_root = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_root / "realdata"))
sys.path.insert(0, str(_root.parent))

from bridge_benchmark.realdata import ieee_cis_adapter as adp  # noqa: E402
from bridge_benchmark.realdata import ieee_cis_policy as pol  # noqa: E402

SAMPLING_MODES = ("natural", "boundary_balanced", "c_targeted")


def _assign_base_tool(transaction_id: int, seed: int) -> str:
    u = adp._stable_unit(transaction_id, seed * 7 + 3)
    return pol.TOOLS[int(u * len(pol.TOOLS)) % len(pol.TOOLS)]


def build_candidates(df_gate, risk, edges, caps, *, theta_base, delta, eps, seed, sampling):
    """One candidate record per gate_pool row (analytic category for its provenance tool)."""
    lo, hi = pol.c_interval(theta_base, delta, eps)        # x1-independent in v1
    cands = []
    for (_, row), r in zip(df_gate.iterrows(), risk):
        tid = int(row["TransactionID"])
        x1 = adp.build_x1(row, edges)
        x2 = adp.build_x2(row, float(r), caps)
        rs = x2["risk_score"]
        tool = _assign_base_tool(tid, seed)
        # c_targeted manufactures witnesses: a row whose risk sits in the analytic C-interval is
        # assigned a LOOSE provenance so the strict-swap joint witness exists (constructed policy).
        if sampling == "c_targeted" and (lo < rs <= hi):
            tool = pol.LOOSE_TOOLS[int(adp._stable_unit(tid, seed) * len(pol.LOOSE_TOOLS))]
        res = pol.analytic_category(rs, tool, x1, theta_base, delta, eps)
        thr = pol.threshold_for_tool(theta_base, tool, x1, delta)
        rec = {
            "uid": f"{adp.SOURCE}:{tid}:{tool}:{pol.ACTION}",
            "source": adp.SOURCE, "domain": pol.DOMAIN, "tool_id": tool,
            "candidate_action": pol.ACTION, "x1": x1, "x2": x2,
            "label": 1 if res["clean_safe"] else 0, "category": res["category"],
            "oracle": {"type": "constructed_provenance_threshold_policy",
                       "theta_base": round(float(theta_base), 6), "delta": round(float(delta), 6),
                       "epsilon": round(float(eps), 6), "threshold_for_tool": round(float(thr), 6)},
            "witness": res["witness"],
            "meta": {"TransactionID": tid,
                     "isFraud": int(row["isFraud"]) if np.isfinite(row.get("isFraud", np.nan)) else None,
                     "split": "gate_pool", "real_label_used_for_policy": False},
        }
        cands.append(rec)
    return cands


def _select(cands, sampling, n_records, *, min_c, rng):
    by_cat = defaultdict(list)
    for c in cands:
        by_cat[c["category"]].append(c)
    for v in by_cat.values():
        v.sort(key=lambda r: r["meta"]["TransactionID"])

    if sampling == "natural":
        chosen = sorted(cands, key=lambda r: r["meta"]["TransactionID"])[:n_records]
        return chosen, {"warning": None}

    cats = [c for c in ("R", "B", "C", "A", "U") if by_cat.get(c)]
    warning = None
    if sampling == "c_targeted":
        n_c = len(by_cat.get("C", []))
        if n_c < min_c:
            warning = f"c_targeted: only {n_c} C records available (< --min-c-records {min_c})"
        # C-heavy but capped at 60% so a balanced filler set (safe+unsafe) keeps the gate trainable
        c_cap = max(min_c, int(round(0.60 * n_records)))
        chosen = list(by_cat.get("C", []))[:min(c_cap, n_records)]
        # fill remainder with a balanced mix so the gate is still trainable (needs safe+unsafe)
        rest_quota = max(0, n_records - len(chosen))
        fillers = [c for c in ("U", "R", "B", "A") if by_cat.get(c)]
        i = 0
        pools = {c: list(by_cat[c]) for c in fillers}
        while rest_quota > 0 and any(pools.values()):
            c = fillers[i % len(fillers)]
            if pools[c]:
                chosen.append(pools[c].pop(0)); rest_quota -= 1
            i += 1
        return chosen, {"warning": warning, "c_count": n_c}

    # boundary_balanced: round-robin equal quota across present categories
    chosen, i = [], 0
    pools = {c: list(by_cat[c]) for c in cats}
    while len(chosen) < n_records and any(pools.values()):
        c = cats[i % len(cats)]
        if pools[c]:
            chosen.append(pools[c].pop(0))
        i += 1
    return chosen, {"warning": warning}


def generate(args):
    df = adp.load_raw(args.input_dir, max_rows=args.max_rows)
    n_raw = len(df)
    split = adp.assign_split(df, args.seed)
    df_train = df[split == "risk_model_train"]
    df_gate = df[split == "gate_pool"]
    edges = adp._amount_band_edges(
        __import__("pandas").to_numeric(df_train["TransactionAmt"], errors="coerce")
        if len(df_train) else __import__("pandas").to_numeric(df["TransactionAmt"], errors="coerce"))
    caps = adp._caps(df_train if len(df_train) else df)

    # risk model
    risk_origin = "fixture_deterministic"
    pipe, auc = None, None
    if args.risk_mode in ("model", "auto") and len(df_train) >= 40:
        pipe, _ = adp.train_risk_model(df_train, edges, seed=args.seed,
                                       max_rows=args.max_risk_train_rows)
        if pipe is not None:
            risk_origin = "heldout_logistic_model"
            auc = adp.heldout_auc(pipe, df_gate, edges)
    risk = adp.predict_risk(pipe, df_gate, edges) if pipe is not None \
        else adp.fixture_deterministic_risk(df_gate)

    theta_base = float(np.quantile(risk, args.theta_quantile)) if len(risk) else 0.5
    theta_base = min(0.95, max(0.05, theta_base))

    cands = build_candidates(df_gate, risk, edges, caps, theta_base=theta_base, delta=args.delta,
                             eps=args.epsilon, seed=args.seed, sampling=args.sampling)
    for c in cands:
        c["meta"]["risk_score_origin"] = risk_origin
    rng = np.random.default_rng(args.seed)
    chosen, info = _select(cands, args.sampling, args.n_records, min_c=args.min_c_records, rng=rng)

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("w", encoding="utf-8") as fh:
        for r in chosen:
            fh.write(json.dumps(r) + "\n")

    cat_counts = Counter(r["category"] for r in chosen)
    config = {"source": adp.SOURCE, "input_dir": str(args.input_dir), "sampling": args.sampling,
              "n_raw_rows": n_raw, "n_risk_model_train": int(len(df_train)),
              "n_gate_pool": int(len(df_gate)), "n_records": len(chosen),
              "theta_quantile": args.theta_quantile, "theta_base": round(theta_base, 6),
              "delta": args.delta, "epsilon": args.epsilon, "seed": args.seed,
              "risk_score_origin": risk_origin, "risk_model_auc": auc,
              "min_c_records": args.min_c_records, "warning": info.get("warning")}
    cfg_path = out.parent / "ieee_cis_generation_config.json"
    cfg_path.write_text(json.dumps(config, indent=2), encoding="utf-8")
    _write_gen_report(out.parent / "ieee_cis_generation_report.md", config, cat_counts, chosen)

    print(f"[realdata_ieee_cis] sampling={args.sampling} raw={n_raw} gate_pool={len(df_gate)} "
          f"-> {len(chosen)} records  theta_base={theta_base:.4f} risk={risk_origin} auc={auc}")
    print(f"  category_counts: {dict(cat_counts)}")
    if info.get("warning"):
        print(f"  WARNING: {info['warning']}")
    print(f"  -> {out}")
    return 0


def _write_gen_report(path, config, cat_counts, chosen):
    n = max(1, len(chosen))
    fraud_all = np.mean([1 for r in chosen if r["meta"].get("isFraud")]) if chosen else float("nan")
    L = ["# IEEE-CIS real-data-grounded generation report\n",
         "> Public transaction datasets provide real feature marginals and outcome labels, but they "
         "do not provide post-tool-return authorization labels or joint discrete–continuous "
         "witnesses. This experiment therefore uses IEEE-CIS transaction features to ground the "
         "continuous channel and constructs a typed provenance-dependent authorization policy with "
         "analytic witnesses.\n",
         "## Configuration\n", "```json\n" + json.dumps(config, indent=2) + "\n```\n",
         "## Category distribution (R/A/B/C/U)\n",
         "| R | A | B | C | U |\n| --- | --- | --- | --- | --- |\n"
         f"| {cat_counts.get('R',0)} | {cat_counts.get('A',0)} | {cat_counts.get('B',0)} | "
         f"{cat_counts.get('C',0)} | {cat_counts.get('U',0)} |\n",
         "Category C = joint-only failure: discrete-only safe AND continuous-only safe, but a single "
         "provenance swap PLUS an ≤ε risk move is unsafe. Each C record stores a joint witness.\n",
         "## What is real vs constructed\n",
         "- **real**: transaction feature marginals (amount, dist, C/D/V aggregates) and `isFraud` "
         "(used ONLY to train the risk model + as a diagnostic).\n"
         "- **constructed**: provenance tools, authorization thresholds θ_t(x1), and Safe(z,a).\n"
         "- **risk_score origin**: " + str(config["risk_score_origin"]) + ".\n",
         f"\nDiagnostic only: fraud rate among selected records ≈ {fraud_all:.3f} "
         "(NOT a certification label).\n",
         "## Limitations\n",
         "- Not real-world certified fraud detection; not a real production authorization policy; "
         "not end-to-end LLM-agent robustness.\n"
         "- The correct claim is: real transaction marginals + constructed typed authorization "
         "policy.\n"]
    Path(path).write_text("\n".join(L), encoding="utf-8")


def main(argv=None):
    ap = argparse.ArgumentParser(description="Generate IEEE-CIS real-data-grounded typed records.")
    ap.add_argument("--input-dir", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--sampling", default="boundary_balanced", choices=SAMPLING_MODES)
    ap.add_argument("--n-records", type=int, default=10000)
    ap.add_argument("--theta-quantile", type=float, default=0.70)
    ap.add_argument("--delta", type=float, default=0.08)
    ap.add_argument("--epsilon", type=float, default=0.10)
    ap.add_argument("--seed", type=int, default=0)
    ap.add_argument("--min-c-records", type=int, default=50)
    ap.add_argument("--max-rows", type=int, default=None, help="cap raw rows loaded (memory)")
    ap.add_argument("--max-risk-train-rows", type=int, default=100000)
    ap.add_argument("--risk-mode", default="auto", choices=["auto", "model", "fixture_deterministic"])
    args = ap.parse_args(argv)
    return generate(args)


if __name__ == "__main__":
    raise SystemExit(main())
