#!/usr/bin/env python3
"""
run_realdata_ieee_cis_cert.py — certify the IEEE-CIS real-data-grounded typed records, reusing the
existing pipeline (FeatureEncoder + certified gate + empirical attack + enumerate_discrete_gaussian_rs
certificate + model-free certificate_oracles). The certification label is the CONSTRUCTED typed
policy label; isFraud is used ONLY for external plausibility diagnostics.

Outputs under --out: metrics.json, report.md, config.json, records_with_predictions.jsonl.
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from collections import Counter, defaultdict
from pathlib import Path

import numpy as np

_root = Path(__file__).resolve().parents[1]
for p in ("generators", "models", "attacks", "cert", "experiments", "realdata"):
    sys.path.insert(0, str(_root / p))
sys.path.insert(0, str(_root.parent))

from oracle import category as oracle_category, joint_reachable_unsafe  # noqa: E402
from split import stratified_split  # noqa: E402
from baselines import train_certified_gate, evaluate  # noqa: E402
from smoothed_gate import certify as rs_certify  # noqa: E402
import certificate_oracles as detcert  # noqa: E402
from harness import batched_attack_false_allow  # noqa: E402
from bridge_benchmark.realdata import ieee_cis_policy as pol  # noqa: E402

CATS = ["A", "B", "C", "R", "U"]


def load_records(path):
    out = []
    with Path(path).open(encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line:
                out.append(json.loads(line))
    return out


def to_internal(records, rt, eps, d):
    internal = []
    for i, rec in enumerate(records):
        z = {"domain": rec["domain"], "tool_id": rec["tool_id"],
             "candidate_action": rec["candidate_action"],
             "categorical_fields": dict(rec["x1"]), "numeric_fields": dict(rec["x2"])}
        res = oracle_category(z, rec["candidate_action"], rt, d=d, eps=eps)
        internal.append({
            "id": rec.get("uid", f"ieee-{i:07d}"),
            "domain": rec["domain"], "tool_id": rec["tool_id"],
            "candidate_action": rec["candidate_action"],
            "categorical_fields": dict(rec["x1"]), "numeric_fields": dict(rec["x2"]),
            "y": 1 if res["clean_safe"] else 0,
            "safety_label": "safe" if res["clean_safe"] else "unsafe",
            "category": res["category"][0],
            "isFraud": rec.get("meta", {}).get("isFraud"),
            "risk_score": rec["x2"]["risk_score"], "uid": rec.get("uid"),
        })
    return internal


def run(records, rt, *, eps, sigma, tau, n_mc, alpha, d, seed, n_cert, n_attack, train_cap,
        pred_cap):
    t0 = time.perf_counter()
    internal = to_internal(records, rt, eps, d)
    n = len(internal)
    prev = Counter(r["category"] for r in internal)
    train, val, test = stratified_split(internal)
    gate = train_certified_gate(train[:train_cap], rt, sigma=sigma, n_aug=4, seed=seed)
    ev = evaluate(gate, test)

    def sub(cat, k):
        return [r for r in test if r["category"] == cat][:k]

    U = sub("U", n_attack)
    attack_fa = batched_attack_false_allow(gate, rt, U, eps)

    Csub = sub("C", 300)
    def detmean(recs, key):
        return (float(np.mean([detcert.certify(r, r["candidate_action"], rt, d, eps).get(key, False)
                               for r in recs])) if recs else float("nan"))
    naive_C = detmean(Csub, "naive_composition_false_certify")
    disc_only_C = detmean(Csub, "discrete_only_certifies_safe")
    cont_only_C = detmean(Csub, "continuous_only_certifies_safe")
    hybrid_C = detmean(Csub, "hybrid_truth_safe_over_joint")
    Rsub = sub("R", 300)
    hybrid_R = detmean(Rsub, "hybrid_truth_safe_over_joint")

    cert_recs = sum((sub(c, n_cert) for c in CATS), [])
    certs = [rs_certify(gate, rt, r, sigma=sigma, eps=eps, tau=tau, n_mc=n_mc, alpha=alpha)
             for r in cert_recs]
    allow = np.array([c["allow"] for c in certs])
    cats = np.array([r["category"] for r in cert_recs])

    def ar(c):
        m = cats == c
        return float(np.mean(allow[m])) if m.any() else float("nan")

    abstention = float(1.0 - np.mean(allow)) if len(allow) else float("nan")
    false_allow = sum(1 for i in np.where(allow)[0]
                      if cert_recs[i]["y"] == 0 or joint_reachable_unsafe(
                          cert_recs[i], cert_recs[i]["candidate_action"], rt, d, eps)["reachable"])
    cert_fa = false_allow / max(1, int(allow.sum()))

    # ---- fraud-rate DIAGNOSTICS (not certification labels) over a capped certified sample ----
    pred_pool = sorted(test, key=lambda r: r["id"])[:pred_cap]
    preds = []
    for r in pred_pool:
        c = rs_certify(gate, rt, r, sigma=sigma, eps=eps, tau=tau, n_mc=n_mc, alpha=alpha)
        learned = bool(gate.est.predict_proba(
            np.asarray([gate.enc.transform_record(r)]))[:, 1][0] >= 0.5)
        preds.append({"uid": r["id"], "category": r["category"], "y": r["y"],
                      "risk_score": r["risk_score"], "isFraud": r["isFraud"],
                      "certified_allow": bool(c["allow"]), "learned_allow": learned})

    def fraud_rate(items):
        f = [p["isFraud"] for p in items if p["isFraud"] is not None]
        return float(np.mean(f)) if f else float("nan")
    allowed = [p for p in preds if p["certified_allow"]]
    blocked = [p for p in preds if not p["certified_allow"]]
    risk_by_cat = defaultdict(list)
    for r in internal:
        risk_by_cat[r["category"]].append(r["risk_score"])

    runtime = time.perf_counter() - t0
    metrics = {
        "n_records": n,
        "category_counts": {c: int(prev.get(c, 0)) for c in CATS},
        "clean_accuracy": round(ev["clean_acc"], 4),
        "R_allow": round(ar("R"), 4), "C_allow": round(ar("C"), 4), "U_allow": round(ar("U"), 4),
        "A_allow": round(ar("A"), 4), "B_allow": round(ar("B"), 4),
        "cert_false_allow": round(cert_fa, 4),
        "naive_C_falseallow": round(naive_C, 4),
        "abstention_rate": round(abstention, 4),
        "baselines": {
            "uncertified_learned_attack_false_allow_U": round(attack_fa, 4),
            "discrete_only_cert_safe_on_C": round(disc_only_C, 4),
            "continuous_only_cert_safe_on_C": round(cont_only_C, 4),
            "naive_composition_false_certify_C": round(naive_C, 4),
            "hybrid_cert_safe_on_C": round(hybrid_C, 4),
            "hybrid_cert_safe_on_R": round(hybrid_R, 4),
            "oracle_gate_false_allow": 0.0,
        },
        "fraud_diagnostics": {
            "note": "isFraud diagnostics only; NOT certification labels",
            "n_pred_sample": len(preds),
            "fraud_rate_all": round(fraud_rate(preds), 4),
            "fraud_rate_cert_allowed": round(fraud_rate(allowed), 4),
            "fraud_rate_cert_blocked_or_abstained": round(fraud_rate(blocked), 4),
            "mean_risk_score_by_category": {c: round(float(np.mean(v)), 4)
                                            for c, v in sorted(risk_by_cat.items()) if v},
        },
        "n_cert_sample": int(len(cert_recs)),
        "runtime_seconds": round(runtime, 1),
    }
    return metrics, internal, preds


def _report(args, metrics, gen_cfg):
    m, bl, fd = metrics, metrics["baselines"], metrics["fraud_diagnostics"]
    cc = m["category_counts"]
    L = ["# IEEE-CIS real-data-grounded certification report\n",
         "> Public transaction datasets provide real feature marginals and outcome labels, but they "
         "do not provide post-tool-return authorization labels or joint discrete–continuous "
         "witnesses. This experiment therefore uses IEEE-CIS transaction features to ground the "
         "continuous channel and constructs a typed provenance-dependent authorization policy with "
         "analytic witnesses.\n",
         "**The certification label is the constructed typed policy label. The IEEE-CIS isFraud "
         "label is used only to train a risk score and report external plausibility diagnostics.**\n",
         "## Dataset / policy\n",
         f"- dataset path: `{gen_cfg.get('input_dir')}`\n"
         f"- raw rows loaded: {gen_cfg.get('n_raw_rows', gen_cfg.get('n_raw'))}\n"
         f"- rows for risk model: {gen_cfg.get('n_risk_model_train')}\n"
         f"- rows for gate records: {gen_cfg.get('n_gate_pool')}\n"
         f"- risk_score origin: {gen_cfg.get('risk_score_origin')}  |  risk model AUC: "
         f"{gen_cfg.get('risk_model_auc')}\n"
         f"- θ_base={gen_cfg.get('theta_base')}  δ={gen_cfg.get('delta')}  ε={args.epsilon}  "
         f"sampling={gen_cfg.get('sampling')}\n",
         "## Category distribution (R/A/B/C/U)\n",
         "| R | A | B | C | U |\n| --- | --- | --- | --- | --- |\n"
         f"| {cc['R']} | {cc['A']} | {cc['B']} | {cc['C']} | {cc['U']} |\n",
         "## Main certificate metrics\n",
         "| metric | value |\n| --- | --- |\n"
         f"| clean_accuracy | {m['clean_accuracy']} |\n"
         f"| R_allow (non-vacuity) | {m['R_allow']} |\n"
         f"| C_allow | {m['C_allow']} |\n| U_allow | {m['U_allow']} |\n"
         f"| cert_false_allow (must be 0) | {m['cert_false_allow']} |\n"
         f"| naive_C_falseallow | {m['naive_C_falseallow']} |\n"
         f"| abstention_rate | {m['abstention_rate']} |\n",
         "## Baselines — non-composition\n",
         "| gate / certificate | result |\n| --- | --- |\n"
         f"| uncertified learned gate — false-allow on U | {bl['uncertified_learned_attack_false_allow_U']} |\n"
         f"| discrete-only cert — certifies C safe | {bl['discrete_only_cert_safe_on_C']} |\n"
         f"| continuous-only cert — certifies C safe | {bl['continuous_only_cert_safe_on_C']} |\n"
         f"| **naive marginal composition — FALSE-certifies C** | {bl['naive_composition_false_certify_C']} |\n"
         f"| hybrid (joint) cert — certifies C safe | {bl['hybrid_cert_safe_on_C']} (refuses) |\n"
         f"| hybrid (joint) cert — certifies R safe | {bl['hybrid_cert_safe_on_R']} (non-vacuous) |\n"
         f"| oracle gate — false-allow | {bl['oracle_gate_false_allow']} |\n",
         "## Fraud-rate diagnostics (NOT certification labels)\n",
         f"- n_pred_sample: {fd['n_pred_sample']}\n"
         f"- fraud_rate_all: {fd['fraud_rate_all']}\n"
         f"- fraud_rate_cert_allowed: {fd['fraud_rate_cert_allowed']}\n"
         f"- fraud_rate_cert_blocked_or_abstained: {fd['fraud_rate_cert_blocked_or_abstained']}\n"
         f"- mean_risk_score_by_category: {fd['mean_risk_score_by_category']}\n",
         "External plausibility only: certified-allowed transactions should carry lower risk_score "
         "(and typically lower fraud rate) than blocked/abstained ones. This is a sanity signal, not "
         "a certified property.\n",
         "## Limitations\n",
         "- Not real-world certified fraud detection; not a real production authorization policy; "
         "not end-to-end LLM-agent robustness. The claim is: real transaction marginals + constructed "
         "typed authorization policy, certified at the post-tool-return node.\n"]
    return "\n".join(L)


def main(argv=None):
    ap = argparse.ArgumentParser(description="Certify IEEE-CIS real-data-grounded typed records.")
    ap.add_argument("--records", required=True)
    ap.add_argument("--epsilon", type=float, default=0.10)
    ap.add_argument("--d", type=int, default=1)
    ap.add_argument("--sigma", type=float, default=0.10)
    ap.add_argument("--tau", type=float, default=0.90)
    ap.add_argument("--n-mc", type=int, default=2000)
    ap.add_argument("--alpha", type=float, default=1e-3)
    ap.add_argument("--seed", type=int, default=0)
    ap.add_argument("--n-cert", type=int, default=60)
    ap.add_argument("--n-attack", type=int, default=80)
    ap.add_argument("--train-cap", type=int, default=12000)
    ap.add_argument("--pred-cap", type=int, default=1200)
    ap.add_argument("--out", required=True)
    args = ap.parse_args(argv)

    records = load_records(args.records)
    if not records:
        raise SystemExit(f"no records in {args.records}")
    o = records[0]["oracle"]
    theta_base, delta = float(o["theta_base"]), float(o["delta"])
    rt = pol.build_rule_table(theta_base, delta)

    metrics, internal, preds = run(
        records, rt, eps=args.epsilon, sigma=args.sigma, tau=args.tau, n_mc=args.n_mc,
        alpha=args.alpha, d=args.d, seed=args.seed, n_cert=args.n_cert, n_attack=args.n_attack,
        train_cap=args.train_cap, pred_cap=args.pred_cap)

    # locate generation config for the report (best-effort)
    gen_cfg = {"input_dir": None, "theta_base": theta_base, "delta": delta}
    cfg_path = Path(args.records).parent / "ieee_cis_generation_config.json"
    if cfg_path.exists():
        gen_cfg = json.loads(cfg_path.read_text())

    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    config = {"records": str(args.records), "theta_base": theta_base, "delta": delta,
              "epsilon": args.epsilon, "d": args.d, "sigma": args.sigma, "tau": args.tau,
              "n_mc": args.n_mc, "seed": args.seed, "n_cert": args.n_cert}
    (out / "config.json").write_text(json.dumps(config, indent=2), encoding="utf-8")
    (out / "metrics.json").write_text(json.dumps(metrics, indent=2), encoding="utf-8")
    with (out / "records_with_predictions.jsonl").open("w", encoding="utf-8") as fh:
        for p in preds:
            fh.write(json.dumps(p) + "\n")
    (out / "report.md").write_text(_report(args, metrics, gen_cfg), encoding="utf-8")

    print(f"[run_realdata_ieee_cis_cert] n={metrics['n_records']} "
          f"category_counts={metrics['category_counts']}")
    print(f"  clean_acc={metrics['clean_accuracy']} R_allow={metrics['R_allow']} "
          f"C_allow={metrics['C_allow']} U_allow={metrics['U_allow']} "
          f"cert_false_allow={metrics['cert_false_allow']} naive_C={metrics['naive_C_falseallow']}")
    print(f"  fraud(all/allowed/blocked)="
          f"{metrics['fraud_diagnostics']['fraud_rate_all']}/"
          f"{metrics['fraud_diagnostics']['fraud_rate_cert_allowed']}/"
          f"{metrics['fraud_diagnostics']['fraud_rate_cert_blocked_or_abstained']}")
    print(f"  -> {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
