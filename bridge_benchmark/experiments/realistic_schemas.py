#!/usr/bin/env python3
"""
realistic_schemas.py — semi-realistic typed-tool schemas (real-looking tool names, categorical
contexts, and numeric fields; SYNTHETIC values and oracle policies). Makes the benchmark read like
actual tool returns rather than a toy. Same pipeline, same certificate (enumerate_discrete_gaussian_rs).

Domains (each: real-looking tools sharing an action with spread thresholds -> C; an affine composite
tool -> D; one robust-interior region -> R):
  finance/compliance : credit_check, sanctions_screen, transaction_monitor, kyc_profile, market_exposure
  sre/monitoring     : latency_metrics, error_budget, traffic_anomaly, saturation_monitor, deploy_status
  ops/security       : ip_reputation, device_risk, login_anomaly, access_policy

Honesty: tool names and field names are realistic; thresholds/weights are synthetic_stress_test grade
(see notes/rule_provenance.md). No real API data.

Writes out/realistic_schema_results.csv and .md, plus a few example records to out/realistic_examples.jsonl.
"""
from __future__ import annotations

import argparse
import csv
import json
import sys
import warnings
from pathlib import Path

warnings.filterwarnings("ignore")
sys.path.insert(0, str(Path(__file__).resolve().parent))
from synthetic_tools import sample_records, DOMAIN  # noqa: E402
from harness import run_setting, to_md, SCALING_COLS  # noqa: E402

OUT = Path(__file__).resolve().parents[1] / "cert" / "out"


def _scalar(tool, action, field, theta, off):
    return {"domain": DOMAIN, "tool_id": tool, "candidate_action": action, "categorical_context": {},
            "rule_family": "scalar_threshold", "numeric_field": field, "unsafe_direction": ">=",
            "threshold": theta, "threshold_offsets": off}


def _affine(tool, action, fields, weights, bias):
    return {"domain": DOMAIN, "tool_id": tool, "candidate_action": action, "categorical_context": {},
            "rule_family": "affine", "numeric_fields": fields, "weights": weights, "bias": bias}


def finance_schema():
    nf = ["risk_score", "match_confidence", "transaction_amount_norm", "exposure"]
    cats = {"entity_type": ["individual", "company", "trust"],
            "jurisdiction": ["low_risk", "medium_risk", "high_risk"]}
    j_off = {"jurisdiction": {"high_risk": -0.08, "medium_risk": -0.03}}
    a = "approve_transaction"
    rules = [
        _scalar("credit_check", a, "risk_score", 0.88, j_off),
        _scalar("sanctions_screen", a, "risk_score", 0.55, j_off),     # lower theta -> C with credit
        _scalar("transaction_monitor", a, "risk_score", 0.70, {}),
        _scalar("kyc_profile", a, "risk_score", 0.80, j_off),
        # market_exposure: affine composite (amount x exposure x match) -> D. Bias placed so the
        # center is robustly safe (fires only for high composites), preserving an R interior.
        _affine("market_exposure", a, nf, [0.2, 0.3, 0.8, 0.9], -1.65),
    ]
    return _wrap("finance_compliance", ["credit_check", "sanctions_screen", "transaction_monitor",
                                        "kyc_profile", "market_exposure"], nf, cats, [a], rules)


def monitoring_schema():
    nf = ["latency_p99_norm", "error_rate", "traffic_norm", "saturation"]
    cats = {"service_tier": ["batch", "standard", "production"],
            "region": ["us", "eu", "apac"]}
    t_off = {"service_tier": {"production": -0.10, "standard": -0.04}}
    a = "suppress_alert"
    rules = [
        _scalar("latency_metrics", a, "latency_p99_norm", 0.85, t_off),
        _scalar("error_budget", a, "error_rate", 0.55, t_off),
        _scalar("traffic_anomaly", a, "traffic_norm", 0.80, {}),
        _scalar("saturation_monitor", a, "saturation", 0.75, t_off),
        _affine("deploy_status", a, nf, [0.9, 0.9, -0.2, 0.6], -1.65),   # golden-signals composite -> D
    ]
    return _wrap("sre_monitoring", ["latency_metrics", "error_budget", "traffic_anomaly",
                                    "saturation_monitor", "deploy_status"], nf, cats, [a], rules)


def ops_security_schema():
    nf = ["ip_risk", "device_risk", "anomaly_score", "session_age_norm"]
    cats = {"account_type": ["user", "admin", "service"], "mfa": ["yes", "no"]}
    m_off = {"mfa": {"no": -0.10}}
    a = "allow_login"
    rules = [
        _scalar("ip_reputation", a, "ip_risk", 0.80, m_off),
        _scalar("device_risk", a, "device_risk", 0.55, m_off),          # lower theta -> C
        _scalar("login_anomaly", a, "anomaly_score", 0.75, m_off),
        _affine("access_policy", a, nf, [0.6, 0.6, 0.7, -0.3], -1.35),  # composite -> D
    ]
    return _wrap("ops_security", ["ip_reputation", "device_risk", "login_anomaly", "access_policy"],
                 nf, cats, [a], rules)


def _wrap(name, tools, nf, cats, actions, rules):
    dc = {"tools": tools, "numeric_fields": nf, "categorical_fields": cats,
          "candidate_actions": actions, "rules": rules,
          "_tool_action": {r["tool_id"]: r["candidate_action"] for r in rules},
          "_action_field": {actions[0]: rules[0]["numeric_field"]}}
    rt = {"meta": {"synthetic": True, "schema": name, "K": len(tools), "k": len(nf),
                   "x1_size": max(len(v) for v in cats.values())},
          "mvp": {"discrete_budget_mvp": 1}, "domains": {DOMAIN: dc}}
    return name, rt


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--n", type=int, default=50000, help="records per domain (min big experiment: 50k)")
    ap.add_argument("--sigma", type=float, default=0.10)
    ap.add_argument("--tau", type=float, default=0.90)
    ap.add_argument("--eps", type=float, default=0.10)
    ap.add_argument("--n-mc", type=int, default=2000)
    ap.add_argument("--n-cert", type=int, default=50)
    ap.add_argument("--n-attack", type=int, default=80)
    ap.add_argument("--seed", type=int, default=1)
    args = ap.parse_args()

    OUT.mkdir(parents=True, exist_ok=True)
    rows = []
    examples = []
    for name, rt in (finance_schema(), monitoring_schema(), ops_security_schema()):
        recs = sample_records(rt, args.n, eps=args.eps, seed=args.seed)
        examples += recs[:2]
        row = run_setting(rt, recs, eps=args.eps, sigma=args.sigma, tau=args.tau, n_mc=args.n_mc,
                          n_cert=args.n_cert, n_attack=args.n_attack, n_aug=6,
                          train_cap=16000, seed=args.seed, label=name)
        row["label"] = name
        rows.append(row)
        print(f"{name:18s} n={row['n_records']:6d} | C%={row['C_pct']:4.1f} R%={row['R_pct']:4.1f} "
              f"| cleanAcc={row['clean_acc']:.3f} attackFA={row['attack_false_allow']:.2f} "
              f"naiveC={row['naive_C_falseallow']:.2f} | C_allow={row['C_allow']:.2f} "
              f"R_allow={row['R_allow']:.2f} U_allow={row['U_allow']:.2f} cFA={row['cert_false_allow']:.2f} "
              f"| {row['runtime_seconds']:.0f}s")

    cols = ["label"] + [c for c in SCALING_COLS if c not in ("label", "K", "x1")]
    with open(OUT / "realistic_schema_results.csv", "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=cols)
        w.writeheader()
        w.writerows([{c: r.get(c, "") for c in cols} for r in rows])
    note = (f"sigma={args.sigma}, tau={args.tau}, eps={args.eps}, n_mc={args.n_mc}, "
            f"{args.n} records/domain. Real-looking schemas, synthetic policies. "
            f"Certificate = enumerate_discrete_gaussian_rs.")
    (OUT / "realistic_schema_results.md").write_text(to_md(rows, cols, "Realistic-schema results", note))
    (OUT / "realistic_examples.jsonl").write_text("\n".join(json.dumps(e) for e in examples) + "\n")
    print(f"\nwrote -> {OUT/'realistic_schema_results.csv'} and .md ; examples -> realistic_examples.jsonl")


if __name__ == "__main__":
    main()
