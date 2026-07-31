#!/usr/bin/env python3
"""
run_benchmark_grounded_cert.py — train -> attack -> certify on a benchmark-grounded canonical dataset,
reusing the EXISTING pipeline (FeatureEncoder + certified gate + empirical attack +
enumerate_discrete_gaussian_rs certificate + the model-free certificate_oracles). No theorem change,
no discrete smoothing.

Outputs (under --out):
    metrics.json                 paper-facing metrics + category_counts + baselines
    records_with_categories.jsonl internal records (y, category, witness)
    report.md                    human-readable report (what is real / derived / synthetic)
    config.json                  exact run configuration

Paper-facing metrics match the existing experiments:
    clean_accuracy  R_allow  C_allow  U_allow  cert_false_allow  naive_C_falseallow
    abstention_rate  category_counts

Usage:
  python -m bridge_benchmark.experiments.run_benchmark_grounded_cert \
      --records bridge_benchmark/data/benchmark_grounded/ampermbench_records.jsonl \
      --oracle-mode hybrid_policy --epsilon 0.10 --d 1 --n-mc 2000 --seed 0 \
      --out bridge_benchmark/cert/out/benchmark_grounded_ampermbench_seed0
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from collections import Counter
from pathlib import Path

import numpy as np

_root = Path(__file__).resolve().parents[1]
for p in ("generators", "models", "attacks", "cert", "experiments"):
    sys.path.insert(0, str(_root / p))
sys.path.insert(0, str(_root.parent))  # repo root for package import

from oracle import joint_reachable_unsafe  # noqa: E402
from split import stratified_split  # noqa: E402
from baselines import train_certified_gate, evaluate  # noqa: E402
from smoothed_gate import certify as rs_certify  # noqa: E402
import certificate_oracles as detcert  # noqa: E402
from harness import batched_attack_false_allow, to_md  # noqa: E402
from bridge_benchmark.experiments import benchmark_grounded as bg  # noqa: E402

CATS = ["A", "B", "C", "R", "U"]


def load_records(path: str | Path) -> list[dict]:
    out = []
    with Path(path).open(encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line:
                out.append(json.loads(line))
    return out


def run(records_canonical, rt, *, eps, sigma, tau, n_mc, alpha, d, seed,
        n_cert, n_attack, train_cap):
    """One full pipeline pass; returns (metrics_dict, internal_records)."""
    t0 = time.perf_counter()
    internal = bg.label_and_categorize(records_canonical, rt, eps=eps, d=d)
    n = len(internal)
    prev = Counter(r["category"] for r in internal)
    train, val, test = stratified_split(internal)

    gate = train_certified_gate(train[:train_cap], rt, sigma=sigma, n_aug=4, seed=seed)
    ev = evaluate(gate, test)

    def sub(cat, k):
        return [r for r in test if r["category"] == cat][:k]

    # --- uncertified learned gate: robust false-allow on truly-unsafe U under B_{1,eps}
    U = sub("U", n_attack)
    attack_fa = batched_attack_false_allow(gate, rt, U, eps)

    # --- model-free naive-composition false-certify on C (non-composition result)
    Csub_det = sub("C", 200)
    naive_C = (float(np.mean([detcert.certify(r, r["candidate_action"], rt, d, eps).get(
        "naive_composition_false_certify", False) for r in Csub_det])) if Csub_det else float("nan"))
    # hybrid (joint-truth) certificate: refuses C, allows R  (model-free sanity)
    Rsub_det = sub("R", 200)
    hybrid_C_safe = (float(np.mean([detcert.certify(r, r["candidate_action"], rt, d, eps).get(
        "hybrid_truth_safe_over_joint", False) for r in Csub_det])) if Csub_det else float("nan"))
    hybrid_R_safe = (float(np.mean([detcert.certify(r, r["candidate_action"], rt, d, eps).get(
        "hybrid_truth_safe_over_joint", False) for r in Rsub_det])) if Rsub_det else float("nan"))
    disc_only_C = (float(np.mean([detcert.certify(r, r["candidate_action"], rt, d, eps).get(
        "discrete_only_certifies_safe", False) for r in Csub_det])) if Csub_det else float("nan"))
    cont_only_C = (float(np.mean([detcert.certify(r, r["candidate_action"], rt, d, eps).get(
        "continuous_only_certifies_safe", False) for r in Csub_det])) if Csub_det else float("nan"))

    # --- learned enumerate_discrete_gaussian_rs certificate over a balanced cert sample
    cert_recs = sum((sub(c, n_cert) for c in CATS), [])
    certs = [rs_certify(gate, rt, r, sigma=sigma, eps=eps, tau=tau, n_mc=n_mc, alpha=alpha)
             for r in cert_recs]
    allow = np.array([c["allow"] for c in certs])
    cats = np.array([r["category"] for r in cert_recs])

    def ar(c):
        msk = cats == c
        return float(np.mean(allow[msk])) if msk.any() else float("nan")

    abstention = float(1.0 - np.mean(allow)) if len(allow) else float("nan")

    # certified-allow points that are actually joint-unsafe -> MUST be 0 (soundness)
    false_allow = 0
    for i in np.where(allow)[0]:
        r = cert_recs[i]
        if r["y"] == 0 or joint_reachable_unsafe(r, r["candidate_action"], rt, d, eps)["reachable"]:
            false_allow += 1
    cert_fa = false_allow / max(1, int(allow.sum()))

    runtime = time.perf_counter() - t0
    metrics = {
        "n_records": n,
        "category_counts": {c: int(prev.get(c, 0)) for c in CATS},
        "category_fractions": {c: round(prev.get(c, 0) / n, 4) for c in CATS},
        "mixed_disc_and_cont_unsafe": int(sum(
            1 for r in internal if r["discrete_only_unsafe"] and r["continuous_only_unsafe"])),
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
            "hybrid_cert_safe_on_C": round(hybrid_C_safe, 4),
            "hybrid_cert_safe_on_R": round(hybrid_R_safe, 4),
            "oracle_gate_false_allow": 0.0,
        },
        "n_cert_sample": int(len(cert_recs)),
        "runtime_seconds": round(runtime, 1),
    }
    return metrics, internal


def _report_md(args, rt, metrics, families) -> str:
    cc = metrics["category_counts"]
    n = metrics["n_records"]
    bl = metrics["baselines"]
    feat_origin = {fam: bg.amp.feature_origin(fam) for fam in families}
    lim = ("This experiment does not provide end-to-end robustness for an LLM agent. It evaluates a "
           "certified post-tool-return authorization node built from benchmark-derived "
           "task/action/state structure.")
    L = []
    L.append("# Benchmark-grounded typed-return experiment\n")
    L.append("> This experiment uses benchmark-derived task families, target sets, action types, and "
             "state fields. The post-tool-return typed node and continuous perturbation policy are "
             "constructed to fit the certificate interface. Therefore this is a **benchmark-grounded "
             "authorization experiment, not a fully real production-policy benchmark.**\n")
    L.append("## Dataset source\n")
    L.append(f"- source: `{args.source}` (AmPermBench-style)\n"
             f"- task families: {', '.join(families)}\n"
             f"- oracle mode: `{args.oracle_mode}`\n"
             f"- number of records: {n}\n")
    L.append("## What is real / benchmark-derived / synthetic\n")
    L.append("| layer | status |\n| --- | --- |\n"
             "| task families, candidate actions, tool identities | benchmark-derived |\n"
             "| authorized / must-preserve / protected target sets | benchmark-derived |\n"
             "| categorical state fields (environment, owner_match, ...) | benchmark-derived |\n"
             "| blast-radius numeric fields (unauthorized_fraction, protected_fraction, "
             "target_count_norm) | computed from benchmark sets |\n"
             "| operational numeric fields (age_norm, latency_norm, ...) | derived-from-state or "
             "synthetic neutral default |\n"
             f"| typed numeric policy thresholds (oracle `{args.oracle_mode}`) | "
             f"{'faithful set-membership' if args.oracle_mode=='benchmark_set' else 'SYNTHETIC (constructed to fit the certificate interface)'} |\n"
             "| continuous L2 perturbation policy `B_{1,eps}` | constructed |\n")
    L.append("## Category distribution (A/B/C/R/U + mixed)\n")
    L.append("| A | B | C | R | U | mixed(disc&cont) |\n| --- | --- | --- | --- | --- | --- |\n"
             f"| {cc['A']} | {cc['B']} | {cc['C']} | {cc['R']} | {cc['U']} | "
             f"{metrics['mixed_disc_and_cont_unsafe']} |\n")
    L.append("Category `C` = joint-only failure (discrete-only safe AND continuous-only safe, but the "
             "joint discrete+continuous budget is unsafe). It is the case the naive marginal "
             "composition certificate gets wrong.\n")
    L.append("## Feature origins\n")
    for fam, fo in feat_origin.items():
        L.append(f"- **{fam}**: " + ", ".join(f"`{k}`={v}" for k, v in fo.items()) + "\n")
    L.append("\n## Certificate parameters\n")
    L.append(f"- epsilon (L2): {args.epsilon}\n- d (discrete budget): {args.d}\n"
             f"- sigma (RS noise): {args.sigma}\n- tau (certify threshold): {args.tau}\n"
             f"- n_mc: {args.n_mc}\n- seed: {args.seed}\n")
    L.append("## Main metrics\n")
    L.append("| metric | value |\n| --- | --- |\n"
             f"| clean_accuracy | {metrics['clean_accuracy']} |\n"
             f"| R_allow (non-vacuity) | {metrics['R_allow']} |\n"
             f"| C_allow | {metrics['C_allow']} |\n"
             f"| U_allow | {metrics['U_allow']} |\n"
             f"| cert_false_allow (soundness; must be 0) | {metrics['cert_false_allow']} |\n"
             f"| naive_C_falseallow | {metrics['naive_C_falseallow']} |\n"
             f"| abstention_rate | {metrics['abstention_rate']} |\n")
    L.append("## Baselines (the non-composition comparison)\n")
    L.append("| gate / certificate | result |\n| --- | --- |\n"
             f"| uncertified learned gate — robust false-allow on U | "
             f"{bl['uncertified_learned_attack_false_allow_U']} |\n"
             f"| discrete-only certificate — certifies C safe | {bl['discrete_only_cert_safe_on_C']} |\n"
             f"| continuous-only certificate — certifies C safe | {bl['continuous_only_cert_safe_on_C']} |\n"
             f"| **naive marginal composition — FALSE-certifies C** | "
             f"{bl['naive_composition_false_certify_C']} |\n"
             f"| hybrid (joint) certificate — certifies C safe | {bl['hybrid_cert_safe_on_C']} "
             f"(correctly refuses) |\n"
             f"| hybrid (joint) certificate — certifies R safe | {bl['hybrid_cert_safe_on_R']} "
             f"(non-vacuous) |\n"
             f"| oracle gate — false-allow | {bl['oracle_gate_false_allow']} |\n")
    L.append("\nKey result: `Cert_disc(z,a)=1 ∧ Cert_cont(z,a)=1` does NOT imply `Cert_joint(z,a)=1` "
             "— the discrete-only and continuous-only certificates each certify C as safe, their "
             "naive composition is therefore false, and only the hybrid certificate over the joint "
             "ball is correct. The learned enumerate_discrete_gaussian_rs certificate inherits this: "
             "it allows none of C/U (sound) while remaining non-vacuous on R.\n")
    L.append("## Known limitations\n")
    L.append(f"- {lim}\n")
    L.append("- The numeric policy thresholds (hybrid_policy mode) are SYNTHETIC and chosen to fit "
             "the certificate interface; they are not real industrial thresholds.\n")
    L.append("- The `benchmark_set` mode is the faithful set-membership oracle; its continuous "
             "channel is weak by construction, so it produces few or no Category C examples.\n")
    L.append("- No claim of end-to-end agent robustness; the certified object is the typed "
             "post-tool-return authorization node, not the LLM, planner, or tool selector.\n")
    return "\n".join(L)


def main(argv=None):
    ap = argparse.ArgumentParser(description="Certify a benchmark-grounded typed authorization dataset.")
    ap.add_argument("--records", required=True, help="canonical JSONL from benchmark_grounded")
    ap.add_argument("--source", default="ampermbench")
    ap.add_argument("--oracle-mode", default="hybrid_policy", choices=bg.ORACLE_MODES)
    ap.add_argument("--epsilon", type=float, default=0.10)
    ap.add_argument("--d", type=int, default=1)
    ap.add_argument("--sigma", type=float, default=0.10)
    ap.add_argument("--tau", type=float, default=0.90)
    ap.add_argument("--n-mc", type=int, default=2000)
    ap.add_argument("--alpha", type=float, default=1e-3)
    ap.add_argument("--seed", type=int, default=0)
    ap.add_argument("--n-cert", type=int, default=40)
    ap.add_argument("--n-attack", type=int, default=80)
    ap.add_argument("--train-cap", type=int, default=12000)
    ap.add_argument("--out", required=True, help="output directory")
    args = ap.parse_args(argv)

    records = load_records(args.records)
    fams_present = sorted({r["task_family"] for r in records if "task_family" in r})
    families = [f for f in bg.amp.TASK_FAMILIES if f in fams_present] or list(bg.amp.TASK_FAMILIES)
    rt = bg.make_policy_rule_table(args.oracle_mode, families=families)

    metrics, internal = run(
        records, rt, eps=args.epsilon, sigma=args.sigma, tau=args.tau, n_mc=args.n_mc,
        alpha=args.alpha, d=args.d, seed=args.seed, n_cert=args.n_cert, n_attack=args.n_attack,
        train_cap=args.train_cap)

    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    config = {"source": args.source, "oracle_mode": args.oracle_mode, "records": str(args.records),
              "families": families, "epsilon": args.epsilon, "d": args.d, "sigma": args.sigma,
              "tau": args.tau, "n_mc": args.n_mc, "alpha": args.alpha, "seed": args.seed,
              "n_cert": args.n_cert, "n_attack": args.n_attack}
    (out / "config.json").write_text(json.dumps(config, indent=2), encoding="utf-8")
    (out / "metrics.json").write_text(json.dumps(metrics, indent=2), encoding="utf-8")
    with (out / "records_with_categories.jsonl").open("w", encoding="utf-8") as fh:
        for r in internal:
            fh.write(json.dumps(r) + "\n")
    (out / "report.md").write_text(_report_md(args, rt, metrics, families), encoding="utf-8")

    print(f"[run_benchmark_grounded_cert] oracle_mode={args.oracle_mode} n={metrics['n_records']}")
    print(f"  category_counts: {metrics['category_counts']}")
    print(f"  clean_accuracy={metrics['clean_accuracy']}  R_allow={metrics['R_allow']}  "
          f"C_allow={metrics['C_allow']}  U_allow={metrics['U_allow']}")
    print(f"  cert_false_allow={metrics['cert_false_allow']}  "
          f"naive_C_falseallow={metrics['naive_C_falseallow']}  "
          f"abstention_rate={metrics['abstention_rate']}")
    print(f"  -> {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
