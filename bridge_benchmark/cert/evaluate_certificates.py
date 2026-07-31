#!/usr/bin/env python3
"""
evaluate_certificates.py — orchestrator producing the MVP paper tables (PLAN3 sec.13).

  Table 1: dataset counts by domain / action / category
  Table 2: clean classifier performance by category
  Table 3: empirical mixed-attack results (subsample)
  Table 4: deterministic certificate sanity table (model-free)
  Table 5: smoothed learned-gate certificate results (hybrid RS over D_1)

Also writes per-record certificates (PLAN3 sec.11) to cert/out/certificates.jsonl.

Runtime is bounded by subsampling the attack and certificate passes (the analytic/clean tables use
the full test split). Tune via CLI flags.
"""
from __future__ import annotations

import argparse
import json
import sys
import warnings
from collections import Counter, defaultdict
from pathlib import Path

import numpy as np

warnings.filterwarnings("ignore")
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "generators"))
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "models"))
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "attacks"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from oracle import joint_reachable_unsafe, _x1  # noqa: E402
from baselines import train_all, train_certified_gate, evaluate  # noqa: E402
from mixed_attack import attack_allows, attack_reaches_true_unsafe_allow  # noqa: E402
from smoothed_gate import certify  # noqa: E402
from certificate_oracles import canonical_rows  # noqa: E402

OUT = Path(__file__).resolve().parent / "out"


def _sub(records, cat, n):
    return [r for r in records if r["category"] == cat][:n]


def table1(records):
    print("\n== Table 1: dataset counts by domain / action / category ==")
    by = defaultdict(Counter)
    for r in records:
        by[(r["domain"], r["candidate_action"])][r["category"]] += 1
    print(f"{'domain':<22} {'action':<20} " + " ".join(f"{c:>5}" for c in "ABCRU"))
    for key in sorted(by):
        c = by[key]
        print(f"{key[0]:<22} {key[1]:<20} " + " ".join(f"{c.get(x,0):>5}" for x in "ABCRU"))


def table2(models, test):
    print("\n== Table 2: clean classifier performance by category ==")
    hdr = f"{'model':<22} {'cleanAcc':>8} {'falseAllow':>10} {'A':>5} {'B':>5} {'C':>5} {'R':>5} {'U':>5}"
    print(hdr); print("-" * len(hdr))
    for name, m in models.items():
        e = evaluate(m, test); bc = e["acc_by_cat"]
        f = lambda x: "  nan" if x != x else f"{x:5.3f}"
        print(f"{name:<22} {f(e['clean_acc']):>8} {f(e['false_allow']):>10} "
              f"{f(bc['A'])} {f(bc['B'])} {f(bc['C'])} {f(bc['R'])} {f(bc['U'])}")


def table3(models, rt, test, eps, n_attack):
    print(f"\n== Table 3: empirical mixed attack (eps={eps}, subsample {n_attack}/stratum) ==")
    unsafe = _sub(test, "U", n_attack)
    cpts = _sub(test, "C", n_attack)
    sel = {k: models[k] for k in ("numeric_only", "joint_mlp") if k in models}
    sel["certified_mlp"] = models["certified_mlp"]
    hdr = f"{'model':<18} {'cleanFalseAllow':>15} {'robustFalseAllow':>17} {'C:allows true-unsafe':>22}"
    print(hdr); print("-" * len(hdr))
    rows = {}
    for name, m in sel.items():
        cfa = np.mean([m.allow_point(r["domain"], r["tool_id"], r["candidate_action"], _x1(r),
                                     r["numeric_fields"]) for r in unsafe]) if unsafe else 0.0
        rob = np.mean([attack_allows(m, rt, r, eps)[1] for r in unsafe]) if unsafe else 0.0
        ctu = np.mean([attack_reaches_true_unsafe_allow(m, rt, r, eps) for r in cpts]) if cpts else 0.0
        rows[name] = (float(cfa), float(rob), float(ctu))
        print(f"{name:<18} {cfa:>15.3f} {rob:>17.3f} {ctu:>22.3f}")
    return rows


def table4(eps):
    print("\n== Table 4: deterministic certificate sanity (model-free) ==")
    hdr = f"{'case':<26} {'cat':<18} {'disc':>5} {'cont':>5} {'naive':>6} {'hybridSafe':>11} {'naiveFALSE':>11}"
    print(hdr); print("-" * len(hdr))
    for label, cat, c in canonical_rows(eps):
        b = lambda x: "T" if c.get(x) else "F"
        print(f"{label:<26} {cat:<18} {b('discrete_only_certifies_safe'):>5} "
              f"{b('continuous_only_certifies_safe'):>5} {b('naive_composition_certifies_safe'):>6} "
              f"{b('hybrid_truth_safe_over_joint'):>11} {b('naive_composition_false_certify'):>11}")


def table5(gate, rt, test, eps, sigma, tau, n_mc, n_cert, alpha=1e-3):
    print(f"\n== Table 5: smoothed learned-gate certificate "
          f"(sigma={sigma}, eps={eps}, tau={tau}, n_mc={n_mc}, alpha={alpha}, {n_cert}/stratum) ==")
    OUT.mkdir(exist_ok=True)
    recs = sum((_sub(test, c, n_cert) for c in "ABCRU"), [])
    certs = [certify(gate, rt, r, sigma=sigma, eps=eps, tau=tau, n_mc=n_mc, alpha=alpha) for r in recs]
    (OUT / "certificates.jsonl").write_text("\n".join(json.dumps(c) for c in certs) + "\n")

    # soundness: among hybrid-allowed, fraction truly joint-unsafe-reachable (oracle)
    allowed = [(r, c) for r, c in zip(recs, certs) if c["allow"]]
    false_allow = 0
    for r, _c in allowed:
        if joint_reachable_unsafe(r, r["candidate_action"], rt, 1, eps)["reachable"] or r["y"] == 0:
            false_allow += 1
    cert_allow_rate = len(allowed) / len(recs)
    cert_false_allow = false_allow / max(1, len(allowed))

    by_cat = {c: np.mean([cc["allow"] for r, cc in zip(recs, certs) if r["category"] == c])
              for c in "ABCRU"}
    print(f"certified allow rate     : {cert_allow_rate:.3f}")
    print(f"certified FALSE allow    : {cert_false_allow:.3f}   (must be ~0; sound by construction up to alpha)")
    print(f"vacuity (refused) rate   : {1 - cert_allow_rate:.3f}")
    print("certified allow by category:", {k: round(float(v), 3) for k, v in by_cat.items()})
    print("\nExpected (PLAN3 sec.12): C refuses, U refuses, R allows non-vacuously.")
    print(f"wrote per-record certificates -> {OUT / 'certificates.jsonl'}")
    return {"cert_allow_rate": cert_allow_rate, "cert_false_allow": cert_false_allow,
            "by_cat": {k: float(v) for k, v in by_cat.items()}}


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--epsilon", "--eps", dest="eps", type=float, default=0.10)
    ap.add_argument("--sigma", type=float, default=0.10,
                    help="smoothing/augmentation noise (raw units); ~0.10 maximizes R non-vacuity at eps=0.10")
    ap.add_argument("--tau", type=float, default=0.90)
    ap.add_argument("--n-mc", type=int, default=2000)
    ap.add_argument("--alpha", type=float, default=1e-3, help="Clopper-Pearson level (confidence 1-alpha)")
    ap.add_argument("--n-cert", type=int, default=40, help="cert subsample per category")
    ap.add_argument("--n-attack", type=int, default=20, help="attack subsample per stratum")
    ap.add_argument("--n-aug", type=int, default=6)
    args = ap.parse_args()

    models, (train, val, test), rt = train_all()
    records = train + val + test
    gate = train_certified_gate(train, rt, sigma=args.sigma, n_aug=args.n_aug)
    models["certified_mlp"] = gate

    print(f"records {len(records)} | train/val/test {len(train)}/{len(val)}/{len(test)} | "
          f"feature dim {models['joint_logistic'].enc.dim}")
    table1(records)
    table2(models, test)
    table3(models, rt, test, args.eps, args.n_attack)
    table4(args.eps)
    table5(gate, rt, test, args.eps, args.sigma, args.tau, args.n_mc, args.n_cert, args.alpha)


if __name__ == "__main__":
    main()
