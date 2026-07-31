#!/usr/bin/env python3
"""
negative_controls.py — NEW_EXPS_7 Part D: the certificate does NOT cover arbitrary endpoint lies.

The certificate covers BOUNDED typed corruption z' ∈ B_{1,ε}(z): it certifies that authorization is
stable for perturbations of size ≤ ε around the OBSERVED return. It is NOT an endpoint-truthfulness
verifier. If a compromised tool endpoint fabricates an arbitrary safe-looking return z_fake that is far
(‖z_fake − z_true‖₂ > ε) from the true (unsafe) state, the certificate around z_fake says nothing
about z_true — and a sound gate will (correctly, for what it was asked) allow the fabricated return.

We construct examples whose TRUE state is unsafe but whose endpoint reports a fabricated safe return,
sweep the fabrication distance, and report exactly where the certified claim stops applying.

Reads the IEEE-CIS real-data records (transparent provenance-threshold oracle on risk_score).
"""
from __future__ import annotations

import argparse
import csv
import json
import math
import sys
import warnings
from pathlib import Path

warnings.filterwarnings("ignore")
_root = Path(__file__).resolve().parents[1]
for p in ("generators", "models", "cert", "realdata", "agents"):
    sys.path.insert(0, str(_root / p))
sys.path.insert(0, str(_root.parent))

from oracle import safe as oracle_safe, _x1  # noqa: E402
from baselines import train_certified_gate  # noqa: E402
from gates import make_gate  # noqa: E402
from bridge_benchmark.realdata import ieee_cis_policy as pol  # noqa: E402

PRIVILEGED = pol.ACTION
RISK = pol.RISK_FIELD


def load_records(path):
    recs = [json.loads(l) for l in open(path) if l.strip()]
    out = []
    for r in recs:
        out.append({"domain": pol.DOMAIN, "tool_id": r["tool_id"], "candidate_action": PRIVILEGED,
                    "categorical_fields": dict(r["x1"]), "numeric_fields": dict(r["x2"]),
                    "id": r.get("uid", ""), "category": r.get("category")})
    o = recs[0]["oracle"]
    return out, float(o["theta_base"]), float(o["delta"])


def l2(a, b, fields):
    return math.sqrt(sum((float(a[f]) - float(b[f])) ** 2 for f in fields))


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--records", default="bridge_benchmark/data/realdata/ieee_cis_boundary_balanced_s0.jsonl")
    ap.add_argument("--n-examples", type=int, default=120)
    ap.add_argument("--epsilon", type=float, default=0.10)
    ap.add_argument("--sigma", type=float, default=0.10)
    ap.add_argument("--tau", type=float, default=0.90)
    ap.add_argument("--n-mc", type=int, default=2000)
    ap.add_argument("--alpha", type=float, default=1e-3)
    ap.add_argument("--train-cap", type=int, default=16000)
    ap.add_argument("--seed", type=int, default=0)
    ap.add_argument("--out-dir", default="bridge_benchmark/cert/out/negative_controls")
    args = ap.parse_args(argv)
    eps = args.epsilon

    pool, theta_base, delta = load_records(args.records)
    rt = pol.build_rule_table(theta_base, delta)
    nfields = rt["domains"][pol.DOMAIN]["numeric_fields"]
    for z in pool:
        z["y"] = 1 if oracle_safe({"domain": pol.DOMAIN, "tool_id": z["tool_id"],
                                   "candidate_action": PRIVILEGED, "categorical_fields": _x1(z),
                                   "numeric_fields": z["numeric_fields"]}, PRIVILEGED, rt) else 0
    model = train_certified_gate(pool[:args.train_cap], rt, sigma=args.sigma, n_aug=6, seed=args.seed)
    gate = make_gate("certified", model=model, rt=rt, tau=args.tau, eps=eps, sigma=args.sigma,
                     n_mc=args.n_mc, alpha=args.alpha)

    # TRUE-unsafe states: clean-unsafe (y=0) records with risk_score above the per-tool threshold.
    true_unsafe = [z for z in pool if z["y"] == 0][:args.n_examples]

    # Fabrication-distance sweep: set fake risk_score to a clearly-safe low value; vary the gap so the
    # distance crosses ε. fake_risk in {true - g} clipped to [0,1].
    gaps = [0.05, eps, 0.20, 0.40, 0.80]      # ‖fake−true‖ along the risk axis ≈ gap
    rows = []
    for g in gaps:
        in_budget = g <= eps + 1e-9
        n = 0
        sum_dist = 0.0
        allow_on_fake = 0
        unsafe_lie = 0
        applicable = 0
        for z in true_unsafe:
            z_fake = {"domain": pol.DOMAIN, "tool_id": z["tool_id"], "candidate_action": PRIVILEGED,
                      "categorical_fields": _x1(z),
                      "numeric_fields": {**z["numeric_fields"],
                                         RISK: max(0.0, float(z["numeric_fields"][RISK]) - g)}}
            dist = l2(z_fake["numeric_fields"], z["numeric_fields"], nfields)
            allow, _ = gate.evaluate(z_fake, PRIVILEGED)
            # the true state is unsafe -> executing the privileged action on the lie is unsafe.
            n += 1
            sum_dist += dist
            allow_on_fake += int(bool(allow))
            # certificate's claim covers the fake ONLY if it lies within B_{1,ε}(z_true)
            within = dist <= eps + 1e-9
            applicable += int(within)
            unsafe_lie += int(bool(allow) and not within)   # allowed a lie outside the certified budget
        rows.append({
            "fabrication_gap": g,
            "n": n,
            "mean_distance_to_true_state": round(sum_dist / n, 4) if n else float("nan"),
            "inside_certified_budget": str(in_budget),
            "gate_allow_on_fake": round(allow_on_fake / n, 4) if n else float("nan"),
            "certified_claim_applicable": round(applicable / n, 4) if n else float("nan"),
            "unsafe_if_endpoint_lies": round(unsafe_lie / n, 4) if n else float("nan"),
        })

    cols = ["fabrication_gap", "n", "mean_distance_to_true_state", "inside_certified_budget",
            "gate_allow_on_fake", "certified_claim_applicable", "unsafe_if_endpoint_lies"]
    out = Path(args.out_dir); out.mkdir(parents=True, exist_ok=True)
    with open(out / "endpoint_lie.csv", "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=cols, extrasaction="ignore")
        w.writeheader(); w.writerows(rows)

    md = ["# Negative control — arbitrary endpoint lies are OUTSIDE the certified budget (Part D)\n",
          f"- IEEE-CIS real-data records; true-unsafe states (risk_score above the per-tool threshold). "
          f"The endpoint fabricates a safe-looking return by lowering `risk_score` by `fabrication_gap`. "
          f"ε={eps}, σ={args.sigma}, τ={args.tau}, n_mc={args.n_mc}. n={len(true_unsafe)} true-unsafe "
          f"examples.\n",
          "`inside_certified_budget` = is the fabrication within ε of the true state; "
          "`certified_claim_applicable` = fraction of fakes that lie within B_{1,ε}(z_true) (so the "
          "certificate around z_true would cover them); `unsafe_if_endpoint_lies` = fraction the gate "
          "allows that are OUTSIDE the certified budget (the certificate makes no claim about these).\n",
          "| " + " | ".join(cols) + " |", "| " + " | ".join("---" for _ in cols) + " |"]
    for r in rows:
        md.append("| " + " | ".join(str(r[c]) for c in cols) + " |")
    md.append("\n**Conclusion.**\n\n"
              "- The gate is **not an endpoint-truthfulness verifier**. It certifies authorization "
              "stability under bounded typed corruption around the *observed* return.\n"
              "- For small fabrications (`fabrication_gap ≤ ε`) the lie is inside B_{1,ε}(z_true): the "
              "certificate's robustness guarantee around the true state still bites, and a sound gate "
              "trained near the boundary tends to refuse.\n"
              "- For large fabrications (`fabrication_gap ≫ ε`) the fake is far outside the budget; the "
              "certificate makes **no claim** (`certified_claim_applicable → 0`) and the gate allows the "
              "fabricated safe return. If the endpoint fabricates an arbitrary false return outside "
              "B_{1,ε}, provenance / capability / trust infrastructure is needed UPSTREAM — this is "
              "outside the node-level certificate's scope.\n")
    (out / "endpoint_lie.md").write_text("\n".join(md) + "\n")
    for r in rows:
        print(f"  gap={r['fabrication_gap']:.2f} dist={r['mean_distance_to_true_state']} "
              f"in_budget={r['inside_certified_budget']} allow_on_fake={r['gate_allow_on_fake']} "
              f"claim_applicable={r['certified_claim_applicable']} "
              f"unsafe_lie={r['unsafe_if_endpoint_lies']}")
    print(f"\n-> {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
