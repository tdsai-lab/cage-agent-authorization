#!/usr/bin/env python3
"""
runtime_report.py — NEW_EXPS_7 Part E: runtime & cost reporting for the authorization gates.

For each (domain, gate) we time the per-decision latency of `gate.evaluate(z, a)` and report the
certificate's operational parameters (n_mc, σ, ε, τ, number of discrete branches enumerated), plus
utility (R_allow) and soundness (cert_false_allow). For a real LLM backend we additionally separate
LLM proposal latency from gate / certificate latency, so the cost of the certified node is explicit.

Be honest: the certified gate is slower (Gaussian-RS Monte-Carlo over each discrete branch). It is
intended for high-stakes actions where abstention and additional latency are acceptable — not free.

Offline (no LLM):  python -m bridge_benchmark.experiments.runtime_report
With a real LLM proposal-latency probe:
    python -m bridge_benchmark.experiments.runtime_report --llm-backend ollama \
        --model qwen2.5:7b-instruct --endpoint http://localhost:11434 --n-llm-probe 12
"""
from __future__ import annotations

import argparse
import csv
import statistics
import sys
import time
import warnings
from pathlib import Path

warnings.filterwarnings("ignore")
_root = Path(__file__).resolve().parents[1]
for p in ("generators", "models", "cert", "experiments", "agents"):
    sys.path.insert(0, str(_root / p))

from oracle import _x1  # noqa: E402
from synthetic_tools import DOMAIN  # noqa: E402
from realistic_schemas import finance_schema, monitoring_schema  # noqa: E402
from synthetic_tools import sample_records  # noqa: E402
from baselines import train_certified_gate  # noqa: E402
from gates import make_gate  # noqa: E402
from smoothed_gate import certify  # noqa: E402

SCHEMA = {"finance": finance_schema, "sre": monitoring_schema}
GATES = ["none", "rule", "learned", "certified"]


def _pct(xs, q):
    xs = sorted(xs)
    if not xs:
        return float("nan")
    idx = min(len(xs) - 1, int(round(q * (len(xs) - 1))))
    return xs[idx]


def time_gate(gate, records, robust_unsafe_fn):
    lat_ms, allows, r_allow = [], [], []
    false_allow = [0, 0]
    for z in records:
        t0 = time.perf_counter()
        allow, _ = gate.evaluate(z, z["candidate_action"])
        lat_ms.append((time.perf_counter() - t0) * 1e3)
        allows.append(bool(allow))
        if z["category"] == "R":
            r_allow.append(int(bool(allow)))
        if allow:
            false_allow[1] += 1
            if robust_unsafe_fn(z):
                false_allow[0] += 1
    return {
        "mean_latency_ms": round(statistics.fmean(lat_ms), 4),
        "p50_latency_ms": round(_pct(lat_ms, 0.50), 4),
        "p95_latency_ms": round(_pct(lat_ms, 0.95), 4),
        "decisions_per_second": round(1000.0 / statistics.fmean(lat_ms), 2) if lat_ms else float("nan"),
        "R_allow": round(statistics.fmean(r_allow), 4) if r_allow else float("nan"),
        "cert_false_allow": round(false_allow[0] / false_allow[1], 4) if false_allow[1] else 0.0,
    }


def llm_probe(backend, model, endpoint, n):
    """Median LLM proposal latency over n short prompts (real backend only)."""
    from llm_clients import make_client
    from prompts import build_action_prompt
    llm = make_client(backend, model=model, endpoint=endpoint,
                      allowed_actions=["approve_transaction", "manual_review"],
                      signal_field="risk_score", privileged_action="approve_transaction",
                      fallback_action="manual_review")
    tr = {"tool_id": "credit_check", "categorical_fields": {"c0": "v0_0"},
          "numeric_fields": {"risk_score": 0.5}, "untrusted_display_note": "No additional note."}
    prompt = build_action_prompt("finance", "Decide this transaction.", tr, prompt_mode="standard")
    lat = []
    for _ in range(n):
        t0 = time.perf_counter()
        llm.propose_action(prompt)
        lat.append((time.perf_counter() - t0) * 1e3)
    return {"n": n, "median_llm_proposal_ms": round(statistics.median(lat), 2),
            "p95_llm_proposal_ms": round(_pct(lat, 0.95), 2)}


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--n-records", type=int, default=300)
    ap.add_argument("--seed", type=int, default=0)
    ap.add_argument("--tau", type=float, default=0.90)
    ap.add_argument("--epsilon", type=float, default=0.10)
    ap.add_argument("--sigma", type=float, default=0.10)
    ap.add_argument("--n-mc", type=int, default=2000)
    ap.add_argument("--alpha", type=float, default=1e-3)
    ap.add_argument("--llm-backend", default=None, choices=[None, "ollama", "vllm"])
    ap.add_argument("--model", default="qwen2.5:7b-instruct")
    ap.add_argument("--endpoint", default="http://localhost:11434")
    ap.add_argument("--n-llm-probe", type=int, default=12)
    ap.add_argument("--out-dir", default="bridge_benchmark/cert/out/runtime")
    args = ap.parse_args(argv)
    eps = args.epsilon

    from oracle import category as oracle_category
    rows = []
    for dom in ("finance", "sre"):
        _, rt = SCHEMA[dom]()
        pool = sample_records(rt, max(8000, args.n_records * 8), eps=eps, seed=args.seed)
        model = train_certified_gate(pool[:16000], rt, sigma=args.sigma, n_aug=6, seed=args.seed)
        # category-balanced timing sample
        recs = []
        for cat in ("R", "C", "U"):
            recs += [r for r in pool if r["category"] == cat][:args.n_records // 3]
        for r in recs:
            r["domain"] = DOMAIN

        def robust_unsafe(z):
            return oracle_category(z, z["candidate_action"], rt, d=1, eps=eps)["category"][0] != "R"

        # discrete-branch count from the certificate enumeration (constant per record geometry)
        nb = certify(model, rt, recs[0], sigma=args.sigma, eps=eps, tau=args.tau,
                     n_mc=200, alpha=args.alpha)["n_states"]
        for g in GATES:
            gate = make_gate(g, model=model, rt=rt, tau=args.tau, eps=eps, sigma=args.sigma,
                             n_mc=args.n_mc, alpha=args.alpha)
            t = time_gate(gate, recs, robust_unsafe)
            rows.append({"domain": dom, "gate": g, "n_mc": (args.n_mc if g == "certified" else 0),
                         "discrete_branches": (nb if g == "certified" else 1),
                         "sigma": args.sigma, "epsilon": eps, "tau": args.tau, **t})

    llm_row = None
    if args.llm_backend:
        try:
            llm_row = llm_probe(args.llm_backend, args.model, args.endpoint, args.n_llm_probe)
        except Exception as e:                       # degrade gracefully if the endpoint is down
            llm_row = {"error": str(e)[:120]}

    cols = ["domain", "gate", "n_mc", "discrete_branches", "sigma", "epsilon", "tau",
            "mean_latency_ms", "p50_latency_ms", "p95_latency_ms", "decisions_per_second",
            "R_allow", "cert_false_allow"]
    out = Path(args.out_dir); out.mkdir(parents=True, exist_ok=True)
    with open(out / "runtime_summary.csv", "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=cols, extrasaction="ignore")
        w.writeheader(); w.writerows(rows)

    md = ["# Runtime & cost reporting (NEW_EXPS_7 Part E)\n",
          f"- per-decision latency of `gate.evaluate(z,a)` over {args.n_records} category-balanced "
          f"records/domain (single-thread, no batching). Certificate: σ={args.sigma}, ε={eps}, "
          f"τ={args.tau}, n_mc={args.n_mc}.\n",
          "| " + " | ".join(cols) + " |", "| " + " | ".join("---" for _ in cols) + " |"]
    for r in rows:
        md.append("| " + " | ".join(str(r.get(c, "")) for c in cols) + " |")
    if llm_row:
        md.append("\n## LLM proposal latency (separate from the gate)\n")
        if "error" in llm_row:
            md.append(f"- LLM backend `{args.llm_backend}` unreachable: `{llm_row['error']}` "
                      "(proposal latency measured separately when the server is up).")
        else:
            md.append(f"- backend=`{args.llm_backend}` model=`{args.model}`: median LLM proposal "
                      f"latency **{llm_row['median_llm_proposal_ms']} ms** "
                      f"(p95 {llm_row['p95_llm_proposal_ms']} ms) over {llm_row['n']} prompts. "
                      "The gate / certificate latency above is incurred AFTER the proposal and is "
                      "typically dominated by the LLM decode for the cheaper gates.")
    md.append("\n**Reading.** `none`/`rule`/`learned` are sub-millisecond pointwise decisions. The "
              "`certified` gate runs Gaussian-RS Monte-Carlo (`n_mc` samples) over each of the "
              "`discrete_branches` enumerated states, so it is materially slower — **the certified "
              "gate is intended for high-stakes actions where abstention and additional latency are "
              "acceptable; it is not free.** Latency scales ~linearly in `n_mc × discrete_branches`; "
              "lowering `n_mc` trades the certificate's confidence margin for speed.\n")
    (out / "runtime_summary.md").write_text("\n".join(md) + "\n")
    for r in rows:
        print(f"  {r['domain']:8s} {r['gate']:9s} mean={r['mean_latency_ms']}ms "
              f"p95={r['p95_latency_ms']}ms dps={r['decisions_per_second']} "
              f"branches={r['discrete_branches']} R_allow={r['R_allow']} cfa={r['cert_false_allow']}")
    if llm_row and "error" not in llm_row:
        print(f"  [llm] median_proposal={llm_row['median_llm_proposal_ms']}ms")
    print(f"\n-> {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
