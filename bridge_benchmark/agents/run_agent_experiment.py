#!/usr/bin/env python3
"""
run_agent_experiment.py — run the controlled LLM-agent experiment and log every episode.

Pipeline per episode: tool_env returns clean z -> attack corrupts to z' -> LLM proposes a candidate
action from z' -> gate authorizes the privileged action -> execute or fall back. Each episode is
evaluated under the requested gate(s) on identical inputs.

We do NOT certify the LLM or tool selection — only the typed authorization gate (SPEC).
"""
from __future__ import annotations

import argparse
import json
import sys
import warnings
from pathlib import Path

warnings.filterwarnings("ignore")
_root = Path(__file__).resolve().parents[1]
for p in ("generators", "models", "cert", "experiments", "agents"):
    sys.path.insert(0, str(_root / p))

from baselines import train_certified_gate  # noqa: E402
from llm_client import get_llm  # noqa: E402
from tool_env import ToolEnvironment  # noqa: E402
from agent_loop import (Gate, LearnedGate, CertifiedGate, OracleGate, ATTACKS, run_agent_episode)  # noqa: E402

OUT = _root / "cert" / "out"
DOMAINS = ["financial_compliance", "sre_monitoring"]


def _episodes(env, attack, n, seed):
    """Build (record, observed) episode inputs for an attack mode."""
    import random
    rng = random.Random(seed)
    if attack == "c_witness":
        pool = env.by_category("C")
        rng.shuffle(pool)
        chosen = pool[:n]
    else:
        per = max(1, n // 3)
        chosen = []
        for c in ("C", "R", "U"):
            xs = env.by_category(c); rng.shuffle(xs); chosen += xs[:per]
    realize = ATTACKS[attack]
    eps = []
    for rec in chosen:
        clean = env.call_tool(rec)
        observed = realize(env.rt, clean, env.eps)
        if observed is None:
            continue
        observed["id"] = rec["id"]
        eps.append((rec, clean, observed))
    return eps


def make_gates(which, model, rt, n_mc):
    g = {}
    if which in ("none", "all"):
        g["none"] = Gate()
    if which in ("learned", "all"):
        g["learned"] = LearnedGate(model)
    if which in ("certified", "all"):
        g["certified"] = CertifiedGate(model, rt, n_mc=n_mc)
    if which in ("oracle", "all"):
        g["oracle"] = OracleGate(rt)
    return g


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--domain", default="both", choices=["financial_compliance", "sre_monitoring", "both"])
    ap.add_argument("--gate", default="all", choices=["none", "learned", "certified", "oracle", "all"])
    ap.add_argument("--attack", default="all", choices=["clean", "c_witness", "mixed", "all"])
    ap.add_argument("--llm", default="mock")
    ap.add_argument("--n", type=int, default=500)
    ap.add_argument("--n-mc", type=int, default=800)
    ap.add_argument("--seed", type=int, default=0)
    ap.add_argument("--pool", type=int, default=8000)
    ap.add_argument("--out", default=str(OUT / "agent_experiment_results.jsonl"))
    args = ap.parse_args()

    domains = DOMAINS if args.domain == "both" else [args.domain]
    attacks = ["clean", "c_witness", "mixed"] if args.attack == "all" else [args.attack]
    if args.attack == "all":
        attacks = ["clean", "c_witness"]  # MVP default; pass --attack mixed explicitly for mixed
    llm = get_llm(args.llm)

    OUT.mkdir(parents=True, exist_ok=True)
    logs = []
    for domain in domains:
        env = ToolEnvironment(domain, n_pool=args.pool, eps=0.10, seed=args.seed)
        model = train_certified_gate(env.records[:16000], env.rt, sigma=0.10, n_aug=6, seed=args.seed)
        gates = make_gates(args.gate, model, env.rt, args.n_mc)
        for attack in attacks:
            episodes = _episodes(env, attack, args.n, args.seed)
            for gname, gate in gates.items():
                for rec, clean, observed in episodes:
                    log = run_agent_episode(rec, observed, llm, gate, env.rt, domain, env)
                    log["attack"] = attack
                    log["llm"] = args.llm
                    log["clean_tool_return"] = clean
                    log["observed_tool_return"] = observed
                    logs.append(log)
            print(f"{domain:20s} attack={attack:9s} | episodes={len(episodes)} x gates={list(gates)}")

    with open(args.out, "w") as f:
        for r in logs:
            f.write(json.dumps(r) + "\n")
    print(f"\nwrote {len(logs)} episode-logs -> {args.out}")


if __name__ == "__main__":
    main()
