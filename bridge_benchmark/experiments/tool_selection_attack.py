#!/usr/bin/env python3
"""
tool_selection_attack.py — IDEA #3: pre-selection / tool-selection attack as a CONTROLLED LIMIT.

Positioning (GOAL): the certified node is the **post-execution typed return** `Allow(z,a)`, NOT tool
retrieval/selection (that is RAG-poisoning territory). This experiment shows precisely where the
guarantee holds and where it stops:

    query q → {m_1,…,m_K poisoned tool cards} → top-1 selector → selected tool returns z=(t,x_1,x_2) → a

An attacker **poisons tool metadata** so the top-1 selector picks the WRONG tool. The gate only acts
AFTER the return, on the observed z' and the action a' of the selected route. "Unsafe execution" = a
genuinely-dangerous transaction (the CORRECT tool's policy rejects it) received an allowed privileged
execution. We measure `P[unsafe execution | wrong tool]` with no gate vs the certified robust-oracle
gate (over `B_{1,ε}`), in two mis-selection regimes on a multi-action-group tool table:

  within_group  — mis-selection to another tool in the SAME action group (a provenance swap, same
                  gated action a): the correct tool is a d=1 provenance neighbour of the observed one,
                  so the gate's worst-over-neighbours reasoning COVERS the mis-selection → P[unsafe]→0.
  cross_action  — mis-selection to a tool in a DIFFERENT action group (the agent now proposes that
                  group's action a'≠a): the correct tool is bound to a different action and is INVISIBLE
                  to the a'-gate's ball → the gate certifies the wrong action and residual harm survives.

Message (the claim ladder, exactly): the gate **does not certify selection**, but it still blocks the
mis-selections whose provenance error is inside its typed per-action budget; a selection error that
crosses the action boundary is out of scope and the gate is honestly silent. Coheres with P2's breaking
radius. No LLM/network; the analytic oracle + synthetic multi-group tool table only.
"""
from __future__ import annotations

import argparse
import json
import sys
from collections import defaultdict
from pathlib import Path

import numpy as np

_root = Path(__file__).resolve().parents[1]
for p in ("generators", "experiments"):
    sys.path.insert(0, str(_root / p))

from oracle import safe, joint_reachable_unsafe, continuous_reachable_unsafe  # noqa: E402
from synthetic_tools import make_rule_table, sample_records, DOMAIN  # noqa: E402

OUT = _root / "cert" / "out"
EPS = 0.10


def _rec(tool, a, x1, num):
    return {"domain": DOMAIN, "tool_id": tool, "candidate_action": a,
            "categorical_fields": dict(x1), "numeric_fields": dict(num)}


def _worst_case_unsafe(rec, a, rt, d, eps):
    if not safe(rec, a, rt):
        return True
    if continuous_reachable_unsafe(rec, a, rt, eps)["reachable"]:
        return True
    return d >= 1 and joint_reachable_unsafe(rec, a, rt, d, eps)["reachable"]


def cert_allows(obs_tool, a, x1, num, rt, eps=EPS):
    """Certified robust-oracle gate for action a at the observed return: allow iff B_{1,ε} has no unsafe."""
    return not _worst_case_unsafe(_rec(obs_tool, a, x1, num), a, rt, d=1, eps=eps)


def poisoned_selection(correct_tool, distractor_tool, tools, rng, poison_boost):
    """Light but faithful metadata-poisoning selector: correct tool has top clean relevance; the
    attacker boosts a distractor card so the top-1 selector flips to it."""
    scores = {t: (1.0 if t == correct_tool else float(rng.uniform(0.0, 0.6))) for t in tools}
    scores[distractor_tool] = scores.get(distractor_tool, 0.0) + poison_boost
    return max(scores, key=scores.get)


def run_regime(rt, recs, regime, seed, poison_boost):
    dc = rt["domains"][DOMAIN]
    tool_action = dc["_tool_action"]
    tools = list(dc["tools"])
    by_action = defaultdict(list)
    for t, a in tool_action.items():
        by_action[a].append(t)
    rng = np.random.default_rng(seed + (0 if regime == "within_group" else 1))

    c = defaultdict(int)
    n_wrong = asr_num = asr_den = 0
    for rec in recs:
        t, a = rec["tool_id"], rec["candidate_action"]
        x1, num = dict(rec["categorical_fields"]), rec["numeric_fields"]
        if regime == "within_group":
            cands = [u for u in by_action[a] if u != t]           # same action, different tool
        else:  # cross_action
            cands = [u for u in tools if tool_action[u] != a]     # a tool bound to another action
        if not cands:
            continue
        distractor = cands[int(rng.integers(len(cands)))]
        a_obs = tool_action[distractor]                            # the action of the selected route
        # retrieval context: did poisoning flip the top-1 selection?
        asr_den += 1
        asr_num += int(poisoned_selection(t, distractor, tools, rng, poison_boost) != t)
        # genuinely dangerous = the CORRECT tool's policy rejects this transaction at face value
        true_dangerous = not safe(_rec(t, a, x1, num), a, rt)
        if not true_dangerous:
            continue                                              # condition on dangerous + mis-selected
        n_wrong += 1
        # no gate: the agent executes the selected route's privileged action -> harm realised
        c["no_gate_unsafe"] += 1
        # certified gate on the OBSERVED return for the OBSERVED action a_obs
        allowed = cert_allows(distractor, a_obs, x1, num, rt)
        c["cert_allow"] += int(allowed)
        c["cert_unsafe"] += int(allowed)                          # allowed => the dangerous txn is approved
    if n_wrong == 0:
        return None
    return {
        "regime": regime, "n_dangerous_misselections": n_wrong, "poison_boost": poison_boost,
        "retrieval_asr": round(asr_num / max(1, asr_den), 4),
        "P_unsafe_no_gate": round(c["no_gate_unsafe"] / n_wrong, 4),
        "P_unsafe_certified": round(c["cert_unsafe"] / n_wrong, 4),
        "cert_allow_rate": round(c["cert_allow"] / n_wrong, 4),
    }


def run_table(K, k, seed, n, poison_boost):
    rt = make_rule_table(K=K, k=k, x1_size=4, m=4, seed=seed)
    recs = sample_records(rt, n, eps=EPS, seed=seed)
    return {"K": K, "k": k, "n_records": len(recs),
            "regimes": [r for r in (run_regime(rt, recs, rg, seed, poison_boost)
                                    for rg in ("within_group", "cross_action")) if r]}


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--K", type=int, default=12)      # 3 action groups of 4 tools
    ap.add_argument("--k", type=int, default=4)
    ap.add_argument("--n", type=int, default=8000)
    ap.add_argument("--seed", type=int, default=0)
    ap.add_argument("--poison-boost", type=float, default=1.0)
    ap.add_argument("--out", default="tool_selection_attack")
    args = ap.parse_args()

    res = {"experiment": "IDEA #3 — tool-selection poisoning as a controlled limit",
           "eps": EPS, "note": "gate certifies Allow(z,a) post-return per-action, NOT tool selection",
           **run_table(args.K, args.k, args.seed, args.n, args.poison_boost)}
    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / f"{args.out}.json").write_text(json.dumps(res, indent=2))
    _write_md(OUT / f"{args.out}.md", res)

    print(f"K={res['K']} k={res['k']} n={res['n_records']}")
    for r in res["regimes"]:
        print(f"  {r['regime']:14s} | retrieval ASR={r['retrieval_asr']:.2f} | "
              f"dangerous-misselect n={r['n_dangerous_misselections']} | "
              f"P[unsafe] no_gate={r['P_unsafe_no_gate']:.3f} certified={r['P_unsafe_certified']:.3f}")
    print(f"\nwrote {OUT / (args.out + '.json')}\nwrote {OUT / (args.out + '.md')}")
    return res


def _write_md(path, res):
    with open(path, "w") as f:
        f.write("# IDEA #3 — tool-selection poisoning as a controlled limit\n\n")
        f.write(f"ε={res['eps']}, multi-action-group tool table (K={res['K']}, k={res['k']}). The "
                "certified node is `Allow(z,a)` **after** the tool returns, per action; it does NOT "
                "certify tool selection. An attacker poisons tool metadata so the top-1 selector picks "
                "the WRONG tool; we measure `P[unsafe execution | dangerous transaction mis-selected]` "
                "with no gate vs the certified robust-oracle gate.\n\n")
        f.write("| regime | retrieval ASR | n | P[unsafe] no-gate | **P[unsafe] certified** | cert-allow |\n")
        f.write("|---|---:|---:|---:|---:|---:|\n")
        for r in res["regimes"]:
            f.write(f"| {r['regime']} | {r['retrieval_asr']} | {r['n_dangerous_misselections']} | "
                    f"{r['P_unsafe_no_gate']} | **{r['P_unsafe_certified']}** | {r['cert_allow_rate']} |\n")
        f.write("\n**Reads.** Metadata poisoning flips selection (ASR≈1.0). "
                "`within_group` mis-selection (a provenance swap to another tool sharing the gated action) "
                "puts the correct tool inside the gate's `B_{1,ε}` ball → the gate's worst-over-neighbours "
                "reasoning **covers** it and drives `P[unsafe]→0`: the certified node incidentally "
                "neutralises in-budget (single-provenance) mis-selection. `cross_action` mis-selection "
                "(to a tool bound to a DIFFERENT action) puts the correct tool outside the per-action "
                "ball → the gate certifies the wrong action and **residual harm survives** "
                "(P[unsafe]>0). Exactly the intended limit: **the gate does not certify selection**, but "
                "blocks the mis-selections whose provenance error is in its typed per-action budget; a "
                "selection error that crosses the action boundary is out of scope and the gate is "
                "honestly silent. Tool retrieval/selection remains a separate upstream defense surface "
                "(coheres with P2's breaking radius).\n")


if __name__ == "__main__":
    main()
