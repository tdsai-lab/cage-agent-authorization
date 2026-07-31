#!/usr/bin/env python3
"""
verify_interaction_type.py — exact, witness-explicit interaction-category verifier.

Thin wrapper over the analytic action-indexed oracle in ``oracle.py``. It classifies a record into
A/B/C/D/R on ``Safe(z, a)`` and, for Category C, REQUIRES an auditable same-state joint-gap witness
(a one-step discrete state that is safe before the continuous move and unsafe after it).

SOUNDNESS DISCIPLINE (the paper's specification (§19); GOAL 9.1):

    analytic oracle        = source of truth (exact margins + exact discrete enumeration)
    grid / random sampling = falsification cross-check only

A C verdict here is NOT "not disc and not cont and joint" inferred from aggregate booleans — it is
"joint-unsafe WITH an explicit witness (t*, x_1*) such that m(t*,x_1*) < 0 and m + eps*scale >= 0".
``falsification_cross_check`` only tries to DISPROVE an R verdict; it never assigns a category.
"""
from __future__ import annotations

import argparse
import json
import math
from pathlib import Path

try:
    from oracle import (
        load_rule_table, category, safe, discrete_swaps, margin_and_scale, get_rule, _x1, _x2, MVP_D,
    )
except ImportError:
    from bridge_benchmark.generators.oracle import (
        load_rule_table, category, safe, discrete_swaps, margin_and_scale, get_rule, _x1, _x2, MVP_D,
    )


def verify_interaction_type(record: dict, rule_table: dict, d: int = MVP_D, eps: float = 0.0) -> dict:
    """Classify ``record`` (must carry ``candidate_action``). Returns the oracle CategoryResult,
    augmented with an explicit witness audit for C."""
    a = record.get("candidate_action")
    if a is None:
        raise ValueError("record must specify candidate_action (safety is action-indexed)")
    res = category(record, a, rule_table, d=d, eps=eps)

    if res["category"] == "C_joint_gap":
        w = res["joint_gap_witness"]
        # Audit invariant: safe before continuous move, unsafe after, via a genuine discrete swap.
        res["witness_audit_ok"] = (
            w["pre_continuous_margin"] < 0.0
            and w["post_continuous_margin"] >= 0.0
            and (
                w["tool_id"] != record["tool_id"]
                or w["categorical_fields"] != _x1(record)
            )
        )
    return res


# --------------------------------------------------------------------------- #
# Falsification-only cross-check (NOT a source of truth) — try to break an R verdict.
# --------------------------------------------------------------------------- #
def falsification_cross_check(record, rule_table, d=MVP_D, eps=0.0, n_cont=4000, seed=0) -> dict:
    dc = rule_table["domains"][record["domain"]]
    a = record["candidate_action"]
    nf = dc["numeric_fields"]
    s_clean = safe(record, a, rule_table)
    x1, num = _x1(record), _x2(record)

    targets = [(record["tool_id"], x1, 0)] + list(discrete_swaps(dc, record["tool_id"], x1, d))
    state = (seed * 1103515245 + 12345) & 0x7FFFFFFF
    k = len(nf)

    def rnd():
        nonlocal state
        state = (state * 1103515245 + 12345) & 0x7FFFFFFF
        return state / 0x7FFFFFFF

    for t2, x12, _r in targets:
        rule = get_rule(dc, t2, a, x12)
        if rule is None:
            continue
        for _ in range(n_cont):
            vec = [2 * rnd() - 1 for _ in range(k)]
            nrm = math.sqrt(sum(c * c for c in vec)) or 1.0
            scale = eps * (rnd() ** (1.0 / k))
            pert = {f: float(num[f]) + scale * c / nrm for f, c in zip(nf, vec)}
            m, _ = margin_and_scale(rule, x12, pert, nf)
            if (m >= 0.0) != (not s_clean):  # label differs from clean
                return {"flip_found": True, "witness": {"tool_id": t2, "numeric": pert}}
    return {"flip_found": False, "witness": None}


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="Witness-explicit interaction-category verifier.")
    ap.add_argument("--record", help="Path to a JSON record (must include candidate_action).")
    ap.add_argument("--selftest", action="store_true", help="Run the oracle/category unit tests.")
    ap.add_argument("-d", type=int, default=MVP_D)
    ap.add_argument("--eps", type=float, default=0.10)
    args = ap.parse_args()
    if args.selftest:
        import test_oracle  # local import to avoid an import cycle at module load
        raise SystemExit(test_oracle._run())
    rt = load_rule_table()
    if args.record:
        rec = json.loads(Path(args.record).read_text(encoding="utf-8"))
        print(json.dumps(verify_interaction_type(rec, rt, args.d, args.eps), indent=2))
    else:
        print("Pass --record <file.json> or --selftest (also: python -m pytest -q).")
