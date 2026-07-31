#!/usr/bin/env python3
"""
certificate_oracles.py — DETERMINISTIC certificate baselines (no randomized smoothing yet).

These are *oracle* certificates computed directly from the analytic safety oracle, used to produce
the paper's key sanity table (the paper's specification (§22); GOAL sec. 6). They are not the learned/​smoothed
certificates — they answer "does a sound certificate of THIS scope certify the clean action safe?"
exactly, so we can exhibit the non-composition failure before any model exists.

For a clean-safe point z and action a, "certify safe over budget X" means: no point in budget X is
unsafe under the oracle.

    discrete-only certificate   certifies safe over B_{d,0}     (no discrete swap is unsafe)
    continuous-only certificate certifies safe over B_{0,eps}   (no eps move at the clean state is unsafe)
    naive composition           AND of the two marginal certificates (the WRONG aggregator)
    hybrid (exact) certificate  certifies safe over B_{d,eps}    (no joint perturbation is unsafe)

The point of interest: on Category C, both marginals certify "safe", their AND (naive composition)
certifies "safe" — but the hybrid oracle shows the joint budget contains an unsafe point, so naive
composition is UNSOUND (a false "safe"). On Category R, all agree and the hybrid certifies safe
non-vacuously.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "generators"))

from oracle import (  # noqa: E402
    load_rule_table, safe, discrete_reachable_unsafe, continuous_reachable_unsafe,
    joint_reachable_unsafe, category,
)


def certify(z: dict, a: str, rt: dict, d: int = 1, eps: float = 0.10) -> dict:
    """Return each certificate's verdict: True = 'certifies the clean action safe over its budget'."""
    if not safe(z, a, rt):
        return {"clean_safe": False}
    disc_unsafe = discrete_reachable_unsafe(z, a, rt, d)["reachable"]
    cont_unsafe = continuous_reachable_unsafe(z, a, rt, eps)["reachable"]
    joint_unsafe = joint_reachable_unsafe(z, a, rt, d, eps)["reachable"]

    discrete_only = not disc_unsafe                       # certifies safe over B_{d,0}
    continuous_only = not cont_unsafe                     # certifies safe over B_{0,eps}
    naive_composition = discrete_only and continuous_only  # AND of marginals (claims B_{d,eps} safe)
    hybrid_truth_safe = not joint_unsafe                   # actual safety over B_{d,eps}

    return {
        "clean_safe": True,
        "discrete_only_certifies_safe": discrete_only,
        "continuous_only_certifies_safe": continuous_only,
        "naive_composition_certifies_safe": naive_composition,
        "hybrid_truth_safe_over_joint": hybrid_truth_safe,
        # naive composition is UNSOUND here iff it says "safe" while the joint budget is unsafe:
        "naive_composition_false_certify": naive_composition and not hybrid_truth_safe,
        "hybrid_non_vacuous_allow": hybrid_truth_safe,  # hybrid can soundly allow over B_{d,eps}
    }


def _row(label, z, a, rt, eps):
    cat = category(z, a, rt, d=1, eps=eps)["category"]
    c = certify(z, a, rt, d=1, eps=eps)
    return label, cat, c


def canonical_rows(eps: float = 0.10):
    """The 4 canonical deterministic-certificate rows (model-free Table 4)."""
    rt = load_rule_table()

    def fin(tool, risk, action="approve_transaction", country="US"):
        return {"domain": "financial_compliance", "tool_id": tool, "candidate_action": action,
                "categorical_fields": {"counterparty_country": country, "channel": "card"},
                "numeric_fields": {"risk_score": risk, "amount_norm": 0.2}}

    def mon(tool, er, lat):
        return {"domain": "system_monitoring", "tool_id": tool, "candidate_action": "suppress_alert",
                "categorical_fields": {"severity": "SEV3"},
                "numeric_fields": {"error_rate": er, "latency_norm": lat}}

    specs = [
        ("finance C   (credit 0.45)", fin("credit_check", 0.45), "approve_transaction"),
        ("finance R   (credit 0.20)", fin("credit_check", 0.20), "approve_transaction"),
        ("monitor C+D (mem .60/.635)", mon("memory_monitor", 0.600, 0.635), "suppress_alert"),
        ("monitor R   (mem .40/.40)", mon("memory_monitor", 0.40, 0.40), "suppress_alert"),
    ]
    out = []
    for label, z, a in specs:
        out.append((label, category(z, a, rt, d=1, eps=eps)["category"], certify(z, a, rt, d=1, eps=eps)))
    return out


def main() -> None:
    rt = load_rule_table()
    EPS = 0.10

    def fin(tool, risk, action="approve_transaction", country="US"):
        return {"domain": "financial_compliance", "tool_id": tool, "candidate_action": action,
                "categorical_fields": {"counterparty_country": country, "channel": "card"},
                "numeric_fields": {"risk_score": risk, "amount_norm": 0.2}}

    def mon(tool, er, lat):
        return {"domain": "system_monitoring", "tool_id": tool, "candidate_action": "suppress_alert",
                "categorical_fields": {"severity": "SEV3"},
                "numeric_fields": {"error_rate": er, "latency_norm": lat}}

    rows = [
        _row("finance C   (credit 0.45)", fin("credit_check", 0.45), "approve_transaction", rt, EPS),
        _row("finance R   (credit 0.20)", fin("credit_check", 0.20), "approve_transaction", rt, EPS),
        _row("monitor C+D (mem .60/.635)", mon("memory_monitor", 0.600, 0.635), "suppress_alert", rt, EPS),
        _row("monitor R   (mem .40/.40)", mon("memory_monitor", 0.40, 0.40), "suppress_alert", rt, EPS),
    ]

    hdr = f"{'case':<26} {'cat':<18} {'disc':>5} {'cont':>5} {'naive':>6} {'hybridSafe':>11} {'naiveFALSE':>11}"
    print(hdr)
    print("-" * len(hdr))
    for label, cat, c in rows:
        def b(x):
            return "T" if c.get(x) else "F"
        print(f"{label:<26} {cat:<18} {b('discrete_only_certifies_safe'):>5} "
              f"{b('continuous_only_certifies_safe'):>5} {b('naive_composition_certifies_safe'):>6} "
              f"{b('hybrid_truth_safe_over_joint'):>11} {b('naive_composition_false_certify'):>11}")

    print("\nKey reads:")
    print("  C rows: disc=T, cont=T, naive=T, hybridSafe=F  =>  naive composition FALSELY certifies safe.")
    print("  R rows: disc=T, cont=T, naive=T, hybridSafe=T  =>  hybrid certifies safe NON-VACUOUSLY over B_{1,eps}.")

    # machine-readable dump
    print("\nJSON:")
    print(json.dumps([{"case": l, "category": cat, **c} for l, cat, c in rows], indent=2))


if __name__ == "__main__":
    main()
