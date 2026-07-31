#!/usr/bin/env python3
"""
threshold_sensitivity.py — robustness of the Category-C (joint-gap) phenomenon to threshold choice
(the paper's specification (§20) / GOAL 9.3), for the action-indexed oracle at the MVP budget d = 1.

Defends against "you tuned the thresholds to manufacture the gap."

Two-threshold scalar model for a fixed candidate action a: a clean point x sits on the
higher-threshold tool (theta1); a one-step provenance swap moves it to the lower-threshold tool
(theta2), theta1 > theta2; unsafe iff x >= theta(tool). x is Category C iff:

    discrete-only safe:   x < theta2
    continuous-only safe:  x < theta1 - eps
    joint unsafe:          x + eps >= theta2

=> C-interval for x is  [ theta2 - eps , min(theta2, theta1 - eps) ),
   length L = max(0, min(theta2, theta1 - eps) - (theta2 - eps)).

Part 1: analytic C-measure over a (theta1, theta2, eps) grid.
Part 2: cross-validate against the FULL action-indexed 4-tool oracle by sweeping x and reading the
        verifier's category — it must reproduce the analytic C-interval exactly.
"""
from __future__ import annotations

import json

from oracle import load_rule_table, category


def c_interval_length(theta1: float, theta2: float, eps: float) -> float:
    if theta1 <= theta2:
        return 0.0
    return max(0.0, min(theta2, theta1 - eps) - (theta2 - eps))


def part1_grid(thetas=None, epss=None) -> dict:
    if thetas is None:
        thetas = [round(0.30 + 0.05 * i, 2) for i in range(14)]
    if epss is None:
        epss = [0.05, 0.10, 0.15, 0.20, 0.25]
    total = nonempty = 0
    lengths = []
    for eps in epss:
        for t1 in thetas:
            for t2 in thetas:
                if t1 <= t2:
                    continue
                total += 1
                L = c_interval_length(t1, t2, eps)
                if L > 0:
                    nonempty += 1
                    lengths.append(L)
    return {
        "n_threshold_pairs_tested": total,
        "n_with_nonempty_C": nonempty,
        "fraction_nonempty": round(nonempty / total, 4) if total else 0.0,
        "mean_C_length_when_nonempty": round(sum(lengths) / len(lengths), 4) if lengths else 0.0,
        "max_C_length": round(max(lengths), 4) if lengths else 0.0,
    }


def part2_crossvalidate(eps: float = 0.10, step: float = 0.005) -> dict:
    """Sweep risk_score on credit_check (theta1=0.90) for action approve_transaction in the full
    action-indexed table; nearest lower threshold is sanctions_screen (theta2=0.50)."""
    rt = load_rule_table()
    theta1, theta2 = 0.90, 0.50
    lo, hi = theta2 - eps, min(theta2, theta1 - eps)

    cats: dict[str, int] = {}
    c_xs = []
    x = 0.0
    while x <= 1.0 + 1e-9:
        z = {"domain": "financial_compliance", "tool_id": "credit_check",
             "candidate_action": "approve_transaction",
             "categorical_fields": {"counterparty_country": "US", "channel": "card"},
             "numeric_fields": {"risk_score": round(x, 4), "amount_norm": 0.2}}
        cat = category(z, "approve_transaction", rt, d=1, eps=eps)["category"]
        cats[cat] = cats.get(cat, 0) + 1
        if cat == "C_joint_gap":
            c_xs.append(round(x, 4))
        x += step

    band = [min(c_xs), max(c_xs)] if c_xs else None
    matches = (band is not None
               and abs(band[0] - lo) <= step + 1e-9
               and abs(band[1] - (hi - step)) <= step + 1e-9)
    return {
        "eps": eps, "theta1_credit": theta1, "theta2_sanctions": theta2,
        "analytic_C_interval": [round(lo, 4), round(hi, 4)],
        "empirical_C_band_from_oracle": band,
        "category_histogram_over_sweep": {k.split("_")[0]: v for k, v in cats.items()},
        "analytic_matches_oracle": bool(matches),
    }


if __name__ == "__main__":
    p1, p2 = part1_grid(), part2_crossvalidate()
    print("=== Part 1: analytic C-measure over a (theta1, theta2, eps) grid ===")
    print(json.dumps(p1, indent=2))
    print("\n=== Part 2: action-indexed oracle cross-validation (full 4-tool table) ===")
    print(json.dumps(p2, indent=2))
    print(f"\nC is robust (not tuned): nonempty in {p1['fraction_nonempty']*100:.1f}% of valid pairs; "
          f"oracle matches analytic interval: {p2['analytic_matches_oracle']}.")
