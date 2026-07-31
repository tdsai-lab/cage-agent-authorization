#!/usr/bin/env python3
"""
synthetic_tools.py — parametric synthetic typed-tool benchmarks for the scaling study.

Builds a rule_table in the SAME schema as schemas/rule_tables.json (so oracle.py, FeatureEncoder,
smoothed_gate.py all work unchanged), with:
    K   tools,
    k   numeric fields,
    |X1| categorical complexity (values per categorical field),
keeping d = 1. The construction GUARANTEES Category C exists: the `approve` action gives the scalar
tools spread thresholds on a shared field (x0), so a one-step provenance swap repositions the
continuous boundary (the proven C condition theta_high > theta_low). Affine tools add Category D
(non-axis-aligned multivariate boundaries) when k >= 2.

`sample_records` draws records (random + boundary-aware) and labels them with the analytic oracle.
Random sampling scales to large k / large n where a dense grid is impossible.
"""
from __future__ import annotations

import sys
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "generators"))
from oracle import category, safe  # noqa: E402

DOMAIN = "synthetic"


def make_rule_table(K=8, k=5, x1_size=4, n_cat_fields=2, m=4, seed=0, affine_frac=0.3):
    """K tools partitioned into action GROUPS of size ~m. Each group has its own candidate action and
    a threshold field, so the per-action valid-swap set is bounded by m regardless of K. This keeps
    Category R non-vacuous as the tool VOCABULARY (feature dim) scales, while C is guaranteed inside
    each group by a scalar threshold gap. The continuous channel dimension is k.
    """
    rng = np.random.default_rng(seed)
    numeric_fields = [f"x{i}" for i in range(k)]
    cat_fields = {f"c{j}": [f"v{j}_{v}" for v in range(x1_size)] for j in range(n_cat_fields)}
    tools = [f"tool_{i:02d}" for i in range(K)]
    n_groups = max(1, (K + m - 1) // m)
    groups = [tools[g * m:(g + 1) * m] for g in range(n_groups)]
    actions = [f"action_{g}" for g in range(n_groups)]
    c0 = next(iter(cat_fields))

    rules = []
    for g, grp in enumerate(groups):
        a = actions[g]
        field = numeric_fields[g % k]                       # different groups use different fields
        is_affine = {t: (k >= 2 and rng.random() < affine_frac) for t in grp}
        scal = [t for t in grp if not is_affine[t]]
        if len(scal) < 2:                                    # guarantee a threshold gap (=> C) per group
            for t in grp[:2]:
                is_affine[t] = False
            scal = [t for t in grp if not is_affine[t]]
        thetas = np.linspace(0.55, 0.90, max(1, len(scal)))
        si = 0
        for t in grp:
            if is_affine[t]:
                w = rng.normal(0, 1, k); w = w / (np.linalg.norm(w) + 1e-9)
                # place the boundary so the cube center is robustly SAFE (margin ~0.3-0.55): the
                # composite tool fires only for genuinely high-composite points, leaving an R interior
                # while still contributing D-geometry / joint flips near its boundary.
                bias = -float(np.dot(w, 0.5 * np.ones(k))) - float(rng.uniform(0.30, 0.55))
                rules.append({"domain": DOMAIN, "tool_id": t, "candidate_action": a,
                              "categorical_context": {}, "rule_family": "affine",
                              "numeric_fields": numeric_fields, "weights": [float(x) for x in w],
                              "bias": float(bias)})
            else:
                theta = float(thetas[si]); si += 1
                rules.append({"domain": DOMAIN, "tool_id": t, "candidate_action": a,
                              "categorical_context": {}, "rule_family": "scalar_threshold",
                              "numeric_field": field, "unsafe_direction": ">=", "threshold": theta,
                              "threshold_offsets": {c0: {cat_fields[c0][-1]: -0.05}}})
    dc = {"tools": tools, "numeric_fields": numeric_fields, "categorical_fields": cat_fields,
          "candidate_actions": actions, "rules": rules,
          "_tool_action": {r["tool_id"]: r["candidate_action"] for r in rules},
          "_action_field": {actions[g]: numeric_fields[g % k] for g in range(n_groups)}}
    return {"meta": {"synthetic": True, "K": K, "k": k, "x1_size": x1_size, "m": m,
                     "n_groups": n_groups}, "mvp": {"discrete_budget_mvp": 1}, "domains": {DOMAIN: dc}}


def sample_records(rt, n, eps=0.10, seed=0, boundary_frac=0.45):
    rng = np.random.default_rng(seed + 12345)
    dc = rt["domains"][DOMAIN]
    tools, nf = dc["tools"], dc["numeric_fields"]
    cats = dc["categorical_fields"]
    tool_action = dc["_tool_action"]
    action_field = dc["_action_field"]
    theta_by_field = {}
    for r in dc["rules"]:
        if r["rule_family"] == "scalar_threshold":
            theta_by_field.setdefault(r["numeric_field"], []).append(r["threshold"])
    recs = []
    for i in range(n):
        tool = str(rng.choice(tools))
        a = tool_action[tool]                                # action determined by the tool's group
        x1 = {c: str(rng.choice(vals)) for c, vals in cats.items()}
        x2 = {f: float(rng.random()) for f in nf}
        fld = action_field[a]
        if fld in theta_by_field and rng.random() < boundary_frac:
            # cluster the action's threshold field near a threshold -> boosts A/B/C prevalence
            x2[fld] = float(rng.choice(theta_by_field[fld])) + float(rng.uniform(-1.6, 1.6)) * eps
        z = {"domain": DOMAIN, "tool_id": tool, "candidate_action": a,
             "categorical_fields": x1, "numeric_fields": x2}
        res = category(z, a, rt, d=1, eps=eps)
        recs.append({"id": f"syn-{i:07d}", "domain": DOMAIN, "tool_id": tool, "candidate_action": a,
                     "categorical_fields": x1, "numeric_fields": x2,
                     "y": 1 if res["clean_safe"] else 0,
                     "safety_label": "safe" if res["clean_safe"] else "unsafe",
                     "category": res["category"][0]})
    return recs


if __name__ == "__main__":
    from collections import Counter
    rt = make_rule_table(K=8, k=5, x1_size=4, seed=0)
    recs = sample_records(rt, 4000, seed=0)
    print("K=8 k=5 |X1|=4:", dict(Counter(r["category"] for r in recs)))
    print("feature fields:", len(rt["domains"][DOMAIN]["numeric_fields"]), "numeric,",
          sum(len(v) for v in rt["domains"][DOMAIN]["categorical_fields"].values()), "cat values")
