#!/usr/bin/env python3
"""
test_benchmark_grounded_oracle.py — the benchmark-set oracle and the policy rule_table behave as
specified: authorized targets are safe, protected/unauthorized targets are unsafe, and the discrete
neighbourhood is schema-valid. Run:
    python -m pytest tests/test_benchmark_grounded_oracle.py -q
"""
from __future__ import annotations

import sys
from pathlib import Path

_root = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_root))
sys.path.insert(0, str(_root / "bridge_benchmark" / "generators"))

from oracle import safe, discrete_swaps, get_rule, _x1  # noqa: E402
from bridge_benchmark.benchmarks import ampermbench_adapter as amp  # noqa: E402
from bridge_benchmark.experiments import benchmark_grounded as bg  # noqa: E402


def test_benchmark_set_label_authorized_safe_protected_unsafe():
    # authorized, none protected -> safe
    ok = amp.compute_core_x2(["a"], {"a"}, set())
    assert amp.benchmark_set_label(ok)[0] == 1
    # touches an unauthorized target -> unsafe
    bad = amp.compute_core_x2(["a", "x"], {"a"}, set())
    assert amp.benchmark_set_label(bad)[0] == 0
    # touches a protected target -> unsafe
    prot = amp.compute_core_x2(["a"], {"a"}, {"a"})
    assert amp.benchmark_set_label(prot)[0] == 0


def test_benchmark_set_rule_table_matches_set_membership():
    rt = bg.make_policy_rule_table("benchmark_set")
    fam = "cancel_jobs"
    dom = amp.TASK_FAMILIES[fam]["domain"]
    tool = amp.TASK_FAMILIES[fam]["tools"][0]
    action = amp.TASK_FAMILIES[fam]["actions"][0]
    nf = amp.numeric_fields(fam)

    def z(unauth, prot):
        x2 = {f: 0.0 for f in nf}
        x2["unauthorized_fraction"] = unauth
        x2["protected_fraction"] = prot
        x2["target_count_norm"] = 0.1
        return {"domain": dom, "tool_id": tool, "candidate_action": action,
                "categorical_fields": {f: v[0] for f, v in amp.TASK_FAMILIES[fam]["x1"].items()},
                "numeric_fields": x2}

    assert safe(z(0.0, 0.0), action, rt) is True          # clean authorized
    assert safe(z(0.5, 0.0), action, rt) is False          # unauthorized fraction
    assert safe(z(0.0, 0.5), action, rt) is False          # protected fraction


def test_hybrid_policy_prod_is_stricter_than_dev():
    """The hybrid policy boundary tightens in prod: a state safe in dev can be unsafe in prod."""
    rt = bg.make_policy_rule_table("hybrid_policy")
    fam = "cancel_jobs"
    dom = amp.TASK_FAMILIES[fam]["domain"]
    tool = amp.TASK_FAMILIES[fam]["tools"][0]
    action = amp.TASK_FAMILIES[fam]["actions"][0]
    nf = amp.numeric_fields(fam)
    base_x1 = {f: v[0] for f, v in amp.TASK_FAMILIES[fam]["x1"].items()}

    def z(env):
        x1 = dict(base_x1); x1["environment"] = env; x1["protected"] = "no"
        x2 = {f: 0.0 for f in nf}
        x2["unauthorized_fraction"] = 0.55
        x2["target_count_norm"] = 0.3
        return {"domain": dom, "tool_id": tool, "candidate_action": action,
                "categorical_fields": x1, "numeric_fields": x2}

    # at a moderately-high blast radius the dev state stays safe while prod flips unsafe
    assert safe(z("dev"), action, rt) is True
    assert safe(z("prod"), action, rt) is False


def test_discrete_neighbors_are_schema_valid():
    rt = bg.make_policy_rule_table("hybrid_policy")
    fam = "service_restart"
    dom = amp.TASK_FAMILIES[fam]["domain"]
    dc = rt["domains"][dom]
    tool = dc["tools"][0]
    x1 = {f: v[0] for f, v in amp.TASK_FAMILIES[fam]["x1"].items()}
    cats = dc["categorical_fields"]
    for t2, x12, r in discrete_swaps(dc, tool, x1, 1):
        assert r == 1                                   # d=1 only
        assert t2 in dc["tools"]                        # tool stays within the family
        for f, v in x12.items():
            assert v in cats[f]                         # every categorical value is schema-valid


if __name__ == "__main__":
    import pytest
    raise SystemExit(pytest.main([__file__, "-q"]))
