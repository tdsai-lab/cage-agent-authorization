#!/usr/bin/env python3
"""NEW_EXPS_7 Part C — held-out policy/schema generalization.

Checks: the held-out threshold split is DISJOINT from training (every scalar threshold shifts); the
held-out tool is removed from the training pool; and the full eval keeps the certified gate SOUND
(cert_false_allow = certified_adaptive_false_allow = 0) across all three conditions.
"""
import csv
import sys
from pathlib import Path

_root = Path(__file__).resolve().parents[1] / "bridge_benchmark"
for p in ("generators", "models", "cert", "experiments", "attacks", "agents"):
    sys.path.insert(0, str(_root / p))

import pytest  # noqa: E402
from synthetic_tools import make_rule_table, sample_records, DOMAIN  # noqa: E402
import generalization_eval as ge  # noqa: E402


def _scalar_thresholds(rt):
    return [r["threshold"] for r in rt["domains"][DOMAIN]["rules"] if r["rule_family"] == "scalar_threshold"]


def test_held_out_threshold_split_is_disjoint():
    rt = make_rule_table(K=8, k=5, x1_size=4, seed=0)
    rt_test = ge.shift_thresholds(rt, -0.05)
    tr, te = _scalar_thresholds(rt), _scalar_thresholds(rt_test)
    assert len(tr) == len(te) and len(tr) > 0
    # every threshold moved by exactly the shift => Θ_test ∩ Θ_train = ∅ (disjoint policy)
    for a, b in zip(tr, te):
        assert abs((a - 0.05) - b) < 1e-9
    assert set(round(x, 6) for x in tr).isdisjoint(round(x, 6) for x in te)


def test_held_out_tool_removed_from_training_pool():
    rt = make_rule_table(K=8, k=5, x1_size=4, seed=0)
    pool = sample_records(rt, 3000, eps=0.10, seed=0)
    held = "tool_01"
    no_tool = [r for r in pool if r["tool_id"] != held]
    assert all(r["tool_id"] != held for r in no_tool)
    assert any(r["tool_id"] == held for r in pool)        # the tool DOES exist in the full pool


def test_shift_thresholds_does_not_mutate_input():
    rt = make_rule_table(K=8, k=5, x1_size=4, seed=0)
    before = _scalar_thresholds(rt)
    ge.shift_thresholds(rt, -0.05)
    assert _scalar_thresholds(rt) == before          # deepcopy, original untouched


def test_generalization_eval_sound(tmp_path):
    ge.main(["--n-train", "1500", "--n-eval-per-cat", "6", "--n-mc", "150",
             "--out-dir", str(tmp_path)])
    with open(tmp_path / "summary.csv") as f:
        rows = {r["condition"]: r for r in csv.DictReader(f)}
    assert set(rows) == {"in_distribution", "held_out_threshold", "held_out_tool"}
    for cond, r in rows.items():
        assert float(r["cert_false_allow"]) == 0.0, f"{cond} certified false-allow != 0"
        assert float(r["certified_adaptive_false_allow"]) == 0.0, f"{cond} cert adaptive FA != 0"


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
