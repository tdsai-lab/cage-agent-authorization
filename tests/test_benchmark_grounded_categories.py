#!/usr/bin/env python3
"""
test_benchmark_grounded_categories.py — category assignment on benchmark-grounded data, with the
defining property of Category C (joint-only failure) checked explicitly, and the experiment command
writing its metrics/report files. Run:
    python -m pytest tests/test_benchmark_grounded_categories.py -q
"""
from __future__ import annotations

import json
import sys
from collections import Counter
from pathlib import Path

_root = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_root))
sys.path.insert(0, str(_root / "bridge_benchmark" / "generators"))

from oracle import (discrete_reachable_unsafe, continuous_reachable_unsafe,  # noqa: E402
                    joint_reachable_unsafe, safe)
from bridge_benchmark.benchmarks import ampermbench_adapter as amp  # noqa: E402
from bridge_benchmark.experiments import benchmark_grounded as bg  # noqa: E402

EPS, D = 0.10, 1


def _internal(mode="hybrid_policy", n=300):
    recs = amp.build_fixture(n_per_family=n, seed=0)
    rt = bg.make_policy_rule_table(mode)
    return bg.label_and_categorize(recs, rt, eps=EPS, d=D), rt


def test_hybrid_policy_yields_all_reported_categories():
    internal, _ = _internal()
    counts = Counter(r["category"] for r in internal)
    # acceptance criterion: counts exist for R/A/C/U (B is structurally rarer); C must be present
    for c in ("A", "C", "R", "U"):
        assert counts.get(c, 0) > 0, f"category {c} absent: {dict(counts)}"


def test_category_C_is_joint_only_failure():
    internal, rt = _internal()
    Cs = [r for r in internal if r["category"] == "C"]
    assert Cs, "no Category C records to check"
    for r in Cs[:200]:
        a = r["candidate_action"]
        assert safe(r, a, rt) is True                                              # clean_safe
        assert discrete_reachable_unsafe(r, a, rt, D)["reachable"] is False        # disc-only safe
        assert continuous_reachable_unsafe(r, a, rt, EPS)["reachable"] is False    # cont-only safe
        assert joint_reachable_unsafe(r, a, rt, D, EPS)["reachable"] is True       # joint unsafe
        assert "witness" in r and r["witness"]["safe_z_prime"] == 0                # witness stored


def test_benchmark_set_mode_has_few_or_no_C():
    internal, _ = _internal(mode="benchmark_set")
    counts = Counter(r["category"] for r in internal)
    # faithful set-membership mode has a degenerate continuous channel -> no joint-only C
    assert counts.get("C", 0) == 0


def test_runner_writes_metrics_and_report(tmp_path):
    from bridge_benchmark.experiments import run_benchmark_grounded_cert as runner
    recs_path = tmp_path / "recs.jsonl"
    recs = amp.build_fixture(n_per_family=300, seed=0)
    with recs_path.open("w", encoding="utf-8") as fh:
        for r in recs:
            fh.write(json.dumps(r) + "\n")
    out = tmp_path / "out"
    rc = runner.main([
        "--records", str(recs_path), "--oracle-mode", "hybrid_policy",
        "--epsilon", "0.10", "--d", "1", "--sigma", "0.10", "--tau", "0.90",
        "--n-mc", "300", "--n-cert", "12", "--n-attack", "20", "--seed", "0",
        "--out", str(out)])
    assert rc == 0
    for f in ("metrics.json", "records_with_categories.jsonl", "report.md", "config.json"):
        assert (out / f).exists(), f"missing output {f}"
    metrics = json.loads((out / "metrics.json").read_text())
    assert "category_counts" in metrics and "cert_false_allow" in metrics
    assert metrics["cert_false_allow"] == 0.0          # soundness must hold
    assert metrics["naive_C_falseallow"] == 1.0        # non-composition on C


if __name__ == "__main__":
    import pytest
    raise SystemExit(pytest.main([__file__, "-q"]))
