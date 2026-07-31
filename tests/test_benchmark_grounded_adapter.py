#!/usr/bin/env python3
"""
test_benchmark_grounded_adapter.py — the AmPermBench-style adapter produces valid canonical records,
and the local-dir loader works without any network. Run:
    python -m pytest tests/test_benchmark_grounded_adapter.py -q
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

_root = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_root))
sys.path.insert(0, str(_root / "bridge_benchmark" / "generators"))

from bridge_benchmark.benchmarks import ampermbench_adapter as amp  # noqa: E402

REQUIRED = ("uid", "source", "domain", "task_family", "tool_id", "candidate_action",
            "x1", "x2", "label", "oracle", "meta")


def _fixture():
    return amp.build_fixture(n_per_family=80, seed=0)


def test_fixture_covers_all_families():
    recs = _fixture()
    fams = {r["task_family"] for r in recs}
    assert fams == set(amp.TASK_FAMILIES)
    assert len(recs) == 80 * len(amp.TASK_FAMILIES)


def test_records_have_required_keys():
    for r in _fixture():
        for k in REQUIRED:
            assert k in r, f"missing {k} in {r.get('uid')}"
        # spec acceptance: tool_id, x1, x2, candidate_action, label always present
        assert r["tool_id"] and r["candidate_action"]
        assert isinstance(r["x1"], dict) and isinstance(r["x2"], dict)
        assert r["label"] in (0, 1)


def test_x2_all_in_unit_interval():
    for r in _fixture():
        for f, v in r["x2"].items():
            assert 0.0 <= v <= 1.0, f"{f}={v} out of [0,1] in {r['uid']}"


def test_tool_and_action_are_family_valid():
    for r in _fixture():
        fam = amp.TASK_FAMILIES[r["task_family"]]
        assert r["tool_id"] in fam["tools"]
        assert r["candidate_action"] in fam["actions"]
        assert set(r["x2"]) == set(amp.numeric_fields(r["task_family"]))


def test_compute_core_x2_from_sets():
    x2 = amp.compute_core_x2(
        proposed=["a", "b", "c", "d"], authorized={"a", "b"}, protected={"a"})
    assert abs(x2["unauthorized_fraction"] - 0.5) < 1e-9   # c, d unauthorized
    assert abs(x2["protected_fraction"] - 0.25) < 1e-9     # a protected
    assert abs(x2["target_count_norm"] - 0.4) < 1e-9       # 4/10


def test_load_from_dir_roundtrip(tmp_path):
    tasks = [
        {"task_family": "cancel_jobs", "proposed_targets": ["j1", "j2"],
         "authorized_targets": ["j1", "j2"], "protected_targets": [],
         "x1": {"environment": "dev"}, "tool_id": "cluster_job_status",
         "candidate_action": "cancel_jobs"},
        {"task_family": "branch_cleanup", "proposed_targets": ["b1"],
         "authorized_targets": [], "protected_targets": [], "x1": {"remote": "yes"}},
    ]
    p = tmp_path / "tasks.jsonl"
    p.write_text("\n".join(json.dumps(t) for t in tasks), encoding="utf-8")
    recs = amp.load_from_dir(tmp_path)
    assert len(recs) == 2
    by_fam = {r["task_family"]: r for r in recs}
    # first task: all authorized, none protected -> benchmark_set label safe
    assert by_fam["cancel_jobs"]["label"] == 1
    # second task: proposed b1 not in authorized -> unsafe
    assert by_fam["branch_cleanup"]["label"] == 0
    for r in recs:
        for k in REQUIRED:
            assert k in r


def test_load_from_dir_missing_dir_raises():
    import pytest
    with pytest.raises(FileNotFoundError):
        amp.load_from_dir("/nonexistent/ampermbench/dir/xyz")


if __name__ == "__main__":
    import pytest
    raise SystemExit(pytest.main([__file__, "-q"]))
