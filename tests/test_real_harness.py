#!/usr/bin/env python3
"""
test_real_harness.py — PLAN_2 P3 smoke test. The rung-1 certified gate logic is unit-tested always; the
real-cluster arms run only if an ephemeral kind cluster `cage-p3` with Kyverno + the P3 policy is up
(external infra — skipped otherwise). Asserts: apply-succeeds-under-no-gate / apply-blocked-under-cert.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

_HARNESS = Path(__file__).resolve().parents[1] / "bridge_benchmark" / "experiments" / "e2e" / "real_harness"
sys.path.insert(0, str(_HARNESS))
import run_p3 as p3  # noqa: E402


# --------------------------------------------------------------------------- #
# pure gate logic — always runs (no cluster)
# --------------------------------------------------------------------------- #
def test_certified_gate_blocks_witness():
    allow, worst = p3.certified_gate_allows(6, eps_margin=0)
    assert allow is False               # 6 > strict cap 3 -> the true-tier branch fails
    assert worst[0] == "strict"


def test_certified_gate_allows_safe():
    allow, _ = p3.certified_gate_allows(2, eps_margin=0)
    assert allow is True                # 2 <= 3 and 2 <= 10 -> safe under every tier in N_1


def test_eps_margin_is_conservative():
    # a value at the strict cap is blocked once an eps margin shrinks the threshold
    assert p3.certified_gate_allows(3, eps_margin=0)[0] is True
    assert p3.certified_gate_allows(3, eps_margin=1)[0] is False


# --------------------------------------------------------------------------- #
# real-cluster arms — only if the kind cluster + Kyverno policy are up
# --------------------------------------------------------------------------- #
_cluster = pytest.mark.skipif(not p3.cluster_ready(),
                              reason="kind cluster cage-p3 + Kyverno P3 policy not available")


@_cluster
def test_deployed_admission_commits_side_effect_under_stale():
    r = p3.run_deployed_admission(6)
    assert r["served_tier"] == "lax"
    assert r["side_effect"] is True     # Kyverno trusts the stale binding -> real Deployment created
    p3.delete_witness()


@_cluster
def test_certified_gate_blocks_side_effect_under_stale():
    r = p3.run_certified_gate(6, eps_margin=0)
    assert r["gate_allow"] is False
    assert r["side_effect"] is False    # gate blocks the apply -> no Deployment on the cluster
    p3.delete_witness()


@_cluster
def test_certified_gate_nonvacuous_on_safe_workload():
    r = p3.run_certified_gate(2, eps_margin=0)
    assert r["gate_allow"] is True
    assert r["side_effect"] is True     # genuinely-safe workload still deploys
    p3.delete_witness()


# --------------------------------------------------------------------------- #
# P3-MCP — real MCP write path (needs the cluster AND node/npx for kubernetes-mcp-server)
# --------------------------------------------------------------------------- #
def _mcp_available():
    import shutil
    return p3.cluster_ready() and shutil.which("npx") is not None


_mcp = pytest.mark.skipif(not _mcp_available(),
                          reason="kind cluster + node/npx (kubernetes-mcp-server) not available")


@_mcp
def test_mcp_apply_commits_side_effect_then_gate_blocks():
    import os
    from mcp_client import kubernetes_mcp
    import run_p3_mcp as mcp_loop
    kc = os.environ.get("KUBECONFIG", str(p3.Path.home() / ".kube" / "p3-config"))
    mcp = kubernetes_mcp(kc, log_path="/tmp/kmcp_test.log")
    try:
        mcp.initialize()
        tools = [t["name"] for t in mcp.list_tools()]
        assert mcp_loop.APPLY_TOOL in tools          # the real write path exists
        # mock proposer, no gate -> real MCP apply commits the side effect
        r_none = mcp_loop.episode(mcp, "mock", "none")
        assert r_none["side_effect"] is True
        # mock proposer, certified gate -> blocked before the MCP call -> no side effect
        r_cert = mcp_loop.episode(mcp, "mock", "certified")
        assert r_cert["gate_blocked"] is True
        assert r_cert["side_effect"] is False
    finally:
        mcp.close()
        p3.delete_witness()


@_mcp
def test_mediation_gap_closed_by_gate():
    # #30: the deployed admission misses the scale subresource; the gate-mediated wrapper covers it.
    import os
    from mcp_client import kubernetes_mcp
    import run_p3_mediation as med
    kc = os.environ.get("KUBECONFIG", str(p3.Path.home() / ".kube" / "p3-config"))
    mcp = kubernetes_mcp(kc, log_path="/tmp/kmcp_med_test.log")
    try:
        mcp.initialize()
        dep_scale = med.run_arm(mcp, "deployed_only", "scale")
        assert dep_scale["unsafe_side_effect"] is True     # Kyverno misses scale -> leak
        gate_scale = med.run_arm(mcp, "mediated_gate", "scale")
        assert gate_scale["unsafe_side_effect"] is False    # mediating gate covers scale
        assert gate_scale["gate_blocked_calls"] >= 1
    finally:
        mcp.close()
        p3.delete_witness()
