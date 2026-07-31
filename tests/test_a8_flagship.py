#!/usr/bin/env python3
"""
test_a8_flagship.py — A8. The certified gate mediates a SECOND, heterogeneous real MCP server
(@modelcontextprotocol/server-filesystem): the deployed path writes a real over-quota file; the gate
blocks it before the MCP call; a safe write still goes through. Gate logic runs always; the real MCP
arms need node/npx.
"""
from __future__ import annotations

import shutil
import sys
from pathlib import Path

import pytest

_H = Path(__file__).resolve().parents[1] / "bridge_benchmark" / "experiments" / "e2e" / "real_harness"
sys.path.insert(0, str(_H))
import a8_flagship as a8  # noqa: E402


def test_gate_blocks_over_quota_allows_safe():
    assert a8.certified_gate_allows_write(1.5)[0] is False    # 1.5+0.1 > strict quota 1.0
    assert a8.certified_gate_allows_write(1.5)[1] == "strict"
    assert a8.certified_gate_allows_write(0.5)[0] is True      # safe under every tier quota


@pytest.mark.skipif(shutil.which("npx") is None, reason="node/npx (filesystem MCP server) required")
def test_real_fs_mcp_mediated():
    res = a8.run(witness_mb=1.5, safe_mb=0.5)
    by = {(r["arm"], r.get("case")): r for r in res["rows"]}
    assert by[("no_gate", None)]["unsafe_side_effect"] is True         # real over-quota file written
    assert by[("certified_gate", None)]["file_written"] is False       # gate blocked the write
    assert by[("certified_gate", "safe_nonvacuity")]["file_written"] is True   # safe write allowed
    assert "write_file" in res["server_write_tools"]
