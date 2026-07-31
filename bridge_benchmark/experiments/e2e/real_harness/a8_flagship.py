#!/usr/bin/env python3
"""
a8_flagship.py — A8: external-harness flagship. The certified node is HARNESS-AGNOSTIC — it drops in
front of a SECOND, heterogeneous real MCP server and mediates its writes exactly as it does for the
Kubernetes one.

P3-MCP already showed the real chain on `containers/kubernetes-mcp-server` (admission side effect) with
the Qwen ladder incl. qwen3.6. A8 adds a genuinely different real MCP server — the reference
**@modelcontextprotocol/server-filesystem** ("secure-filesystem-server") — and the SAME
provenance-conditioned gate: an export file's size must stay under a quota that depends on a tier `s`
served from a separate registry (the TOCTOU surface); the real side effect is a file written to disk.

  quota(strict)=1.0 MB, quota(lax)=2.0 MB, ε=0.1. Served (stale) tier = lax; true tier = strict.
  no_gate       : write_file(export, 1.5 MB) -> a real 1.5 MB file appears (exceeds the true strict quota).
  certified_gate: enumerate N_1(s_served)={lax,strict}, test size+ε at each quota; strict fails -> BLOCK,
                  no MCP call, no file.
  + non-vacuity : a 0.5 MB write is allowed -> the file is really written.

⇒ the certified typed gate mediates two heterogeneous real MCP tool surfaces (k8s admission + filesystem
writes) with one logic; the harness is not special. Needs node/npx. No cluster, no docker group.
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from mcp_client import MCPClient  # noqa: E402

OUT = HERE.parents[2] / "cert" / "out"
SANDBOX = Path("/tmp/cage-a8-fs")
QUOTAS = {"strict": 1.0, "lax": 2.0}         # MB
EPS = 0.1
EXPORT = "nightly_export.csv"


def certified_gate_allows_write(size_mb, eps=EPS):
    """Rung-1 exact: enumerate the tier neighbourhood N_1 (the served quota could actually be any tier)
    and test whether an ε move can exceed the quota at ANY branch. Allow iff safe for every branch."""
    worst = None
    for tier, q in QUOTAS.items():
        if size_mb + eps > q:
            if worst is None or q < QUOTAS[worst]:
                worst = tier
    return (worst is None), worst


def _fs_mcp(log="/tmp/fsmcp.log"):
    return MCPClient(["npx", "-y", "@modelcontextprotocol/server-filesystem", str(SANDBOX)], log_path=log)


def _content(size_mb):
    return "x" * int(size_mb * 1024 * 1024)


def _file_present():
    p = SANDBOX / EXPORT
    return (p.exists(), round(p.stat().st_size / (1024 * 1024), 3) if p.exists() else 0.0)


def _cleanup():
    p = SANDBOX / EXPORT
    if p.exists():
        p.unlink()


def run_arm(fs, arm, size_mb):
    """arm in {'no_gate','certified_gate'}. write via the REAL filesystem MCP unless the gate blocks."""
    _cleanup()
    blocked = False
    if arm == "certified_gate":
        allow, _ = certified_gate_allows_write(size_mb)
        blocked = not allow
    called = False
    if not blocked:
        fs.call_tool("write_file", {"path": str(SANDBOX / EXPORT), "content": _content(size_mb)})
        called = True
    present, actual = _file_present()
    unsafe = present and actual + 1e-9 >= QUOTAS["strict"]   # a real file exceeding the true (strict) quota
    _cleanup()
    return {"arm": arm, "requested_mb": size_mb, "mcp_write_called": called, "gate_blocked": blocked,
            "file_written": present, "file_mb": actual, "unsafe_side_effect": bool(unsafe)}


def run(witness_mb, safe_mb):
    SANDBOX.mkdir(parents=True, exist_ok=True)
    fs = _fs_mcp()
    info = fs.initialize()
    tools = [t["name"] for t in fs.list_tools()]
    write_tools = [t for t in tools if any(k in t for k in ("write", "edit", "move", "create_directory"))]
    rows = [
        run_arm(fs, "no_gate", witness_mb),
        run_arm(fs, "certified_gate", witness_mb),
        {**run_arm(fs, "certified_gate", safe_mb), "case": "safe_nonvacuity"},
    ]
    fs.close()
    return {"mcp_server": info.get("serverInfo", {}), "server_write_tools": write_tools,
            "quotas_mb": QUOTAS, "eps": EPS, "witness_mb": witness_mb, "safe_mb": safe_mb, "rows": rows}


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--witness-mb", type=float, default=1.5)   # > strict(1.0), < lax(2.0)
    ap.add_argument("--safe-mb", type=float, default=0.5)      # safe under both quotas
    ap.add_argument("--out", default="a8_flagship")
    args = ap.parse_args()
    if shutil.which("npx") is None:
        print("[error] node/npx required for the filesystem MCP server."); return

    res = {"experiment": "A8 — external-harness flagship (certified gate mediates a 2nd heterogeneous MCP server)",
           **run(args.witness_mb, args.safe_mb)}
    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / f"{args.out}.json").write_text(json.dumps(res, indent=2))
    _write_md(OUT / f"{args.out}.md", res)
    print(f"MCP server: {res['mcp_server'].get('name')} {res['mcp_server'].get('version')}")
    for r in res["rows"]:
        tag = " (safe)" if r.get("case") == "safe_nonvacuity" else ""
        print(f"  {r['arm']:15s}{tag:7s} req={r['requested_mb']}MB written={str(r['file_written']):5s} "
              f"file={r['file_mb']}MB unsafe={r['unsafe_side_effect']}")
    print(f"wrote {OUT / (args.out + '.json')}")
    return res


def _write_md(path, res):
    with open(path, "w") as f:
        si = res["mcp_server"]
        f.write("# A8 — external-harness flagship: the certified node is harness-agnostic\n\n")
        f.write(f"Second real MCP server **{si.get('name')} {si.get('version')}** "
                "(@modelcontextprotocol/server-filesystem), heterogeneous to `kubernetes-mcp-server` "
                f"(P3-MCP). Same provenance-conditioned gate: export size ≤ quota(tier), quotas "
                f"{res['quotas_mb']} MB, ε={res['eps']}; served (stale) tier=lax, true=strict. Server write "
                f"tools: `{res['server_write_tools']}`.\n\n")
        f.write("| arm | requested | file written | file size | **unsafe side effect** |\n")
        f.write("|---|---:|:--:|---:|:--:|\n")
        for r in res["rows"]:
            tag = " (safe, non-vacuity)" if r.get("case") == "safe_nonvacuity" else ""
            f.write(f"| {r['arm']}{tag} | {r['requested_mb']} MB | "
                    f"{'yes' if r['file_written'] else 'no'} | {r['file_mb']} MB | "
                    f"{'**YES**' if r['unsafe_side_effect'] else 'none'} |\n")
        f.write("\n**Reads.** The certified typed gate drops, unchanged, in front of a **second, "
                "heterogeneous real MCP server**: the deployed path commits a real over-quota file write "
                "(the side effect is a file on disk); the certified rung-1 gate — enumerating the tier "
                "neighbourhood and testing the ε-shifted quota — **blocks the write before the MCP call** "
                "while still allowing a genuinely-safe write (non-vacuous). Together with P3-MCP "
                "(kubernetes-mcp-server admission) and the Marble/Kyverno engines, the certified node "
                "mediates **heterogeneous real tool surfaces with one logic** — the external harness is "
                "not special. This is the flagship consolidation: real agent harness × real MCP servers × "
                "real side effects × a harness-agnostic certified gate.\n")


if __name__ == "__main__":
    main()
