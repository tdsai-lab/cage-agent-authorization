#!/usr/bin/env python3
"""
introspect.py — NEW_MCP_EXP DEFERRED escalation (Option 2). **NOT run in the shipped experiment.**

Decision (see RESULTS Experiment MCP-SUBSTRATE and NEW_MCP_EXP_TO_DO): the live-introspection corpus is
gated behind a free, zero-execution Stage 0 (`stage0_static.py`). Stage 0 returned substrate_rate=0 — no
typed MCP return pairs a continuous operational field with a pipeline-set provenance field — so there is NO
target to justify executing third-party code, and this script is DECLINED. The risk asymmetry is decisive:
executing external packages on a research machine for a bonus experiment whose null is the expected,
acceptable outcome violates the "cannot lose credibility" precondition.

If (and only if) a future Stage 0 finds a genuine operational typed-return target, this is re-enabled
RESTRICTED to FIRST-PARTY `@modelcontextprotocol/*` servers (Option 2) — never the arbitrary third-party
set (Option 1, permanently declined). It spawns each server and captures the EXACT JSON Schema via the
`initialize` + `tools/list` handshake (tools/list is static metadata; no tool calls). A hard `--allow-execution`
flag is required to run at all. Unreachable servers are recorded with the failure reason (never imputed).
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from pathlib import Path

_HERE = Path(__file__).resolve().parent
_BB = _HERE.parents[1]
OUT = _BB / "cert" / "out" / "mcp_substrate"

# Frozen server set: (key, MCPTox_name, launcher) — npm via npx -y, or python via uvx. Dummy env lets
# credential-gated servers start far enough to answer tools/list. Args kept minimal/benign.
DUMMY_ENV = {
    "GITHUB_PERSONAL_ACCESS_TOKEN": "x", "GITLAB_PERSONAL_ACCESS_TOKEN": "x", "GITLAB_API_URL": "https://gitlab.com/api/v4",
    "GOOGLE_MAPS_API_KEY": "x", "BRAVE_API_KEY": "x", "SLACK_BOT_TOKEN": "xoxb-x", "SLACK_TEAM_ID": "T0",
    "EVERART_API_KEY": "x", "SENTRY_AUTH_TOKEN": "x", "REDIS_URL": "redis://localhost:6379",
    "PERPLEXITY_API_KEY": "x", "TAVILY_API_KEY": "x",
}
# Option-2 set ONLY: first-party @modelcontextprotocol/* reference servers (+ official uvx servers). The
# arbitrary third-party set (Option 1: github/gitlab/slack/brave/redis/sentry/puppeteer/...) is permanently
# declined and intentionally NOT listed here.
SERVERS = [
    ("filesystem", "FileSystem", ["npx", "-y", "@modelcontextprotocol/server-filesystem", "/tmp/mcp_sandbox"]),
    ("memory", "Memory", ["npx", "-y", "@modelcontextprotocol/server-memory"]),
    ("everything", "Everything", ["npx", "-y", "@modelcontextprotocol/server-everything"]),
    ("sequentialthinking", "Sequential Thinking", ["npx", "-y", "@modelcontextprotocol/server-sequential-thinking"]),
    ("git", "Git", ["uvx", "mcp-server-git"]),
    ("fetch", "Fetch", ["uvx", "mcp-server-fetch"]),
    ("time", "Time", ["uvx", "mcp-server-time"]),
]

_HANDSHAKE = [
    {"jsonrpc": "2.0", "id": 1, "method": "initialize",
     "params": {"protocolVersion": "2025-06-18", "capabilities": {},
                "clientInfo": {"name": "substrate-scan", "version": "0"}}},
    {"jsonrpc": "2.0", "method": "notifications/initialized"},
    {"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
]


def introspect(cmd, timeout=120):
    """Spawn an MCP stdio server, send the handshake, return (tools|None, error|None)."""
    env = {**os.environ, **DUMMY_ENV}
    stdin = "\n".join(json.dumps(m) for m in _HANDSHAKE) + "\n"
    try:
        proc = subprocess.run(cmd, input=stdin, capture_output=True, text=True, timeout=timeout, env=env)
    except subprocess.TimeoutExpired as e:
        out = (e.stdout or "") if isinstance(e.stdout, str) else ""
        return _parse_tools(out) or (None, "timeout")
    except FileNotFoundError:
        return None, "launcher_not_found"
    tools, _ = _parse_tools_with_err(proc.stdout)
    if tools is not None:
        return tools, None
    return None, f"no_tools_list (rc={proc.returncode}; stderr={proc.stderr.strip()[:160]})"


def _parse_tools_with_err(stdout):
    for line in stdout.splitlines():
        line = line.strip()
        if not line or not line.startswith("{"):
            continue
        try:
            o = json.loads(line)
        except Exception:  # noqa: BLE001
            continue
        if o.get("id") == 2 and isinstance(o.get("result"), dict) and "tools" in o["result"]:
            return o["result"]["tools"], None
    return None, "no_tools_list"


def _parse_tools(stdout):
    t, _ = _parse_tools_with_err(stdout)
    return (t, None) if t is not None else None


def main():
    if "--allow-execution" not in sys.argv:
        print("REFUSED: introspect.py executes third-party MCP server packages (npx/uvx). It is the DEFERRED "
              "Option-2 escalation and is DECLINED in the shipped experiment (Stage 0 substrate_rate=0 → no "
              "target). Re-enable only on a genuine Stage-0 target, first-party servers only, with "
              "--allow-execution. See module docstring + RESULTS Experiment MCP-SUBSTRATE.")
        return None
    OUT.mkdir(parents=True, exist_ok=True)
    corpus, status = [], []
    for key, mcptox_name, cmd in SERVERS:
        t0 = time.time()
        tools, err = introspect(cmd)
        dt = round(time.time() - t0, 1)
        if tools is None:
            status.append({"server": key, "mcptox_name": mcptox_name, "reachable": False,
                           "n_tools": 0, "error": err, "secs": dt})
            print(f"  [{key:20s}] UNREACHABLE ({err}) {dt}s", flush=True)
            continue
        for t in tools:
            corpus.append({"server": key, "mcptox_name": mcptox_name, "tool": t.get("name"),
                           "description": t.get("description", ""),
                           "inputSchema": t.get("inputSchema"), "outputSchema": t.get("outputSchema")})
        n_out = sum(1 for t in tools if t.get("outputSchema"))
        status.append({"server": key, "mcptox_name": mcptox_name, "reachable": True,
                       "n_tools": len(tools), "n_outputSchema": n_out, "secs": dt})
        print(f"  [{key:20s}] {len(tools):3d} tools ({n_out} with outputSchema) {dt}s", flush=True)

    payload = {"servers_attempted": len(SERVERS),
               "servers_reachable": sum(s["reachable"] for s in status),
               "n_tools_total": len(corpus),
               "n_tools_with_outputSchema": sum(1 for c in corpus if c["outputSchema"]),
               "status": status, "corpus": corpus}
    (OUT / "tool_corpus.json").write_text(json.dumps(payload, indent=2))
    print(f"\nreachable {payload['servers_reachable']}/{payload['servers_attempted']} servers, "
          f"{payload['n_tools_total']} tools ({payload['n_tools_with_outputSchema']} with outputSchema)")
    print(f"wrote -> {OUT/'tool_corpus.json'}")
    return payload


if __name__ == "__main__":
    sys.exit(0 if main() else 0)
