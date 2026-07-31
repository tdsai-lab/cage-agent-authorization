#!/usr/bin/env python3
"""
mcp_client.py — a minimal MCP (Model Context Protocol) stdio JSON-RPC 2.0 client, just enough to drive
`containers/kubernetes-mcp-server` from the P3-MCP loop: spawn the server, initialize, list tools, and
call a tool. Newline-delimited JSON per the MCP stdio transport. Stdlib only.
"""
from __future__ import annotations

import json
import os
import subprocess
import threading
from pathlib import Path


class MCPClient:
    def __init__(self, cmd, env=None, log_path=None):
        self.cmd = cmd
        self._id = 0
        self._log = open(log_path, "w") if log_path else subprocess.DEVNULL
        self.proc = subprocess.Popen(
            cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=self._log,
            text=True, bufsize=1, env={**os.environ, **(env or {})})
        self._lock = threading.Lock()

    def _rpc(self, method, params=None, notify=False, timeout=60):
        with self._lock:
            msg = {"jsonrpc": "2.0", "method": method}
            if params is not None:
                msg["params"] = params
            if not notify:
                self._id += 1
                msg["id"] = self._id
            self.proc.stdin.write(json.dumps(msg) + "\n")
            self.proc.stdin.flush()
            if notify:
                return None
            want = self._id
            while True:
                line = self.proc.stdout.readline()
                if not line:
                    raise RuntimeError(f"MCP server closed stdout (method={method})")
                line = line.strip()
                if not line:
                    continue
                try:
                    resp = json.loads(line)
                except json.JSONDecodeError:
                    continue                      # skip any non-JSON banner line
                if resp.get("id") == want:
                    if "error" in resp:
                        raise RuntimeError(f"MCP error on {method}: {resp['error']}")
                    return resp.get("result")

    def initialize(self, name="cage-p3", version="0.1"):
        res = self._rpc("initialize", {
            "protocolVersion": "2024-11-05", "capabilities": {},
            "clientInfo": {"name": name, "version": version}})
        self._rpc("notifications/initialized", notify=True)
        return res

    def list_tools(self):
        return self._rpc("tools/list").get("tools", [])

    def call_tool(self, name, arguments):
        return self._rpc("tools/call", {"name": name, "arguments": arguments})

    def close(self):
        try:
            self.proc.stdin.close()
            self.proc.terminate()
            self.proc.wait(timeout=10)
        except Exception:
            self.proc.kill()
        if self._log not in (subprocess.DEVNULL, None):
            self._log.close()


def kubernetes_mcp(kubeconfig, log_path=None, read_only=False, disable_destructive=False):
    """Spawn containers/kubernetes-mcp-server over stdio, pointed at `kubeconfig`."""
    cmd = ["npx", "-y", "kubernetes-mcp-server@latest",
           "--kubeconfig", str(kubeconfig), "--log-file", "stderr"]
    if read_only:
        cmd.append("--read-only")
    if disable_destructive:
        cmd.append("--disable-destructive")
    return MCPClient(cmd, log_path=log_path)


if __name__ == "__main__":                      # probe: list the tools
    import sys
    kc = os.environ.get("KUBECONFIG", str(Path.home() / ".kube" / "p3-config"))
    c = kubernetes_mcp(kc, log_path="/tmp/kmcp.log")
    info = c.initialize()
    print("server:", info.get("serverInfo"))
    tools = c.list_tools()
    print(f"\n{len(tools)} tools:")
    for t in tools:
        ann = t.get("annotations", {}) or {}
        hints = ",".join(k for k in ("readOnlyHint", "destructiveHint", "idempotentHint")
                         if ann.get(k))
        print(f"  {t['name']:34s} [{hints}]  {t.get('description','')[:60]}")
    c.close()
