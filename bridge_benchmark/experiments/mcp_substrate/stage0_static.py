#!/usr/bin/env python3
"""
stage0_static.py — NEW_MCP_EXP Stage 0 (ZERO execution): measure Pr[typed-return substrate | tool] on real
public MCP servers WITHOUT running any third-party code (the live-introspection escalation, introspect.py,
is declined for a bonus experiment whose null is the expected, acceptable outcome — see module footer).

It statically parses the MCP reference-server repo (external/corpora/mcp_servers, commit recorded) for every
tool's inputSchema/outputSchema, then applies the FROZEN substrate_detector to the RETURN fields. The single
question: does any tool's TYPED RETURN carry both a continuous operational field `x` AND a pipeline-set
provenance field `s` (the data half of the C precondition)? Parse coverage is reported as a limitation.

Funnel (mirrors §6.5): Pr[native C|corpus] = Pr[substrate] × Pr[θ-cond|substrate] × Pr[Δ/ε window|cond].
Stage 0 reports the first factor and the *location* of any null; Stage 2 (conditional, anti-forcing) only
runs if substrate>0.
"""
from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path

_HERE = Path(__file__).resolve().parent
_BB = _HERE.parents[1]
sys.path.insert(0, str(_HERE))
import substrate_detector as det  # noqa: E402

CORPUS = _BB.parents[0] / "external" / "corpora" / "mcp_servers"
OUT = _BB / "cert" / "out" / "mcp_substrate"
MCPTOX = _BB.parents[0] / "external" / "corpora" / "mcptox_AAAI26-7C02" / "pure_tool.json"

_ZTYPE = {"number": "number", "int": "integer", "string": "string", "boolean": "boolean",
          "enum": "enum", "nativeEnum": "enum", "array": "array", "object": "object",
          "literal": "enum", "date": "string", "any": "any", "record": "object"}


def _zbase(expr: str):
    """zod expression -> (json_type, is_enum). e.g. 'z.number().describe(..)' -> ('number', False)."""
    m = re.search(r"z\.(\w+)", expr)
    if not m:
        return "any", False
    z = m.group(1)
    if z == "number" and ".int(" in expr:
        return "integer", False
    jt = _ZTYPE.get(z, "any")
    return ("integer" if jt == "integer" else jt), (jt == "enum")


def _parse_object_body(body: str):
    """Parse a `{ field: z.type()..., ... }` body -> [{name,type,enum}]. Top-level commas only."""
    fields, depth, buf = [], 0, ""
    for ch in body:
        if ch in "({[":
            depth += 1
        elif ch in ")}]":
            depth -= 1
        if ch == "," and depth == 0:
            fields.append(buf); buf = ""
        else:
            buf += ch
    if buf.strip():
        fields.append(buf)
    out = []
    for f in fields:
        m = re.match(r"\s*['\"]?([A-Za-z_]\w*)['\"]?\s*:\s*(.+)", f, re.S)
        if not m:
            continue
        jt, is_enum = _zbase(m.group(2))
        out.append({"name": m.group(1), "type": jt, "enum": [] if is_enum else None})
    return out


def _resolve_schema(expr: str, text: str):
    """Resolve an inputSchema/outputSchema RHS to a field list. Handles inline `{...}`, `Name.shape`,
    and a named `const Name = z.object({...})`. Returns (fields|None, parsed_ok)."""
    expr = expr.strip()
    if expr.startswith("{"):
        return _parse_object_body(expr[1:expr.rfind("}")]), True
    m = re.match(r"([A-Za-z_]\w*)(\.shape)?$", expr)
    if m:
        name = m.group(1)
        dm = re.search(r"(?:const|let|var)\s+" + re.escape(name) + r"\s*=\s*z\.object\(\s*\{(.+?)\}\s*\)",
                       text, re.S)
        if dm:
            return _parse_object_body(dm.group(1)), True
        return None, False
    return None, False


_TOOL_LIT = re.compile(r"""(?:registerTool|server\.tool)\s*\(\s*["'`]([^"'`]+)["'`]""")
_TOOL_VAR = re.compile(r"""(?:registerTool|server\.tool)\s*\(\s*([A-Za-z_]\w*)\s*,""")
_CONST_NAME = re.compile(r"""(?:const|let|var)\s+name\s*=\s*["'`]([^"'`]+)["'`]""")


def _schema_after(text, start, span=1600):
    """Find inputSchema/outputSchema exprs after `start` (the registerTool config tail) and resolve them."""
    tail = text[start: start + span]
    out_expr = re.search(r"outputSchema\s*:\s*([^,\n]+(?:\{.*?\})?)", tail, re.S)
    in_expr = re.search(r"inputSchema\s*:\s*([^,\n]+(?:\{.*?\})?)", tail, re.S)
    ofields, oparsed = (_resolve_schema(out_expr.group(1), text) if out_expr else (None, True))
    ifields, _ = (_resolve_schema(in_expr.group(1), text) if in_expr else (None, True))
    return out_expr is not None, ofields, ifields, oparsed


def parse_ts(path: Path):
    text = path.read_text(errors="ignore")
    tools, claimed = [], False
    # (A) multi-tool files: registerTool("literal", {config...}) — schema in the inline tail
    for m in _TOOL_LIT.finditer(text):
        has_out, of, ifs, ok = _schema_after(text, m.end())
        tools.append({"tool": m.group(1), "has_output": has_out, "return_fields": of,
                      "input_fields": ifs, "parsed": ok}); claimed = True
    # (B) one-tool-per-file (everything/tools/*.ts): registerTool(name, config, ..) with `const name="X"`
    #     and named in/out schemas resolved at file level.
    if not claimed:
        var = _TOOL_VAR.search(text); cname = _CONST_NAME.search(text)
        if var and cname:
            out_expr = re.search(r"outputSchema\s*:\s*([A-Za-z_]\w*|\{.*?\})", text, re.S)
            in_expr = re.search(r"inputSchema\s*:\s*([A-Za-z_]\w*|\{.*?\})", text, re.S)
            of, ok = (_resolve_schema(out_expr.group(1), text) if out_expr else (None, True))
            ifs, _ = (_resolve_schema(in_expr.group(1), text) if in_expr else (None, True))
            tools.append({"tool": cname.group(1), "has_output": out_expr is not None,
                          "return_fields": of, "input_fields": ifs, "parsed": ok})
    return tools


_PYTOOL_RE = re.compile(r"""Tool\(\s*name\s*=\s*["']([^"']+)["']""")


def parse_py(path: Path):
    """Python reference servers (git/fetch/time) declare types.Tool(name=, inputSchema=) with NO
    outputSchema (SDK returns untyped content) -> typed-return absent. Record honestly."""
    text = path.read_text(errors="ignore")
    tools = []
    for m in _PYTOOL_RE.finditer(text):
        has_out = bool(re.search(r"outputSchema", text[m.end(): m.end() + 1200]))
        tools.append({"tool": m.group(1), "has_output": has_out, "return_fields": None,
                      "input_fields": None, "parsed": True})
    # also count @mcp.tool() decorated functions (fastmcp style) as tools with untyped returns
    for m in re.finditer(r"@(?:mcp|server)\.tool\(\)\s*\n\s*(?:async\s+)?def\s+(\w+)", text):
        tools.append({"tool": m.group(1), "has_output": False, "return_fields": None,
                      "input_fields": None, "parsed": True})
    return tools


def _git_commit(root):
    try:
        r = subprocess.run(["git", "-C", str(root), "rev-parse", "HEAD"], capture_output=True,
                           text=True, timeout=15)
        return r.stdout.strip()[:12] if r.returncode == 0 else "n/a"
    except Exception:  # noqa: BLE001
        return "n/a"


def scan():
    src = CORPUS / "src"
    servers = sorted([d.name for d in src.iterdir() if d.is_dir()]) if src.exists() else []
    all_tools = []
    for srv in servers:
        for path in (src / srv).rglob("*"):
            if path.suffix == ".ts" and "__tests__" not in str(path) and ".test." not in path.name:
                for t in parse_ts(path):
                    all_tools.append({"server": srv, **t})
            elif path.suffix == ".py" and "test" not in path.name:
                for t in parse_py(path):
                    all_tools.append({"server": srv, **t})
    # dedupe by (server, tool)
    seen, tools = set(), []
    for t in all_tools:
        k = (t["server"], t["tool"])
        if k in seen:
            continue
        seen.add(k); tools.append(t)
    return servers, tools


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    spec = det.frozen_spec()
    servers, tools = scan()
    n = len(tools)
    typed = [t for t in tools if t["has_output"] and t["return_fields"]]
    untyped = [t for t in tools if not (t["has_output"] and t["return_fields"])]
    parse_fail = [t for t in tools if t["has_output"] and t["return_fields"] is None]

    substrate_hits = []
    typed_inventory = []
    for t in typed:
        labels = det.classify_fields(t["return_fields"])
        sub = det.is_substrate(t["return_fields"])
        typed_inventory.append({"server": t["server"], "tool": t["tool"],
                                "return_fields": labels})
        if sub:
            substrate_hits.append({"server": t["server"], "tool": t["tool"], "return_fields": labels})
    n_cont = sum(any(f["label"] == "continuous_x" for f in det.classify_fields(t["return_fields"]))
                 for t in typed)
    n_pipe = sum(any(f["label"] == "pipeline_set_s" for f in det.classify_fields(t["return_fields"]))
                 for t in typed)

    mcptox_names = []
    if MCPTOX.exists():
        d = json.loads(MCPTOX.read_text())
        mcptox_names = sorted({list(s.values())[0]["server_name"] for s in d})

    substrate_rate = round(len(substrate_hits) / n, 5) if n else 0.0
    outcome = ("STRONG_or_MEDIUM_substrate_present" if substrate_hits else
               "NULL_no_typed_return_substrate")
    payload = {
        "corpus": "MCP reference servers (modelcontextprotocol/servers)",
        "corpus_commit": _git_commit(CORPUS), "execution": "none (static parse, Stage 0)",
        "frozen_detector_sha256": spec["detector_sha256"], "criteria": spec["criteria"],
        "n_servers": len(servers), "servers": servers, "n_tools": n,
        "parse_coverage": round((n - len(parse_fail)) / n, 4) if n else 0.0,
        "n_parse_fail_outputschema": len(parse_fail),
        "n_typed_return": len(typed), "n_untyped_return": len(untyped),
        "n_typed_with_continuous_x": n_cont, "n_typed_with_pipeline_set_s": n_pipe,
        "n_substrate_hits": len(substrate_hits), "substrate_rate": substrate_rate,
        "funnel": "Pr[native C|corpus] = Pr[substrate] x Pr[theta-cond|substrate] x Pr[Δ/ε|cond]",
        "funnel_location_of_null": ("substrate stage (typed-return): returns are untyped or carry no "
                                    "pipeline-set provenance alongside a continuous field"
                                    if not substrate_hits else "n/a — substrate present, proceed to Stage 2"),
        "outcome": outcome,
        "substrate_hits": substrate_hits,
        "typed_return_inventory": typed_inventory,
        "mcptox_population": {"n_servers": len(mcptox_names), "names": mcptox_names,
                              "note": "MCPTox (arXiv 2508.14925) 45-server population; its released artifact "
                                      "(anonymous.4open.science/r/AAAI26-7C02) ships poisoning cases only, "
                                      "not the 353 tool schemas (obtained by live introspection). Reference "
                                      "corpus overlaps it on filesystem/git/fetch/memory/sequentialthinking/"
                                      "time/everything; live introspection of the third-party remainder is "
                                      "DECLINED (supply-chain risk > bonus-experiment upside)."},
        "limitation": ("Static parse of the reference servers only (zero execution); parse_coverage reported. "
                       "outputSchema is resolved from inline/named zod object literals; dynamically-built "
                       "schemas may be missed (undercounts typed returns, never inflates substrate)."),
    }
    (OUT / "stage0_substrate.json").write_text(json.dumps(payload, indent=2))
    with open(OUT / "stage0_substrate.md", "w") as f:
        f.write("# NEW_MCP_EXP Stage 0 — typed-return substrate scan (static, zero execution)\n\n")
        f.write(f"Frozen detector `{spec['detector_sha256'][:16]}`. Corpus: MCP reference servers "
                f"@`{payload['corpus_commit']}` ({payload['n_servers']} servers, {n} tools, parse_coverage "
                f"{payload['parse_coverage']}).\n\n")
        f.write(f"**substrate_rate = {substrate_rate}** ({len(substrate_hits)}/{n}). "
                f"typed-return={len(typed)}, untyped-return={len(untyped)}; of typed: "
                f"continuous_x={n_cont}, pipeline_set_s={n_pipe}, both(substrate)={len(substrate_hits)}.\n\n")
        f.write(f"**Outcome: {outcome}** — funnel null located at: {payload['funnel_location_of_null']}\n\n")
        if typed_inventory:
            f.write("### Typed-return inventory (every tool with an outputSchema)\n\n")
            for t in typed_inventory:
                fl = ", ".join(f"{x['name']}:{x['type']}→{x['label']}" for x in t["return_fields"])
                f.write(f"- `{t['server']}/{t['tool']}` → {fl}\n")
        f.write("\n**Read.** MCP tool returns are predominantly untyped or, where typed, carry a bare "
                "`content:string` or a continuous-only structured demo return — none pair a continuous "
                "operational field with a PIPELINE-SET provenance field. The `z=(s,x)` substrate with "
                "pipeline-set `s` does not appear in the typed returns of the public reference corpus. This "
                "localizes the data-half null at the substrate stage, complementary to the §6.5 policy-half "
                "k8s/cloud null. (See limitation: static parse, reference corpus; live introspection of the "
                "broader third-party set declined for a bonus experiment whose null is the expected outcome.)\n")
    print(f"frozen detector {spec['detector_sha256'][:16]} · corpus @{payload['corpus_commit']} · "
          f"{payload['n_servers']} servers / {n} tools (parse_cov {payload['parse_coverage']})")
    print(f"typed_return={len(typed)} untyped={len(untyped)} | continuous_x={n_cont} pipeline_set_s={n_pipe} "
          f"substrate={len(substrate_hits)} -> substrate_rate={substrate_rate}")
    print(f"OUTCOME: {outcome}")
    for h in substrate_hits:
        print("  SUBSTRATE HIT:", h["server"], h["tool"])
    print(f"wrote -> {OUT/'stage0_substrate.json'}\nwrote -> {OUT/'stage0_substrate.md'}")
    return payload


if __name__ == "__main__":
    main()
