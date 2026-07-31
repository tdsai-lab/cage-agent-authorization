#!/usr/bin/env python3
"""
registry_scan.py — NEW_EXPS Tier-2 #6: scale the typed-return substrate scan (NEW_MCP_EXP) from the 43
public reference servers to the third-party MCP *registries* (Smithery ~6.7k servers, Glama). Same question,
same FROZEN detector (substrate_detector.py, sha256 221aa906…), n×100 servers → the null gets a confidence
interval (or a habitat is discovered). ZERO EXECUTION: we parse only the PUBLISHED tool schemas that the
registry APIs serve as JSON. We never install / `npx` / run any MCP server (that is the deliberately-declined
supply-chain-risky live introspection path, introspect.py). Fetched schemas are cached so re-runs are
deterministic and offline-replayable.

Question (data-half of C): does a real MCP tool's TYPED RETURN (outputSchema) carry BOTH a continuous
operational field `x` AND a pipeline-set provenance field `s` (the z=(s,x) substrate)?

Funnel (mirrors stage0_static.py / openapi_scan.py):
  Pr[native C|corpus] = Pr[substrate] × Pr[θ-cond|substrate] × Pr[Δ/ε window|cond].
This scan reports the FIRST factor (substrate_rate) with a Wilson 95% CI + the *location* of any null.

Registry notes (verified 2026-07):
  • Smithery `registry.smithery.ai/servers` — paginated; per-server detail carries `tools` with real
    `inputSchema` and (for a large minority) `outputSchema`. This is the workhorse: typed returns exist.
  • Glama `glama.ai/api/mcp/v1/servers` — cursor-paginated; the PUBLIC API does not populate tool schemas
    (`tools:[]` in list and detail across a 600-server probe). Glama therefore contributes server COUNTS +
    coverage only; every Glama server is recorded typed_return=absent (honest — never inflates substrate).
Both endpoints answered HTTP 200 unauthenticated; a descriptive User-Agent is sent. If an endpoint 4xx/5xx
or the network drops mid-run, we fall back to whatever is cached and LOG the coverage.
"""
from __future__ import annotations

import argparse
import json
import sys
import time
import urllib.parse
import urllib.request
from math import sqrt
from pathlib import Path

_HERE = Path(__file__).resolve().parent
_BB = _HERE.parents[1]
sys.path.insert(0, str(_HERE))
import substrate_detector as det  # noqa: E402

DEFAULT_OUT = _BB / "cert" / "out" / "exp_mcp_registry"
_UA = {"User-Agent": "mcp-substrate-scan/1.0 (research; zero-exec published-schema fetch)",
       "Accept": "application/json"}

SMITHERY_LIST = "https://registry.smithery.ai/servers"
SMITHERY_DETAIL = "https://registry.smithery.ai/servers/{q}"
GLAMA_LIST = "https://glama.ai/api/mcp/v1/servers"
GLAMA_DETAIL = "https://glama.ai/api/mcp/v1/servers/{id}"


# ── HTTP with on-disk cache (deterministic / offline-replayable) ─────────────
class Fetcher:
    def __init__(self, cache_dir: Path, offline: bool = False, sleep: float = 0.05):
        self.cache = cache_dir
        self.cache.mkdir(parents=True, exist_ok=True)
        self.offline = offline
        self.sleep = sleep
        self.n_net = self.n_cache = self.n_fail = 0

    def _key(self, url: str) -> Path:
        safe = urllib.parse.quote(url, safe="")
        return self.cache / (safe[:180] + ".json")

    def get(self, url: str):
        """Return parsed JSON (dict/list) or None. Cache-first; on live failure fall back to cache."""
        kp = self._key(url)
        if kp.exists():
            self.n_cache += 1
            try:
                return json.loads(kp.read_text())
            except Exception:  # noqa: BLE001
                pass
        if self.offline:
            self.n_fail += 1
            return None
        try:
            req = urllib.request.Request(url, headers=_UA)
            with urllib.request.urlopen(req, timeout=30) as r:
                raw = r.read().decode("utf-8", "ignore")
            data = json.loads(raw)
            kp.write_text(raw)
            self.n_net += 1
            if self.sleep:
                time.sleep(self.sleep)
            return data
        except Exception as e:  # noqa: BLE001
            self.n_fail += 1
            sys.stderr.write(f"  [fetch-fail] {url} :: {type(e).__name__}\n")
            return None


# ── JSON-Schema leaf extraction (the outputSchema analogue of openapi_scan._leaves) ──
_MAX_DEPTH = 6
_MAX_LEAVES = 250


def _leaves(schema, defs, seen, depth, out):
    """Collect scalar leaf fields {name,type,enum,format} from a JSON-Schema object. $ref (#/…), allOf,
    array items, nested objects handled; depth/cycle/leaf-count bounded (undercount only, never inflate)."""
    if not isinstance(schema, dict) or depth > _MAX_DEPTH or len(out) >= _MAX_LEAVES:
        return
    if "$ref" in schema and isinstance(schema["$ref"], str):
        ref = schema["$ref"]
        if ref.startswith("#/") and ref not in seen:
            tgt = defs.get(ref.split("/")[-1])
            if tgt:
                _leaves(tgt, defs, seen | {ref}, depth + 1, out)
        return
    if isinstance(schema.get("allOf"), list):
        for sub in schema["allOf"]:
            _leaves(sub, defs, seen, depth + 1, out)
    props = schema.get("properties")
    if isinstance(props, dict):
        for name, sub in props.items():
            if not isinstance(sub, dict):
                continue
            t = sub.get("type")
            if isinstance(t, list):
                t = next((x for x in t if x != "null"), t[0] if t else None)
            if t == "object" or "properties" in sub or "$ref" in sub or "allOf" in sub:
                _leaves(sub, defs, seen, depth + 1, out)
            elif t == "array":
                _leaves(sub.get("items", {}) or {}, defs, seen, depth + 1, out)
            else:
                out.append({"name": str(name), "type": t, "enum": sub.get("enum"),
                            "format": sub.get("format")})
            if len(out) >= _MAX_LEAVES:
                return
    elif schema.get("type") == "array":
        _leaves(schema.get("items", {}) or {}, defs, seen, depth + 1, out)


def output_leaves(output_schema):
    """outputSchema (JSON Schema dict) -> leaf field list, or [] if untyped/empty. A bare {'type':'object'}
    with no properties is UNTYPED (the Brave-search / reference-corpus mode) -> []."""
    if not isinstance(output_schema, dict):
        return []
    defs = output_schema.get("$defs") or output_schema.get("definitions") or {}
    leaves = []
    _leaves(output_schema, defs, set(), 0, leaves)
    return leaves


# ── per-tool classification via the FROZEN detector ──────────────────────────
def classify_tool(tool: dict):
    """Return (typed:bool, labels:list|None, substrate:bool). typed iff outputSchema resolves to ≥1 leaf."""
    leaves = output_leaves(tool.get("outputSchema"))
    if not leaves:
        return False, None, False
    labels = det.classify_fields(leaves)
    return True, labels, det.is_substrate(leaves)


# ── Smithery ─────────────────────────────────────────────────────────────────
def smithery_server_names(f: Fetcher, max_servers: int, page_size: int = 100):
    names, page, total = [], 1, None
    while len(names) < max_servers:
        data = f.get(f"{SMITHERY_LIST}?page={page}&pageSize={page_size}")
        if not isinstance(data, dict) or not data.get("servers"):
            break
        total = (data.get("pagination") or {}).get("totalCount", total)
        names += [s.get("qualifiedName") for s in data["servers"] if s.get("qualifiedName")]
        pg = data.get("pagination") or {}
        if page >= pg.get("totalPages", page):
            break
        page += 1
    # deterministic order + dedupe, then cap
    names = sorted({n for n in names if n})
    return names[:max_servers], total


def smithery_scan(f: Fetcher, max_servers: int):
    names, total_available = smithery_server_names(f, max_servers)
    per_server = []
    for nm in names:
        d = f.get(SMITHERY_DETAIL.format(q=urllib.parse.quote(nm, safe="")))
        if not isinstance(d, dict):
            continue
        tools = d.get("tools") or []
        rec = _tally_server("smithery", nm, tools)
        per_server.append(rec)
    return per_server, total_available, len(names)


# ── Glama (server counts + coverage only; public API serves no tool schemas) ──
def glama_scan(f: Fetcher, max_servers: int, page_size: int = 100):
    per_server, cursor, n = [], None, 0
    while n < max_servers:
        url = f"{GLAMA_LIST}?first={page_size}" + (f"&after={cursor}" if cursor else "")
        data = f.get(url)
        if not isinstance(data, dict) or not data.get("servers"):
            break
        for s in data["servers"]:
            if n >= max_servers:
                break
            sid = s.get("id") or s.get("slug") or s.get("name")
            tools = s.get("tools") or []          # empty on the public API -> all untyped (honest)
            per_server.append(_tally_server("glama", sid, tools))
            n += 1
        pi = data.get("pageInfo") or {}
        if not pi.get("hasNextPage"):
            break
        cursor = pi.get("endCursor")
    return per_server, n


def _tally_server(registry: str, name, tools):
    n_tools = typed = cont = pipe = subst = 0
    evidence = []
    for t in tools or []:
        if not isinstance(t, dict):
            continue
        n_tools += 1
        is_typed, labels, sub = classify_tool(t)
        if not is_typed:
            continue
        typed += 1
        cont += int(any(l["label"] == "continuous_x" for l in labels))
        pipe += int(any(l["label"] == "pipeline_set_s" for l in labels))
        if sub:
            subst += 1
            evidence.append({"tool": t.get("name"), "return_fields": labels})
    return {"registry": registry, "server": name, "n_tools": n_tools, "typed_returns": typed,
            "continuous_x": cont, "pipeline_set_s": pipe, "substrate": subst, "evidence": evidence}


# ── Wilson score interval (binomial, the point of scaling) ───────────────────
def wilson_ci(k: int, n: int, z: float = 1.959963984540054):
    if n == 0:
        return (0.0, 0.0)
    p = k / n
    z2 = z * z
    denom = 1 + z2 / n
    center = (p + z2 / (2 * n)) / denom
    half = (z * sqrt(p * (1 - p) / n + z2 / (4 * n * n))) / denom
    return (max(0.0, round(center - half, 6)), min(1.0, round(center + half, 6)))


def run(registries, max_servers, out_dir: Path, offline: bool, sleep: float):
    out_dir.mkdir(parents=True, exist_ok=True)
    cache = out_dir / "cache"
    f = Fetcher(cache, offline=offline, sleep=sleep)
    spec = det.frozen_spec()

    per_server, per_reg = [], {}
    for reg in registries:
        if reg == "smithery":
            recs, avail, n_scanned = smithery_scan(f, max_servers)
            per_reg["smithery"] = {"n_servers_scanned": n_scanned, "n_servers_available": avail,
                                   "capped": (avail is not None and n_scanned < avail)}
        elif reg == "glama":
            recs, n_scanned = glama_scan(f, max_servers)
            per_reg["glama"] = {"n_servers_scanned": n_scanned, "n_servers_available": None,
                                "note": "public API serves no tool schemas (tools:[]); counts+coverage only"}
        else:
            sys.stderr.write(f"  [skip] unknown registry {reg}\n")
            continue
        per_server += recs

    # per-registry substrate tallies
    for reg in per_reg:
        rr = [r for r in per_server if r["registry"] == reg]
        per_reg[reg].update({
            "n_tools": sum(r["n_tools"] for r in rr),
            "typed_returns": sum(r["typed_returns"] for r in rr),
            "continuous_x": sum(r["continuous_x"] for r in rr),
            "pipeline_set_s": sum(r["pipeline_set_s"] for r in rr),
            "substrate_hits": sum(r["substrate"] for r in rr)})

    n_servers = len(per_server)
    n_tools = sum(r["n_tools"] for r in per_server)
    typed = sum(r["typed_returns"] for r in per_server)
    n_cont = sum(r["continuous_x"] for r in per_server)
    n_pipe = sum(r["pipeline_set_s"] for r in per_server)
    hits = sum(r["substrate"] for r in per_server)

    # substrate_rate over TYPED returns (the meaningful denominator: an untyped return cannot be substrate);
    # also report over all tools for comparability with the reference-corpus per-tool rate.
    rate_typed = round(hits / typed, 6) if typed else 0.0
    rate_alltools = round(hits / n_tools, 6) if n_tools else 0.0
    ci_typed = wilson_ci(hits, typed)
    ci_alltools = wilson_ci(hits, n_tools)
    outcome = ("SUBSTRATE_PRESENT_candidate_hits" if hits else "NULL_no_typed_return_substrate")

    payload = {
        "experiment": "NEW_EXPS Tier-2 #6 — MCP registry-scale typed-return substrate scan",
        "corpus": "third-party MCP registries: " + ", ".join(registries),
        "execution": "none (zero-execution: published registry-API tool schemas parsed as JSON; "
                     "no server installed / npx'd / run — that is the declined introspect.py path)",
        "frozen_detector_sha256": spec["detector_sha256"], "criteria": spec["criteria"],
        "max_servers_cap_per_registry": max_servers,
        "n_servers": n_servers, "n_tools": n_tools,
        "typed_returns": typed, "untyped_returns": n_tools - typed,
        "typed_return_coverage": round(typed / n_tools, 4) if n_tools else 0.0,
        "n_typed_with_continuous_x": n_cont, "n_typed_with_pipeline_set_s": n_pipe,
        "n_substrate_hits": hits,
        "substrate_rate_over_typed": rate_typed, "wilson95_over_typed": ci_typed,
        "substrate_rate_over_all_tools": rate_alltools, "wilson95_over_all_tools": ci_alltools,
        "per_registry": per_reg,
        "funnel": "Pr[native C|corpus] = Pr[substrate] x Pr[theta-cond|substrate] x Pr[Δ/ε|cond]",
        "funnel_location_of_null": ("substrate stage (typed return): typed returns exist at registry scale "
                                    "but none pairs a continuous operational field with a PIPELINE-SET "
                                    "provenance field" if not hits
                                    else "n/a — candidate substrate present; adjudicate (Stage 2)"),
        "outcome": outcome,
        "fetch": {"net": f.n_net, "cache": f.n_cache, "fail": f.n_fail, "offline": offline},
        "substrate_hits": [r for r in per_server if r["substrate"]][:100],
        "note": ("Smithery serves real inputSchema/outputSchema per tool; a bare {'type':'object'} "
                 "outputSchema with no properties is UNTYPED (the reference-corpus mode) and cannot be "
                 "substrate. Glama's public API serves no tool schemas -> its servers are recorded "
                 "typed_return=absent (honest; never inflates substrate). Any hit is a CANDIDATE from the "
                 "frozen automated detector and would need Stage-2 manual adjudication (pipeline-set vs "
                 "subject-keyed), exactly as in openapi_adjudicate.py."),
        "limitation": ("Zero-execution: we parse published schemas, not runtime returns; dynamically-built "
                       "outputSchemas and servers whose registry omits an outputSchema are undercounted (an "
                       "honest undercount of typed returns, logged as coverage — never inflates substrate). "
                       "Smithery paginates with a page cap; the cap and total-available are logged. Glama "
                       "contributes counts only. Live third-party introspection remains DECLINED "
                       "(supply-chain risk > bonus-experiment upside)."),
    }

    (out_dir / "summary.json").write_text(json.dumps(payload, indent=2))
    with open(out_dir / "per_server.jsonl", "w") as fh:
        for r in per_server:
            fh.write(json.dumps(r) + "\n")
    _write_md(out_dir / "summary.md", payload)

    print(f"frozen detector {spec['detector_sha256'][:16]} · registries={registries} "
          f"(net={f.n_net} cache={f.n_cache} fail={f.n_fail})")
    print(f"n_servers={n_servers} n_tools={n_tools} typed_returns={typed} "
          f"(coverage {payload['typed_return_coverage']})")
    print(f"continuous_x={n_cont} pipeline_set_s={n_pipe} substrate={hits}")
    print(f"substrate_rate(over typed)={rate_typed} Wilson95={ci_typed}  |  "
          f"(over all tools)={rate_alltools} Wilson95={ci_alltools}")
    print(f"OUTCOME: {outcome}")
    for r in [r for r in per_server if r["substrate"]][:15]:
        print("  SUBSTRATE HIT:", r["registry"], r["server"], r["evidence"])
    print(f"wrote -> {out_dir/'summary.json'}\nwrote -> {out_dir/'per_server.jsonl'}\n"
          f"wrote -> {out_dir/'summary.md'}")
    return payload


def _write_md(path: Path, p: dict):
    with open(path, "w") as f:
        f.write("# NEW_EXPS T2-6 — MCP registry-scale typed-return substrate scan (zero execution)\n\n")
        f.write(f"Frozen detector `{p['frozen_detector_sha256'][:16]}` (identical to the reference-server "
                f"scan). Corpus: {p['corpus']}. Execution: {p['execution']}\n\n")
        f.write(f"**substrate_rate = {p['substrate_rate_over_typed']}** over {p['typed_returns']} typed "
                f"returns (Wilson 95% CI {p['wilson95_over_typed']}); "
                f"{p['substrate_rate_over_all_tools']} over all {p['n_tools']} tools "
                f"(Wilson 95% CI {p['wilson95_over_all_tools']}).\n\n")
        f.write("### Funnel\n\n")
        f.write("| stage | count |\n|---|---|\n")
        f.write(f"| servers scanned | {p['n_servers']} |\n")
        f.write(f"| tools | {p['n_tools']} |\n")
        f.write(f"| typed returns (outputSchema w/ properties) | {p['typed_returns']} "
                f"(coverage {p['typed_return_coverage']}) |\n")
        f.write(f"| typed w/ continuous_x | {p['n_typed_with_continuous_x']} |\n")
        f.write(f"| typed w/ pipeline_set_s | {p['n_typed_with_pipeline_set_s']} |\n")
        f.write(f"| substrate (both, frozen detector) | {p['n_substrate_hits']} |\n\n")
        f.write("### Per-registry\n\n| registry | servers (scanned/avail) | tools | typed | cont_x | "
                "pipe_s | substrate |\n|---|---|---|---|---|---|---|\n")
        for reg, d in p["per_registry"].items():
            avail = d.get("n_servers_available")
            f.write(f"| {reg} | {d.get('n_servers_scanned')}/{avail if avail is not None else '?'} | "
                    f"{d.get('n_tools',0)} | {d.get('typed_returns',0)} | {d.get('continuous_x',0)} | "
                    f"{d.get('pipeline_set_s',0)} | {d.get('substrate_hits',0)} |\n")
        f.write(f"\n**Outcome: {p['outcome']}** — funnel null located at: {p['funnel_location_of_null']}\n\n")
        f.write(f"Fetch: net={p['fetch']['net']} cache={p['fetch']['cache']} fail={p['fetch']['fail']} "
                f"(offline={p['fetch']['offline']}).\n\n")
        f.write(f"**Note.** {p['note']}\n\n**Limitation.** {p['limitation']}\n")


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--registries", nargs="+", default=["smithery", "glama"],
                    choices=["smithery", "glama"])
    ap.add_argument("--max-servers", type=int, default=800,
                    help="cap on servers scanned PER registry (logged alongside total-available)")
    ap.add_argument("--out", type=Path, default=DEFAULT_OUT)
    ap.add_argument("--offline", action="store_true", help="cache-only (no live HTTP); fails soft")
    ap.add_argument("--sleep", type=float, default=0.05, help="polite inter-request sleep (s)")
    ap.add_argument("--quick", action="store_true",
                    help="small scan (--max-servers 20), offline if cache present")
    a = ap.parse_args()
    if a.quick:
        a.max_servers = min(a.max_servers, 20)
    run(a.registries, a.max_servers, a.out, a.offline, a.sleep)


if __name__ == "__main__":
    main()
