#!/usr/bin/env python3
"""Tests for NEW_EXPS Tier-2 #6 (experiments/mcp_substrate/registry_scan.py). Offline: no live network —
the frozen-detector assertion, fixture classification, and a cached/quick-scan output check with a valid
Wilson CI. Network-skip-guarded (uses a tiny prebuilt cache, never a live fetch)."""
from __future__ import annotations

import json
import sys
import urllib.parse
from pathlib import Path

_HERE = Path(__file__).resolve().parent
_MCP = _HERE.parents[0] / "bridge_benchmark" / "experiments" / "mcp_substrate"
sys.path.insert(0, str(_MCP))

import registry_scan as rs  # noqa: E402
import substrate_detector as det  # noqa: E402

# recorded at build time; MUST match the frozen detector (no post-hoc tuning)
RECORDED_DETECTOR_SHA256 = "221aa906dca8a79e5ad3d47abfad1756d93a6ea44a825a0a21e241834b9b57f6"


def test_frozen_detector_hash_matches():
    assert det.frozen_spec()["detector_sha256"] == RECORDED_DETECTOR_SHA256


def test_detector_classifies_fixture_returns():
    # continuous operational x + pipeline-set provenance s  -> substrate
    sub_tool = {"name": "score_txn", "outputSchema": {
        "type": "object", "properties": {
            "risk_score": {"type": "number"},
            "source_endpoint": {"type": "string"},
            "note": {"type": "string"}}}}
    typed, labels, sub = rs.classify_tool(sub_tool)
    assert typed and sub
    lab = {l["name"]: l["label"] for l in labels}
    assert lab["risk_score"] == "continuous_x" and lab["source_endpoint"] == "pipeline_set_s"

    # bare content:string -> typed but NOT substrate (no continuous_x + pipeline_set_s pair)
    bare = {"name": "echo", "outputSchema": {
        "type": "object", "properties": {"content": {"type": "string"}}}}
    typed_b, _, sub_b = rs.classify_tool(bare)
    assert typed_b and not sub_b

    # bare {"type":"object"} with NO properties -> untyped (the reference-corpus / Brave mode)
    empty = {"name": "x", "outputSchema": {"type": "object"}}
    typed_e, labels_e, sub_e = rs.classify_tool(empty)
    assert (not typed_e) and labels_e is None and (not sub_e)

    # continuous-only (weather demo) -> NOT substrate
    weather = {"name": "w", "outputSchema": {"type": "object", "properties": {
        "temperature": {"type": "number"}, "humidity": {"type": "number"}}}}
    _, _, sub_w = rs.classify_tool(weather)
    assert not sub_w


def test_wilson_ci_valid():
    lo, hi = rs.wilson_ci(0, 500)
    assert lo == 0.0 and 0.0 < hi < 0.05        # tight upper bound for a zero-count large-n null
    lo2, hi2 = rs.wilson_ci(5, 100)
    assert 0.0 <= lo2 <= 0.05 <= hi2 <= 1.0
    assert rs.wilson_ci(0, 0) == (0.0, 0.0)


def _seed_cache(cache: Path):
    """Write tiny fixture responses into the on-disk cache so run(offline=True) replays with no network."""
    cache.mkdir(parents=True, exist_ok=True)

    def w(url, obj):
        safe = urllib.parse.quote(url, safe="")
        (cache / (safe[:180] + ".json")).write_text(json.dumps(obj))

    # one Smithery list page (single server), then its detail with one substrate + one bare tool
    w(f"{rs.SMITHERY_LIST}?page=1&pageSize=100",
      {"servers": [{"qualifiedName": "acme/fraud"}],
       "pagination": {"currentPage": 1, "pageSize": 100, "totalPages": 1, "totalCount": 1}})
    w(rs.SMITHERY_DETAIL.format(q=urllib.parse.quote("acme/fraud", safe="")),
      {"qualifiedName": "acme/fraud", "tools": [
          {"name": "score", "outputSchema": {"type": "object", "properties": {
              "risk_score": {"type": "number"}, "upstream": {"type": "string"}}}},
          {"name": "echo", "outputSchema": {"type": "object", "properties": {
              "content": {"type": "string"}}}}]})


def test_quick_scan_emits_files_and_ci(tmp_path):
    out = tmp_path / "exp_mcp_registry"
    _seed_cache(out / "cache")
    payload = rs.run(["smithery"], max_servers=20, out_dir=out, offline=True, sleep=0.0)

    for fn in ("summary.json", "per_server.jsonl", "summary.md"):
        assert (out / fn).exists(), fn
    j = json.loads((out / "summary.json").read_text())
    assert j["frozen_detector_sha256"] == RECORDED_DETECTOR_SHA256
    assert j["n_servers"] == 1 and j["n_tools"] == 2
    assert j["typed_returns"] == 2                 # both tools have an outputSchema with properties
    assert j["n_substrate_hits"] == 1              # only the risk_score+upstream tool
    lo, hi = j["wilson95_over_typed"]
    assert 0.0 <= lo <= j["substrate_rate_over_typed"] <= hi <= 1.0
    # per_server jsonl parses and carries the evidence for the hit
    rows = [json.loads(l) for l in (out / "per_server.jsonl").read_text().splitlines()]
    assert rows and rows[0]["substrate"] == 1 and rows[0]["evidence"]
    assert payload["outcome"] == "SUBSTRATE_PRESENT_candidate_hits"
