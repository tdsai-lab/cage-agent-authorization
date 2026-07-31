#!/usr/bin/env python3
"""
test_mcp_substrate.py — NEW_MCP_EXP Stage-0 substrate scan. The frozen detector classifies typed fields and
the static parser extracts tool return schemas WITHOUT executing any MCP server. Pure stdlib; no network.

Invariants: detector frozen+hashed; the pipeline-set vs subject-keyed call is conservative (subject→OUT);
substrate requires a typed return with BOTH a continuous operational field AND a pipeline-set provenance
field; the static parser recovers inline + named zod output schemas.
"""
from __future__ import annotations

import sys
from pathlib import Path

_BB = Path(__file__).resolve().parents[1] / "bridge_benchmark"
sys.path.insert(0, str(_BB / "experiments" / "mcp_substrate"))

import substrate_detector as det  # noqa: E402
import stage0_static as s0  # noqa: E402
import openapi_detector as odet  # noqa: E402
import openapi_scan as oscan  # noqa: E402
import openapi_adjudicate as oadj  # noqa: E402


def test_detector_frozen_and_hashed():
    spec = det.frozen_spec()
    assert len(spec["detector_sha256"]) == 64
    assert "continuous_x" in spec["criteria"] and "pipeline_set_s" in spec["criteria"]


def test_field_classification():
    assert det.classify_field("risk_score", "number") == "continuous_x"
    assert det.classify_field("amount", "number") == "continuous_x"
    assert det.classify_field("source_endpoint", "string") == "pipeline_set_s"
    assert det.classify_field("cache_origin", "string") == "pipeline_set_s"
    # subject-keyed entity attributes are OUT (mirror the §6.5 OpenFisca subject-keyed null)
    assert det.classify_field("region", "string") == "subject_keyed"
    assert det.classify_field("account_tier", "string") == "subject_keyed"
    # quantized small enum is NOT continuous (Azure keySize failure mode)
    assert det.classify_field("key_size", "integer", enum=[2048, 3072, 4096]) != "continuous_x"


def test_substrate_requires_continuous_AND_pipeline():
    weather = [{"name": "temperature", "type": "number"}, {"name": "humidity", "type": "number"}]
    assert det.is_substrate(weather) is False                       # continuous, but no provenance
    risk_region = [{"name": "risk_score", "type": "number"}, {"name": "region", "type": "string"}]
    assert det.is_substrate(risk_region) is False                   # provenance is subject-keyed -> OUT
    cwit = [{"name": "risk_score", "type": "number"}, {"name": "source_endpoint", "type": "string"}]
    assert det.is_substrate(cwit) is True                           # continuous + pipeline-set -> substrate


def test_static_parser_recovers_output_schema(tmp_path):
    ts = tmp_path / "t.ts"
    ts.write_text(
        'const S = z.object({ risk: z.number(), source_endpoint: z.string() });\n'
        'server.registerTool("scoreit", { description: "d", inputSchema: { q: z.string() }, '
        'outputSchema: { content: z.string() } }, async () => {});\n')
    tools = s0.parse_ts(ts)
    by = {t["tool"]: t for t in tools}
    assert "scoreit" in by and by["scoreit"]["has_output"]
    # inline outputSchema {content: z.string()} parsed -> a single string field -> NOT substrate
    assert det.is_substrate(by["scoreit"]["return_fields"]) is False


def test_static_parser_named_schema_one_tool_per_file(tmp_path):
    ts = tmp_path / "tool.ts"
    ts.write_text(
        'const name = "weather";\n'
        'const OutSchema = z.object({ temperature: z.number(), conditions: z.string() });\n'
        'const config = { description: "d", inputSchema: InSchema, outputSchema: OutSchema };\n'
        'export const reg = (server) => { server.registerTool(name, config, async () => {}); };\n')
    tools = s0.parse_ts(ts)
    assert len(tools) == 1 and tools[0]["tool"] == "weather"
    labels = [f["label"] for f in det.classify_fields(tools[0]["return_fields"])]
    assert "continuous_x" in labels                                  # temperature recovered as continuous
    assert det.is_substrate(tools[0]["return_fields"]) is False       # but no pipeline-set provenance


# ── OpenAPI scan (NEW_EXP, third frozen-detector scan; zero execution) ───────
def test_openapi_detector_frozen_and_conservative():
    spec = odet.frozen_spec()
    assert len(spec["detector_sha256"]) == 64
    assert odet.classify_field("amount", "number") == "continuous_x"
    assert odet.classify_field("acquirer", "string") == "pipeline_set_s"
    assert odet.classify_field("card_type", "string") == "subject_keyed"     # entity attribute -> OUT
    assert odet.classify_field("country", "string") == "subject_keyed"        # region/country -> OUT
    assert odet.classify_field("count", "integer") == "other"                 # pagination/count, not x
    assert odet.classify_field(True, "boolean") == "other"                    # non-str key coerced safely


def test_openapi_substrate_requires_continuous_AND_pipeline():
    assert odet.is_substrate([{"name": "amount", "type": "number"},
                              {"name": "acquirer", "type": "string"}]) is True
    assert odet.is_substrate([{"name": "amount", "type": "number"},
                              {"name": "card_type", "type": "string"}]) is False   # subject-keyed
    assert odet.is_substrate([{"name": "count", "type": "integer"},
                              {"name": "data_source", "type": "string"}]) is False  # count not continuous


def test_openapi_scan_resolves_refs_and_detects_substrate():
    spec = {"openapi": "3.0.0",
            "paths": {"/charge": {"get": {"responses": {"200": {"content": {"application/json":
                     {"schema": {"$ref": "#/components/schemas/Charge"}}}}}}}},
            "components": {"schemas": {"Charge": {"type": "object", "properties": {
                "amount": {"type": "number"}, "data_source": {"type": "string"},
                "card_type": {"type": "string", "enum": ["visa", "mc"]}}}}}}
    leaves = []
    for _p, _m, _c, sch in oscan._response_schemas(spec):
        oscan._leaves(sch, spec["components"]["schemas"], set(), 0, leaves)
    names = {f["name"] for f in leaves}
    assert {"amount", "data_source", "card_type"} <= names              # $ref resolved
    assert odet.is_substrate(leaves) is True                            # amount(cont) + data_source(pipeline)


def test_openapi_adjudication_conservative_categories():
    # Step-2 conservative adjudication: schema-metadata / subject / dual-use all resolve OUT
    assert oadj.adjudicate("apiVersion") == "SCHEMA_RESOURCE_META"
    assert oadj.adjudicate("resourceVersion") == "SCHEMA_RESOURCE_META"
    assert oadj.adjudicate("routing_number") == "SUBJECT_INSTRUMENT"
    assert oadj.adjudicate("fundingSource") == "SUBJECT_INSTRUMENT"
    assert oadj.adjudicate("source") == "DUALUSE_AMBIGUOUS"
    assert oadj.adjudicate("provider") == "DUALUSE_AMBIGUOUS"           # dual-use -> conservative OUT


# ── EXP-A2: registry-scale Stage-2 substrate adjudication ──────────────────────────
import registry_adjudicate as radj  # noqa: E402


def test_registry_adjudicate_two_pass_conservative():
    # cache/freshness key = the one field both passes confirm as pipeline-set
    final, lex, sem, _ = radj.adjudicate("cache_respected")
    assert final == "CONFIRMED_PIPELINE" and lex == "CONFIRMED_PIPELINE" and sem == "CONFIRMED_PIPELINE"
    # subject/instrument + dual-use fields all resolve OUT (never CONFIRMED)
    for f in ("cloud_provider", "source_origin", "vhf_channel", "product_url", "refRoute", "feed"):
        assert radj.adjudicate(f)[0] != "CONFIRMED_PIPELINE"
    # schema/version metadata OUT
    assert radj.adjudicate("version")[0] == "SCHEMA_RESOURCE_META"
    # disagreement (semantic CONFIRMED, lexical DUALUSE via 'origin') → conservative OUT
    assert radj.adjudicate("data_origin_unverified")[0] != "CONFIRMED_PIPELINE"


def test_registry_adjudicate_frozen_and_wilson():
    assert len(radj._frozen_hash()) == 64
    assert radj.wilson_ci(0, 622) == (0.0, radj.wilson_ci(0, 622)[1]) and radj.wilson_ci(0, 622)[1] > 0
    assert radj.wilson_ci(0, 0) == (0.0, 0.0)


def test_registry_adjudicate_run_null_at_theta_stage():
    if not radj.T2_6_SUMMARY.exists():
        import pytest
        pytest.skip("T2-6 registry summary not present")
    import tempfile
    with tempfile.TemporaryDirectory() as td:
        p = radj.run(radj.T2_6_SUMMARY, Path(td))
    assert p["n_candidate_tools"] == 31 and p["n_candidate_servers"] == 8
    # strong (documented θ(s)) hits = 0 → the fourth informative null; structural residual is small & named
    assert p["n_strong_confirmed_tools_with_documented_theta_s"] == 0
    assert p["n_structurally_confirmed_tools"] <= 2
    assert "cache_respected" in p["s_fields_by_final_category"].get("CONFIRMED_PIPELINE", [])
