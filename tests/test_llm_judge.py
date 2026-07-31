#!/usr/bin/env python3
"""Tests for experiments/llm_judge_baselines.py (Tier-1 #4).

Fast + offline: the LLM is mocked so no Ollama is required. Covers (a) the verdict parser, (b) the
certified reference row invariant (allow_on_W==0 & cert_FA==0), (c) a --quick run emits the outputs.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

_bench = Path(__file__).resolve().parents[1] / "bridge_benchmark"
for p in ("experiments", "generators", "models", "cert", "agents"):
    sys.path.insert(0, str(_bench / p))

import llm_judge_baselines as J  # noqa: E402


# --------------------------------------------------------------------------- #
# (a) verdict parser
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("raw,expected", [
    ('{"verdict": "allow", "rationale": "ok"}', "allow"),
    ('{"verdict": "deny", "rationale": "no"}', "deny"),
    ('  {"verdict":"ALLOW"}  ', "allow"),
    ("The action is safe, so allow.", "allow"),
    ("This is unsafe, deny the action.", "deny"),
    ("prose then {\"verdict\": \"deny\"} trailing", "deny"),
])
def test_parse_verdict_clear(raw, expected):
    assert J.parse_verdict(raw) == expected


@pytest.mark.parametrize("garbage", ["", "   ", "!!!###", None, "﻿\n\n"])
def test_parse_verdict_garbage_fails_safe_to_deny(garbage):
    assert J.parse_verdict(garbage) == "deny"


def test_parse_verdict_deny_wins_ties():
    # both keywords present -> fail-safe deny
    assert J.parse_verdict("It looks safe but is actually unsafe") == "deny"


def test_parse_guard_verdict():
    assert J.parse_guard_verdict("safe") == "allow"
    assert J.parse_guard_verdict("unsafe\nS1") == "deny"
    assert J.parse_guard_verdict("") == "deny"
    assert J.parse_guard_verdict("garbage words") == "deny"


# --------------------------------------------------------------------------- #
# (b) certified reference row invariant
# --------------------------------------------------------------------------- #
def test_certified_reference_row_is_zero(tmp_path, monkeypatch):
    # force the LLM-unavailable path so the run is instant and offline
    monkeypatch.setattr(J, "ollama_up", lambda endpoint=J.ENDPOINT: (False, "test: forced offline"))
    args = J.build_parser().parse_args(
        ["--quick", "--out", str(tmp_path / "ref")])
    summary = J.run(args)
    ref = summary["stages"]["certified_gate_reference"]
    assert ref["allow_on_W"] == 0.0
    assert ref["cert_FA"] == 0.0
    # LLM stages are skipped, but the structure is still emitted
    assert summary["stages"]["point"]["status"] == "SKIPPED_UNAVAILABLE"
    assert (tmp_path / "ref" / "summary.json").exists()
    assert (tmp_path / "ref" / "summary.csv").exists()
    assert (tmp_path / "ref" / "summary.md").exists()


# --------------------------------------------------------------------------- #
# (c) --quick run with a MOCKED LLM emits all output files + sane metrics
# --------------------------------------------------------------------------- #
def test_quick_run_with_mocked_llm(tmp_path, monkeypatch):
    monkeypatch.setattr(J, "ollama_up", lambda endpoint=J.ENDPOINT: (True, "reachable"))
    monkeypatch.setattr(J, "model_available", lambda model, endpoint=J.ENDPOINT: True)

    # Mock LLM: a POINT-like judge that ALWAYS allows (mimics the predicted point-judge behaviour:
    # allow-on-W ~ 1.0). Guard model returns a plain "safe". This exercises every stage + parsing.
    def fake_raw_complete(model, prompt, endpoint, *, seed, json_format, temperature, timeout=120.0):
        if not json_format:  # guard model path -> plain word
            return "safe"
        return json.dumps({"verdict": "allow", "rationale": "mock"})

    monkeypatch.setattr(J, "raw_complete", fake_raw_complete)

    args = J.build_parser().parse_args(
        ["--quick", "--guard-model", "llama-guard3:1b", "--out", str(tmp_path / "run")])
    summary = J.run(args)

    st = summary["stages"]
    # point judge always-allow -> allow_on_W == 1.0 (the by-construction prediction)
    assert st["point"]["allow_on_W"] == pytest.approx(1.0)
    # cert_FA must be > 0 (allowing C-witnesses is a robust-oracle false-allow)
    assert st["point"]["cert_FA"] > 0.0
    # threat-aware aggregate present with the per-variant/seed breakdown
    assert "allow_on_W_agg" in st["threat_aware"]
    assert st["threat_aware"]["n_seeds"] == 1
    assert len(st["threat_aware"]["per_variant_seed"]) == st["threat_aware"]["n_variants"]
    # guard stage ran (mock allows -> allow_on_W 1.0)
    assert st["guard"]["allow_on_W"] == pytest.approx(1.0)
    # certified reference invariant still holds
    assert st["certified_gate_reference"]["allow_on_W"] == 0.0
    assert st["certified_gate_reference"]["cert_FA"] == 0.0

    for f in ("per_query.jsonl", "summary.json", "summary.csv", "summary.md"):
        assert (tmp_path / "run" / f).exists(), f
    # per_query.jsonl has the expected fields
    lines = (tmp_path / "run" / "per_query.jsonl").read_text().strip().splitlines()
    assert lines
    rec = json.loads(lines[0])
    for k in ("judge_stage", "prompt_variant", "seed", "verdict", "oracle_safe",
              "oracle_category", "is_C_witness"):
        assert k in rec
