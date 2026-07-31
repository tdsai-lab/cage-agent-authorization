#!/usr/bin/env python3
"""
test_engine_idiomaticity.py — PLAN_2_RESCAN_BIS Workstream B1. The per-engine idiomaticity inventory is a
QUALITATIVE companion to the structural scan: it must (i) emit NO prevalence rate, (ii) place itself below
structural prevalence and above permits-in-principle, (iii) carry first-class/partial verdicts grounded by
a construct + a shipped example + an evidence tier. No cloned corpora needed (curated inventory).
"""
from __future__ import annotations

import sys
from pathlib import Path

_BB = Path(__file__).resolve().parents[1] / "bridge_benchmark"
sys.path.insert(0, str(_BB / "experiments" / "detector"))

import engine_idiomaticity as ei  # noqa: E402


def test_inventory_emits_no_rate():
    payload = ei.build_inventory()
    assert payload["emits_rate"] is False
    # no field anywhere should look like a prevalence rate
    blob = str(payload).lower()
    assert "idiom_rate" not in blob and "prevalence_rate" not in blob


def test_every_entry_is_grounded():
    for e in ei.INVENTORY:
        assert e.first_class in ("yes", "partial", "no")
        assert e.evidence_tier in ("on_disk_verified", "public_docs")
        assert e.construct and e.shipped            # a named construct + a concrete shipped example
        assert e.s_typical in ("subject_self_reported", "provenance_upstream", "typology", "mixed")


def test_decision_table_engines_are_first_class():
    by = {e.engine: e for e in ei.INVENTORY}
    # the decision-table engines (DMN, ZEN) and the AML band/score engines must be first-class
    assert by["DMN / FEEL decision table"].first_class == "yes"
    assert by["GoRules ZEN / JDM"].first_class == "yes"
    assert by["Tazama (tazama-lf)"].first_class == "yes"
    # general policy engines express it but not as a dedicated construct
    assert by["OPA / Rego"].first_class == "partial"


def test_summary_counts_consistent():
    payload = ei.build_inventory()
    s = payload["summary"]
    assert s["n_engines"] == len(ei.INVENTORY)
    assert s["first_class_yes"] + s["first_class_partial"] + s["first_class_no"] == s["n_engines"]
    assert s["on_disk_verified"] + s["public_docs"] == s["n_engines"]
    assert s["on_disk_verified"] >= 1               # at least one entry grounded in vendored corpora
