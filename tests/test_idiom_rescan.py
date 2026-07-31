#!/usr/bin/env python3
"""
test_idiom_rescan.py — PLAN_2 P1-B. The re-scan keeps the Phase-1 structural predicate FROZEN (adds
parsers only), computes the two axes (structural idiom + s_semantics), and the funnel ordering holds
(provenance_upstream ⊆ structural). Uses small inline fixtures (no dependency on cloned corpora).
"""
from __future__ import annotations

import sys
from pathlib import Path

_BB = Path(__file__).resolve().parents[1] / "bridge_benchmark"
_DET = _BB / "experiments" / "detector"
sys.path.insert(0, str(_DET))

import idiom_detector as idet  # noqa: E402
import idiom_rescan as resc  # noqa: E402

_FIX = _DET / "fixtures"


def test_phase1_predicate_frozen_and_referenced():
    # the rescan references the FROZEN Phase-1 detector hash; it must not redefine the predicate string
    spec = idet.frozen_spec()
    assert len(spec["detector_sha256"]) == 64
    assert "theta(s)" in spec["idiom_predicate"]
    # the structural rule mirrors the frozen predicate (keyed θ, ≥2 values, ordered op)
    assert resc.structural_idiom("<", True, 2) is True
    assert resc.structural_idiom("<", False, 2) is False     # constant threshold -> not the idiom
    assert resc.structural_idiom("==", True, 2) is False     # equality is not in the op set
    assert resc.structural_idiom("<", True, 1) is False       # needs ≥2 distinct θ values


def test_openfisca_parser_fires_on_enum_keyed_threshold():
    on = resc.detect_openfisca(_FIX / "openfisca_idiom.py")
    off = resc.detect_openfisca(_FIX / "openfisca_constant.py")
    assert any(h.structural_idiom for h in on)
    assert on[0].s_field == "zone_logement"
    assert off == []                                          # constant threshold -> silent


def test_s_semantics_axis():
    assert resc.classify_s_semantics("sanctions_list_source") == "provenance_upstream"
    assert resc.classify_s_semantics("counterparty_channel") == "provenance_upstream"
    assert resc.classify_s_semantics("zone_logement") == "subject_self_reported"
    assert resc.classify_s_semantics("statut_couple") == "subject_self_reported"


def test_funnel_provenance_subset_of_structural():
    # build a tiny corpus from the fixtures dir; provenance_upstream must be <= structural
    corpus = [resc.Corpus("fix", "H2_legislation", _FIX, "openfisca", ("*.py",), "fixtures")]
    res = resc.scan(corpus)[0]
    assert res["files_with_structural_idiom"] >= 1
    assert res["files_with_provenance_upstream"] <= res["files_with_structural_idiom"]
    assert res["files_with_provenance_upstream"] == 0        # the fixtures are subject-keyed


# --------------------------------------------------------------------------- #
# RESCAN_BIS Workstream A — DMN decision-table parser (added parser; frozen predicate unchanged)
# --------------------------------------------------------------------------- #
def test_dmn_parser_fires_on_category_keyed_threshold():
    on = resc.detect_dmn(_FIX / "dmn_idiom.dmn")
    off = resc.detect_dmn(_FIX / "dmn_constant.dmn")
    assert len(on) == 1
    h = on[0]
    assert h.structural_idiom and h.language == "dmn"
    assert h.f_num == "Amount" and h.s_field == "Channel"   # θ(amount) keyed by the Channel column
    assert h.op in ("<", "<=", ">", ">=")
    assert h.s_semantics == "provenance_upstream"           # "channel" is a provenance key
    assert off == []                                        # constant threshold -> silent (no θ(s))


def test_dmn_requires_two_distinct_thetas_and_a_selector():
    # the FEEL parser distinguishes ordered comparisons from ranges/literals
    assert resc._parse_feel("<= 35") == ("cmp", "<=", 35.0)
    assert resc._parse_feel("> 3000") == ("cmp", ">", 3000.0)
    assert resc._parse_feel("(0..2000]")[0] == "range"     # a bucket -> selector-eligible, not a θ
    assert resc._parse_feel("-")[0] == "other"             # "any" cell
    # a single-column table (no selector) or a constant θ must not fire (mirrors the frozen predicate)
    assert resc.detect_dmn(_FIX / "dmn_constant.dmn") == []


def test_dmn_parser_is_namespace_agnostic():
    # the idiom fixture uses a default-namespaced <definitions>; the parser matches by localname
    hits = resc.detect_dmn(_FIX / "dmn_idiom.dmn")
    assert hits and hits[0].structural_idiom
