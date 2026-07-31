#!/usr/bin/env python3
"""NEW_EXPS_8 — registered methodological controls for the OPA-gate experiment.

Checks (no OPA needed): the idiom detector separates authored (provenance-conditioned) from third-party
Gatekeeper policies and the corpus funnel idiom_rate is 0; the frozen discrete neighborhood is
mechanism-tagged and excludes inert fields; registered_swaps drops the inert fields; Δ/ε geometry is
computed. Checks needing the OPA binary (skipped if absent): the exact verifier never false-allows, and
excluded inert edges never flip the OPA verdict (so excluding them is sound).
"""
import glob
import sys
from pathlib import Path

_OPA = Path(__file__).resolve().parents[1] / "bridge_benchmark" / "experiments" / "opa_gate"
sys.path.insert(0, str(_OPA))
sys.path.insert(0, str(_OPA / "scripts"))
sys.path.insert(0, str(_OPA.parents[1] / "generators"))

import pytest  # noqa: E402
import methodology as M  # noqa: E402
import schema as S  # noqa: E402

AUTHORED = {d: (_OPA / "policies" / "authored" / f"{d}.rego") for d in ("finance", "sre", "ops")}
GK = sorted(glob.glob(str(_OPA / "policies" / "third_party" / "gatekeeper_library" / "*" / "policy.rego")) +
            glob.glob(str(_OPA / "policies" / "third_party" / "gatekeeper_library" / "*" / "lib_*.rego")))


def _opa_available():
    try:
        import opa_bridge
        opa_bridge.opa_version()
        return True
    except Exception:
        return False


# --------------------------------------------------------------------------- #
# Gap 1 — idiom detector + two-stage funnel
# --------------------------------------------------------------------------- #
def test_idiom_detector_flags_authored_not_gatekeeper():
    for d, p in AUTHORED.items():
        assert M.has_category_conditioned_threshold(p.read_text())["present"], f"{d} should be idiom+"
    for p in GK:
        assert not M.has_category_conditioned_threshold(Path(p).read_text())["present"], \
            f"{p} should be idiom-"


def test_corpus_funnel_idiom_rate_zero():
    funnel = M.scan_corpus_for_idiom(GK)
    assert funnel["files_scanned"] == len(GK) > 0
    assert funnel["files_with_idiom"] == 0
    assert funnel["idiom_rate"] == 0.0          # the null is localized at stage 1, not the sampler


# --------------------------------------------------------------------------- #
# Gap 4 — frozen mechanism-tagged neighborhood
# --------------------------------------------------------------------------- #
def test_every_registered_edge_has_a_known_mechanism():
    nb = M.load_neighborhoods()
    taxonomy = set(nb["tm2_mechanisms"])
    for dom, block in nb["domains"].items():
        assert block["registered_edges"], f"{dom} has no registered edges"
        for field, spec in block["registered_edges"].items():
            assert spec["mechanism"] in taxonomy, f"{dom}.{field} mechanism not in taxonomy"
        assert "excluded_fields" in block        # every domain documents what it dropped (and why)


def test_registered_swaps_drop_inert_fields():
    # finance: entity_type is inert -> never a registered swap axis; jurisdiction + tool are.
    x1 = {"jurisdiction": "domestic", "entity_type": "sme"}
    fields = {f for *_rest, f, _m in M.registered_swaps("finance", "t_credit", x1)}
    assert "jurisdiction" in fields and "__tool__" in fields
    assert "entity_type" not in fields
    # registered |N_1| (6 = 1 self + 2 other tools + 3 other jurisdictions) < structural (includes 2
    # other entity_type values -> 8).
    assert M.registered_state_count("finance", "t_credit", x1) == 6


# --------------------------------------------------------------------------- #
# Gap 3 — Δ/ε geometry
# --------------------------------------------------------------------------- #
def test_delta_epsilon_geometry():
    de = M.delta_epsilon("finance", AUTHORED["finance"].read_text(), 0.10)
    assert de["min_delta"] > 0
    for row in de["per_gap"]:
        assert row["predicted_C_interval_len"] == min(row["delta"], 0.10)


# --------------------------------------------------------------------------- #
# Gap 2 — registered sampling schemes
# --------------------------------------------------------------------------- #
def test_sampling_schemes_registered_and_distinct():
    assert S.SAMPLING_SCHEMES == ("natural", "boundary")
    nat = S.sample_records("finance", 50, seed=0, scheme="natural")
    bnd = S.sample_records("finance", 50, seed=0, scheme="boundary")
    f = "risk_score"
    # boundary clusters the policy field in the (narrower, higher) threshold band
    assert max(r["numeric_fields"][f] for r in bnd) <= 0.70 + 1e-9
    assert sum(r["numeric_fields"][f] for r in nat) / 50 != sum(r["numeric_fields"][f] for r in bnd) / 50
    with pytest.raises(ValueError):
        S.sample_records("finance", 5, scheme="nope")


# --------------------------------------------------------------------------- #
# Addition 1 + Gap 4 soundness — need the OPA binary
# --------------------------------------------------------------------------- #
@pytest.mark.skipif(not _opa_available(), reason="OPA binary not available")
def test_exact_verifier_never_false_allows():
    from opa_oracle import OpaOracle
    orc = OpaOracle("finance")
    recs = S.sample_records("finance", 200, seed=3, scheme="natural")
    cats = orc.categorize(recs, eps=0.10)
    for c in cats:
        # exact verifier allows iff category == R; R <=> not truly_unsafe_reachable (no false allow)
        assert (c["category"] == "R") == (not c["truly_unsafe_reachable"])


@pytest.mark.skipif(not _opa_available(), reason="OPA binary not available")
def test_excluded_inert_edge_never_flips_verdict():
    # swapping an EXCLUDED field (entity_type) must not change the OPA Safe verdict -> excluding it from
    # the neighborhood is sound (it can never create an A/C witness).
    from opa_oracle import OpaOracle
    orc = OpaOracle("finance")
    recs = S.sample_records("finance", 120, seed=5, scheme="boundary")
    base = orc.safe_records(recs)
    other = {"individual": "corp", "sme": "individual", "corp": "sme"}
    swapped = []
    for r in recs:
        r2 = {**r, "categorical_fields": {**r["categorical_fields"],
              "entity_type": other[r["categorical_fields"]["entity_type"]]}}
        swapped.append(r2)
    assert orc.safe_records(swapped) == base


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
