#!/usr/bin/env python3
"""NEW experiments — Azure existence wire-in (Exp 1) + PSD2/AML continuous C-witness mechanism (Exp 2).

Checks: Azure idiom (keyType->keySize) evaluator + existence labels; the regulatory families are
source-locked (a source note exists per source_note_id), carry the correct provenance label, produce
C-witnesses with explicit witnesses, traverse ONLY registered mechanism-tagged adjacency edges, keep
the certified gate sound (certified-allowed never truly-unsafe), and never use unsourced AML
jurisdictions. ε is in normalized space.
"""
import json
import sys
from pathlib import Path

_EXP = Path(__file__).resolve().parents[1] / "bridge_benchmark" / "experiments" / "policy_idiom_prevalence"
sys.path.insert(0, str(_EXP / "scripts"))

import pytest  # noqa: E402
import eval_azure_keyvault_policy as az  # noqa: E402
import regulatory_oracle as R  # noqa: E402

NOTES = _EXP / "sources" / "regulatory_notes"


# --------------------------------------------------------------------------- #
# Experiment 1 — Azure existence
# --------------------------------------------------------------------------- #
def test_azure_keytype_selects_keysize_threshold():
    # RSA family uses {2048,3072,4096}; oct family {128,192,256,512}
    assert az.threshold_for("RSA", "min_3072") == 3072
    assert az.threshold_for("oct-HSM", "min_256") == 256
    # category-conditioned: same policy_instance label is illegal across families
    with pytest.raises(ValueError):
        az.threshold_for("RSA", "min_128")


def test_azure_safe_is_keysize_geq_threshold():
    z = {"s": {"keyType": "RSA", "policy_instance": "min_3072"}, "x": {"keySize": 2048},
         "action": az.PRIVILEGED}
    assert az.safe(z) is False                      # 2048 < 3072
    z["x"]["keySize"] = 4096
    assert az.safe(z) is True


def test_azure_existence_metrics_present():
    metrics = json.loads((_EXP / "results" / "tables" / "azure_existence_metrics.json").read_text())
    assert metrics["policy_provenance"] == "third_party_logic_reimplemented"
    assert metrics["continuous_channel_quality"] == "quantized"
    assert metrics["validated_T1_families"] == 1


# --------------------------------------------------------------------------- #
# Experiment 2 — regulatory source-locking + provenance
# --------------------------------------------------------------------------- #
def test_every_family_is_source_locked_and_correctly_labelled():
    for fam, cfg in R.FAMILIES.items():
        assert (NOTES / f"{cfg['source_note_id']}.md").exists(), f"{fam} missing source note"
    assert R.PROVENANCE == "regulatory_grounded_authored_policy"


def test_aml_jurisdiction_not_unsourced():
    # only US is source-locked; jurisdiction must NOT be a varying categorical (no invented EU/JP).
    assert "jurisdiction" not in R.FAMILIES["aml_ctr"]["selectors"]


def test_psd2_thresholds_match_source_notes():
    # Art16 remote €30 / Art11 contactless €50 over the €60 cap
    b = R.FAMILIES["psd2_low_value"]["base"]
    assert abs(b["remote"] - 30 / 60) < 1e-9 and abs(b["contactless"] - 50 / 60) < 1e-9
    # TRA ETV €100/€250/€500 over €600
    t = R.FAMILIES["psd2_tra"]["base"]
    assert abs(t["tier_3"] - 100 / 600) < 1e-9 and abs(t["tier_1"] - 500 / 600) < 1e-9


# --------------------------------------------------------------------------- #
# Experiment 2 — neighborhoods, witnesses, soundness
# --------------------------------------------------------------------------- #
def test_neighborhoods_are_adjacency_only_with_mechanisms():
    nb = R.load_neighbors()
    for fam in R.FAMILIES:
        for field, edges in nb[fam].items():
            for e in edges:
                assert e.get("mechanism") and e.get("allowed") is True
                assert len(e["edge"]) == 2
    # registered neighbors of a tier_2 record are only its adjacent tiers (no tier_1<->tier_3 jump here)
    s = {"fraud_rate_tier": "tier_2", "merchant_category": "standard"}
    fields = {f for _s2, f, _m in R.registered_neighbor_states("psd2_tra", s)}
    assert "fraud_rate_tier" in fields and "merchant_category" in fields


def test_c_witnesses_have_explicit_witness_and_normalized_delta():
    recs = R.sample_records("psd2_low_value", 600, seed=1, scheme="boundary")
    cats = R.categorize("psd2_low_value", recs, eps=0.10)
    cs = [c for c in cats if c["category"] == "C"]
    assert cs, "expected C-witnesses in boundary mode"
    for c in cs:
        w = c["witness"]
        assert w and "witness_s_prime" in w and "witness_x_prime" in w and w["mechanism"]
        assert c["normalized_delta"] is not None and c["delta_over_epsilon"] is not None
        assert c["epsilon"] == 0.10                 # epsilon recorded in normalized space


def test_certify_registered_is_sound():
    fam = "aml_ctr"
    rt = R.build_rt(fam)
    gate = R.train_gate(fam, R.sample_records(fam, 600, seed=0, scheme="natural"), rt,
                        sigma=0.10, n_aug=4, seed=0)
    recs = R.sample_records(fam, 200, seed=2, scheme="boundary")
    cats = R.categorize(fam, recs, eps=0.10)
    for c, r in zip(cats, recs):
        cz = R.certify_registered(gate, rt, fam, r, sigma=0.10, eps=0.10, tau=0.90, n_mc=600, alpha=1e-3)
        if cz["allow"]:
            assert not c["truly_unsafe_reachable"], "certified-allowed point is truly unsafe (UNSOUND)"


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
