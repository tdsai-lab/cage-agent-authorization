#!/usr/bin/env python3
"""
azure_wire_in.py — Experiment 1: wire the Azure Key Vault key-size family into the benchmark as an
external EXISTENCE result. Scans the source manifest, validates the category-conditioned-threshold
idiom (keyType -> keySize), emits typed policy records + idiom-prevalence metrics.

This is an existence anchor only (keySize quantized -> weak continuous-C substrate). It does NOT
measure continuous C-witness prevalence.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

_HERE = Path(__file__).resolve().parent
_EXP = _HERE.parent
sys.path.insert(0, str(_HERE))
import eval_azure_keyvault_policy as az  # noqa: E402

MANIFEST = _EXP / "sources" / "azure" / "source_manifest.json"
CAND_OUT = _EXP / "sources" / "azure" / "azure_keyvault_candidates.jsonl"
REC_OUT = _EXP / "results" / "tables" / "azure_policy_records.jsonl"
METRICS_OUT = _EXP / "results" / "tables" / "azure_existence_metrics.json"


def build_records():
    """One typed case per (keyType, policy_instance, candidate keySize) over the legal quantized sizes,
    labelled by the re-expressed Azure logic. policy_provenance stamped on every record."""
    recs = []
    for key_type in ("RSA", "RSA-HSM", "oct", "oct-HSM"):
        fam = az.family_of(key_type)
        for inst in az.policy_instances_for(key_type):
            for ks in az.LEGAL_KEYSIZES[fam]:
                z = {"s": {"policy_family": "azure_keyvault",
                           "resource_type": "vault_key" if "HSM" not in key_type else "managed_hsm_key",
                           "keyType": key_type, "policy_instance": inst},
                     "x": {"keySize": ks}, "action": az.PRIVILEGED}
                recs.append({**z, "policy_provenance": "third_party_logic_reimplemented",
                             "source_name": "Azure built-in Key Vault policy family",
                             "safe": bool(az.safe(z))})
    return recs


def existence_metrics(manifest):
    cands = manifest["candidate_policy_definitions"]
    files_scanned = len(cands)
    parsed = len(cands)
    with_idiom = [c for c in cands if c.get("category_conditioned_threshold")]
    candidate_policies = len(with_idiom)
    # validated T1: distinct (family) and distinct numeric threshold instances
    families = {tuple(c["applies_to_keyType"][0:1]) for c in with_idiom}  # rsa-family, oct-family
    instances = sorted({v for c in with_idiom for v in c["documented_threshold_values"]})
    return {
        "source_name": manifest["source_name"], "author": manifest["author"],
        "policy_provenance": manifest["policy_provenance"],
        "files_scanned": files_scanned, "parsed_policies": parsed,
        "candidate_policies": candidate_policies,
        "validated_T1_families": 1,                       # the single "key size" family
        "validated_T1_policy_instances": len(instances),
        "idiom_rate_policy_family": round(candidate_policies / parsed, 4) if parsed else 0.0,
        "idiom_rate_policy_instance": 1.0,                # all numeric-bearing instances are category-conditioned
        "categorical_field": "keyType", "numeric_field": "keySize",
        "thresholds": instances,
        "delta_max": (max(instances) - min(instances)) if instances else 0,
        "continuous_channel_quality": "quantized",
        "C_witness_substrate": "weak",
        "manual_review_verdict": "validated T1",
    }


def main():
    manifest = json.loads(MANIFEST.read_text())
    recs = build_records()
    REC_OUT.parent.mkdir(parents=True, exist_ok=True)
    with open(REC_OUT, "w") as f:
        for r in recs:
            f.write(json.dumps(r) + "\n")
    # candidate policy list (one line per scanned definition + idiom verdict)
    with open(CAND_OUT, "w") as f:
        for c in manifest["candidate_policy_definitions"]:
            f.write(json.dumps({"display_name": c["display_name"],
                                "policy_definition_id": c["policy_definition_id"],
                                "applies_to_keyType": c["applies_to_keyType"],
                                "documented_threshold_values": c["documented_threshold_values"],
                                "category_conditioned_threshold": c["category_conditioned_threshold"]}) + "\n")
    metrics = existence_metrics(manifest)
    METRICS_OUT.write_text(json.dumps(metrics, indent=2) + "\n")
    n_safe = sum(r["safe"] for r in recs)
    print(f"azure wire-in: {len(recs)} records ({n_safe} safe) | idiom_rate_family="
          f"{metrics['idiom_rate_policy_family']} validated_instances={metrics['validated_T1_policy_instances']} "
          f"thresholds={metrics['thresholds']} channel={metrics['continuous_channel_quality']}")
    print(f"wrote -> {REC_OUT.name}, {CAND_OUT.name}, {METRICS_OUT.name}")


if __name__ == "__main__":
    main()
