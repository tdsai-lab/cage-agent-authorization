#!/usr/bin/env python3
"""
eval_azure_keyvault_policy.py — Experiment 1 evaluator for the Azure Key Vault key-size idiom.

policy_provenance = third_party_logic_reimplemented. The decision logic is Microsoft's: `keyType`
selects the applicable minimum `keySize` threshold (a category-conditioned numeric threshold
`x >= theta(s)`). We re-express it as a small evaluator — we do NOT execute Azure Policy.

    Safe(z, allow_key_creation) = 1  <=>  keySize >= threshold(keyType, policy_instance)

`keySize` is integer-quantized, so this family is an EXISTENCE anchor, not a continuous-C substrate.
"""
from __future__ import annotations

# category-conditioned numeric thresholds (documented Azure built-in values; see source_manifest.json)
RSA_THRESHOLDS = {"min_2048": 2048, "min_3072": 3072, "min_4096": 4096}     # RSA / RSA-HSM
OCT_THRESHOLDS = {"min_128": 128, "min_192": 192, "min_256": 256, "min_512": 512}  # oct / oct-HSM
KEYTYPE_FAMILY = {"RSA": "rsa", "RSA-HSM": "rsa", "oct": "oct", "oct-HSM": "oct"}
# the legal (quantized) key sizes a request can actually carry, per family
LEGAL_KEYSIZES = {"rsa": [2048, 3072, 4096], "oct": [128, 192, 256, 512]}
PRIVILEGED = "allow_key_creation"


def family_of(key_type: str) -> str:
    if key_type not in KEYTYPE_FAMILY:
        raise ValueError(f"unknown keyType {key_type!r}")
    return KEYTYPE_FAMILY[key_type]


def threshold_for(key_type: str, policy_instance: str) -> int:
    fam = family_of(key_type)
    table = RSA_THRESHOLDS if fam == "rsa" else OCT_THRESHOLDS
    if policy_instance not in table:
        raise ValueError(f"policy_instance {policy_instance!r} not valid for keyType family {fam!r}")
    return table[policy_instance]


def safe(z: dict, action: str | None = None) -> bool:
    """Safe(z, allow_key_creation) iff keySize >= threshold(keyType, policy_instance). Non-privileged
    actions (deny/escalate) are conservative and always policy-safe."""
    a = action or z.get("action", PRIVILEGED)
    if a != PRIVILEGED:
        return True
    s, x = z["s"], z["x"]
    return float(x["keySize"]) >= threshold_for(s["keyType"], s["policy_instance"])


def policy_instances_for(key_type: str):
    fam = family_of(key_type)
    return list((RSA_THRESHOLDS if fam == "rsa" else OCT_THRESHOLDS).keys())
