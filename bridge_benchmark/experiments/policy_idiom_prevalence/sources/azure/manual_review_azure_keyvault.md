# Manual review — Azure Key Vault key-size policy family

**Provenance:** `third_party_logic_reimplemented` (Microsoft-authored decision logic, re-expressed as a
small evaluator; NOT executed through Azure Policy, so NOT labelled third-party-executable).

## The idiom (validated)

Azure built-in Key Vault policies select the applicable **minimum `keySize` threshold from the key's
`keyType`**:

```
keyType ∈ {RSA, RSA-HSM}  ⇒  keySize ≥ θ ,  θ ∈ {2048, 3072, 4096}
keyType ∈ {oct, oct-HSM}  ⇒  keySize ≥ θ ,  θ ∈ {128, 192, 256, 512}
```

This is a **category-conditioned numerical threshold** `x ▷ θ(s)` with `s = keyType` (the categorical
selector) and `x = keySize` (the numeric field). The built-in RSA policy
("Keys using RSA cryptography should have a specified minimum key size",
`82067dbb-e53b-4e06-b631-546d197452d9`) exposes the threshold as the `minimumRSAKeySize` parameter with
allowed values 2048/3072/4096 — Microsoft-authored, in third-party policy code.

## Verdict

- **Validated T1 family:** 1 (Key Vault key size).
- **Validated T1 policy instances:** the distinct minimum-size thresholds {128, 192, 256, 512, 2048,
  3072, 4096}.
- **EC family excluded from the numeric idiom:** the EC policy constrains the curve *name* (discrete
  allow-list), not a numeric key-size threshold — parsed but not validated as the numeric idiom.

## Honest scope

- This **establishes third-party EXISTENCE** of the `x ▷ θ(s)` idiom — the antecedent appears in
  third-party policy code authored by Microsoft.
- It does **not** establish that C-witnesses are common.
- `keySize` is **integer-quantized** (a handful of legal values), so the continuous channel is weak:
  `continuous_channel_quality = quantized`, `C_witness_substrate = weak`. We therefore use Azure as an
  **external-validity anchor**, not the main continuous robustness substrate. The continuous mechanism
  is evaluated separately on the source-locked PSD2/AML policies (Experiment 2).
