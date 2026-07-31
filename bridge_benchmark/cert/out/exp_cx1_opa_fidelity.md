# EXP-CX1 — learned-policy vs exact-OPA fidelity benchmark

Source: NEW_EXP_OPA_CHECK.md (P0). Ground truth: R_OPA = exact robust-safe set via opa_joint_unsafe_map (engine, batched). ε=0.1, σ=0.1, τ=0.9, n_mc=800, d=1, seeds=[0, 1, 2], n_train=5000, n_eval=800.

**Framing.** gate-policy fidelity benchmark (price of a surrogate under known ground truth), NOT evidence a learned gate should replace OPA; the exact backend is the deployment choice when the policy is robustly evaluable at low cost. VERIFIED SCOPE: the three authored OPA domains are the SAME provenance-conditioned scalar-threshold policy with the numeric field renamed (categorize identical across them) — a renaming-invariance check, not three complexity tiers; the multivariate-affine tier is covered by EXP-CX4.

### finance — tier: provenance-scalar-threshold (field=risk_score)

**natural eval** — policy_FA (Wilson 95% upper) | robust-safe coverage | precision | recall | Jaccard | point-acc

| system | policy_FA | ≤upper | coverage | precision | recall | Jaccard | pt-acc |
|---|--:|--:|--:|--:|--:|--:|--:|
| opa_point | 0.458±0.0097 (674/1471) | 0.5023±0.0094 | 1.0 | 0.542±0.0097 | 1.0 | 0.542±0.0097 | 1.0 |
| cage_exact | 0.0 (0/797) | 0.0143±0.0001 | 1.0 | 1.0 | 1.0 | 1.0 | 0.7192±0.0112 |
| point_mlp | 0.3762±0.0084 (481/1278) | 0.4231±0.0081 | 1.0 | 0.6238±0.0084 | 1.0 | 0.6238±0.0084 | 0.9137±0.0027 |
| cage_lip | 0.0 (0/518) | 0.0222±0.0033 | 0.6504±0.0929 | 1.0 | 0.6504±0.0929 | 0.6504±0.0929 | 0.6029±0.0245 |
| cage_rs | 0.0 (0/9) | 0.5832±0.1052 | 0.0113±0.0052 | 1.0 | 0.0113±0.0052 | 0.0113±0.0052 | 0.3908±0.0106 |

**boundary eval** — policy_FA (Wilson 95% upper) | robust-safe coverage | precision | recall | Jaccard | point-acc

| system | policy_FA | ≤upper | coverage | precision | recall | Jaccard | pt-acc |
|---|--:|--:|--:|--:|--:|--:|--:|
| opa_point | 0.3016±0.0193 (345/1142) | 0.3495±0.0194 | 1.0 | 0.6984±0.0193 | 1.0 | 0.6984±0.0193 | 1.0 |
| cage_exact | 0.0 (0/797) | 0.0143±0.0001 | 1.0 | 1.0 | 1.0 | 1.0 | 0.7835±0.0195 |
| point_mlp | 0.2319±0.0124 (241/1038) | 0.2792±0.0125 | 1.0 | 0.7681±0.0124 | 1.0 | 0.7681±0.0124 | 0.9297±0.0086 |
| cage_lip | 0.0 (0/518) | 0.0222±0.0033 | 0.6504±0.0929 | 1.0 | 0.6504±0.0929 | 0.6504±0.0929 | 0.6087±0.0283 |
| cage_rs | 0.0 (0/9) | 0.5832±0.1052 | 0.0113±0.0052 | 1.0 | 0.0113±0.0052 | 0.0113±0.0052 | 0.2891±0.018 |

### sre — tier: provenance-scalar-threshold (field=signal, renamed)

**natural eval** — policy_FA (Wilson 95% upper) | robust-safe coverage | precision | recall | Jaccard | point-acc

| system | policy_FA | ≤upper | coverage | precision | recall | Jaccard | pt-acc |
|---|--:|--:|--:|--:|--:|--:|--:|
| opa_point | 0.458±0.0097 (674/1471) | 0.5023±0.0094 | 1.0 | 0.542±0.0097 | 1.0 | 0.542±0.0097 | 1.0 |
| cage_exact | 0.0 (0/797) | 0.0143±0.0001 | 1.0 | 1.0 | 1.0 | 1.0 | 0.7192±0.0112 |
| point_mlp | 0.3715±0.0037 (471/1268) | 0.4185±0.0038 | 1.0 | 0.6285±0.0037 | 1.0 | 0.6285±0.0037 | 0.9112±0.0064 |
| cage_lip | 0.0 (0/447) | 0.0253±0.0021 | 0.5613±0.0526 | 1.0 | 0.5613±0.0526 | 0.5613±0.0526 | 0.5733±0.0185 |
| cage_rs | 0.0 (0/6) | 0.6923±0.1431 | 0.0075±0.0053 | 1.0 | 0.0075±0.0053 | 0.0075±0.0053 | 0.3896±0.0106 |

**boundary eval** — policy_FA (Wilson 95% upper) | robust-safe coverage | precision | recall | Jaccard | point-acc

| system | policy_FA | ≤upper | coverage | precision | recall | Jaccard | pt-acc |
|---|--:|--:|--:|--:|--:|--:|--:|
| opa_point | 0.3016±0.0193 (345/1142) | 0.3495±0.0194 | 1.0 | 0.6984±0.0193 | 1.0 | 0.6984±0.0193 | 1.0 |
| cage_exact | 0.0 (0/797) | 0.0143±0.0001 | 1.0 | 1.0 | 1.0 | 1.0 | 0.7835±0.0195 |
| point_mlp | 0.2276±0.007 (235/1032) | 0.2748±0.0071 | 1.0 | 0.7724±0.007 | 1.0 | 0.7724±0.007 | 0.9259±0.0074 |
| cage_lip | 0.0 (0/447) | 0.0253±0.0021 | 0.5613±0.0526 | 1.0 | 0.5613±0.0526 | 0.5613±0.0526 | 0.5642±0.0184 |
| cage_rs | 0.0 (0/6) | 0.6923±0.1431 | 0.0075±0.0053 | 1.0 | 0.0075±0.0053 | 0.0075±0.0053 | 0.2873±0.018 |

### ops — tier: provenance-scalar-threshold (field=login_risk, renamed)

**natural eval** — policy_FA (Wilson 95% upper) | robust-safe coverage | precision | recall | Jaccard | point-acc

| system | policy_FA | ≤upper | coverage | precision | recall | Jaccard | pt-acc |
|---|--:|--:|--:|--:|--:|--:|--:|
| opa_point | 0.458±0.0097 (674/1471) | 0.5023±0.0094 | 1.0 | 0.542±0.0097 | 1.0 | 0.542±0.0097 | 1.0 |
| cage_exact | 0.0 (0/797) | 0.0143±0.0001 | 1.0 | 1.0 | 1.0 | 1.0 | 0.7192±0.0112 |
| point_mlp | 0.3714±0.0046 (471/1268) | 0.4184±0.0042 | 1.0 | 0.6286±0.0046 | 1.0 | 0.6286±0.0046 | 0.9088±0.001 |
| cage_lip | 0.0 (0/530) | 0.0218±0.0034 | 0.6657±0.103 | 1.0 | 0.6657±0.103 | 0.6657±0.103 | 0.6079±0.0303 |
| cage_rs | 0.0 (0/8) | 0.5935±0.0453 | 0.01±0.0017 | 1.0 | 0.01±0.0017 | 0.01±0.0017 | 0.3904±0.0122 |

**boundary eval** — policy_FA (Wilson 95% upper) | robust-safe coverage | precision | recall | Jaccard | point-acc

| system | policy_FA | ≤upper | coverage | precision | recall | Jaccard | pt-acc |
|---|--:|--:|--:|--:|--:|--:|--:|
| opa_point | 0.3016±0.0193 (345/1142) | 0.3495±0.0194 | 1.0 | 0.6984±0.0193 | 1.0 | 0.6984±0.0193 | 1.0 |
| cage_exact | 0.0 (0/797) | 0.0143±0.0001 | 1.0 | 1.0 | 1.0 | 1.0 | 0.7835±0.0195 |
| point_mlp | 0.2298±0.0093 (238/1035) | 0.277±0.0094 | 1.0 | 0.7702±0.0093 | 1.0 | 0.7702±0.0093 | 0.9265±0.0083 |
| cage_lip | 0.0 (0/530) | 0.0218±0.0034 | 0.6657±0.103 | 1.0 | 0.6657±0.103 | 0.6657±0.103 | 0.6164±0.0361 |
| cage_rs | 0.0 (0/8) | 0.5935±0.0453 | 0.01±0.0017 | 1.0 | 0.01±0.0017 | 0.01±0.0017 | 0.2885±0.0198 |

**Verdict.** STRONG: learned certs keep policy_false_allow=0 (Lip & RS, both eval sets, all tiers) AND recover a substantial fraction of R_OPA (Lip natural coverage mean 0.626) — tight surrogate with modest learning tax; the point baselines pay the boundary price.
