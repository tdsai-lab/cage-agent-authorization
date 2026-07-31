# EXP-A2 — registry-scale substrate adjudication (audited subsample)

Stage-1 detector `221aa906dca8a79e`; adjudication module `f26b57a976210cb8` (frozen). two independent passes (lexical + frozen semantic table), disagreement → OUT; CONFIRMED_PIPELINE iff BOTH passes agree; Step-3 requires a DOCUMENTED third-party θ(s) for a strong C-substrate hit.

**Candidates:** 31 tools across 8 servers (the full T2-6 substrate-candidate set); corpus = 622 typed returns.

### Distinct candidate `s`-field verdicts (two passes, disagreement → OUT)

| s-field | lexical | semantic | **final** | rationale |
|---|---|---|---|---|
| `cache_respected` | CONFIRMED_PIPELINE | CONFIRMED_PIPELINE | **CONFIRMED_PIPELINE** | contrastapi seo_audit: boolean — did the return-assembly honour the cache (cache-freshness of THIS response); a genuine transport/freshness key |
| `acceptedSources` | DUALUSE_AMBIGUOUS | SCHEMA_RESOURCE_META | **SCHEMA_RESOURCE_META** | nausika_describe_place_schema: a list describing the schema — schema metadata |
| `cloud_provider` | DUALUSE_AMBIGUOUS | SUBJECT_INSTRUMENT | **SUBJECT_INSTRUMENT** | contrastapi: which cloud hosts the QUERIED IP — an attribute of the IP being looked up |
| `data_origin_unverified` | DUALUSE_AMBIGUOUS | CONFIRMED_PIPELINE | **DUALUSE_AMBIGUOUS** | nausika: a TRUST qualifier the adapter attaches to the data's origin — assembly-layer provenance; closest structural pipeline-set field |
| `data_source` | DUALUSE_AMBIGUOUS | DUALUSE_AMBIGUOUS | **DUALUSE_AMBIGUOUS** | nausika_tides: the upstream data source — dual-use attribution |
| `feed` | SUBJECT_INSTRUMENT | SUBJECT_INSTRUMENT | **SUBJECT_INSTRUMENT** | hn_get_stories: which HN feed was requested — a reflected query parameter |
| `first_seen_source` | DUALUSE_AMBIGUOUS | DUALUSE_AMBIGUOUS | **DUALUSE_AMBIGUOUS** | contrastapi cve_lookup: where the CVE was first observed — provenance of the subject, dual-use |
| `forbiddenSources` | DUALUSE_AMBIGUOUS | SCHEMA_RESOURCE_META | **SCHEMA_RESOURCE_META** | nausika_describe_place_schema: a list describing the schema — schema metadata |
| `product_url` | SUBJECT_INSTRUMENT | SUBJECT_INSTRUMENT | **SUBJECT_INSTRUMENT** | surprise-buddy find_gifts: the gift product's URL — a subject attribute |
| `refRoute` | DUALUSE_AMBIGUOUS | SUBJECT_INSTRUMENT | **SUBJECT_INSTRUMENT** | TRIALPATH get_credit_transactions: the payment route/rail of the transaction — an instrument attribute |
| `source` | DUALUSE_AMBIGUOUS | DUALUSE_AMBIGUOUS | **DUALUSE_AMBIGUOUS** | generic attribution field (arxiv/pubmed/nausika) — dual-use |
| `sourcePmid` | SUBJECT_INSTRUMENT | SUBJECT_INSTRUMENT | **SUBJECT_INSTRUMENT** | pubmed: the source PMID — a subject identifier |
| `source_external_url` | DUALUSE_AMBIGUOUS | SUBJECT_INSTRUMENT | **SUBJECT_INSTRUMENT** | memestack: the external URL hosting the image — a property of the reported image |
| `source_origin` | DUALUSE_AMBIGUOUS | SUBJECT_INSTRUMENT | **SUBJECT_INSTRUMENT** | memestack: where the meme image originally came from — an attribute of the image entity |
| `source_url` | DUALUSE_AMBIGUOUS | DUALUSE_AMBIGUOUS | **DUALUSE_AMBIGUOUS** | nausika: the upstream URL the geodata was fetched from — attribution/dual-use, not a policy-conditioning transport key |
| `version` | SCHEMA_RESOURCE_META | SCHEMA_RESOURCE_META | **SCHEMA_RESOURCE_META** | contrastapi: CVSS spec version — schema/version metadata |
| `vhf_channel` | SUBJECT_INSTRUMENT | SUBJECT_INSTRUMENT | **SUBJECT_INSTRUMENT** | nausika: a marina/place's VHF radio channel — a property of the reported place |

### Confirmed-pipeline funnel

| stage | count | rate over typed | Wilson 95% |
|---|---|---|---|
| candidate tools (Stage-1) | 31 | 0.0498 | — |
| structurally CONFIRMED_PIPELINE | 1 | 0.001608 | (0.000284, 0.00905) |
| strong (documented θ(s)) | 0 | 0.0 | (0.0, 0.006138) |

### Two worked examples

- **contrastcyber/contrastapi · threat_report / ip_lookup** — continuous_x = risk_score (0-100 integer, operational); candidate `s` = `cloud_provider` → **SUBJECT_INSTRUMENT**. The Stage-1 detector fired on `provider`. But cloud_provider is an attribute of the IP being LOOKED UP (alongside is_datacenter, asn_name) — the response DESCRIBES that IP. A d=1 swap of cloud_provider fabricates a different lookup subject, it is not a return-assembly adapter fault → SUBJECT_INSTRUMENT, OUT. No policy documents a risk_score threshold conditioned on cloud_provider.
- **contrastcyber/contrastapi · seo_audit** — continuous_x = score / h1_count / external_link_count (operational); candidate `s` = `cache_respected` → **CONFIRMED_PIPELINE**. cache_respected is a boolean about whether THIS response's assembly honoured the cache — a genuine transport/freshness key set by the pipeline, so BOTH passes confirm it (structurally CONFIRMED_PIPELINE). But Step-3: NO published policy documents an SEO-score threshold θ(cache_respected). So it is a structural pipeline-set field with no documented θ(s) → NOT a strong C-substrate hit.

**Outcome: STRUCTURAL_PIPELINE_SET_no_documented_theta.** The T2-6 Stage-1 candidate habitat (5.0% of typed returns, 31 tools/8 servers) collapses under conservative Stage-2 adjudication to 1/31 STRUCTURALLY pipeline-set tool (only `cache_respected`, a cache-freshness key, survives both passes; every source/origin/channel/provider field resolves SUBJECT or DUALUSE → OUT) and to 0/31 with a documented θ(s). So the security-relevant (θ(s)-conditioned) confirmed rate is 0.0 of typed returns [Wilson (0.0, 0.006138)] — a FOURTH informative null joining the k8s policy-half, MCP data-half and OpenAPI data-half nulls: the C substrate is not spontaneous in commodity typed ecosystems. The paper's necessity + soundness story never rested on prevalence; the honest structural residual (cache_respected) is named, not hidden.

*Kill criterion.*  kill: 0 strong-confirmed → replace 'candidate habitat' by a fourth informative null (done). The one structural pipeline-set field is reported as an honest residual, with no documented θ(s).

**Limitation.** Zero-execution schema adjudication (published Smithery schemas, not runtime returns). 8 servers / 31 tools = the full T2-6 candidate set (R1 suggested ≥20 servers; the candidate population spans 8). The semantic pass is frozen per-field; disagreements with the lexical pass resolve OUT (conservative). A documented θ(s) discovered later would upgrade the corresponding structural field to a strong hit.
