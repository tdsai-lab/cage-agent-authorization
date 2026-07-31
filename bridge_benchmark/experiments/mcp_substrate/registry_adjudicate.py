#!/usr/bin/env python3
"""
registry_adjudicate.py — EXP-A2. STAGE-2 manual adjudication of
the T2-6 registry-scan substrate CANDIDATES.

T2-6 (`registry_scan.py`, frozen detector 221aa906…) flagged **31 candidate substrate tools across 8 servers**
(5.0% of typed returns): a typed return carrying BOTH a continuous operational field `x` AND a field the
Stage-1 detector labelled `pipeline_set_s`. The Stage-1 `_PIPELINE` lexicon is deliberately PERMISSIVE
(it fires on source/version/cache/provider/channel/feed/route/origin), so a candidate is not yet a confirmed
`z=(s,x)` C-substrate. This module applies the SAME conservative Stage-2 adjudication the OpenAPI scan used
(`openapi_adjudicate.py`, §6.5 rule "ambiguous → subject-keyed / OUT"): every distinct candidate `s`-field is
categorised CONFIRMED_PIPELINE / SUBJECT_INSTRUMENT / SCHEMA_RESOURCE_META / DUALUSE_AMBIGUOUS.

Protocol (pre-registered, mirrors R1's ≥20-server ask; we have 8 servers / 31 tools → adjudicate ALL):
  * TWO INDEPENDENT PASSES, disagreement → OUT (the conservative tie-break, never inflates):
      pass-1 LEXICAL   — keyword rule over the field name (documented lexicons below).
      pass-2 SEMANTIC  — a per-field reading of what the field MEANS in its tool's schema/docs (frozen
                         `_SEMANTIC` table with a one-line rationale each). This is the "author + second pass"
                         the review asks for, encoded deterministically so the collapse is auditable.
    final = CONFIRMED_PIPELINE **iff both passes say CONFIRMED_PIPELINE**, else OUT.
  * STEP-3 gate (mirrors openapi_adjudicate): a CONFIRMED_PIPELINE field is a *structural* pipeline-set key;
    it only becomes a **C-substrate STRONG hit** with a DOCUMENTED third-party θ(s) conditioning a threshold
    on the continuous field. Authoring one is a protocol violation → we report structural-confirmed and
    θ(s)-documented separately.

Categories (all but CONFIRMED_PIPELINE are OUT):
  SCHEMA_RESOURCE_META  version/schema/apiVersion/etag/revision — API/resource control-plane metadata.
  SUBJECT_INSTRUMENT    an attribute OF THE ENTITY the tool reports on (the IP's cloud_provider, a meme's
                        external source URL, a place's VHF channel, a gift's product URL): a d=1 swap
                        fabricates a different query, NOT an adapter fault (the §6.5 subject-keyed rule).
  DUALUSE_AMBIGUOUS     source/origin/channel/provider/route/datasource/feed/url — genuinely dual-use →
                        conservative OUT ("ambiguous → subject-keyed").
  CONFIRMED_PIPELINE    unambiguously return-assembly / transport / cache-freshness assigned AND none above.

Zero execution: reads only the cached T2-6 `summary.json` (published schemas). No server run.
"""
from __future__ import annotations

import hashlib
import json
import sys
from math import sqrt
from pathlib import Path

_HERE = Path(__file__).resolve().parent
_BB = _HERE.parents[1]
T2_6_SUMMARY = _BB / "cert" / "out" / "exp_mcp_registry" / "summary.json"
DEFAULT_OUT = _BB / "cert" / "out" / "exp_mcp_registry_adjudication"

# ── pass-1 LEXICAL rule (documented keyword lexicons; conservative order META→SUBJECT→DUALUSE→CONFIRMED) ──
_META = ("version", "schema", "apiversion", "resource", "etag", "revision", "generation", "guid")
_SUBJECT = ("product", "image", "meme", "gift", "place", "paper", "article", "pmid", "cve", "ip",
            "country", "region", "currency", "card", "account", "name", "title", "vhf", "feed",
            "leaderboard", "author", "tag", "category")
_DUALUSE = ("source", "origin", "channel", "provider", "endpoint", "gateway", "acquirer", "route",
            "datasource", "data_source", "feed", "connector", "integration", "url", "uri", "host",
            "system", "reference", "ref", "delivery", "sender")
# fields that are genuinely return-assembly / cache-freshness assigned (the detector's cache/freshness intent)
_PIPELINE_LEX = ("cache", "freshness", "stale", "ttl", "policy_pack", "policypack", "shard", "replica",
                 "backend", "transport", "assembled_by", "served_from", "adapter")


def _lexical(name: str) -> str:
    n = (name or "").lower()
    if any(k in n for k in _PIPELINE_LEX):
        return "CONFIRMED_PIPELINE"          # cache/freshness/transport keywords are unambiguously pipeline
    if any(k in n for k in _META):
        return "SCHEMA_RESOURCE_META"
    if any(k in n for k in _SUBJECT):
        return "SUBJECT_INSTRUMENT"
    if any(k in n for k in _DUALUSE):
        return "DUALUSE_AMBIGUOUS"
    return "CONFIRMED_PIPELINE"


# ── pass-2 SEMANTIC table: a per-field reading of the field IN ITS TOOL'S CONTEXT + one-line rationale.
#    Frozen. Keyed by the exact s-field name observed in the T2-6 candidates. Any candidate s-field not
#    listed here is treated as DUALUSE_AMBIGUOUS (conservative default → OUT).
_SEMANTIC = {
    "source_origin": ("SUBJECT_INSTRUMENT",
                      "memestack: where the meme image originally came from — an attribute of the image entity"),
    "source_external_url": ("SUBJECT_INSTRUMENT",
                            "memestack: the external URL hosting the image — a property of the reported image"),
    "source_url": ("DUALUSE_AMBIGUOUS",
                   "nausika: the upstream URL the geodata was fetched from — attribution/dual-use, not a "
                   "policy-conditioning transport key"),
    "source": ("DUALUSE_AMBIGUOUS", "generic attribution field (arxiv/pubmed/nausika) — dual-use"),
    "cloud_provider": ("SUBJECT_INSTRUMENT",
                       "contrastapi: which cloud hosts the QUERIED IP — an attribute of the IP being looked up"),
    "vhf_channel": ("SUBJECT_INSTRUMENT",
                    "nausika: a marina/place's VHF radio channel — a property of the reported place"),
    "data_origin_unverified": ("CONFIRMED_PIPELINE",
                               "nausika: a TRUST qualifier the adapter attaches to the data's origin — "
                               "assembly-layer provenance; closest structural pipeline-set field"),
    "cache_respected": ("CONFIRMED_PIPELINE",
                        "contrastapi seo_audit: boolean — did the return-assembly honour the cache "
                        "(cache-freshness of THIS response); a genuine transport/freshness key"),
    "first_seen_source": ("DUALUSE_AMBIGUOUS",
                          "contrastapi cve_lookup: where the CVE was first observed — provenance of the "
                          "subject, dual-use"),
    "version": ("SCHEMA_RESOURCE_META", "contrastapi: CVSS spec version — schema/version metadata"),
    "feed": ("SUBJECT_INSTRUMENT", "hn_get_stories: which HN feed was requested — a reflected query parameter"),
    "sourcePmid": ("SUBJECT_INSTRUMENT", "pubmed: the source PMID — a subject identifier"),
    "data_source": ("DUALUSE_AMBIGUOUS", "nausika_tides: the upstream data source — dual-use attribution"),
    "acceptedSources": ("SCHEMA_RESOURCE_META",
                        "nausika_describe_place_schema: a list describing the schema — schema metadata"),
    "forbiddenSources": ("SCHEMA_RESOURCE_META",
                         "nausika_describe_place_schema: a list describing the schema — schema metadata"),
    "refRoute": ("SUBJECT_INSTRUMENT",
                 "TRIALPATH get_credit_transactions: the payment route/rail of the transaction — an "
                 "instrument attribute"),
    "product_url": ("SUBJECT_INSTRUMENT", "surprise-buddy find_gifts: the gift product's URL — a subject "
                    "attribute"),
}


def _semantic(name: str):
    return _SEMANTIC.get(name, ("DUALUSE_AMBIGUOUS", "not in frozen semantic table → conservative dual-use"))


def adjudicate(name: str):
    """Return (final_category, lexical_cat, semantic_cat, semantic_rationale). final = CONFIRMED_PIPELINE
    iff BOTH passes agree on CONFIRMED_PIPELINE; else OUT (disagreement → conservative OUT)."""
    lex = _lexical(name)
    sem_cat, sem_why = _semantic(name)
    if lex == "CONFIRMED_PIPELINE" and sem_cat == "CONFIRMED_PIPELINE":
        final = "CONFIRMED_PIPELINE"
    else:
        # disagreement or both-OUT → report the semantic category as the OUT reason (more specific)
        final = sem_cat if sem_cat != "CONFIRMED_PIPELINE" else lex
    return final, lex, sem_cat, sem_why


# ── Step-3: documented third-party θ(s)? (a threshold on the continuous field conditioned on the s-field) ──
# We searched each candidate tool's published schema/docs for a documented policy that conditions a numeric
# threshold on the pipeline-set field. NONE is documented (authoring one would violate the protocol).
_DOCUMENTED_THETA_S = {}   # field -> citation ; empty = no documented θ(s) on this corpus


def wilson_ci(k: int, n: int, z: float = 1.959963984540054):
    if n == 0:
        return (0.0, 0.0)
    p = k / n
    z2 = z * z
    denom = 1 + z2 / n
    center = (p + z2 / (2 * n)) / denom
    half = (z * sqrt(p * (1 - p) / n + z2 / (4 * n * n))) / denom
    return (max(0.0, round(center - half, 6)), min(1.0, round(center + half, 6)))


def _frozen_hash() -> str:
    return hashlib.sha256(Path(__file__).read_bytes()).hexdigest()


def load_candidates(summary_path: Path = T2_6_SUMMARY):
    """Return (candidate_tools, typed_returns_total, stage1_hash). Each candidate tool = one evidence entry
    with its server, tool name, s-fields (pipeline_set_s) and x-fields (continuous_x)."""
    p = json.loads(summary_path.read_text())
    tools = []
    for srv in p["substrate_hits"]:
        for e in srv["evidence"]:
            s_fields, x_fields = [], []
            for l in e["return_fields"]:
                if l["label"] == "pipeline_set_s":
                    s_fields.append(l["name"])
                elif l["label"] == "continuous_x":
                    x_fields.append(l["name"])
            tools.append({"server": srv["server"], "tool": e["tool"],
                          "s_fields": sorted(set(s_fields)), "x_fields": sorted(set(x_fields))})
    return tools, int(p["typed_returns"]), p["frozen_detector_sha256"]


def run(summary_path: Path, out_dir: Path):
    out_dir.mkdir(parents=True, exist_ok=True)
    tools, n_typed, stage1_hash = load_candidates(summary_path)

    # adjudicate every distinct candidate s-field once
    distinct_s = sorted({s for t in tools for s in t["s_fields"]})
    field_verdicts = {}
    for s in distinct_s:
        final, lex, sem, why = adjudicate(s)
        field_verdicts[s] = {"final": final, "lexical": lex, "semantic": sem, "rationale": why,
                             "documented_theta_s": _DOCUMENTED_THETA_S.get(s)}

    # a candidate TOOL is structurally-confirmed if ≥1 of its s-fields is CONFIRMED_PIPELINE
    # (it already carries ≥1 continuous_x by construction of the Stage-1 substrate detector).
    for t in tools:
        conf = [s for s in t["s_fields"] if field_verdicts[s]["final"] == "CONFIRMED_PIPELINE"]
        t["confirmed_pipeline_s_fields"] = conf
        t["structurally_confirmed"] = bool(conf)
        t["theta_s_documented"] = any(field_verdicts[s]["documented_theta_s"] for s in conf)

    n_tools = len(tools)
    n_struct = sum(t["structurally_confirmed"] for t in tools)
    n_strong = sum(t["theta_s_documented"] for t in tools)         # confirmed AND documented θ(s)
    n_servers = len({t["server"] for t in tools})
    n_servers_struct = len({t["server"] for t in tools if t["structurally_confirmed"]})

    # rates: over the 31 candidates, and over ALL typed returns in the corpus (the prevalence denominator)
    rate_struct_over_cand = round(n_struct / n_tools, 6) if n_tools else 0.0
    rate_struct_over_typed = round(n_struct / n_typed, 6) if n_typed else 0.0
    rate_strong_over_typed = round(n_strong / n_typed, 6) if n_typed else 0.0
    ci_struct_cand = wilson_ci(n_struct, n_tools)
    ci_struct_typed = wilson_ci(n_struct, n_typed)
    ci_strong_typed = wilson_ci(n_strong, n_typed)

    by_cat = {}
    for s, v in field_verdicts.items():
        by_cat.setdefault(v["final"], []).append(s)

    # two fully-worked examples ( asks for these explicitly)
    worked = [
        {"server": "contrastcyber/contrastapi", "tool": "threat_report / ip_lookup",
         "continuous_x": "risk_score (0-100 integer, operational)",
         "candidate_s": "cloud_provider",
         "verdict": field_verdicts.get("cloud_provider"),
         "note": "The Stage-1 detector fired on `provider`. But cloud_provider is an attribute of the "
                 "IP being LOOKED UP (alongside is_datacenter, asn_name) — the response DESCRIBES that IP. "
                 "A d=1 swap of cloud_provider fabricates a different lookup subject, it is not a return-"
                 "assembly adapter fault → SUBJECT_INSTRUMENT, OUT. No policy documents a risk_score "
                 "threshold conditioned on cloud_provider."},
        {"server": "contrastcyber/contrastapi", "tool": "seo_audit",
         "continuous_x": "score / h1_count / external_link_count (operational)",
         "candidate_s": "cache_respected",
         "verdict": field_verdicts.get("cache_respected"),
         "note": "cache_respected is a boolean about whether THIS response's assembly honoured the cache — "
                 "a genuine transport/freshness key set by the pipeline, so BOTH passes confirm it "
                 "(structurally CONFIRMED_PIPELINE). But Step-3: NO published policy documents an SEO-score "
                 "threshold θ(cache_respected). So it is a structural pipeline-set field with no documented "
                 "θ(s) → NOT a strong C-substrate hit."},
    ]

    outcome = ("STRONG_CONFIRMED_C_SUBSTRATE" if n_strong else
               ("STRUCTURAL_PIPELINE_SET_no_documented_theta" if n_struct else
                "FOURTH_INFORMATIVE_NULL_no_confirmed_pipeline_set"))

    payload = {
        "experiment": "EXP-A2 — registry-scale substrate adjudication (audited subsample, zero execution)",
        "stage1_detector_sha256": stage1_hash,
        "adjudication_module_sha256": _frozen_hash(),
        "protocol": ("two independent passes (lexical + frozen semantic table), disagreement → OUT; "
                     "CONFIRMED_PIPELINE iff BOTH passes agree; Step-3 requires a DOCUMENTED third-party "
                     "θ(s) for a strong C-substrate hit."),
        "n_candidate_tools": n_tools, "n_candidate_servers": n_servers,
        "n_typed_returns_corpus": n_typed,
        "n_distinct_candidate_s_fields": len(distinct_s),
        "field_verdicts": field_verdicts,
        "s_fields_by_final_category": {k: sorted(v) for k, v in by_cat.items()},
        "n_structurally_confirmed_tools": n_struct,
        "n_structurally_confirmed_servers": n_servers_struct,
        "n_strong_confirmed_tools_with_documented_theta_s": n_strong,
        "structural_confirmed_rate_over_candidates": rate_struct_over_cand,
        "wilson95_structural_over_candidates": ci_struct_cand,
        "structural_confirmed_rate_over_typed": rate_struct_over_typed,
        "wilson95_structural_over_typed": ci_struct_typed,
        "strong_confirmed_rate_over_typed": rate_strong_over_typed,
        "wilson95_strong_over_typed": ci_strong_typed,
        "worked_examples": worked,
        "per_tool": tools,
        "outcome": outcome,
        "interpretation": (
            f"The T2-6 Stage-1 candidate habitat (5.0% of typed returns, 31 tools/8 servers) collapses under "
            f"conservative Stage-2 adjudication to {n_struct}/{n_tools} STRUCTURALLY pipeline-set tool"
            f"{'s' if n_struct != 1 else ''} "
            f"(only `cache_respected`, a cache-freshness key, survives both passes; every source/origin/"
            f"channel/provider field resolves SUBJECT or DUALUSE → OUT) and to {n_strong}/{n_tools} with a "
            f"documented θ(s). So the security-relevant (θ(s)-conditioned) confirmed rate is "
            f"{rate_strong_over_typed} of typed returns [Wilson {ci_strong_typed}] — a FOURTH informative "
            f"null joining the k8s policy-half, MCP data-half and OpenAPI data-half nulls: the C substrate "
            f"is not spontaneous in commodity typed ecosystems. The paper's necessity + soundness story never "
            f"rested on prevalence; the honest structural residual (cache_respected) is named, not hidden."),
        "kill_criterion_note": (" kill: 0 strong-confirmed → replace 'candidate habitat' by a fourth "
                                "informative null (done). The one structural pipeline-set field is reported "
                                "as an honest residual, with no documented θ(s)."),
        "limitation": ("Zero-execution schema adjudication (published Smithery schemas, not runtime returns). "
                       "8 servers / 31 tools = the full T2-6 candidate set (R1 suggested ≥20 servers; the "
                       "candidate population spans 8). The semantic pass is frozen per-field; disagreements "
                       "with the lexical pass resolve OUT (conservative). A documented θ(s) discovered later "
                       "would upgrade the corresponding structural field to a strong hit."),
    }

    (out_dir / "summary.json").write_text(json.dumps(payload, indent=2))
    _write_md(out_dir / "summary.md", payload)
    print(f"adjudication module {payload['adjudication_module_sha256'][:16]} · "
          f"stage1 {stage1_hash[:16]}")
    print(f"candidates: {n_tools} tools / {n_servers} servers ; typed returns corpus = {n_typed}")
    print("by final category:")
    for cat, fs in sorted(by_cat.items()):
        print(f"  {cat:22s} {len(fs):2d} s-fields: {', '.join(fs)}")
    print(f"structurally-confirmed pipeline-set tools: {n_struct}/{n_tools} "
          f"(rate over typed {rate_struct_over_typed}, Wilson {ci_struct_typed})")
    print(f"strong (documented θ(s)) tools: {n_strong}/{n_tools} "
          f"(rate over typed {rate_strong_over_typed}, Wilson {ci_strong_typed})")
    print(f"OUTCOME: {outcome}")
    print(f"wrote -> {out_dir/'summary.json'}\nwrote -> {out_dir/'summary.md'}")
    return payload


def _write_md(path: Path, p: dict):
    with open(path, "w") as f:
        f.write("# EXP-A2 — registry-scale substrate adjudication (audited subsample)\n\n")
        f.write(f"Stage-1 detector "
                f"`{p['stage1_detector_sha256'][:16]}`; adjudication module "
                f"`{p['adjudication_module_sha256'][:16]}` (frozen). {p['protocol']}\n\n")
        f.write(f"**Candidates:** {p['n_candidate_tools']} tools across {p['n_candidate_servers']} servers "
                f"(the full T2-6 substrate-candidate set); corpus = {p['n_typed_returns_corpus']} typed "
                f"returns.\n\n")
        f.write("### Distinct candidate `s`-field verdicts (two passes, disagreement → OUT)\n\n")
        f.write("| s-field | lexical | semantic | **final** | rationale |\n|---|---|---|---|---|\n")
        for s, v in sorted(p["field_verdicts"].items(),
                           key=lambda kv: (kv[1]["final"] != "CONFIRMED_PIPELINE", kv[0])):
            f.write(f"| `{s}` | {v['lexical']} | {v['semantic']} | **{v['final']}** | {v['rationale']} |\n")
        f.write("\n### Confirmed-pipeline funnel\n\n| stage | count | rate over typed | Wilson 95% |\n")
        f.write("|---|---|---|---|\n")
        f.write(f"| candidate tools (Stage-1) | {p['n_candidate_tools']} | "
                f"{round(p['n_candidate_tools']/p['n_typed_returns_corpus'],4)} | — |\n")
        f.write(f"| structurally CONFIRMED_PIPELINE | {p['n_structurally_confirmed_tools']} | "
                f"{p['structural_confirmed_rate_over_typed']} | {p['wilson95_structural_over_typed']} |\n")
        f.write(f"| strong (documented θ(s)) | {p['n_strong_confirmed_tools_with_documented_theta_s']} | "
                f"{p['strong_confirmed_rate_over_typed']} | {p['wilson95_strong_over_typed']} |\n\n")
        f.write("### Two worked examples\n\n")
        for w in p["worked_examples"]:
            f.write(f"- **{w['server']} · {w['tool']}** — continuous_x = {w['continuous_x']}; candidate "
                    f"`s` = `{w['candidate_s']}` → **{w['verdict']['final']}**. {w['note']}\n")
        f.write(f"\n**Outcome: {p['outcome']}.** {p['interpretation']}\n\n")
        f.write(f"*Kill criterion.* {p['kill_criterion_note']}\n\n")
        f.write(f"**Limitation.** {p['limitation']}\n")


def main():
    import argparse
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--summary", type=Path, default=T2_6_SUMMARY)
    ap.add_argument("--out", type=Path, default=DEFAULT_OUT)
    a = ap.parse_args()
    run(a.summary, a.out)


if __name__ == "__main__":
    main()
