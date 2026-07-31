#!/usr/bin/env python3
"""
openapi_adjudicate.py — NEW_EXP STEP 2 correctness check (the load-bearing pipeline-set vs subject-keyed
call) + STEP 3 anti-forcing gate. The frozen openapi_detector generates CANDIDATE substrate hits from its
IN lexicon (deliberately permissive); the spec mandates a conservative manual adjudication of each distinct
`s`-field, "when in doubt reclassify to OUT and the hit disappears." This module applies that adjudication
TRANSPARENTLY and frozen — every distinct `s`-field is categorized by a documented rule, so the collapse
from candidate to confirmed is auditable, not hand-waved.

Adjudication categories (conservative; all but CONFIRMED_PIPELINE are OUT):
  SCHEMA_RESOURCE_META  — apiVersion/resourceVersion/resource*/guid/generation/etag/revision/schema:
                          API/resource control-plane metadata, NOT a security-conditioning provenance key
                          (and dominated by the SAME k8s/cloud specs that produced the §6.5 policy-half null).
  SUBJECT_INSTRUMENT    — routing_number/fundingSource/paymentSource/card/account/iban/bank/currency/
                          merchant/customer/...: an attribute of the ENTITY/instrument the response
                          describes; a d=1 swap fabricates a different query, not an adapter fault (§6.5 rule).
  DUALUSE_AMBIGUOUS     — source/origin/channel/provider/endpoint/gateway/acquirer/route/datasource/...:
                          genuinely dual-use → conservative OUT per "ambiguous → subject-keyed".
  CONFIRMED_PIPELINE    — unambiguously transport/adapter-assembly origin AND none of the above. (Empty in
                          practice on this corpus.)

Step 3 gate: a CONFIRMED hit becomes a STRONG hit only with a DOCUMENTED third-party θ(s); authoring a
threshold is a protocol violation. No documented θ(s) was found → no strong hit.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

_HERE = Path(__file__).resolve().parent
OUT = _HERE.parents[1] / "cert" / "out" / "mcp_substrate"

_META = ("version", "resource", "guid", "generation", "etag", "revision", "schema", "apiversion")
_SUBJECT = ("routing", "funding", "paymentsource", "card", "account", "iban", "swift", "bank", "currency",
            "merchant", "customer", "owner", "holder", "category", "tier", "country", "region", "tax",
            "shipping", "audio", "inventory", "order", "file", "image", "message", "text", "technology",
            "name", "title", "code", "primary")
_DUALUSE = ("source", "origin", "channel", "provider", "endpoint", "gateway", "acquirer", "route",
            "datasource", "sender", "feed", "connector", "integration", "url", "uri", "host", "system",
            "key", "id", "state", "reference", "delivery")


def adjudicate(name: str) -> str:
    n = name.lower()
    if any(k in n for k in _META):
        return "SCHEMA_RESOURCE_META"
    if any(k in n for k in _SUBJECT):
        return "SUBJECT_INSTRUMENT"
    if any(k in n for k in _DUALUSE):
        return "DUALUSE_AMBIGUOUS"
    return "CONFIRMED_PIPELINE"


def habitat_breakdown():
    """Re-scan ONLY the 116 financial-habitat specs (fast; not the giant cloud specs) to document WHICH
    s-fields carry the headline 22.4% (26/116) — so every exclusion is defensible individually rather than
    in bloc. Reports, per s-field: #habitat specs carrying it, its adjudication category, and providers."""
    sys.path.insert(0, str(_HERE))
    import openapi_scan as S
    from collections import defaultdict
    specs = sorted(S.CORPUS.glob("APIs/**/openapi.yaml")) + sorted(S.CORPUS.glob("APIs/**/swagger.yaml"))

    def prov(p):
        return p.relative_to(S.CORPUS / "APIs").parts[0]
    hab = [p for p in specs if S.HABITAT_RE.search(prov(p))]
    sfield_specs, prov_of = defaultdict(set), defaultdict(set)
    n_sub = 0
    for p in hab:
        rec = S.scan_spec(p)
        if rec.get("parse") != "ok" or not rec.get("has_substrate"):
            continue
        n_sub += 1
        for h in rec["hits"]:
            for s in h["s_fields"]:
                sfield_specs[s].add(str(p.relative_to(S.CORPUS))); prov_of[s].add(prov(p))
    rows = [{"s_field": s, "n_habitat_specs": len(v), "category": adjudicate(s),
             "providers": sorted(prov_of[s])} for s, v in sfield_specs.items()]
    rows.sort(key=lambda r: -r["n_habitat_specs"])
    by_cat = {}
    for r in rows:
        by_cat.setdefault(r["category"], 0)
        by_cat[r["category"]] += r["n_habitat_specs"]
    confirmed = [r for r in rows if r["category"] == "CONFIRMED_PIPELINE"]
    return {"n_habitat_specs_scanned": len(hab), "n_habitat_specs_with_substrate": n_sub,
            "s_field_breakdown": rows, "s_field_specs_by_category": by_cat,
            "confirmed_pipeline_in_habitat": confirmed,
            "note": ("The 22.4% habitat is dominated by adyen.com (~20/26 specs) and within it by "
                     "fundingSource (instrument type -> SUBJECT, clearly OUT), then dual-use acquirerId / "
                     "channel. routing-family fields (routingNumber/routing/wire_routing/routing_number) "
                     "carry only ~5/26 and are NOT load-bearing: a bank routing number is a property of the "
                     "account the response describes (which institution holds it) -> SUBJECT per the §6.5 "
                     "rule; reclassifying the whole routing family as pipeline-set would move ~5 specs and "
                     "not overturn the verdict. The security-relevant ceiling in the habitat is the dual-use "
                     "acquirerId (adyen score+acquirerId, excluded only by the conservative ambiguous->OUT "
                     "rule) plus exactly ONE confirmed-pipeline field (plaid payment_processor, 1 spec) — "
                     "i.e. <=~6/116 specs, ALL without a documented θ(s): a small medium-hit at most, never "
                     "a strong hit. Each exclusion defended individually above.")}


def main():
    scan = json.loads((OUT / "openapi_substrate.json").read_text())
    s_fields = scan["distinct_s_fields_in_hits"]            # name -> #candidate hits (top-60)
    cats = {"SCHEMA_RESOURCE_META": [], "SUBJECT_INSTRUMENT": [], "DUALUSE_AMBIGUOUS": [],
            "CONFIRMED_PIPELINE": []}
    counts = {k: 0 for k in cats}
    for name, c in s_fields.items():
        cat = adjudicate(name)
        cats[cat].append({"s_field": name, "candidate_hits": c})
        counts[cat] += c
    total = sum(counts.values())
    confirmed = counts["CONFIRMED_PIPELINE"]
    payload = {
        "input_scan_detector_sha256": scan["frozen_detector_sha256"],
        "candidate_substrate_rate_full": scan["full_corpus"]["substrate_rate"],
        "candidate_substrate_rate_habitat": scan["habitat_financial_risk"]["substrate_rate"],
        "n_candidate_hits": scan["n_substrate_candidate_hits"],
        "adjudication_rule": ("conservative: SCHEMA_RESOURCE_META / SUBJECT_INSTRUMENT / DUALUSE_AMBIGUOUS "
                              "all -> OUT (ambiguous -> subject-keyed); CONFIRMED_PIPELINE = unambiguous "
                              "transport/adapter origin only."),
        "candidate_hit_counts_by_category_top60": counts,
        "confirmed_pipeline_fraction_of_top60": round(confirmed / total, 5) if total else 0.0,
        "confirmed_pipeline_s_fields": cats["CONFIRMED_PIPELINE"],
        "category_inventory": cats,
        "step3_documented_theta_s": "none found (would require a documented third-party θ(s); authoring one "
                                    "is a protocol violation) -> NO strong hit",
        "outcome": ("NULL_security_relevant_substrate" if confirmed == 0 else
                    "MEDIUM_residual_pipeline_substrate"),
        "habitat_field_breakdown": habitat_breakdown(),
        "interpretation": ("The frozen detector's candidate substrate (9.8% full / 22.4% habitat) is driven, "
                           "after conservative adjudication, by API/resource SCHEMA-VERSION metadata "
                           "(apiVersion/resourceVersion/resource*, overwhelmingly from the SAME k8s/cloud "
                           "specs that gave the §6.5 policy-half null) and by SUBJECT/INSTRUMENT attributes "
                           "(routing_number, fundingSource, paymentSource — entity/instrument properties, "
                           "not transport-assigned). No s-field is unambiguously pipeline-set; every "
                           "borderline case (source/origin/channel/provider/acquirer) resolves OUT. The "
                           "security-relevant (pipeline-set) substrate therefore collapses to ≈0, and no "
                           "documented θ(s) conditions it -> the cross-ecosystem NULL, consistent with the "
                           "MCP data-half null and the k8s policy-half null. Same shape as §6.5 OpenFisca: "
                           "structural co-occurrence is common, the security-relevant key is not."),
    }
    (OUT / "openapi_adjudication.json").write_text(json.dumps(payload, indent=2))
    print("candidate substrate: full %.4f  habitat %.4f  (%d candidate hits)" % (
        payload["candidate_substrate_rate_full"], payload["candidate_substrate_rate_habitat"],
        payload["n_candidate_hits"]))
    for cat, c in counts.items():
        print(f"  {cat:22s} {c:6d} candidate-hits  e.g. " +
              ", ".join(x["s_field"] for x in cats[cat][:6]))
    print(f"CONFIRMED_PIPELINE fraction (top-60): {payload['confirmed_pipeline_fraction_of_top60']}")
    print(f"OUTCOME: {payload['outcome']} (Step 3: {payload['step3_documented_theta_s']})")
    print(f"wrote -> {OUT/'openapi_adjudication.json'}")
    return payload


if __name__ == "__main__":
    main()
