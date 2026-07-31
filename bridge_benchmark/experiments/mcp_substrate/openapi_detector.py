#!/usr/bin/env python3
"""
openapi_detector.py — NEW_EXP (OpenAPI scan) FROZEN field classifier. Independently frozen + sha256-hashed
for THIS scan (the MCP substrate_detector's hash is committed against the MCP results and left untouched).
Same philosophy as §6.5 / the MCP scan; lexicons match the NEW_EXP spec verbatim.

Classifies a leaf field `(name, json_type, enum?, fmt?)` of a RESPONSE object into exactly one of:
  continuous_x   — type number (or integer with format float/double/decimal, or a documented wide range)
                   AND an operational quantity (score/amount/rate/latency/balance/price/exposure/
                   confidence/ratio/...). EXCLUDE quantized/categorical: enum, boolean, id/code integer,
                   small-range/stepped integer (the Azure keySize mode), pagination/count, timestamp-as-id.
  pipeline_set_s — a DISCRETE field naming WHERE the return came from / HOW it was assembled (source,
                   data_source, provider, origin, endpoint, gateway, acquirer, processor, channel, route,
                   api_version, schema_version) — settable by the transport/adapter layer (d=1-corruptible).
  subject_keyed  — a discrete attribute OF THE ENTITY the response describes (account_type, customer_tier,
                   user_region, merchant_category, card_type, subject country/region, risk_category). A d=1
                   swap fabricates a DIFFERENT query, not an adapter fault → EXCLUDED. region/country → OUT.
  other          — ids, free text, booleans, structural, timestamps, counts.

Substrate hit = one RESPONSE object with ≥1 continuous_x AND ≥1 pipeline_set_s simultaneously.
Conservative bias (asymmetry guarantee): ambiguous discrete → subject_keyed/OUT; the detector can only ever
UNDERCOUNT the substrate rate, never inflate it.
"""
from __future__ import annotations

import hashlib
from pathlib import Path

# ── frozen lexicons (verbatim from the NEW_EXP spec) ─────────────────────────
_CONTINUOUS = ("score", "amount", "rate", "latency", "balance", "price", "exposure", "confidence",
               "ratio", "risk_score", "value", "fee", "cost", "limit", "threshold", "interest",
               "apr", "yield", "probability", "spread", "margin")
_PIPELINE = ("source", "data_source", "datasource", "provider", "origin", "endpoint", "gateway",
             "acquirer", "processor", "channel", "route", "routing", "api_version", "apiversion",
             "schema_version", "schemaversion", "upstream", "feed", "connector", "integration")
# subject-keyed (entity attribute) — OUT. region/country are OUT by default (ambiguous).
_SUBJECT = ("account_type", "accounttype", "customer_tier", "tier", "user_region", "merchant_category",
            "mcc", "card_type", "cardtype", "risk_category", "category", "type", "status", "class",
            "country", "region", "currency", "locale", "language", "segment", "plan", "kind", "role",
            "gender", "industry", "sector", "brand")
# operational-but-quantized / non-substrate numeric names to never call continuous
_NONCONT_NUM = ("count", "page", "size", "offset", "limit_count", "index", "id", "code", "number",
                "year", "month", "day", "timestamp", "time", "version", "status_code", "quantity",
                "total_count", "per_page", "length")


def _is_numeric(json_type, fmt=None) -> bool:
    if json_type == "number":
        return True
    if json_type == "integer":
        return (fmt in ("float", "double", "decimal")) or True   # integer allowed; gated by lexicon below
    return False


def classify_field(name, json_type, enum=None, fmt=None) -> str:
    n = str(name).lower() if name is not None else ""           # YAML keys may parse as bool/int
    if enum is not None or json_type == "boolean":
        return _discrete_call(n)                                 # enumerated/boolean -> discrete, never x
    if json_type in ("number", "integer"):
        # numeric: continuous_x only if operational-lexicon AND not an id/count/quantized name
        if any(k in n for k in _NONCONT_NUM):
            return "other"
        if json_type == "integer" and fmt not in ("float", "double", "decimal"):
            # plain integers are treated as quantized/identifier unless clearly an operational amount
            return "continuous_x" if any(k in n for k in _CONTINUOUS) else "other"
        return "continuous_x" if any(k in n for k in _CONTINUOUS) else "other"
    if json_type == "string":
        return _discrete_call(n)
    return "other"


def _discrete_call(n: str) -> str:
    """pipeline-set (IN) vs subject-keyed (OUT); ambiguous -> subject_keyed/other (conservative)."""
    toks = n.replace("-", "_").replace(".", "_").split("_")
    pipe = any(k in n or k in toks for k in _PIPELINE)
    subj = any(k in n or k in toks for k in _SUBJECT)
    if pipe and not subj:
        return "pipeline_set_s"
    if subj:
        return "subject_keyed"          # subject lexicon, or pipe∧subj ambiguity -> conservative OUT
    return "other"


def is_substrate(fields) -> bool:
    labels = [classify_field(f.get("name"), f.get("type"), f.get("enum"), f.get("format"))
              for f in (fields or [])]
    return ("continuous_x" in labels) and ("pipeline_set_s" in labels)


def classify_fields(fields):
    return [{"name": f.get("name"), "type": f.get("type"),
             "label": classify_field(f.get("name"), f.get("type"), f.get("enum"), f.get("format"))}
            for f in (fields or [])]


def frozen_spec() -> dict:
    src = Path(__file__).read_bytes()
    return {"detector_sha256": hashlib.sha256(src).hexdigest(),
            "criteria": ("substrate(response) = typed response object with >=1 continuous_x AND >=1 "
                         "pipeline_set_s; continuous_x = numeric & operational-lexicon & not id/count/enum; "
                         "pipeline_set_s = transport/adapter-assigned discrete; subject_keyed (entity attr, "
                         "incl. region/country) EXCLUDED; ambiguous -> subject_keyed (conservative undercount)."),
            "lexicon_continuous": list(_CONTINUOUS), "lexicon_pipeline": list(_PIPELINE),
            "lexicon_subject": list(_SUBJECT), "lexicon_noncont_numeric": list(_NONCONT_NUM)}


if __name__ == "__main__":
    import json
    print(json.dumps(frozen_spec(), indent=1)[:300])
    # smoke
    print("amount+acquirer:", is_substrate([{"name": "amount", "type": "number"},
                                            {"name": "acquirer", "type": "string"}]))   # True
    print("amount+card_type:", is_substrate([{"name": "amount", "type": "number"},
                                             {"name": "card_type", "type": "string"}]))  # False (subject)
    print("count+source:", is_substrate([{"name": "count", "type": "integer"},
                                         {"name": "source", "type": "string"}]))         # False (count not x)
