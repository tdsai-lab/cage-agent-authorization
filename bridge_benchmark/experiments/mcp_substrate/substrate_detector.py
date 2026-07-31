#!/usr/bin/env python3
"""
substrate_detector.py — NEW_MCP_EXP frozen field classifier (the schema analogue of the §6.5 sha256-hashed
AST idiom detector). Criteria are FROZEN here and the file is self-hashed (`frozen_spec()`); the hash is
recorded in the scan output BEFORE any result is read. No post-hoc criteria tuning.

It classifies a single typed field `(name, json_type, enum?, n_distinct?)` into exactly one of:
  continuous_x     — a real-valued OPERATIONAL quantity with a meaningful ε-ball (score/confidence/risk/
                     amount/price/balance/latency/rate/count/temperature/...), numeric & NOT quantized.
  quantized        — numeric but integer-stepped small range or finite enum (the Azure keySize failure
                     mode: existence anchor, NOT continuous substrate).
  pipeline_set_s   — a DISCRETE field assigned by the return-assembly/transport layer (server/tool identity,
                     source endpoint/API origin, schema/version tag, routing/multiplexing label, cache-
                     origin/freshness tag, policy-pack id, environment) — corruptible by a d=1 adapter swap.
  subject_keyed    — a discrete attribute OF THE ENTITY the tool reports on (user region, account tier,
                     customer status, document class, device). A d=1 swap fabricates a different query, NOT
                     an adapter fault. EXCLUDED (mirrors the §6.5 OpenFisca subject-keyed null).
  other            — free text, ids, booleans, structural fields, etc.

Substrate (return-side) = a single tool's TYPED RETURN carrying ≥1 continuous_x AND ≥1 pipeline_set_s.
Conservative bias (honesty rule): when the pipeline-set vs subject-keyed call is ambiguous, classify as
subject_keyed (OUT) — never inflate the security-relevant rate.
"""
from __future__ import annotations

import hashlib
import re
from pathlib import Path

# ── frozen lexicons ─────────────────────────────────────────────────────────
# continuous operational quantities (must ALSO be a numeric type and not quantized)
_CONTINUOUS = ("score", "confidence", "risk", "amount", "price", "cost", "balance", "latency",
               "duration", "rate", "ratio", "probability", "temperature", "humidity", "distance",
               "value", "weight", "size", "bytes", "length", "count", "total", "sum", "average",
               "percent", "percentage", "level", "magnitude", "volume", "speed")
# pipeline-set provenance / transport-assigned (IN — security-relevant)
_PIPELINE = ("server", "tool", "source", "endpoint", "origin", "provider", "upstream", "api",
             "schema_version", "schemaversion", "version", "route", "routing", "channel", "cache",
             "freshness", "stale", "ttl", "policy_pack", "policypack", "environment", " env", "env_",
             "staging", "prod", "datasource", "data_source", "feed", "vendor", "gateway", "transport",
             "backend", "shard", "replica", "node", "host")
# subject-keyed (OUT — an attribute of the reported entity; a swap fabricates a different query)
_SUBJECT = ("region", "country", "locale", "tier", "status", "class", "category", "type", "kind",
            "device", "user", "customer", "account", "owner", "gender", "age", "segment", "plan",
            "role", "group", "department", "currency", "language", "lang", "city", "state", "zip",
            "address", "name", "title", "label", "tag", "genre", "color", "brand")

COMPARE = ()  # (the detector classifies fields, not comparisons; thresholds are Stage 2's job)


def _num(json_type) -> bool:
    return json_type in ("number", "integer")


def classify_field(name: str, json_type, enum=None, n_distinct=None, fmt=None) -> str:
    n = (name or "").lower()
    # quantized: an enum, or an integer constrained to a small finite set (Azure keySize mode)
    if enum is not None or (json_type == "integer" and n_distinct is not None and n_distinct <= 8):
        # an enumerated/stepped field is discrete -> route to a provenance/subject call, never continuous_x
        return _discrete_call(n) if not _num(json_type) or enum is not None else "quantized"
    if _num(json_type) and any(k in n for k in _CONTINUOUS):
        return "continuous_x"
    if _num(json_type):
        return "quantized" if json_type == "integer" else "continuous_x" if any(k in n for k in _CONTINUOUS) else "other"
    # non-numeric (string/boolean/etc.): only a DISCRETE provenance/subject string can be `s`
    if json_type in ("string", "boolean") or enum is not None:
        return _discrete_call(n)
    return "other"


def _discrete_call(n: str) -> str:
    """pipeline-set (IN) vs subject-keyed (OUT); conservative -> subject_keyed when ambiguous."""
    pipe = any(k.strip("_ ") in n.replace("-", "_").split("_") or k in n for k in _PIPELINE)
    subj = any(k in n for k in _SUBJECT)
    if pipe and not subj:
        return "pipeline_set_s"
    if subj:
        return "subject_keyed"           # subject lexicon (or ambiguous both) -> conservative OUT
    return "other"                       # unknown discrete field -> not security-relevant, not subject


def is_substrate(return_fields) -> bool:
    """return_fields: list of dicts {name, type, enum?, n_distinct?}. Substrate iff the TYPED RETURN has
    ≥1 continuous_x AND ≥1 pipeline_set_s simultaneously."""
    labels = [classify_field(f.get("name"), f.get("type"), f.get("enum"), f.get("n_distinct"))
              for f in (return_fields or [])]
    return ("continuous_x" in labels) and ("pipeline_set_s" in labels)


def classify_fields(fields):
    return [{"name": f.get("name"), "type": f.get("type"),
             "label": classify_field(f.get("name"), f.get("type"), f.get("enum"), f.get("n_distinct"))}
            for f in (fields or [])]


def frozen_spec() -> dict:
    src = Path(__file__).read_bytes()
    return {"detector_sha256": hashlib.sha256(src).hexdigest(),
            "criteria": ("substrate(return) = typed return with >=1 continuous_x AND >=1 pipeline_set_s; "
                         "continuous_x = numeric & operational-lexicon & not quantized; pipeline_set_s = "
                         "discrete transport/provenance-assigned; subject_keyed (entity attribute) EXCLUDED; "
                         "ambiguous discrete -> subject_keyed (conservative)."),
            "lexicon_continuous": list(_CONTINUOUS), "lexicon_pipeline": list(_PIPELINE),
            "lexicon_subject": list(_SUBJECT)}


if __name__ == "__main__":
    import json
    print(json.dumps(frozen_spec(), indent=1)[:400])
    # smoke: the everything demo weather return (continuous, NO provenance) is NOT substrate
    demo = [{"name": "temperature", "type": "number"}, {"name": "humidity", "type": "number"},
            {"name": "conditions", "type": "string"}]
    print("weather-demo substrate:", is_substrate(demo))           # expect False (no pipeline_set_s)
    cwit = [{"name": "risk_score", "type": "number"}, {"name": "source_endpoint", "type": "string"}]
    print("constructed (risk+source) substrate:", is_substrate(cwit))   # expect True
