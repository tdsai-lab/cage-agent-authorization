#!/usr/bin/env python3
"""
openapi_scan.py — NEW_EXP STEP 1+2: scan public OpenAPI/Swagger response schemas for the data-half-of-C
substrate (a typed RESPONSE object pairing a continuous operational `x` with a pipeline-set provenance `s`).
ZERO execution: pure static YAML parse of the APIs.guru directory (external/corpora/apisguru_openapi-directory),
the OpenAPI analogue of the MCP static zod parse and the §6.5 AST scan. Frozen detector = openapi_detector
(sha256 recorded below, committed before results).

Why OpenAPI: response schemas are MANDATORILY typed, so the typing failure that drove the MCP null (67%
untyped returns) cannot recur — only the PAIRING of `x` and pipeline-set `s` in one response object is in
question. Dual-rate (full corpus + financial/risk habitat), all cardinals, verbatim hits, parse-coverage.
"""
from __future__ import annotations

import json
import re
import signal
import subprocess
import sys
import time
from collections import Counter
from pathlib import Path

import yaml

_HERE = Path(__file__).resolve().parent
_BB = _HERE.parents[1]
sys.path.insert(0, str(_HERE))
import openapi_detector as det  # noqa: E402

CORPUS = _BB.parents[0] / "external" / "corpora" / "apisguru_openapi-directory"
OUT = _BB / "cert" / "out" / "mcp_substrate"
HABITAT_RE = re.compile(r"pay|bank|fraud|risk|kyc|aml|credit|transaction|sanction|lending|exposure|"
                        r"finance|stripe|adyen|plaid|qualpay|velopay|payrun|paylocity|nowpayments", re.I)
MAX_SPEC_BYTES = 4_000_000     # skip pathologically huge specs (logged as parse-skip; undercount only)
MAX_DEPTH = 6
MAX_LEAVES = 250
SPEC_TIMEOUT = 12              # per-spec hard wall (signal); on timeout -> parse=timeout (undercount only)


class _SpecTimeout(Exception):
    pass


def _on_alarm(signum, frame):
    raise _SpecTimeout()


def _deref(node, defs, seen, depth):
    """Resolve a $ref (local) and flatten allOf into a single schema dict. Cycle/depth guarded."""
    if not isinstance(node, dict) or depth > MAX_DEPTH:
        return {}
    if "$ref" in node:
        ref = node["$ref"]
        if not isinstance(ref, str) or not ref.startswith("#/") or ref in seen:
            return {}
        seen = seen | {ref}
        target = defs.get(ref.split("/")[-1])
        return _deref(target, defs, seen, depth + 1) if target else {}
    if "allOf" in node and isinstance(node["allOf"], list):
        merged = {"type": "object", "properties": {}}
        for sub in node["allOf"]:
            r = _deref(sub, defs, seen, depth + 1)
            merged["properties"].update(r.get("properties", {}) or {})
        # carry any sibling properties
        merged["properties"].update(node.get("properties", {}) or {})
        return merged
    return node


def _leaves(schema, defs, seen, depth, out):
    """Collect scalar leaf fields {name,type,enum,format} of a resolved response schema (bounded)."""
    if len(out) >= MAX_LEAVES or depth > MAX_DEPTH or not isinstance(schema, dict):
        return
    s = _deref(schema, defs, seen, depth)
    props = s.get("properties")
    if isinstance(props, dict):
        for name, sub in props.items():
            sub = _deref(sub, defs, seen, depth + 1) if isinstance(sub, dict) else {}
            t = sub.get("type")
            if isinstance(t, list):
                t = next((x for x in t if x != "null"), t[0] if t else None)
            if t in ("object",) or "properties" in sub:
                _leaves(sub, defs, seen, depth + 1, out)
            elif t == "array":
                _leaves(sub.get("items", {}) or {}, defs, seen, depth + 1, out)
            else:
                out.append({"name": str(name), "type": t, "enum": sub.get("enum"),
                            "format": sub.get("format")})
                if len(out) >= MAX_LEAVES:
                    return
    elif s.get("type") == "array":
        _leaves(s.get("items", {}) or {}, defs, seen, depth + 1, out)


def _response_schemas(spec):
    """Yield (path, method, code, schema) for every response body schema (OAS3 content / Swagger2 schema)."""
    for path, methods in (spec.get("paths") or {}).items():
        if not isinstance(methods, dict):
            continue
        for method, op in methods.items():
            if not isinstance(op, dict) or method not in ("get", "post", "put", "patch", "delete"):
                continue
            for code, resp in (op.get("responses") or {}).items():
                if not isinstance(resp, dict):
                    continue
                if "schema" in resp:                                   # Swagger 2
                    yield path, method, code, resp["schema"]
                for mt, media in (resp.get("content") or {}).items():  # OpenAPI 3
                    if isinstance(media, dict) and "schema" in media:
                        yield path, method, code, media["schema"]


def scan_spec(path: Path):
    """Return a per-spec record: typed-response presence + substrate hits (verbatim), or a parse error.
    Guarded by a per-spec wall (SPEC_TIMEOUT) — on timeout the spec is recorded parse=timeout (an honest
    undercount, logged in parse-coverage; never inflates the substrate rate)."""
    signal.signal(signal.SIGALRM, _on_alarm)
    signal.alarm(SPEC_TIMEOUT)
    try:
        return _scan_spec_inner(path)
    except _SpecTimeout:
        return {"parse": "timeout"}
    except Exception as e:  # noqa: BLE001
        return {"parse": f"error:{type(e).__name__}"}
    finally:
        signal.alarm(0)


def _scan_spec_inner(path: Path):
    if path.stat().st_size > MAX_SPEC_BYTES:
        return {"parse": "skip_too_big"}
    spec = yaml.safe_load(path.read_text(errors="ignore"))
    if not isinstance(spec, dict) or "paths" not in spec:
        return {"parse": "no_paths"}
    defs = (spec.get("components", {}) or {}).get("schemas", {}) or spec.get("definitions", {}) or {}
    n_resp = has_cont = has_pipe = 0
    hits = []
    for p, m, code, schema in _response_schemas(spec):
        leaves = []
        try:
            _leaves(schema, defs, set(), 0, leaves)
        except Exception:  # noqa: BLE001
            continue
        if not leaves:
            continue
        n_resp += 1
        labels = det.classify_fields(leaves)
        cset = [f for f in labels if f["label"] == "continuous_x"]
        pset = [f for f in labels if f["label"] == "pipeline_set_s"]
        has_cont += bool(cset); has_pipe += bool(pset)
        if cset and pset:
            hits.append({"path": p, "method": m, "code": code,
                         "x_fields": [f["name"] for f in cset][:5],
                         "s_fields": [f["name"] for f in pset][:5]})
    return {"parse": "ok", "n_typed_response": n_resp, "has_continuous": has_cont > 0,
            "has_pipeline": has_pipe > 0, "has_substrate": bool(hits), "hits": hits}


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    spec = det.frozen_spec()
    specs = sorted(CORPUS.glob("APIs/**/openapi.yaml")) + sorted(CORPUS.glob("APIs/**/swagger.yaml"))
    commit = _git_commit(CORPUS)

    def provider(p):                       # APIs/<provider>/...  -> provider dir
        rel = p.relative_to(CORPUS / "APIs")
        return rel.parts[0]

    tot = {"full": Counter(), "habitat": Counter()}
    hits_all, parse_fail = [], Counter()
    s_field_inv, x_field_inv = Counter(), Counter()    # distinct field-name inventory for Step-2 adjudication
    n_specs = n_habitat = 0
    apis_full, apis_hab = set(), set()
    t0 = time.time()
    for i, sp in enumerate(specs):
        prov = provider(sp)
        is_hab = bool(HABITAT_RE.search(prov))
        rec = scan_spec(sp)
        n_specs += 1; apis_full.add(prov)
        if is_hab:
            n_habitat += 1; apis_hab.add(prov)
        if rec["parse"] != "ok":
            parse_fail[rec["parse"]] += 1
            continue
        for scope, flag in (("full", True), ("habitat", is_hab)):
            if not flag:
                continue
            tot[scope]["parsed"] += 1
            tot[scope]["typed_resp"] += int(rec["n_typed_response"] > 0)
            tot[scope]["continuous"] += int(rec["has_continuous"])
            tot[scope]["pipeline"] += int(rec["has_pipeline"])
            tot[scope]["substrate"] += int(rec["has_substrate"])
        if rec["has_substrate"]:
            for h in rec["hits"]:
                hits_all.append({"provider": prov, "spec": str(sp.relative_to(CORPUS)), "habitat": is_hab, **h})
                for s in h["s_fields"]:
                    s_field_inv[s] += 1
                for x in h["x_fields"]:
                    x_field_inv[x] += 1
        if (i + 1) % 500 == 0:
            print(f"  ... {i+1}/{len(specs)} specs ({round(time.time()-t0)}s)", flush=True)

    def rate(scope, denom):
        return round(tot[scope]["substrate"] / denom, 5) if denom else 0.0
    substrate_full = rate("full", n_specs)
    substrate_hab = rate("habitat", n_habitat)
    n_parse_fail = sum(parse_fail.values())
    outcome = "SUBSTRATE_PRESENT_candidate_hits" if hits_all else "NULL_no_substrate"
    payload = {
        "corpus": "APIs.guru openapi-directory", "corpus_commit": commit, "execution": "none (static YAML parse)",
        "frozen_detector_sha256": spec["detector_sha256"], "criteria": spec["criteria"],
        "n_specs": n_specs, "n_apis": len(apis_full), "n_habitat_specs": n_habitat,
        "n_habitat_apis": len(apis_hab),
        "parse_coverage": round((n_specs - n_parse_fail) / n_specs, 4) if n_specs else 0.0,
        "parse_failures": dict(parse_fail),
        "full_corpus": {**tot["full"], "substrate_rate": substrate_full},
        "habitat_financial_risk": {**tot["habitat"], "substrate_rate": substrate_hab},
        "funnel": "Pr[native C|corpus] = Pr[substrate] x Pr[θ-cond|substrate] x Pr[Δ/ε|cond]",
        "outcome": outcome,
        "n_substrate_candidate_hits": len(hits_all),
        "n_specs_with_candidate_substrate": tot["full"]["substrate"],
        "distinct_s_fields_in_hits": dict(s_field_inv.most_common(60)),
        "distinct_x_fields_in_hits": dict(x_field_inv.most_common(30)),
        "substrate_candidate_hits": hits_all[:150],
        "note": ("Hits are CANDIDATES from the frozen automated detector; the pipeline-set vs subject-keyed "
                 "call is conservative (ambiguous->OUT) but each verbatim hit must be manually adjudicated "
                 "(Step-2 correctness check) — borderline `s` re-reads to subject_keyed and the hit drops. "
                 "is_substrate undercounts only (unresolved $ref / >8MB specs skipped, logged as "
                 "parse-coverage); it never inflates."),
        "limitation": ("Static parse; specs >8MB skipped; $ref resolved locally only; oneOf/anyOf branches "
                       "not exhaustively expanded. An OpenAPI response object is NOT identical to an "
                       "agent-consumed tool return in a loop — Step-3 caveat applies to any medium hit."),
    }
    (OUT / "openapi_substrate.json").write_text(json.dumps(payload, indent=2))
    print(f"\nfrozen detector {spec['detector_sha256'][:16]} · corpus @{commit} · "
          f"{n_specs} specs / {len(apis_full)} providers (parse_cov {payload['parse_coverage']})")
    print(f"FULL:    typed_resp={tot['full']['typed_resp']} continuous={tot['full']['continuous']} "
          f"pipeline={tot['full']['pipeline']} substrate={tot['full']['substrate']} "
          f"-> rate={substrate_full}")
    print(f"HABITAT: specs={n_habitat} typed_resp={tot['habitat']['typed_resp']} "
          f"continuous={tot['habitat']['continuous']} pipeline={tot['habitat']['pipeline']} "
          f"substrate={tot['habitat']['substrate']} -> rate={substrate_hab}")
    print(f"OUTCOME: {outcome} · candidate hits={len(hits_all)}")
    for h in hits_all[:15]:
        print(f"  HIT {h['provider']} {h['method'].upper()} {h['path']} [{h['code']}] "
              f"x={h['x_fields']} s={h['s_fields']}")
    print(f"wrote -> {OUT/'openapi_substrate.json'}")
    return payload


def _git_commit(root):
    try:
        r = subprocess.run(["git", "-C", str(root), "rev-parse", "HEAD"], capture_output=True,
                           text=True, timeout=15)
        return r.stdout.strip()[:12] if r.returncode == 0 else "n/a"
    except Exception:  # noqa: BLE001
        return "n/a"


if __name__ == "__main__":
    main()
