#!/usr/bin/env python3
"""
idiom_detector.py — PLAN_2 P1 Task A: a per-language matcher for the continuous provenance-conditioned
threshold idiom

    op(f_num, theta)   with   theta = theta(s),   s discrete (>=2 values),   op in {<, <=, >, >=}

i.e. a NUMERIC input field compared against a threshold that is SELECTED BY A DISCRETE/PROVENANCE key
(so a single discrete swap repositions the boundary -> the Category-C joint-gap becomes possible). Each
language matcher emits the same intermediate representation (IdiomHit). Rego uses the real `opa parse
--format json` AST (confidence 1.0); Kyverno / Cloud Custodian use the structured YAML; Sentinel uses a
heuristic tokenizer (low confidence, no public AST).

CONSERVATIVE bias (documented): the matcher recognises the explicit forms above; alternative encodings
(deeply nested if/else returning numeric thresholds, thresholds assembled by arithmetic across several
data refs) may be missed. Misses UNDER-count idiom_rate -> they under-state prevalence, never inflate it.

Calibrated on the authored #9b Rego (ground truth known). Frozen + hashed for pre-registration
(frozen_spec()); the scan (Task B) must cite that hash.
"""
from __future__ import annotations

import hashlib
import json
import re
import subprocess
import sys
from dataclasses import dataclass, asdict
from pathlib import Path

_HERE = Path(__file__).resolve().parent
_OPA = _HERE.parents[0] / "opa_gate"
sys.path.insert(0, str(_OPA))

COMPARE_OPS = {"lt": "<", "gt": ">", "lte": "<=", "gte": ">="}

# the idiom predicate, frozen verbatim into the pre-registration hash
IDIOM_PREDICATE = (
    "op(f_num, theta) with theta=theta(s); f_num a numeric INPUT ref; theta NON-scalar selected by a "
    "DISCRETE key s (function call / dict-index-by-variable / conditional keyed on a discrete field); "
    "op in {<,<=,>,>=}; s has >=2 distinct threshold values."
)


@dataclass
class IdiomHit:
    language: str
    idiom_present: bool
    f_num: str | None = None
    s_field: str | None = None
    thetas: list | None = None
    op: str | None = None
    source: str = ""
    confidence: float = 0.0
    evidence: str = ""
    numeric_threshold: bool = False   # a numeric comparison exists (keyed OR constant) — funnel signal

    def as_dict(self):
        return asdict(self)


# --------------------------------------------------------------------------- #
# Rego — real AST via `opa parse --format json`
# --------------------------------------------------------------------------- #
def _opa_path():
    p = _OPA / "bin" / "opa"
    return str(p) if p.exists() else "opa"


def _opa_parse(path) -> dict:
    proc = subprocess.run([_opa_path(), "parse", "--format", "json", str(path)],
                          capture_output=True, text=True, timeout=60)
    if proc.returncode != 0:
        raise RuntimeError(f"opa parse failed: {proc.stderr[:400]}")
    return json.loads(proc.stdout)


def _opname(t):
    if isinstance(t, dict) and t.get("type") == "ref":
        val = t.get("value")
        if isinstance(val, list) and val and val[0].get("type") == "var":
            return val[0].get("value")
    return None


def _iter_comparisons(node):
    """Yield (op, lhs, rhs) for every ordered comparison — in head values ({"type":"call",...}) and in
    body expressions ({"terms":[op,a,b]})."""
    if isinstance(node, dict):
        if node.get("type") == "call" and isinstance(node.get("value"), list) and len(node["value"]) >= 3:
            op = _opname(node["value"][0])
            if op in COMPARE_OPS:
                yield op, node["value"][1], node["value"][2]
        ts = node.get("terms")
        if isinstance(ts, list) and len(ts) >= 3:
            op = _opname(ts[0])
            if op in COMPARE_OPS:
                yield op, ts[1], ts[2]
        for v in node.values():
            yield from _iter_comparisons(v)
    elif isinstance(node, list):
        for v in node:
            yield from _iter_comparisons(v)


def _ref_tail(t):
    """Last string segment of a ref (the field name), e.g. c.x2.risk_score -> 'risk_score'."""
    if t.get("type") == "ref" and isinstance(t.get("value"), list):
        strs = [s["value"] for s in t["value"][1:] if s.get("type") == "string"]
        if strs:
            return strs[-1]
        if t["value"][0].get("type") == "var":
            return t["value"][0]["value"]
    return None


def _is_input_ref(t):
    """A ref rooted at a document variable (input, data, or a rule arg like `c`) — not a builtin call."""
    return (t.get("type") == "ref" and isinstance(t.get("value"), list)
            and t["value"] and t["value"][0].get("type") == "var")


def _is_scalar(t):
    return t.get("type") in ("number", "string", "boolean", "null")


def _threshold_dependency(t):
    """If `t` is a NON-scalar threshold selected by a discrete key, return (s_field, kind); else None.
    Forms: a function call threshold(<disc>) ; a ref indexing a collection by a variable key base[key]."""
    if t.get("type") == "call" and isinstance(t.get("value"), list) and len(t["value"]) >= 2:
        # function call: args after the function ref carry the discrete key(s)
        for arg in t["value"][1:]:
            s = _ref_tail(arg)
            if s:
                return s, "function_call"
        return "(arg)", "function_call"
    if t.get("type") == "ref" and isinstance(t.get("value"), list) and len(t["value"]) >= 2:
        # dict/array index by a VARIABLE key: base[tool]  (value=[{var base},{var tool}])
        for seg in t["value"][1:]:
            if seg.get("type") == "var":
                return seg.get("value"), "dict_index_by_var"
    return None


def detect_rego(path) -> IdiomHit:
    path = Path(path)
    try:
        ast = _opa_parse(path)
    except Exception as e:  # noqa: BLE001
        return IdiomHit("rego", False, source=str(path), confidence=0.0, evidence=f"parse_error:{e}")
    numeric_threshold = False
    for op, a, b in _iter_comparisons(ast):
        for num, thr in ((a, b), (b, a)):
            if _is_input_ref(num) and not _is_scalar(num):
                # a numeric input field is being compared against something (keyed or constant)
                numeric_threshold = numeric_threshold or _is_scalar(thr) or _threshold_dependency(thr) is not None
                if not _is_scalar(thr):
                    dep = _threshold_dependency(thr)
                    if dep is not None:
                        s_field, kind = dep
                        thetas = _recover_thetas(path)
                        if thetas is None or len(set(thetas)) >= 2:
                            return IdiomHit("rego", True, f_num=_ref_tail(num), s_field=s_field,
                                            thetas=thetas, op=COMPARE_OPS[op], source=str(path),
                                            confidence=1.0, evidence=f"ast:{kind}",
                                            numeric_threshold=True)
    return IdiomHit("rego", False, source=str(path), confidence=1.0,
                    evidence="no_provenance_threshold", numeric_threshold=numeric_threshold)


def _recover_thetas(path):
    """Best-effort distinct threshold values from numeric-literal dicts / conditional offsets in text."""
    txt = Path(path).read_text()
    vals = []
    for body in re.findall(r":=\s*\{([^}]*)\}", txt):
        vals += [float(v) for _, v in re.findall(r'"([^"]+)"\s*:\s*(-?\d+(?:\.\d+)?)', body)]
    # delta-style additive offset (theta_base + delta) -> a second distinct value
    base = re.search(r"theta_base\s*:=\s*(-?\d+(?:\.\d+)?)", txt)
    delta = re.search(r"delta\s*:=\s*(-?\d+(?:\.\d+)?)", txt)
    if base and delta:
        b, d = float(base.group(1)), float(delta.group(1))
        vals += [b, b + d]
    return vals or None


# --------------------------------------------------------------------------- #
# Kyverno — structured YAML (validate.deny.conditions / validate.cel.expressions)
# --------------------------------------------------------------------------- #
def _load_yaml_docs(path):
    import yaml
    with open(path) as f:
        return [d for d in yaml.safe_load_all(f) if isinstance(d, dict)]


_CEL_CMP = re.compile(r"([A-Za-z_][\w.\[\]'\"]*)\s*(<=|>=|<|>)\s*([A-Za-z_][\w.\[\]'\"()]*)")
_DISCRETE_KEYS = ("label", "namespace", "tier", "env", "annotation", "kind", "team", "role",
                  "tenant", "tenant")


_KYV_NUM_OP = {"GreaterThan": ">", "LessThan": "<", "GreaterThanOrEquals": ">=",
               "LessThanOrEquals": "<=", "GreaterThanEquals": ">=", "LessThanEquals": "<="}
_TPL_KEYED = re.compile(r"\{\{.*\b(namespace|label|tier|env|annotation|team|tenant|role)\b.*\}\}",
                        re.IGNORECASE)


def _kyverno_conditions(docs):
    """Yield deny/precondition entries {key, operator, value} anywhere in the policy tree."""
    def walk(o):
        if isinstance(o, dict):
            if "operator" in o and ("value" in o or "key" in o):
                yield o
            for v in o.values():
                yield from walk(v)
        elif isinstance(o, list):
            for v in o:
                yield from walk(v)
    for d in docs:
        yield from walk(d)


def detect_kyverno(path) -> IdiomHit:
    try:
        docs = _load_yaml_docs(path)
    except Exception as e:  # noqa: BLE001
        return IdiomHit("kyverno", False, source=str(path), evidence=f"yaml_error:{e}")
    numeric_threshold = False
    blob = json.dumps(docs)
    # (a) CEL expressions: numeric comparison whose RHS resolves from a map keyed on a discrete field
    for m in _CEL_CMP.finditer(blob):
        lhs, op, rhs = m.groups()
        numeric_threshold = True
        if ("[" in rhs) and any(k in rhs.lower() for k in _DISCRETE_KEYS):
            return IdiomHit("kyverno", True, f_num=lhs.split(".")[-1], s_field="(cel_map_key)",
                            op=op, source=str(path), confidence=0.7, evidence="cel_map_index",
                            numeric_threshold=True)
    # (b) deny.conditions / preconditions: numeric operator whose `value` (threshold) is keyed on a
    # discrete field via a {{ ... label/namespace/tier ... }} template (vs a constant literal).
    for cond in _kyverno_conditions(docs):
        opname = str(cond.get("operator", ""))
        if opname in _KYV_NUM_OP:
            numeric_threshold = True
            val = str(cond.get("value", ""))
            if _TPL_KEYED.search(val):
                return IdiomHit("kyverno", True, f_num=str(cond.get("key", ""))[:40],
                                s_field="(template_key)", op=_KYV_NUM_OP[opname], source=str(path),
                                confidence=0.6, evidence="deny_condition_templated_threshold",
                                numeric_threshold=True)
    return IdiomHit("kyverno", False, source=str(path), confidence=0.7,
                    evidence="no_keyed_threshold", numeric_threshold=numeric_threshold)


# --------------------------------------------------------------------------- #
# Cloud Custodian — YAML value filters {type: value, op: greater-than|lt|.., value: N}
# --------------------------------------------------------------------------- #
_C7N_OPS = {"greater-than": ">", "gt": ">", "ge": ">=", "gte": ">=", "less-than": "<",
            "lt": "<", "le": "<=", "lte": "<=", "greater-than-or-equal": ">=",
            "less-than-or-equal": "<="}


def _c7n_value_filters(docs):
    """Yield value-filter dicts {type: value, op: ..., value/value_from: ...} anywhere in the tree."""
    def walk(o):
        if isinstance(o, dict):
            if o.get("type") == "value" and "op" in o:
                yield o
            for v in o.values():
                yield from walk(v)
        elif isinstance(o, list):
            for v in o:
                yield from walk(v)
    for d in docs:
        yield from walk(d)


def detect_cloud_custodian(path) -> IdiomHit:
    try:
        docs = _load_yaml_docs(path)
    except Exception as e:  # noqa: BLE001
        return IdiomHit("cloud_custodian", False, source=str(path), evidence=f"yaml_error:{e}")
    numeric_threshold = False
    for filt in _c7n_value_filters(docs):
        if str(filt.get("op", "")) in _C7N_OPS:
            numeric_threshold = True
            # idiom: the numeric bound is selected from a per-categorical map (value_from), not a constant
            if "value_from" in filt:
                return IdiomHit("cloud_custodian", True, f_num=str(filt.get("key", ""))[:40],
                                s_field="(value_from_map)", op=_C7N_OPS[str(filt["op"])],
                                source=str(path), confidence=0.6, evidence="value_from_threshold_map",
                                numeric_threshold=True)
    return IdiomHit("cloud_custodian", False, source=str(path), confidence=0.6,
                    evidence="no_value_from_threshold", numeric_threshold=numeric_threshold)


# --------------------------------------------------------------------------- #
# Sentinel — heuristic tokenizer (no clean public AST) -> low-confidence flag
# --------------------------------------------------------------------------- #
_SENTINEL_CMP = re.compile(r"([A-Za-z_][\w.]*)\s*(<=|>=|<|>)\s*([A-Za-z_][\w.\[\]\"']*)")


def detect_sentinel(path) -> IdiomHit:
    txt = Path(path).read_text()
    for m in _SENTINEL_CMP.finditer(txt):
        lhs, op, rhs = m.groups()
        if ("[" in rhs) and any(k in rhs.lower() for k in _DISCRETE_KEYS):
            return IdiomHit("sentinel", True, f_num=lhs.split(".")[-1], s_field="(map_key)", op=op,
                            source=str(path), confidence=0.4, evidence="heuristic_map_index")
    return IdiomHit("sentinel", False, source=str(path), confidence=0.4, evidence="no_keyed_threshold")


# --------------------------------------------------------------------------- #
# dispatch + calibration + frozen spec
# --------------------------------------------------------------------------- #
_DETECTORS = {".rego": detect_rego, ".yaml": detect_kyverno, ".yml": detect_kyverno,
              ".sentinel": detect_sentinel, ".hcl": detect_sentinel}


def detect_file(path, language=None) -> IdiomHit:
    path = Path(path)
    if language == "cloud_custodian":
        return detect_cloud_custodian(path)
    if language and language in ("rego", "kyverno", "sentinel", "cloud_custodian"):
        return {"rego": detect_rego, "kyverno": detect_kyverno, "sentinel": detect_sentinel,
                "cloud_custodian": detect_cloud_custodian}[language](path)
    fn = _DETECTORS.get(path.suffix.lower())
    if fn is None:
        return IdiomHit("unknown", False, source=str(path), evidence="unsupported_extension")
    return fn(path)


def frozen_spec() -> dict:
    """Pre-registration record: sha256 of this detector + the frozen idiom predicate."""
    src = Path(__file__).read_bytes()
    return {"detector_sha256": hashlib.sha256(src).hexdigest(),
            "idiom_predicate": IDIOM_PREDICATE,
            "compare_ops": sorted(COMPARE_OPS.values()),
            "languages": ["rego(ast)", "kyverno(yaml)", "cloud_custodian(yaml)", "sentinel(heuristic)"]}


def calibrate(positives, negatives, language="rego") -> dict:
    """precision / recall on a labelled calibration set (positives = idiom present)."""
    tp = sum(detect_file(p, language).idiom_present for p in positives)
    fn = len(positives) - tp
    fp = sum(detect_file(n, language).idiom_present for n in negatives)
    tn = len(negatives) - fp
    precision = tp / max(1, tp + fp)
    recall = tp / max(1, tp + fn)
    return {"tp": tp, "fp": fp, "tn": tn, "fn": fn, "precision": round(precision, 4),
            "recall": round(recall, 4)}


def _authored():
    pol = _OPA / "policies" / "authored"
    pos = [pol / f for f in ("ieee_fraud.rego", "finance.rego", "sre.rego", "ops.rego")]
    neg = [pol / "constant_threshold_control.rego"]
    return [p for p in pos if p.exists()], [n for n in neg if n.exists()]


def main():
    pos, neg = _authored()
    cal = calibrate(pos, neg, "rego")
    spec = frozen_spec()
    out = _OPA.parents[1] / "cert" / "out"
    out.mkdir(parents=True, exist_ok=True)
    rows = [detect_file(p, "rego").as_dict() for p in pos + neg]
    res = {"frozen_spec": spec, "calibration": cal, "per_file": rows}
    (out / "idiom_detector_calibration.json").write_text(json.dumps(res, indent=2))

    print(f"detector sha256: {spec['detector_sha256']}")
    print(f"calibration (Rego authored): precision={cal['precision']} recall={cal['recall']} "
          f"(tp={cal['tp']} fp={cal['fp']} tn={cal['tn']} fn={cal['fn']})")
    for r in rows:
        print(f"  {Path(r['source']).name:36s} idiom={int(r['idiom_present'])} "
              f"f_num={r['f_num']} s={r['s_field']} op={r['op']} conf={r['confidence']} "
              f"[{r['evidence']}]")
    print(f"\nwrote {out / 'idiom_detector_calibration.json'}")


if __name__ == "__main__":
    main()
