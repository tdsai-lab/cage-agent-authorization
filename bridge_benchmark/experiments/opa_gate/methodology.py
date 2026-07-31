#!/usr/bin/env python3
"""
methodology.py — registered methodological controls for the OPA-gate experiment (NEW_EXPS_8).

The review (NEW_EXPS_8.md) notes that the policy THRESHOLDS are protected from tuning, but three other
degrees of freedom — the discrete neighborhood, the input sampling scheme, and the normalization — are
not, and those jointly determine C% as much as the thresholds. This module makes all three explicit and
pre-registerable, and adds the exact-verification baseline:

  * registered discrete neighborhoods (frozen, mechanism-tagged) — `discrete_neighborhoods.json`;
  * `has_category_conditioned_threshold(...)` idiom detector for the two-stage prevalence funnel;
  * documented field ranges / normalization constants + the implied Δ/ε per registered edge, so the
    geometric C-interval-length = min(Δ, ε) law is testable out-of-house;
  * provenance tiers + the pre-registered interpretation ladder;
  * the exact-verification-over-B_{1,ε} baseline is the OPA oracle's own `category == "R"` decision
    (it enumerates N_1 and checks the threshold at x ± ε per branch), exposed here as a calibration
    reference for the smoothed gate's looseness.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

_HERE = Path(__file__).resolve().parent
_NEIGH = _HERE / "discrete_neighborhoods.json"

# domain config key in discrete_neighborhoods.json for the synthetic-K8s Track-A corpus
K8S_KEY = "k8s_gatekeeper"


# --------------------------------------------------------------------------- #
# frozen neighborhoods + registered swaps
# --------------------------------------------------------------------------- #
def load_neighborhoods() -> dict:
    return json.loads(_NEIGH.read_text())


def _domain_block(domain: str) -> dict:
    nb = load_neighborhoods()
    return nb["domains"][domain]


def registered_edge_fields(domain: str) -> dict:
    """field_name -> {values, mechanism, affects_threshold}. '__tool__' denotes the tool identity."""
    return _domain_block(domain)["registered_edges"]


def registered_swaps(domain: str, tool: str, x1: dict, d: int = 1):
    """Yield (tool', x1', changed_field, mechanism) for every d=1 swap along a REGISTERED edge only.
    Edges with no assignable TM2 mechanism (see excluded_fields) are never traversed. d>1 not used."""
    if d != 1:
        raise ValueError("registered neighborhood is frozen at d=1 (MVP threat model)")
    edges = registered_edge_fields(domain)
    for field, spec in edges.items():
        mech = spec["mechanism"]
        if field == "__tool__":
            for v in spec["values"]:
                if v != tool:
                    yield v, dict(x1), "__tool__", mech
        else:
            if field not in x1:
                continue
            for v in spec["values"]:
                if v != x1[field]:
                    x12 = dict(x1); x12[field] = v
                    yield tool, x12, field, mech


def registered_state_count(domain: str, tool: str, x1: dict) -> int:
    """|N_1(s)| over registered edges, INCLUDING the identity state (for the family-wise α split)."""
    return 1 + sum(1 for _ in registered_swaps(domain, tool, x1, 1))


# --------------------------------------------------------------------------- #
# idiom detector — provenance-conditioned numeric threshold (Gap 1 funnel)
# --------------------------------------------------------------------------- #
# The idiom that makes joint-gap (Category-C) witnesses possible: a NUMERIC field is compared against a
# threshold that is INDEXED BY A CATEGORICAL/provenance field (so a discrete swap repositions the
# numeric boundary). We detect it structurally on Rego text.
_NUM_CMP = re.compile(r"[\w.]+\s*[<>]=?\s*[\w.]")          # a numeric comparison `a < b`
_THRESHOLD_FN = re.compile(r"\bthreshold\s*\(")           # an explicit threshold(...) helper


def has_category_conditioned_threshold(rego_text: str) -> dict:
    """Structural detector for the provenance-conditioned-threshold idiom: a NUMERIC threshold value is
    selected by INDEXING A NUMERIC-LITERAL DICT with a categorical/provenance key, and that value feeds
    a numeric comparison (so a discrete swap repositions the boundary). Returns {present, evidence}.

    Scope (documented honesty): this detects the `base[tool] + adj[x1.field]` representation used by
    policy-as-code. It will NOT recognise alternative encodings (e.g. nested if/else returning numeric
    thresholds keyed on a label). That bias is CONSERVATIVE — it can only UNDER-count idiom_rate, which
    under-states the prevalence product P(C|corpus) rather than inflating it. A fixed numeric limit
    (`input.parameters.cpu`) or a pure regex/equality policy has no numeric-literal threshold dict and is
    correctly negative."""
    evidence = []
    num_cmp = bool(_NUM_CMP.search(rego_text))
    numeric_dicts = parse_rego_thresholds(rego_text)            # name -> {key: number}
    # a numeric-literal dict that is actually INDEXED somewhere (the threshold is selected by a key)
    indexed = [name for name in numeric_dicts if re.search(rf"\b{re.escape(name)}\s*\[", rego_text)]
    present = bool(num_cmp and indexed)
    if num_cmp:
        evidence.append("numeric_comparison")
    if indexed:
        evidence.append(f"numeric_threshold_dict_indexed:{sorted(indexed)}")
    if _THRESHOLD_FN.search(rego_text):
        evidence.append("threshold_helper")
    return {"present": present, "evidence": evidence}


def scan_corpus_for_idiom(rego_paths) -> dict:
    """Two-stage prevalence funnel (Gap 1): scan a corpus, return the registered ratio
    files_with_idiom / files_scanned and the per-file verdicts."""
    per_file, n_idiom = [], 0
    for p in rego_paths:
        p = Path(p)
        det = has_category_conditioned_threshold(p.read_text())
        per_file.append({"file": p.name, "present": det["present"], "evidence": det["evidence"]})
        n_idiom += int(det["present"])
    n = len(per_file)
    return {"files_scanned": n, "files_with_idiom": n_idiom,
            "idiom_rate": (round(n_idiom / n, 4) if n else float("nan")), "per_file": per_file}


# --------------------------------------------------------------------------- #
# normalization constants + Δ/ε (Gap 3) — derived from the documented policy source
# --------------------------------------------------------------------------- #
# numeric channel normalization, documented at the source (authored Rego: risk/signal/login_risk live in
# [0,1] already; the policy_field operating band is field_range). Track-A K8s caps are millicores / MiB.
NORMALIZATION = {
    "finance": {"policy_field": "risk_score", "field_range": [0.20, 0.80], "unit": "normalized_[0,1]"},
    "sre": {"policy_field": "signal", "field_range": [0.20, 0.80], "unit": "normalized_[0,1]"},
    "ops": {"policy_field": "login_risk", "field_range": [0.20, 0.80], "unit": "normalized_[0,1]"},
    "k8s_gatekeeper": {"cpu_cap_millicores": 2000.0, "mem_cap_mib": 4096.0,
                       "unit": "raw_/_cap -> normalized_[0,1]"},
}

_REGO_DICT = re.compile(r"^\s*(\w+)\s*:=\s*\{([^}]*)\}", re.MULTILINE)
_REGO_KV = re.compile(r'"([^"]+)"\s*:\s*(-?\d+(?:\.\d+)?)')


def parse_rego_thresholds(rego_text: str) -> dict:
    """Extract the `base := {...}` and `adj := {...}` numeric dicts from an authored Rego policy."""
    out = {}
    for name, body in _REGO_DICT.findall(rego_text):
        kv = {k: float(v) for k, v in _REGO_KV.findall(body)}
        if kv:
            out[name] = kv
    return out


def threshold_gaps(domain: str, rego_text: str) -> dict:
    """All threshold gaps Δ a single REGISTERED swap can introduce, from the authored Rego dicts:
    tool swaps move `base`, provenance swaps move `adj`. Returns the gap set + summary stats."""
    dicts = parse_rego_thresholds(rego_text)
    base = list(dicts.get("base", {}).values())
    adj = list(dicts.get("adj", {}).values())
    gaps = set()
    for vals in (base, adj):
        for i in range(len(vals)):
            for j in range(i + 1, len(vals)):
                g = round(abs(vals[i] - vals[j]), 6)
                if g > 0:
                    gaps.add(g)
    gaps = sorted(gaps)
    return {"gaps": gaps, "min_delta": (gaps[0] if gaps else float("nan")),
            "max_delta": (gaps[-1] if gaps else float("nan"))}


def delta_epsilon(domain: str, rego_text: str, eps: float) -> dict:
    """Implied Δ/ε per registered edge + the predicted C-interval length = min(Δ, ε) (Gap 3). Makes the
    geometric law testable on the policy: a swap with gap Δ contributes a C-band of width min(Δ, ε)."""
    tg = threshold_gaps(domain, rego_text)
    gaps = tg["gaps"]
    rows = [{"delta": g, "delta_over_eps": round(g / eps, 4),
             "predicted_C_interval_len": round(min(g, eps), 6)} for g in gaps]
    return {"epsilon": eps, "min_delta": tg["min_delta"], "max_delta": tg["max_delta"],
            "min_delta_over_eps": (round(tg["min_delta"] / eps, 4) if gaps else float("nan")),
            "per_gap": rows}


# --------------------------------------------------------------------------- #
# provenance tiers + interpretation ladder (Gaps 1 & 6, pre-registered wording)
# --------------------------------------------------------------------------- #
PROVENANCE_TIERS = load_neighborhoods()["provenance_tiers"]

# Pre-registered claim ladder — the wording is fixed BEFORE seeing results so no rung is improvised.
INTERPRETATION_LADDER = [
    ("third_party_unmodified_C_positive",
     "C% > 0 on UNMODIFIED third-party policies -> interaction-only failure is not authored by us "
     "(strongest external-validity claim)."),
    ("third_party_logic_reimplemented_C_positive",
     "C% > 0 only on third_party_logic_reimplemented policies -> the idiom AS DOCUMENTED in third-party "
     "logic produces C-witnesses; executable-unchanged evidence remains open (intermediate claim)."),
    ("authored_mechanism_C_positive",
     "C% ~ 10-12% on authored_rego with provenance-conditioned thresholds, certified gate blocks them "
     "(C_allow=U_allow=cert_false_allow=0, R_allow>0) -> controlled MECHANISM evidence."),
    ("third_party_informative_null",
     "C% ~ 0 on unmodified third-party policies -> informative null: C-witnesses REQUIRE policies where "
     "discrete provenance shifts a numerical decision boundary; pure validation policies lack this."),
]

# The headline prevalence quantity is a PRODUCT, not the second stage alone (Gap 1):
#   P(C | corpus) = P(idiom present | corpus) x P(C | idiom present, sampling scheme).
PREVALENCE_DECOMPOSITION = (
    "P(C | corpus) = idiom_rate(corpus) x C_rate_given_idiom(sampling_scheme). "
    "Report BOTH stages; the selection step (filtering for the idiom) is a prevalence inflater if the "
    "first stage is hidden.")
