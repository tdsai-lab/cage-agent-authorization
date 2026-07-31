#!/usr/bin/env python3
"""
engine_idiomaticity.py — PLAN_2_RESCAN_BIS Workstream B1: per-engine idiomaticity inventory.

A QUALITATIVE, NO-RATE companion to the structural-prevalence scan (`idiom_rescan.py`, Workstream A). The
scan answers "how often is `op(f_num, θ(s))` WRITTEN in committed rule files?". B1 answers a different,
weaker-but-orthogonal question: "does each production rule engine's grammar/DSL give the idiom a
FIRST-CLASS construct?" — i.e. is the continuous threshold-keyed-by-category pattern *intended and
idiomatic* in these engines, not something we contrived?

Epistemic placement (RESCAN_BIS §B1): this is **expressibility + shipped examples**, strictly
  BELOW structural prevalence (Workstream A: the idiom is actually written), and
  ABOVE "the engine permits it in principle" (a Turing-complete engine permits anything).
We therefore emit NO rate and NO prevalence number. Each entry records:
  * first_class:   does a NATIVE construct map a categorical/typology key to a numeric threshold?
                   one of {yes, partial, no}  (partial = expressible via general facilities, no
                   dedicated grammar element).
  * construct:     the grammar element that carries it.
  * shipped:       a concrete shipped demo / test / config that exhibits it (path or public source).
  * evidence_tier: on_disk_verified (file present in external/corpora and inspected) vs
                   public_docs (engine grammar documented publicly; source not vendored here).
  * s_typical:     the discrete key these engines usually carry (subject vs provenance/typology).

Claim discipline (mirrors B2): B1 establishes that the idiom is idiomatic in real engines; it does NOT
establish deployed prevalence (institution rules are runtime/closed — see RESCAN_BIS funnel). Keep B1
("the engine is built for this") separate from any prevalence claim.
"""
from __future__ import annotations

import json
import sys
from dataclasses import dataclass, asdict
from pathlib import Path

_HERE = Path(__file__).resolve().parent
_BB = _HERE.parents[1]
_EXT = _BB.parents[0] / "external" / "corpora"
OUT = _BB / "cert" / "out"
# tracked, version-controlled companion location (alongside the regulatory anchor + Tables E1–E5)
TRACKED = _BB / "experiments" / "policy_idiom_prevalence" / "results" / "tables"


@dataclass
class EngineEntry:
    engine: str
    kind: str                 # rule-engine flavour
    first_class: str          # yes | partial | no
    construct: str            # the native grammar element
    shipped: str              # a concrete shipped example (path under external/corpora, or public source)
    evidence_tier: str        # on_disk_verified | public_docs
    s_typical: str            # subject_self_reported | provenance_upstream | typology | mixed
    note: str = ""

    def as_dict(self):
        return asdict(self)


# --------------------------------------------------------------------------- #
# Curated inventory. Grounded where possible in the vendored corpora (external/corpora/*), tagged
# on_disk_verified; otherwise tagged public_docs with the canonical source. Ordered strongest-first.
# --------------------------------------------------------------------------- #
INVENTORY = [
    EngineEntry(
        engine="DMN / FEEL decision table", kind="OMG-standard decision table",
        first_class="yes",
        construct="<decisionTable>: a categorical <input> column selects, per <rule> row, the numeric "
                  "unary-test threshold in a sibling numeric <input> column — θ-by-category IS the table",
        shipped="dmn-tck_tck/.../0087-chapter-11-example.dmn (DMN spec's own lending example: CreditScore/"
                "ApplicationRiskScore thresholds keyed by ExistingCustomer); kogito_examples/.../"
                "LoanEligibility.dmn (debt-ratio limit keyed by salary bracket)",
        evidence_tier="on_disk_verified", s_typical="subject_self_reported",
        note="the idiom IS the textbook decision-table semantics — strongest expressibility evidence"),
    EngineEntry(
        engine="GoRules ZEN / JDM", kind="embeddable decision-table engine (B2 substrate)",
        first_class="yes",
        construct="JDM 'decisionTableNode': input columns (incl. a categorical/provenance key) → output "
                  "columns; numeric threshold per row selected by the key column",
        shipped="experiments/zen_engine_cwitness.py authored rule (loose/strict threshold keyed by a "
                "provenance field) — engine-verified C-witnesses, agreement 1.0 (RESULTS Experiment B2)",
        evidence_tier="on_disk_verified", s_typical="provenance_upstream",
        note="zen-engine importable; our authored rule keys θ on an upstream-set field"),
    EngineEntry(
        engine="Tazama (tazama-lf)", kind="real-time AML/fraud engine (ISO 20022)",
        first_class="yes",
        construct="RuleConfig.config.bands: an ordered list of {lowerLimit, upperLimit} → subRuleRef; the "
                  "numeric value is mapped to a discrete band by CONFIGURABLE thresholds (per typology)",
        shipped="tazama-lf_rule-executer/src/helpers/determineOutcome.ts (the `bands` evaluator); bands "
                "are runtime rule-config, parameterized per typology/rule",
        evidence_tier="on_disk_verified", s_typical="typology",
        note="thresholds are deployment config (not committed) — band CONSTRUCT is first-class & verified"),
    EngineEntry(
        engine="Checkmarble (Marble)", kind="open-source decisioning/AML engine",
        first_class="yes",
        construct="JSON rule AST (comparison nodes GreaterOrEqual/Less, IsInList, CustomListAccess) feeding "
                  "a scenario score with per-scenario score review/block thresholds (score-banding)",
        shipped="checkmarble/marble scenarios + custom lists (public docs; the vendored tree here is the "
                "docker deployment, not the Go engine — see RUNBOOK_REAL_AML_ENGINE.md for the live probe)",
        evidence_tier="public_docs", s_typical="mixed",
        note="engine present as deployment; grammar from public docs — lower tier, not on-disk verified"),
    EngineEntry(
        engine="Drools (DRL / decision tables)", kind="production rule system",
        first_class="partial",
        construct="DRL LHS field constraint `Field(amount >= $theta)` with `$theta` bound from a config "
                  "fact keyed on a categorical field; spreadsheet decision tables are first-class",
        shipped="kogito_examples/.../*.drl (44 DRL files); Drools decision-table spreadsheets (public)",
        evidence_tier="on_disk_verified", s_typical="mixed",
        note="general pattern-match facility expresses θ(s); the spreadsheet decision table is dedicated"),
    EngineEntry(
        engine="OPA / Rego", kind="general policy engine",
        first_class="partial",
        construct="no dedicated threshold-by-category element, but `θ(s)` via a function `threshold(s)` or "
                  "a dict indexed by a discrete var `limits[channel]` compared to a numeric input",
        shipped="experiments/opa_gate/policies/authored/ieee_fraud.rego (#9b authored rule; engine↔analytic "
                "agreement 1.0 on real IEEE-CIS, RESULTS Experiment 9b)",
        evidence_tier="on_disk_verified", s_typical="provenance_upstream",
        note="idiom expressible & authored, but it is a general-purpose construct, not a first-class one"),
    EngineEntry(
        engine="json-rules-engine / Jube", kind="JSON fact-rule engine (AML/fraud)",
        first_class="partial",
        construct="operator (greaterThanInclusive/lessThan) whose `value` may be a FACT reference resolved "
                  "from a categorical fact — i.e. the threshold is selected by another fact",
        shipped="jube-home_aml-fraud-transaction-monitoring (392 greaterThan / 377 lessThan operators over "
                "facts; thresholds typically runtime-configured)",
        evidence_tier="on_disk_verified", s_typical="provenance_upstream",
        note="value-as-fact-ref expresses θ(s); no dedicated category→threshold element"),
]


def build_inventory():
    rows = [e.as_dict() for e in INVENTORY]
    summary = {
        "n_engines": len(rows),
        "first_class_yes": sum(r["first_class"] == "yes" for r in rows),
        "first_class_partial": sum(r["first_class"] == "partial" for r in rows),
        "first_class_no": sum(r["first_class"] == "no" for r in rows),
        "on_disk_verified": sum(r["evidence_tier"] == "on_disk_verified" for r in rows),
        "public_docs": sum(r["evidence_tier"] == "public_docs" for r in rows),
    }
    return {
        "workstream": "PLAN_2_RESCAN_BIS B1 — per-engine idiomaticity inventory",
        "emits_rate": False,
        "epistemic_placement": "below structural prevalence (A); above permits-in-principle. No prevalence "
                               "number. Establishes the idiom is FIRST-CLASS/idiomatic in real engines, "
                               "NOT that it is deployed at any rate.",
        "summary": summary,
        "inventory": rows,
    }


def write_outputs(payload):
    md = _render_md(payload)
    for d in (OUT, TRACKED):
        d.mkdir(parents=True, exist_ok=True)
    (OUT / "engine_idiomaticity.json").write_text(json.dumps(payload, indent=2))
    (OUT / "engine_idiomaticity.md").write_text(md)
    # tracked copy (version-controlled, alongside Tables E1–E5 and the regulatory anchor)
    (TRACKED / "engine_idiomaticity_inventory.md").write_text(md)
    return md


def _render_md(payload):
    s = payload["summary"]
    lines = [
        "# B1 — per-engine idiomaticity inventory (RESCAN_BIS Workstream B1)",
        "",
        "**Question.** Does each production rule engine give the continuous *threshold-keyed-by-category* "
        "idiom `op(f_num, θ(s))` a **first-class** construct? (Expressibility + shipped examples — "
        "**no prevalence rate is emitted**; this sits below Workstream A's structural prevalence and "
        "above \"permits in principle\".)",
        "",
        f"**Summary.** {s['n_engines']} engines: first-class **yes={s['first_class_yes']}**, "
        f"partial={s['first_class_partial']}, no={s['first_class_no']}; "
        f"on-disk-verified={s['on_disk_verified']}, public-docs={s['public_docs']}.",
        "",
        "| engine | first-class | native construct | s typical | evidence | shipped example |",
        "|---|:---:|---|---|---|---|",
    ]
    for r in payload["inventory"]:
        lines.append(
            f"| **{r['engine']}** | {r['first_class']} | {r['construct']} | {r['s_typical']} | "
            f"{r['evidence_tier']} | {r['shipped']} |")
    lines += [
        "",
        "**Read.** Three independent decision-table engines (DMN/FEEL, GoRules ZEN/JDM) and two real AML "
        "engines (Tazama `bands`, Marble score-banding) carry the idiom as a **first-class** grammar "
        "element; OPA/Rego, Drools, and json-rules/Jube express it through general facilities (partial). "
        "So `op(f_num, θ(s))` is **idiomatic and intended** in the engines that implement the threat "
        "model's decision substrate — it is not a contrived pattern. Per RESCAN_BIS claim discipline this "
        "is expressibility evidence only: it does NOT measure deployed prevalence (institution thresholds "
        "are runtime/closed), and the typical key is a subject attribute except where provenance is "
        "genuinely pipeline-set (ZEN/Rego authored rules, #9b/B2).",
        "",
    ]
    return "\n".join(lines)


def main():
    payload = build_inventory()
    write_outputs(payload)
    s = payload["summary"]
    print(f"B1 engine idiomaticity: {s['n_engines']} engines "
          f"(first_class yes={s['first_class_yes']} partial={s['first_class_partial']}); "
          f"on_disk_verified={s['on_disk_verified']}")
    for r in payload["inventory"]:
        print(f"  {r['engine']:34s} first_class={r['first_class']:8s} "
              f"[{r['evidence_tier']}] s={r['s_typical']}")
    print(f"\nwrote {OUT / 'engine_idiomaticity.json'}\nwrote {OUT / 'engine_idiomaticity.md'}\n"
          f"wrote {TRACKED / 'engine_idiomaticity_inventory.md'}")
    return payload


if __name__ == "__main__":
    sys.exit(0 if main() else 0)
