#!/usr/bin/env python3
"""make_claim_ladder.py — Table E5 (claim ladder) + claim_ladder_snippet.tex. Binds the three rungs of
the evidence ladder to their generated numbers and provenance labels. Keep the rungs SEPARATE: Azure =
third-party existence; PSD2/AML = continuous mechanism; OPA/Rego = certified defense benchmark."""
from __future__ import annotations

import csv
import json
from pathlib import Path

_EXP = Path(__file__).resolve().parent.parent
TAB = _EXP / "results" / "tables"
SNIP = _EXP / "results" / "snippets"
AZ = TAB / "azure_existence_metrics.json"
E3 = TAB / "regulatory_c_prevalence.csv"
E4 = TAB / "regulatory_certified_gate.csv"


def _read_csv(p):
    return list(csv.DictReader(open(p))) if p.exists() else []


def main():
    az = json.loads(AZ.read_text()) if AZ.exists() else {}
    e3 = _read_csv(E3)
    e4 = _read_csv(E4)
    nat10 = [r for r in e3 if r["sampling_mode"] == "natural" and float(r["epsilon"]) == 0.10]
    cprev = "/".join(f"{r['policy_family']} {100*float(r['C_pct']):.1f}%" for r in nat10) or "n/a"
    g4 = [r for r in e4 if r["sampling_mode"] == "natural" and float(r["epsilon"]) == 0.10]
    cert_C = max((float(r["certified_C_allow"]) for r in g4 if r["certified_C_allow"] not in ("", "nan")),
                 default=float("nan")) if g4 else float("nan")
    cfa = max((float(r["cert_false_allow"]) for r in g4), default=float("nan")) if g4 else float("nan")

    rows = [
        {"claim": "Third-party existence of idiom", "evidence": "Azure Key Vault key size",
         "provenance": "third_party_logic_reimplemented",
         "caveat": "keySize is quantized (existence anchor, not continuous substrate)",
         "numbers": f"keyType->keySize; validated instances {az.get('validated_T1_policy_instances','?')}; "
                    f"idiom_rate_family {az.get('idiom_rate_policy_family','?')}"},
        {"claim": "Continuous mechanism", "evidence": "PSD2/AML source-locked policies",
         "provenance": "regulatory_grounded_authored_policy",
         "caveat": "executable policy authored from sourced thresholds (not third-party executable)",
         "numbers": f"natural C% {cprev}; certified_C_allow {cert_C}; cert_false_allow {cfa}"},
        {"claim": "Certified defense", "evidence": "OPA/Rego benchmark (Track C)",
         "provenance": "authored_provenance_conditioned_rego",
         "caveat": "node-level, learned-gate certificate",
         "numbers": "C ~10-12% under OPA; certified C_allow=U_allow=cert_false_allow=0 (see cert/out/opa_gate)"},
    ]
    cols = ["claim", "evidence", "provenance", "caveat", "numbers"]
    TAB.mkdir(parents=True, exist_ok=True)
    with open(TAB / "claim_ladder.csv", "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=cols); w.writeheader(); w.writerows(rows)

    SNIP.mkdir(parents=True, exist_ok=True)
    SNIP.joinpath("claim_ladder_snippet.tex").write_text(
        "% Claim-ladder snippet (NEW experiments: Azure existence + PSD2/AML mechanism)\n"
        "We separate external existence from mechanism evaluation. A scan of public policy corpora found "
        "a Microsoft-authored Azure Key Vault family in which the categorical field \\texttt{keyType} "
        "selects the applicable numerical \\texttt{keySize} threshold, establishing that the "
        "category-conditioned-threshold idiom appears in third-party policy code. Because \\texttt{keySize} "
        "is quantized, we do not use this family as the main continuous robustness substrate. Instead, we "
        "instantiate source-locked PSD2/AML threshold policies, where transaction amounts, aggregate "
        "amounts, fraud rates, and risk scores provide continuous or quasi-continuous channels. On these "
        "regulatory-grounded policies, we measure $C$-witness prevalence and evaluate whether the "
        "certified gate blocks joint-gap false allows while retaining robust-safe utility "
        f"(natural $C\\%$: {cprev}; certified $C_{{\\mathrm{{allow}}}}={cert_C}$, "
        f"$\\texttt{{cert\\_false\\_allow}}={cfa}$).\n")
    print("Table E5 — claim ladder:")
    for r in rows:
        print(f"  {r['claim']:32s} | {r['evidence']:30s} | {r['provenance']:34s} | {r['caveat']}")
    print(f"\nwrote -> {TAB/'claim_ladder.csv'} ; {SNIP/'claim_ladder_snippet.tex'}")


if __name__ == "__main__":
    main()
