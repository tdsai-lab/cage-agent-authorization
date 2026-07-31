#!/usr/bin/env python3
"""make_azure_existence_table.py — Experiment 1 output: Table E1 (azure_existence_table.csv) + the
azure_existence_snippet.tex from the wire-in metrics."""
from __future__ import annotations

import csv
import json
from pathlib import Path

_EXP = Path(__file__).resolve().parent.parent
METRICS = _EXP / "results" / "tables" / "azure_existence_metrics.json"
TABLE = _EXP / "results" / "tables" / "azure_existence_table.csv"
SNIPPET = _EXP / "results" / "snippets" / "azure_existence_snippet.tex"

COLS = ["source", "policy_family", "author", "policy_provenance", "files_scanned", "parsed_policies",
        "validated_families", "validated_instances", "categorical_field", "numeric_field",
        "thresholds", "delta_max", "continuous_channel_quality", "manual_review_verdict"]


def main():
    m = json.loads(METRICS.read_text())
    row = {
        "source": "Azure built-in policy", "policy_family": "Key Vault key size",
        "author": m["author"], "policy_provenance": m["policy_provenance"],
        "files_scanned": m["files_scanned"], "parsed_policies": m["parsed_policies"],
        "validated_families": m["validated_T1_families"],
        "validated_instances": m["validated_T1_policy_instances"],
        "categorical_field": m["categorical_field"], "numeric_field": m["numeric_field"],
        "thresholds": "/".join(str(t) for t in m["thresholds"]),
        "delta_max": m["delta_max"], "continuous_channel_quality": m["continuous_channel_quality"],
        "manual_review_verdict": m["manual_review_verdict"],
    }
    TABLE.parent.mkdir(parents=True, exist_ok=True)
    with open(TABLE, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=COLS); w.writeheader(); w.writerow(row)

    SNIPPET.parent.mkdir(parents=True, exist_ok=True)
    SNIPPET.write_text(
        "% Azure external-existence snippet (Experiment 1)\n"
        "A scan of public policy corpora found a Microsoft-authored Azure Key Vault family in which the "
        "categorical field \\texttt{keyType} selects the applicable numerical \\texttt{keySize} "
        f"threshold (validated instances: {row['thresholds']}; "
        f"$\\Delta_{{\\max}}={m['delta_max']}$), establishing that the category-conditioned-threshold "
        "idiom $x \\triangleright \\theta(s)$ appears in third-party policy code "
        "(\\texttt{policy\\_provenance = third\\_party\\_logic\\_reimplemented}). Because "
        "\\texttt{keySize} is integer-quantized, we use this family as an external-validity anchor "
        "rather than the main continuous $C$-witness substrate.\n")
    print(f"wrote -> {TABLE}\nwrote -> {SNIPPET}")
    print(f"row: {row}")


if __name__ == "__main__":
    main()
