#!/usr/bin/env python3
"""
summarize_patterns.py
=====================

Roll up the JSON produced by ``extract_agentdojo_static_patterns.py`` into a
compact, quantitative summary: how many tools expose numeric output, which
return-type shapes dominate, and how the (tool -> numeric field) channels map
onto the bridge-benchmark ``x_2`` design.

Reads ``notes/agentdojo_patterns.json`` and prints a markdown summary to stdout
(also appends it to ``notes/agentdojo_patterns.md`` under a Summary heading).
"""
from __future__ import annotations

import argparse
import json
from collections import Counter
from pathlib import Path


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--json", default="notes/agentdojo_patterns.json")
    ap.add_argument("--append-to", default="notes/agentdojo_patterns.md")
    args = ap.parse_args()

    data = json.loads(Path(args.json).read_text(encoding="utf-8"))
    models = data["models"]
    patterns = data["patterns"]

    # How many distinct return models carry >=1 numeric field?
    numeric_models = {k: v for k, v in models.items()
                      if any(any(t in a for t in ("int", "float", "Decimal")) for _, a in v["fields"])}

    # Return-type shape histogram over extracted patterns.
    shapes = Counter()
    for p in patterns:
        rt = p["return_type"]
        if p["return_model"]:
            shapes["pydantic model (list of / single)"] += 1
        elif "dict" in rt and "float" in rt or "dict" in rt and "int" in rt:
            shapes["dict[str, number]"] += 1
        elif rt in ("float", "int"):
            shapes["bare scalar number"] += 1
        else:
            shapes["other"] += 1

    numeric_channel = []
    for p in patterns:
        if p["numeric_fields"]:
            numeric_channel.append((p["tool"], p["numeric_fields"]))

    lines: list[str] = []
    lines.append("\n---\n")
    lines.append("# Pattern Summary (quantitative)\n")
    lines.append(f"- Tool functions scanned: **{data['n_tools']}**")
    lines.append(f"- Distinct return models: **{data['n_models']}**")
    lines.append(f"- Return models carrying >=1 numeric field: **{len(numeric_models)}** "
                 f"({', '.join(sorted(numeric_models)) or 'none'})")
    lines.append(f"- Tasks scanned (user + injection, v1): **{data['n_tasks']}**\n")

    lines.append("## Return-type shapes among extracted patterns\n")
    for shape, n in shapes.most_common():
        lines.append(f"- {shape}: {n}")
    lines.append("")

    lines.append("## Candidate numeric channel (x_2) per tool\n")
    lines.append("These are the numeric fields that *exist in the typed Python return* and that the "
                 "bridge benchmark would surface as an explicit `x_2` vector (in AgentDojo they are "
                 "flattened into YAML text):\n")
    for tool, nums in numeric_channel:
        lines.append(f"- `{tool}` -> {', '.join(nums)}")
    lines.append("")

    lines.append("## Takeaway\n")
    lines.append(
        "Numeric fields are common in AgentDojo tool *returns* (amounts, balances, ratings, prices), "
        "so the `x_2` channel of the bridge benchmark is well-motivated by real tool schemas. "
        "However, every such field is delivered to the model as YAML text, and no AgentDojo component "
        "consumes `(tool_id, numeric_fields)` to emit a typed action. That gap is exactly what "
        "`ToolDecisionBench` factors out. See the paper's motivation section and "
        "`notes/benchmark_spec.md`.\n"
    )

    summary = "\n".join(lines)
    print(summary)

    if args.append_to:
        p = Path(args.append_to)
        existing = p.read_text(encoding="utf-8") if p.exists() else ""
        # Avoid duplicate appends on re-run.
        marker = "# Pattern Summary (quantitative)"
        if marker in existing:
            existing = existing.split("\n---\n# Pattern Summary")[0]
        p.write_text(existing.rstrip() + "\n" + summary, encoding="utf-8")


if __name__ == "__main__":
    main()
