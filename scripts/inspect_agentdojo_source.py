#!/usr/bin/env python3
"""
inspect_agentdojo_source.py
===========================

Static reconnaissance of an AgentDojo checkout.

The script does NOT import or run AgentDojo. It walks the source tree, classifies
files by topic (suites, tools, tasks, attacks, defenses, logging, pipeline, ...),
and extracts symbol names (classes / functions) with a lightweight regex/AST pass.
It writes a readable source map to ``notes/agentdojo_source_map.md``.

Usage
-----
    python scripts/inspect_agentdojo_source.py \
        --agentdojo external/agentdojo \
        --out notes/agentdojo_source_map.md

If ``--agentdojo`` is omitted, the script tries a few standard locations:
the cloned ``external/agentdojo`` and the installed ``agentdojo`` package.
"""
from __future__ import annotations

import argparse
import ast
import importlib.util
import re
from collections import defaultdict
from pathlib import Path

# --------------------------------------------------------------------------- #
# Topic classification: (topic title) -> list of substrings matched against the
# POSIX path of each .py file (relative to the package root).
# --------------------------------------------------------------------------- #
TOPIC_RULES: list[tuple[str, tuple[str, ...]]] = [
    ("Suites", ("task_suite/", "default_suites/", "load_suites")),
    ("Tool Definitions", ("/tools/", "functions_runtime")),
    ("Tool Calls / Outputs", ("tool_execution", "functions_runtime", "types.py")),
    ("User & Injection Tasks", ("base_tasks", "user_tasks", "injection_tasks")),
    ("Attacks", ("attacks/",)),
    ("Defenses", ("pi_detector", "tool_filter", "transformers")),
    ("Environment State", ("environment", "task_suite.py")),
    ("Utility / Security Checks", ("base_tasks", "benchmark.py", "task_suite.py")),
    ("Logging / Traces", ("logging.py",)),
    ("Pipeline / Model Classes", ("agent_pipeline/", "/llms/", "base_pipeline_element")),
]

# Symbols that signal a relevant decision/eval primitive worth reading manually.
INTEREST_SYMBOLS = re.compile(
    r"\b(utility|security|ground_truth|register_user_task|register_injection_task|"
    r"tool_result_to_str|run_function|detect|transform|query)\b"
)


def find_agentdojo(explicit: str | None) -> Path:
    """Locate the agentdojo *package* directory (the folder that holds __init__.py)."""
    candidates: list[Path] = []
    if explicit:
        candidates.append(Path(explicit))
    candidates.append(Path("external/agentdojo"))
    # Installed package, if importable.
    spec = importlib.util.find_spec("agentdojo")
    if spec and spec.origin:
        candidates.append(Path(spec.origin).parent.parent)

    for cand in candidates:
        cand = cand.expanduser().resolve()
        # Normalise: accept either the repo root or the src/agentdojo package dir.
        for pkg in (cand / "src" / "agentdojo", cand / "agentdojo", cand):
            if (pkg / "__init__.py").exists() and (pkg / "functions_runtime.py").exists():
                return pkg
    raise SystemExit(
        "Could not locate the agentdojo package. Pass --agentdojo <path-to-repo-or-package>."
    )


def extract_symbols(path: Path) -> tuple[list[str], list[str]]:
    """Return (class_names, top_level_function_names) via AST; empty on parse error."""
    try:
        tree = ast.parse(path.read_text(encoding="utf-8", errors="replace"))
    except (SyntaxError, ValueError):
        return [], []
    classes = [n.name for n in tree.body if isinstance(n, ast.ClassDef)]
    funcs = [n.name for n in tree.body if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))]
    return classes, funcs


def grep_interest(path: Path) -> set[str]:
    text = path.read_text(encoding="utf-8", errors="replace")
    return set(INTEREST_SYMBOLS.findall(text))


def classify(rel_posix: str) -> list[str]:
    topics = []
    for title, needles in TOPIC_RULES:
        if any(n in rel_posix for n in needles):
            topics.append(title)
    return topics


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--agentdojo", default=None, help="Path to agentdojo repo or package.")
    ap.add_argument("--out", default="notes/agentdojo_source_map.md")
    args = ap.parse_args()

    pkg = find_agentdojo(args.agentdojo)
    repo_root = pkg.parents[1] if pkg.parent.name == "src" else pkg.parent

    py_files = sorted(p for p in pkg.rglob("*.py") if "__pycache__" not in p.parts)

    topic_files: dict[str, list[Path]] = defaultdict(list)
    suites: list[str] = []
    interest_hits: dict[Path, set[str]] = {}

    for f in py_files:
        rel = f.relative_to(pkg).as_posix()
        for t in classify(rel):
            topic_files[t].append(f)
        # A suite is a directory under default_suites/<version>/<name>/ with task_suite.py
        if f.name == "task_suite.py" and "default_suites" in rel:
            suites.append(f.parent.name)
        hits = grep_interest(f)
        if hits:
            interest_hits[f] = hits

    suites = sorted(set(suites))

    def section(title: str, limit: int = 25) -> str:
        files = topic_files.get(title, [])
        lines = [f"## {title} Found", ""]
        if not files:
            lines.append("_None found._")
            return "\n".join(lines) + "\n"
        for f in files[:limit]:
            rel = f.relative_to(repo_root).as_posix()
            classes, funcs = extract_symbols(f)
            sym = ", ".join((classes + funcs)[:8]) or "(no top-level symbols)"
            lines.append(f"- `{rel}` — {sym}")
        if len(files) > limit:
            lines.append(f"- … and {len(files) - limit} more")
        return "\n".join(lines) + "\n"

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)

    parts: list[str] = []
    parts.append("# AgentDojo Source Map\n")
    parts.append(
        "_Generated by `scripts/inspect_agentdojo_source.py` via static AST/regex inspection. "
        "AgentDojo is **not** imported or executed._\n"
    )

    parts.append("## Package / Repository Location\n")
    parts.append(f"- Package: `{pkg}`")
    parts.append(f"- Repo root: `{repo_root}`")
    parts.append(f"- Python files scanned: **{len(py_files)}**\n")

    parts.append("## Main Directories\n")
    top_dirs = sorted({p.relative_to(pkg).parts[0] for p in py_files if len(p.relative_to(pkg).parts) > 1})
    for d in top_dirs:
        n = sum(1 for p in py_files if p.relative_to(pkg).parts[0] == d)
        parts.append(f"- `agentdojo/{d}/` — {n} files")
    parts.append("")

    parts.append("## Suites Found\n")
    parts.append(f"Distinct suite names (by `default_suites/*/<name>/task_suite.py`): **{len(suites)}**\n")
    for s in suites:
        parts.append(f"- {s}")
    parts.append("")

    parts.append(section("Tool Definitions"))
    parts.append(section("User & Injection Tasks"))
    # Split user vs injection by filename for the report.
    parts.append(section("Attacks"))
    parts.append(section("Defenses"))
    parts.append(section("Logging / Traces"))
    parts.append(section("Pipeline / Model Classes"))

    parts.append("## Relevant Files to Read Manually\n")
    parts.append("Files containing decision/eval primitives "
                 "(`utility`, `security`, `ground_truth`, `tool_result_to_str`, `run_function`, `detect`, `query`):\n")
    ranked = sorted(interest_hits.items(), key=lambda kv: (-len(kv[1]), kv[0].as_posix()))
    for f, hits in ranked[:20]:
        rel = f.relative_to(repo_root).as_posix()
        parts.append(f"- `{rel}` — {', '.join(sorted(hits))}")
    parts.append("")

    out.write_text("\n".join(parts), encoding="utf-8")
    print(f"Wrote {out} ({len(py_files)} files scanned, {len(suites)} suites).")


if __name__ == "__main__":
    main()
