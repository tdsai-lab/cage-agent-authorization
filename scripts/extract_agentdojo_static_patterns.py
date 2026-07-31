#!/usr/bin/env python3
"""
extract_agentdojo_static_patterns.py
====================================

Extract candidate *tool-output / action* patterns from an AgentDojo checkout by
static AST inspection (no import, no execution).

For every suite it collects:

* tool functions          -> name, return-type annotation, docstring, arg names;
* pydantic return models   -> field names + types, with numeric fields flagged
                              (these are the candidate ``x_2`` channel);
* user tasks               -> PROMPT + the tool names used in ``ground_truth``
                              (the realised "action" sequence);
* injection tasks          -> GOAL + the tool names used in ``ground_truth``
                              (the unsafe action the attack wants).

It then assembles >= 5 patterns of the form requested in PLAN.md Step 3 and
writes them to ``notes/agentdojo_patterns.md``. A machine-readable dump is also
written to ``notes/agentdojo_patterns.json`` for the summariser.
"""
from __future__ import annotations

import argparse
import ast
import json
from dataclasses import dataclass, field, asdict
from pathlib import Path

NUMERIC_ANNOTATIONS = {"int", "float", "Decimal"}


def find_pkg(explicit: str | None) -> Path:
    cand = Path(explicit or "external/agentdojo").expanduser().resolve()
    for pkg in (cand / "src" / "agentdojo", cand / "agentdojo", cand):
        if (pkg / "functions_runtime.py").exists():
            return pkg
    raise SystemExit("Could not find agentdojo package; pass --agentdojo")


def ann_to_str(node: ast.expr | None) -> str:
    if node is None:
        return "None"
    try:
        return ast.unparse(node)
    except Exception:  # pragma: no cover - very old pythons
        return "<expr>"


def docstring_first_line(node: ast.AST) -> str:
    doc = ast.get_docstring(node) or ""
    return doc.strip().splitlines()[0] if doc.strip() else ""


# --------------------------------------------------------------------------- #
# Data containers
# --------------------------------------------------------------------------- #
@dataclass
class ModelInfo:
    name: str
    fields: list[tuple[str, str]] = field(default_factory=list)  # (name, annotation)

    @property
    def numeric_fields(self) -> list[str]:
        return [n for n, a in self.fields if any(t in a for t in NUMERIC_ANNOTATIONS)]

    @property
    def text_fields(self) -> list[str]:
        return [n for n, a in self.fields if not any(t in a for t in NUMERIC_ANNOTATIONS)]


@dataclass
class ToolInfo:
    suite_tools_module: str
    name: str
    return_annotation: str
    doc: str
    args: list[str]


@dataclass
class TaskInfo:
    suite: str
    kind: str  # "user" | "injection"
    cls: str
    text: str  # PROMPT or GOAL
    actions: list[str]  # tool names used in ground_truth


def collect_models_and_tools(path: Path, module_label: str) -> tuple[dict[str, ModelInfo], list[ToolInfo]]:
    tree = ast.parse(path.read_text(encoding="utf-8", errors="replace"))
    models: dict[str, ModelInfo] = {}
    tools: list[ToolInfo] = []

    for node in tree.body:
        if isinstance(node, ast.ClassDef):
            mi = ModelInfo(name=node.name)
            for stmt in node.body:
                if isinstance(stmt, ast.AnnAssign) and isinstance(stmt.target, ast.Name):
                    mi.fields.append((stmt.target.id, ann_to_str(stmt.annotation)))
            if mi.fields:
                models[node.name] = mi
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            # Heuristic: a "tool" has a docstring and is not a private helper.
            if node.name.startswith("_") or node.name.startswith("set_") or node.name == "next_id":
                continue
            doc = docstring_first_line(node)
            if not doc:
                continue
            args = [a.arg for a in node.args.args if a.arg not in ("self", "account")]
            tools.append(
                ToolInfo(
                    suite_tools_module=module_label,
                    name=node.name,
                    return_annotation=ann_to_str(node.returns),
                    doc=doc,
                    args=args,
                )
            )
    return models, tools


def collect_tasks(path: Path, suite: str, kind: str) -> list[TaskInfo]:
    tree = ast.parse(path.read_text(encoding="utf-8", errors="replace"))
    tasks: list[TaskInfo] = []
    for node in tree.body:
        if not isinstance(node, ast.ClassDef):
            continue
        text = ""
        actions: list[str] = []
        for stmt in ast.walk(node):
            # PROMPT / GOAL class attributes (string constants)
            if isinstance(stmt, ast.Assign):
                for tgt in stmt.targets:
                    if isinstance(tgt, ast.Name) and tgt.id in ("PROMPT", "GOAL"):
                        if isinstance(stmt.value, ast.Constant) and isinstance(stmt.value.value, str):
                            text = stmt.value.value
            # FunctionCall(function="...") inside ground_truth
            if isinstance(stmt, ast.Call):
                callee = stmt.func
                is_fc = (isinstance(callee, ast.Name) and callee.id == "FunctionCall")
                if is_fc:
                    for kw in stmt.keywords:
                        if kw.arg == "function" and isinstance(kw.value, ast.Constant):
                            actions.append(str(kw.value.value))
        if text or actions:
            tasks.append(TaskInfo(suite=suite, kind=kind, cls=node.name, text=text, actions=actions))
    return tasks


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--agentdojo", default=None)
    ap.add_argument("--out", default="notes/agentdojo_patterns.md")
    ap.add_argument("--json-out", default="notes/agentdojo_patterns.json")
    args = ap.parse_args()

    pkg = find_pkg(args.agentdojo)
    repo_root = pkg.parents[1] if pkg.parent.name == "src" else pkg.parent

    # 1. Tools + return models from the shared tools dir.
    all_models: dict[str, ModelInfo] = {}
    all_tools: list[ToolInfo] = []
    tools_dir = pkg / "default_suites" / "v1" / "tools"
    for f in sorted(tools_dir.glob("*.py")):
        if f.name == "__init__.py":
            continue
        models, tools = collect_models_and_tools(f, f.stem)
        all_models.update(models)
        all_tools.extend(tools)

    # 2. Tasks (v1 suites is enough for representative patterns).
    all_tasks: list[TaskInfo] = []
    for suite_dir in sorted((pkg / "default_suites" / "v1").iterdir()):
        if not suite_dir.is_dir() or suite_dir.name == "tools":
            continue
        ut = suite_dir / "user_tasks.py"
        it = suite_dir / "injection_tasks.py"
        if ut.exists():
            all_tasks.extend(collect_tasks(ut, suite_dir.name, "user"))
        if it.exists():
            all_tasks.extend(collect_tasks(it, suite_dir.name, "injection"))

    # Index: tool name -> the user/injection tasks whose ground_truth invokes it.
    tool_to_user = {}
    tool_to_inj = {}
    for t in all_tasks:
        for a in t.actions:
            (tool_to_user if t.kind == "user" else tool_to_inj).setdefault(a, []).append(t)

    # 3. Assemble patterns: prefer tools whose return type is a model with numeric fields.
    def return_model(tool: ToolInfo) -> ModelInfo | None:
        ra = tool.return_annotation
        for name, mi in all_models.items():
            if name in ra:
                return mi
        return None

    scored: list[tuple[int, ToolInfo, ModelInfo | None]] = []
    for tool in all_tools:
        mi = return_model(tool)
        numeric = len(mi.numeric_fields) if mi else (1 if any(t in tool.return_annotation for t in NUMERIC_ANNOTATIONS) else 0)
        # prefer tools that (a) expose numeric output and (b) appear in some task ground_truth
        used = 1 if (tool.name in tool_to_user or tool.name in tool_to_inj) else 0
        scored.append((numeric * 2 + used, tool, mi))
    scored.sort(key=lambda x: -x[0])

    patterns = []
    for _, tool, mi in scored:
        if len(patterns) >= 12:
            break
        numeric_fields = mi.numeric_fields if mi else ([tool.return_annotation] if any(t in tool.return_annotation for t in NUMERIC_ANNOTATIONS) else [])
        text_fields = mi.text_fields if mi else []
        user_uses = tool_to_user.get(tool.name, [])
        inj_uses = tool_to_inj.get(tool.name, [])
        # Only keep patterns that are interesting: numeric output OR used as an action.
        if not numeric_fields and not user_uses and not inj_uses:
            continue
        patterns.append(
            {
                "tool": tool.name,
                "module": tool.suite_tools_module,
                "return_type": tool.return_annotation,
                "return_model": mi.name if mi else None,
                "doc": tool.doc,
                "args": tool.args,
                "numeric_fields": numeric_fields,
                "text_fields": text_fields,
                "user_task_example": (user_uses[0].cls + ": " + user_uses[0].text[:120]) if user_uses else None,
                "injection_task_example": (inj_uses[0].cls + ": " + inj_uses[0].text[:160]) if inj_uses else None,
            }
        )

    # ----------------------------------------------------------------------- #
    # Write markdown
    # ----------------------------------------------------------------------- #
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    lines: list[str] = []
    lines.append("# AgentDojo Tool-Output / Action Patterns\n")
    lines.append(
        "_Generated by `scripts/extract_agentdojo_static_patterns.py` (static AST extraction). "
        f"Scanned {len(all_tools)} tool functions, {len(all_models)} return models, "
        f"{len(all_tasks)} tasks across the v1 suites._\n"
    )
    lines.append(
        "> **Key structural fact (applies to every pattern below).** AgentDojo tools return "
        "pydantic models / dicts / primitives, but `agentdojo/agent_pipeline/tool_execution.py:"
        "tool_result_to_str` serialises every return value to a **YAML string** before it is put "
        "back into the chat as a `tool` message. The numeric fields below are *present in the "
        "Python return value* but reach the model only as text. The 'next action' is then produced "
        "by the LLM in free generation — there is **no explicit `(tool, output) -> action` node**. "
        "See the paper's motivation section.\n"
    )

    for i, p in enumerate(patterns, 1):
        action = "fused in LLM (no explicit node)"
        lines.append(f"## Pattern {i}\n")
        lines.append(f"Suite/module: `{p['module']}`")
        lines.append(f"Tool: `{p['tool']}({', '.join(p['args'])})` — {p['doc']}")
        lines.append(f"Tool identity representation: Python function name `\"{p['tool']}\"` "
                     "(string in `FunctionCall.function`); schema auto-generated from type hints.")
        lines.append(f"Return type: `{p['return_type']}`" + (f" (model `{p['return_model']}`)" if p["return_model"] else ""))
        lines.append(f"Next action: {action}. "
                     + (f"Realised in user task {p['user_task_example']!r}" if p["user_task_example"] else "Not directly an action target in v1 user tasks."))
        lines.append("Security relevance: "
                     + (f"targeted by injection task {p['injection_task_example']!r}" if p["injection_task_example"]
                        else "indirect — feeds the context the LLM trusts."))
        lines.append(f"Structured fields visible: {', '.join(p['text_fields']) or '(scalar / dict return)'}")
        lines.append(f"Numerical fields visible: {', '.join(p['numeric_fields']) or '(none in typed return)'}")
        lines.append("Is the decision node explicit or fused in the LLM? **Fused.** The YAML-stringified "
                     "return is appended to the prompt and the model emits the next `tool_calls` directly.\n")

    out.write_text("\n".join(lines), encoding="utf-8")

    Path(args.json_out).write_text(
        json.dumps(
            {
                "n_tools": len(all_tools),
                "n_models": len(all_models),
                "n_tasks": len(all_tasks),
                "models": {k: asdict(v) for k, v in all_models.items()},
                "patterns": patterns,
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    print(f"Wrote {out} with {len(patterns)} patterns; json -> {args.json_out}")


if __name__ == "__main__":
    main()
