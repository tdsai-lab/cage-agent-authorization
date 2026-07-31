#!/usr/bin/env python3
"""
vs_camel.py — PLAN_2 P5 Task I: CAGE joint-certificate vs **CaMeL** (capability-based prompt-injection
defense; Debenedetti et al., "Defeating Prompt Injections by Design", 2025).

Thesis: the two defenses are **orthogonal layers**, and neither subsumes the other.
- **CaMeL** bounds *provenance / capabilities*: it tracks where each value came from and enforces a
  security policy on which (untrusted) data may flow to which sink / influence control flow. It defeats
  prompt injection by construction — attacker-controlled data cannot acquire the capability to reach a
  protected tool call. It does **NOT** reason about the *numerical decision boundary*: whether a value
  that legitimately came from an authorized tool sits, under bounded typed corruption `B_{1,ε}`, close
  enough to a provenance-conditioned threshold that a d=1 swap between two **equally-authorized** tools
  plus an ε move flips the safety verdict (Category C).
- The **CAGE joint certificate** bounds exactly that numerical boundary over `B_{1,ε}`, and is blind to
  data-source taint (it authorizes the *typed value*, not its text provenance).

We exhibit the full 2×2 (in-scope vs injected provenance) × (robust vs joint-gap region) on the real
finance schema. The decisive cell is **(in-scope, joint-gap)**: CaMeL ADMITS (provenance/capabilities
are legitimate — the value came from an authorized compliance tool, flowing to its authorized sink) yet
the CAGE joint certificate BLOCKS (the region hides an unsafe realization). The mirror cell
**(injected, robust)** is the reverse: CaMeL blocks a source-taint attack the certificate would allow.
⇒ orthogonal, composable — CaMeL for provenance/injection, CAGE for the boundary under typed corruption.

Faithfulness note: CaMeL security policies are arbitrary code, so one *could* plug a numeric-boundary
check into a CaMeL policy — but that check IS the CAGE certificate; CaMeL's *capability model* supplies
no such mechanism out of the box (a swap between two capability-equivalent authorized tools is invisible
to it). We model CaMeL faithfully at the capability level and state the composition explicitly. Offline,
deterministic, stdlib + the analytic oracle only.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

_root = Path(__file__).resolve().parents[1]
for p in ("generators", "agents"):
    sys.path.insert(0, str(_root / p))

from oracle import safe, joint_reachable_unsafe  # noqa: E402
from tool_env import ToolEnvironment, DOMAIN_SPEC  # noqa: E402

OUT = _root / "cert" / "out"
DOMAIN_KEY = "synthetic"  # internal rule-table domain key


# --------------------------------------------------------------------------- #
# Faithful minimal CaMeL: values carry Capabilities (provenance sources + trust); a security policy
# decides whether a value may flow to the protected sink (the privileged action).
# --------------------------------------------------------------------------- #
class Capability:
    """A CaMeL capability: the set of provenance sources a value derives from, and whether every source
    is a trusted, sink-authorized tool. Prompt-injected data carries an untrusted source and thus cannot
    satisfy the policy for a protected sink."""

    def __init__(self, sources, trusted):
        self.sources = frozenset(sources)
        self.trusted = bool(trusted)


class CaMeLPolicy:
    """A faithful capability policy for the privileged sink. `authorized_sources` are the tools whose
    output the org has cleared to drive the protected action (all legitimate compliance/monitoring
    tools). The policy ADMITS iff every argument value's provenance is trusted AND drawn from an
    authorized source — i.e. no untrusted (attacker-controlled) data reaches the sink. This is CaMeL's
    entire contract; it has NO view of numeric thresholds."""

    def __init__(self, authorized_sources):
        self.authorized_sources = frozenset(authorized_sources)

    def admits(self, cap: Capability) -> bool:
        return cap.trusted and cap.sources.issubset(self.authorized_sources)


def cage_joint_cert_blocks(observed, action, rt, eps=0.10, d=1) -> bool:
    """The CAGE joint certificate blocks iff B_{d,ε}(z) contains an unsafe realization (model-free
    analytic robust oracle — the definition of Category C; the shipped learned smoothed gate agrees,
    see #29 / end_to_end_exploit)."""
    rec = {"domain": DOMAIN_KEY, "tool_id": observed["tool_id"], "candidate_action": action,
           "categorical_fields": observed["categorical_fields"],
           "numeric_fields": observed["numeric_fields"]}
    return bool(joint_reachable_unsafe(rec, action, rt, d, eps)["reachable"])


def _pick(env, category):
    xs = env.by_category(category)
    if not xs:
        raise RuntimeError(f"no {category} records in env")
    return env.call_tool(xs[0])


def build_2x2(env, spec, eps):
    """Concrete (s, x, a) for each (provenance, region) cell + both defenses' verdicts."""
    action = spec["privileged"]
    authorized = set(env.rt["domains"][DOMAIN_KEY]["_tool_action"].keys())  # all legitimate tools
    policy = CaMeLPolicy(authorized)

    def row(prov_label, region_label, observed):
        if prov_label == "in_scope":
            cap = Capability(sources={observed["tool_id"]}, trusted=True)        # legit authorized tool
        else:  # 'injected': the numeric value was lifted from attacker-controlled untrusted text
            cap = Capability(sources={observed["tool_id"], "untrusted_email_body"}, trusted=False)
        camel_admits = policy.admits(cap)
        cage_blocks = cage_joint_cert_blocks(observed, action, env.rt, eps=eps)
        point_safe = bool(safe({"domain": DOMAIN_KEY, "tool_id": observed["tool_id"],
                                "candidate_action": action,
                                "categorical_fields": observed["categorical_fields"],
                                "numeric_fields": observed["numeric_fields"]}, action, env.rt))
        return {
            "provenance": prov_label, "region": region_label,
            "tool_id": observed["tool_id"],
            "categorical": dict(observed["categorical_fields"]),
            "primary_signal": round(env.primary_signal(observed), 4),
            "safe_at_observed_point": point_safe,
            "camel_admits": camel_admits,
            "cage_joint_cert_blocks": cage_blocks,
        }

    robust = _pick(env, "R")       # safe for all of B_{1,ε}
    jointgap = _pick(env, "C")     # safe at point, unsafe somewhere in B_{1,ε}
    return [
        row("in_scope", "robust", robust),
        row("in_scope", "joint_gap", jointgap),      # <-- decisive: CaMeL admits, CAGE blocks
        row("injected", "robust", robust),           # <-- mirror: CaMeL blocks, CAGE allows
        row("injected", "joint_gap", jointgap),
    ]


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--domain", default="financial_compliance",
                    choices=["financial_compliance", "sre_monitoring"])
    ap.add_argument("--eps", type=float, default=0.10)
    ap.add_argument("--pool", type=int, default=8000)
    ap.add_argument("--seed", type=int, default=0)
    ap.add_argument("--out", default="vs_camel")
    args = ap.parse_args()

    env = ToolEnvironment(args.domain, n_pool=args.pool, eps=args.eps, seed=args.seed)
    spec = DOMAIN_SPEC[args.domain]
    grid = build_2x2(env, spec, args.eps)

    key_cell = next(g for g in grid if g["provenance"] == "in_scope" and g["region"] == "joint_gap")
    mirror_cell = next(g for g in grid if g["provenance"] == "injected" and g["region"] == "robust")

    # orthogonality checks
    camel_misses_C = key_cell["camel_admits"] and key_cell["cage_joint_cert_blocks"]
    cage_misses_injection = (not mirror_cell["camel_admits"]) and (not mirror_cell["cage_joint_cert_blocks"])

    res = {
        "domain": args.domain, "eps": args.eps,
        "comparator": "CaMeL (capability-based prompt-injection defense)",
        "grid": grid,
        "decisive_cell_in_scope_joint_gap": key_cell,
        "mirror_cell_injected_robust": mirror_cell,
        "camel_admits_but_cage_blocks": bool(camel_misses_C),
        "cage_allows_but_camel_blocks": bool(cage_misses_injection),
        "orthogonal": bool(camel_misses_C and cage_misses_injection),
    }
    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / f"{args.out}.json").write_text(json.dumps(res, indent=2))
    _write_md(OUT / f"{args.out}.md", res)
    print(json.dumps({k: v for k, v in res.items() if k != "grid"}, indent=2))
    print(f"\nwrote {OUT / (args.out + '.json')}\nwrote {OUT / (args.out + '.md')}")
    return res


def _write_md(path, res):
    with open(path, "w") as f:
        f.write("# P5 Task I — CAGE joint certificate vs CaMeL (orthogonal defenses)\n\n")
        f.write(f"Domain `{res['domain']}`, ε={res['eps']}. **CaMeL** (Debenedetti et al. 2025) bounds "
                "provenance/capabilities (which data may reach a sink); **CAGE joint cert** bounds the "
                "numerical decision boundary over B_{1,ε}. 2×2 over (provenance) × (region):\n\n")
        f.write("| provenance | region | primary | safe@point | CaMeL admits | CAGE blocks |\n")
        f.write("|---|---|---:|:--:|:--:|:--:|\n")
        for g in res["grid"]:
            f.write(f"| {g['provenance']} | {g['region']} | {g['primary_signal']} | "
                    f"{'yes' if g['safe_at_observed_point'] else 'no'} | "
                    f"{'ADMIT' if g['camel_admits'] else 'BLOCK'} | "
                    f"{'BLOCK' if g['cage_joint_cert_blocks'] else 'allow'} |\n")
        kc = res["decisive_cell_in_scope_joint_gap"]
        mc = res["mirror_cell_injected_robust"]
        f.write("\n**Decisive cell (in-scope, joint-gap)** — the explicit `(s, x, a)` the plan asks for: "
                f"tool `{kc['tool_id']}`, categorical `{kc['categorical']}`, primary_signal "
                f"{kc['primary_signal']}, safe at the observed point → **CaMeL ADMITS** (provenance is a "
                "legitimate authorized compliance tool flowing to its authorized sink) but **CAGE joint "
                "cert BLOCKS** (a d=1 swap to an equally-authorized tool + ε move reaches an unsafe state "
                "inside B_{1,ε}). CaMeL cannot see this: the swap is between two capability-equivalent "
                "authorized tools.\n\n")
        f.write("**Mirror cell (injected, robust)** — tool "
                f"`{mc['tool_id']}` but the value is tainted by an untrusted source "
                "(`untrusted_email_body`): **CaMeL BLOCKS** (capability violation) while **CAGE allows** "
                "(it authorizes the typed value at a robustly-safe point; it does not model source "
                "taint).\n\n")
        f.write(f"**Verdict.** `camel_admits_but_cage_blocks={res['camel_admits_but_cage_blocks']}`, "
                f"`cage_allows_but_camel_blocks={res['cage_allows_but_camel_blocks']}` ⇒ "
                f"**orthogonal={res['orthogonal']}**. The two are composable layers: CaMeL bounds "
                "provenance/injection, CAGE bounds the numerical boundary under bounded typed corruption. "
                "Neither subsumes the other; deploying both covers both attack surfaces.\n")


if __name__ == "__main__":
    main()
