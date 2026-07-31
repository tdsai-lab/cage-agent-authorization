#!/usr/bin/env python3
"""
marble_e2e.py — B2-Marble END-TO-END: a certified gate + a REAL committed side effect on a purpose-built
AML engine (Marble). Lifts marble_cwitness.py (which only *labels* C-witnesses) to the #29 exploit chain,
but the runtime that commits the side effect is Marble's own **decision API** — every POST /v1/decisions
persists a decision record (queryable via GET /v1/decisions), the externally-inspectable side effect.

Threat (certify-the-region, as #29): the pipeline serves the nominal provenance `s`=loose (the
`wrong_provenance_binding` fault serves the prior admissible tier); the gate certifies the whole ball
B_{1,ε}(loose, risk); the adversary realizes the worst case (strict, risk+ε) inside it. For a Category-C
witness the nominal (loose, risk) is APPROVED by Marble (safe-looking) while the realized worst case is a
REVIEW (unsafe) — so an approve decision committed on a C-witness is a real harmful side effect.

Arms over real IEEE-CIS C-witnesses (+ R for non-vacuity):
  engine_only    — submit the decision at the served nominal (loose, risk): Marble APPROVES and PERSISTS
                   a real approve decision record -> committed unsafe side effect.
  certified_gate — enumerate N_1(s_served)={loose,strict} and test risk+ε at each branch; the strict
                   branch fails -> BLOCK -> never submit -> no decision record committed.
  oracle         — submit at the true worst case (strict, risk+ε): Marble REVIEWS (ground truth unsafe).

Metric = committed approve decisions on truly-unsafe C-witnesses (read back off the engine). Needs the
Marble stack up (see HANDOFF_MARBLE_PODMAN.md) + a seeded API key. No LLM (Marble has no MCP server; the
proposer is scripted, orthogonal — Exp F). No docker group (Marble runs under rootless podman).
"""
from __future__ import annotations

import argparse
import os
import datetime
import json
import sys
import urllib.request
from collections import Counter
from pathlib import Path

_HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(_HERE))
import marble_cwitness as mc  # noqa: E402  (MarbleGate, load_records, THETA, THETA_LOOSE, provenance)

OUT = _HERE.parents[0] / "cert" / "out"
MARBLE_DIR = Path(os.environ.get("MARBLE_DIR", "external/marble_src"))
API = mc.API
EPS = 0.10


def theta(prov):
    return mc.THETA_LOOSE if prov == "loose" else mc.THETA


def certified_gate_allows(served_prov, risk, eps=EPS):
    """Rung-1 exact joint gate: authorize B_{1,ε}(served_prov, risk). Enumerate the provenance
    neighbourhood N_1 = {loose, strict} (a d=1 wrong_provenance_binding swap) and test whether an ε move
    can reach unsafe (risk+ε ≥ θ(prov)) at ANY branch. Allow iff safe for every branch. Does NOT trust
    the served binding."""
    worst = None
    for prov in ("loose", "strict"):
        if risk + eps >= theta(prov):                 # unsafe reachable within B_{1,ε} at this provenance
            if worst is None or theta(prov) < theta(worst):
                worst = prov
    return (worst is None), worst


def _decisions_present(api_key):
    """Proof the side effect is real: does GET /v1/decisions return persisted records (with an approve
    outcome and a has_more page)? Returns (page_count, has_more) or (None, None)."""
    now = datetime.datetime.now(datetime.timezone.utc)
    start = (now - datetime.timedelta(days=1)).strftime("%Y-%m-%dT%H:%M:%SZ")
    end = (now + datetime.timedelta(days=1)).strftime("%Y-%m-%dT%H:%M:%SZ")
    req = urllib.request.Request(f"{API}/v1/decisions?start={start}&end={end}",
                                 headers={"X-Api-Key": api_key})
    try:
        with urllib.request.urlopen(req, timeout=20) as r:
            d = json.load(r)
            return len(d.get("data", [])), bool(d.get("pagination", {}).get("has_more"))
    except Exception:
        return None, None


def run(scenario_id, api_key, n_c, n_r):
    gate = mc.MarbleGate(api_key, scenario_id)         # .safe(prov, risk) POSTs a decision (persists it)
    recs = mc.load_records()
    cwit = [r for r in recs if r["analytic_category"] == "C"][:n_c]
    rrec = [r for r in recs if r["analytic_category"] == "R"][:n_r]

    rows = {}

    # --- engine_only: submit at served nominal (loose, risk) -> Marble approves -> committed side effect
    committed_unsafe = 0
    for r in cwit:
        cls = mc._provenance_class(r["tool_id"])       # served (loose)
        approve = gate.safe(cls, r["risk_score"])       # REAL POST -> persisted decision record
        realized_unsafe = (r["risk_score"] + EPS) >= mc.THETA   # worst case (strict, risk+ε) unsafe
        if approve and realized_unsafe:
            committed_unsafe += 1
    page_n, has_more = _decisions_present(api_key)     # proof the records really persisted on the engine
    rows["engine_only"] = {"witnesses": len(cwit), "committed_unsafe_approvals": committed_unsafe,
                           "marble_persists_decisions": (page_n is not None and page_n > 0),
                           "decisions_page_count": page_n, "decisions_has_more_page": has_more,
                           "P_unsafe_side_effect": round(committed_unsafe / max(1, len(cwit)), 4)}

    # --- certified_gate: gate authorizes the ball; submit ONLY if allowed
    committed_unsafe = submitted = 0
    for r in cwit:
        cls = mc._provenance_class(r["tool_id"])
        allow, _ = certified_gate_allows(cls, r["risk_score"])
        if allow:
            submitted += 1
            approve = gate.safe(cls, r["risk_score"])
            if approve and (r["risk_score"] + EPS) >= mc.THETA:
                committed_unsafe += 1
    rows["certified_gate"] = {"witnesses": len(cwit), "submitted": submitted,
                              "committed_unsafe_approvals": committed_unsafe,
                              "P_unsafe_side_effect": round(committed_unsafe / max(1, len(cwit)), 4)}

    # --- oracle: submit at the true worst case (strict, risk+ε) -> Marble should REVIEW
    reviews = 0
    for r in cwit[:min(len(cwit), 40)]:
        approve = gate.safe("strict", r["risk_score"] + EPS)
        reviews += int(not approve)                    # not-approve == review == unsafe (correct)
    rows["oracle_true_worstcase"] = {"checked": min(len(cwit), 40), "engine_reviews": reviews,
                                     "review_rate": round(reviews / max(1, min(len(cwit), 40)), 4)}

    # --- non-vacuity: R records -> gate allows -> submitted -> Marble approves (safe side effect)
    r_allow = r_approve = 0
    for r in rrec:
        cls = mc._provenance_class(r["tool_id"])
        allow, _ = certified_gate_allows(cls, r["risk_score"])
        if allow:
            r_allow += 1
            if gate.safe(cls, r["risk_score"]):
                r_approve += 1
    rows["nonvacuity_R"] = {"R_records": len(rrec), "gate_allowed": r_allow,
                            "engine_approved": r_approve,
                            "allow_rate": round(r_allow / max(1, len(rrec)), 4)}
    return rows


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--n-c", type=int, default=100)
    ap.add_argument("--n-r", type=int, default=100)
    ap.add_argument("--out", default="marble_e2e")
    args = ap.parse_args()

    # liveness + creds
    try:
        with urllib.request.urlopen(f"{API}/liveness", timeout=8) as r:
            r.read()
    except Exception:
        print(f"[error] Marble not live at {API}. Bring the stack up (HANDOFF_MARBLE_PODMAN.md)."); return
    if not (MARBLE_DIR / ".scenario_id").exists() or not (MARBLE_DIR / ".api_key").exists():
        print("[error] .scenario_id / .api_key missing. Run marble_cwitness.py setup first."); return
    scenario_id = (MARBLE_DIR / ".scenario_id").read_text().strip()
    api_key = (MARBLE_DIR / ".api_key").read_text().strip()

    rows = run(scenario_id, api_key, args.n_c, args.n_r)
    res = {"experiment": "B2-Marble e2e — certified gate + real committed side effect on Marble's decision API",
           "engine": "Marble v1.4.0 (purpose-built AML engine)", "side_effect": "persisted decision record",
           "eps": EPS, "scenario_id": scenario_id, "arms": rows}
    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / f"{args.out}.json").write_text(json.dumps(res, indent=2))
    _write_md(OUT / f"{args.out}.md", res)

    eo, cg = rows["engine_only"], rows["certified_gate"]
    orc, nv = rows["oracle_true_worstcase"], rows["nonvacuity_R"]
    print(f"engine_only     : committed unsafe approvals {eo['committed_unsafe_approvals']}/{eo['witnesses']} "
          f"(P={eo['P_unsafe_side_effect']}), persisted={eo['marble_persists_decisions']} "
          f"(page={eo['decisions_page_count']}, has_more={eo['decisions_has_more_page']})")
    print(f"certified_gate  : committed unsafe approvals {cg['committed_unsafe_approvals']}/{cg['witnesses']} "
          f"(P={cg['P_unsafe_side_effect']}), submitted {cg['submitted']}")
    print(f"oracle          : engine reviews {orc['engine_reviews']}/{orc['checked']} (rate {orc['review_rate']})")
    print(f"non-vacuity (R) : gate allowed {nv['gate_allowed']}/{nv['R_records']} -> engine approved {nv['engine_approved']}")
    print(f"wrote {OUT / (args.out + '.json')}")
    return res


def _write_md(path, res):
    r = res["arms"]; eo, cg, orc, nv = (r["engine_only"], r["certified_gate"],
                                        r["oracle_true_worstcase"], r["nonvacuity_R"])
    with open(path, "w") as f:
        f.write("# B2-Marble e2e — certified gate + real committed side effect on Marble's decision API\n\n")
        f.write(f"Engine **{res['engine']}**; the side effect is a **{res['side_effect']}** (POST "
                "/v1/decisions persists it, GET /v1/decisions reads it back). ε=" f"{res['eps']}. "
                "`wrong_provenance_binding` serves nominal `loose`; the adversary realizes the worst case "
                "`(strict, risk+ε)` in the ball. Category-C witnesses: nominal approved, worst case unsafe.\n\n")
        f.write("| arm | committed unsafe approvals | note |\n|---|---:|---|\n")
        f.write(f"| engine_only | **{eo['committed_unsafe_approvals']}/{eo['witnesses']}** "
                f"(P={eo['P_unsafe_side_effect']}) | Marble persists the decision records "
                f"(GET /v1/decisions: page={eo['decisions_page_count']}, has_more={eo['decisions_has_more_page']}) |\n")
        f.write(f"| certified_gate | **{cg['committed_unsafe_approvals']}/{cg['witnesses']}** "
                f"(P={cg['P_unsafe_side_effect']}) | gate blocked the ball; only {cg['submitted']} submitted |\n")
        f.write(f"| oracle (strict,risk+ε) | — | engine REVIEWS {orc['engine_reviews']}/{orc['checked']} "
                f"(rate {orc['review_rate']}) = ground truth unsafe |\n")
        f.write(f"| non-vacuity (R) | — | gate allowed {nv['gate_allowed']}/{nv['R_records']} "
                f"(rate {nv['allow_rate']}) → engine approved {nv['engine_approved']} (safe side effects) |\n")
        f.write("\n**Reads.** On a REAL purpose-built AML engine, the deployed decision path trusts the "
                "served provenance and **commits real approve decision records** on Category-C witnesses "
                "whose realized worst case Marble itself would REVIEW (the oracle row). The certified "
                "joint gate — enumerating the provenance neighbourhood and testing the ε-shifted "
                "threshold — drives committed unsafe approvals to **0** while still letting genuinely-safe "
                "(R) transactions through to Marble (non-vacuous). This lifts B2 (engine-labelled "
                "C-witness) and #29 (in-process side effect) to a **real AML engine committing a real "
                "side effect**, gated soundly.\n")


if __name__ == "__main__":
    main()
