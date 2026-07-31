#!/usr/bin/env python3
"""
marble_cwitness.py — RUNBOOK_REAL_AML_ENGINE closure: a Category-C witness on the `x ▷ θ(s)` idiom
implemented and labelled by a REAL, PURPOSE-BUILT AML/fraud decision engine — **Marble**
(`checkmarble/marble`, a deployed-grade anti-money-laundering / fraud transaction-monitoring engine).

This is one rung above #9b (real OPA engine, authored Rego) and B2 (GoRules ZEN, a *general* rule
engine): Marble is a domain fraud/AML engine. We author the idiom `safe = risk_score < θ(provenance)`
as a Marble **scenario** (score classifier: a rule fires and adds score iff `risk ≥ θ(provenance)`, so
`score ≥ review_threshold ⟺ REVIEW/unsafe`, else `APPROVE/safe`), publish it, then run REAL IEEE-CIS
transactions through Marble's own **decision API** and port the #9b/B2 four-point solver: per transaction
the ENGINE labels the joint ball B_{1,ε} — clean, the d=1 provenance swap (loose↔strict = the #16
`wrong_provenance_binding` fault), the +ε risk probe, and the joint swap+ε point.

  C  ⟺  engine says  clean-safe ∧ swap-only-safe ∧ ε-only-safe ∧ swap+ε-UNSAFE.

Claim discipline: ENGINE-valid witness inside a purpose-built AML engine — strictly above #9b/B2 on
domain authenticity. Still an AUTHORED rule on REAL data (θ constants from the real IEEE-CIS generation),
NOT a claim the idiom was mined from a bank's confidential deployed rules (that gap is covered by the
regulatory documentary anchor). `s` = provenance / list-source class = genuinely upstream-set.

Infra: rootless podman + Marble v1.4.0 backend on host-networking (see HANDOFF_MARBLE_PODMAN.md).
Auth: admin ops use a marble access token (firebase-emulator ID token → POST /token); the decision API
uses an X-Api-Key seeded in Postgres. Both are read from files under marble_src/ (see --marble-dir).
"""
from __future__ import annotations

import argparse
import os
import json
import sys
import time
import urllib.error
import urllib.request
from collections import Counter
from pathlib import Path

_HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(_HERE.parents[0] / "realdata"))
import ieee_cis_policy as pol  # noqa: E402  (real generation constants + loose/strict provenance)

_BB = _HERE.parents[0]
IEEE_PATH = _BB / "data" / "realdata" / "ieee_cis_boundary_balanced_s0.jsonl"
OUT = _BB / "cert" / "out"

THETA = 0.488808               # real IEEE-CIS theta_base (strict provenance threshold)
DELTA = 0.08                   # loose tools trust more -> +delta
THETA_LOOSE = round(THETA + DELTA, 6)
REVIEW_SCORE = 10              # a fired rule adds this; score >= review_threshold => REVIEW (unsafe)

API = "http://localhost:8080"
EMU = "http://localhost:9099"
FIREBASE_KEY = "placeholder"
PROJECT = "test-project"
# Credentials of the local Marble dev deployment. Override to whatever your instance seeds:
#   MARBLE_ADMIN_EMAIL / MARBLE_ADMIN_PASSWORD
ADMIN_EMAIL = os.environ.get("MARBLE_ADMIN_EMAIL", "admin@example.invalid")
ADMIN_PASSWORD = os.environ.get("MARBLE_ADMIN_PASSWORD", "password123")
TABLE = "transactions"
SCENARIO_NAME = "cage_provenance_gate"


# --------------------------------------------------------------------------------------------------
# tiny HTTP helper
# --------------------------------------------------------------------------------------------------
def _http(method, url, body=None, headers=None):
    data = None
    if body is not None:
        data = body if isinstance(body, (bytes, bytearray)) else json.dumps(body).encode()
    req = urllib.request.Request(url, data=data, method=method,
                                 headers={"Content-Type": "application/json", **(headers or {})})
    try:
        resp = urllib.request.urlopen(req, timeout=30)
        raw = resp.read().decode()
        return resp.getcode(), (json.loads(raw) if raw else {})
    except urllib.error.HTTPError as e:
        raw = e.read().decode()
        try:
            return e.code, json.loads(raw)
        except Exception:
            return e.code, {"__raw": raw[:400]}


# --------------------------------------------------------------------------------------------------
# admin auth: firebase emulator ID token -> marble /token -> access token
# --------------------------------------------------------------------------------------------------
def get_admin_token():
    # ensure a verified emulator user exists with a known password (idempotent)
    _http("DELETE", f"{EMU}/emulator/v1/projects/{PROJECT}/accounts")
    code, su = _http("POST", f"{EMU}/identitytoolkit.googleapis.com/v1/accounts:signUp?key={FIREBASE_KEY}",
                     {"email": ADMIN_EMAIL, "password": ADMIN_PASSWORD, "returnSecureToken": True})
    lid = su["localId"]
    _http("POST", f"{EMU}/identitytoolkit.googleapis.com/v1/accounts:update?key={FIREBASE_KEY}",
          {"localId": lid, "emailVerified": True}, headers={"Authorization": "Bearer owner"})
    code, si = _http("POST", f"{EMU}/identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key={FIREBASE_KEY}",
                     {"email": ADMIN_EMAIL, "password": ADMIN_PASSWORD, "returnSecureToken": True})
    code, tok = _http("POST", f"{API}/token", None, headers={"Authorization": f"Bearer {si['idToken']}"})
    access = tok.get("access_token")
    if not access:
        raise RuntimeError(f"admin /token exchange failed: {code} {tok}")
    return access


# --------------------------------------------------------------------------------------------------
# AST builders (Marble NodeDto JSON)
# --------------------------------------------------------------------------------------------------
def _payload(field):
    return {"name": "Payload", "children": [{"constant": field}]}


def _rule_ast(provenance, threshold):
    """risk_score >= θ(provenance)  AND  provenance == <provenance>   ==> fires (unsafe)."""
    return {"name": "And", "children": [
        {"name": "=", "children": [_payload("provenance"), {"constant": provenance}]},
        {"name": ">=", "children": [_payload("risk_score"), {"constant": threshold}]},
    ]}


# --------------------------------------------------------------------------------------------------
# setup: data model table + scenario + iteration + rules + publish (idempotent-ish)
# --------------------------------------------------------------------------------------------------
def ensure_data_model(hdr):
    code, dm = _http("GET", f"{API}/data-model", headers=hdr)
    tables = dm.get("data_model", {}).get("tables", {})
    if TABLE in tables:
        return  # already created
    code, r = _http("POST", f"{API}/data-model/tables", {
        "name": TABLE, "description": "IEEE-CIS transactions (CAGE C-witness probe)",
        "alias": "Transactions", "semantic_type": "other",
        "fields": [
            {"name": "object_id", "alias": "Object ID", "type": "String", "nullable": False},
            {"name": "updated_at", "alias": "Updated At", "type": "Timestamp", "nullable": False},
            {"name": "risk_score", "alias": "Risk Score", "type": "Float", "nullable": False},
            {"name": "provenance", "alias": "Provenance", "type": "String", "nullable": False},
        ]}, headers=hdr)
    if code not in (200, 201):
        raise RuntimeError(f"create table failed: {code} {r}")


def find_scenario(hdr):
    code, arr = _http("GET", f"{API}/scenarios", headers=hdr)
    for s in (arr if isinstance(arr, list) else []):
        if s.get("name") == SCENARIO_NAME:
            return s
    return None


def ensure_scenario(hdr):
    existing = find_scenario(hdr)
    if existing and existing.get("live_version_id"):
        return existing["id"]

    if existing:
        scenario_id = existing["id"]
    else:
        code, s = _http("POST", f"{API}/scenarios",
                        {"name": SCENARIO_NAME, "description": "safe = risk_score < theta(provenance)",
                         "trigger_object_type": TABLE}, headers=hdr)
        if code not in (200, 201):
            raise RuntimeError(f"create scenario failed: {code} {s}")
        scenario_id = s["id"]

    # draft iteration
    code, it = _http("POST", f"{API}/scenario-iterations", {"scenario_id": scenario_id}, headers=hdr)
    if code not in (200, 201):
        raise RuntimeError(f"create iteration failed: {code} {it}")
    iid = it["id"]

    # trigger condition = always true (risk_score >= -1), score thresholds
    trigger = {"name": ">=", "children": [_payload("risk_score"), {"constant": -1.0}]}
    code, r = _http("PATCH", f"{API}/scenario-iterations/{iid}", {"body": {
        "score_review_threshold": REVIEW_SCORE,
        "score_block_and_review_threshold": 100,
        "score_decline_threshold": 100,
        "trigger_condition_ast_expression": trigger,
    }}, headers=hdr)
    if code not in (200, 201):
        raise RuntimeError(f"patch iteration failed: {code} {r}")

    # two provenance-conditioned threshold rules (fire == unsafe)
    for prov, thr, name in (("loose", THETA_LOOSE, "loose-provenance gate"),
                            ("strict", THETA, "strict-provenance gate")):
        code, r = _http("POST", f"{API}/scenario-iteration-rules", {
            "scenario_iteration_id": iid, "name": name,
            "formula_ast_expression": _rule_ast(prov, thr), "score_modifier": REVIEW_SCORE},
            headers=hdr)
        if code not in (200, 201):
            raise RuntimeError(f"create rule ({prov}) failed: {code} {r}")

    _http("POST", f"{API}/scenario-iterations/{iid}/validate", None, headers=hdr)
    code, r = _http("POST", f"{API}/scenario-iterations/{iid}/commit", None, headers=hdr)
    if code not in (200, 201):
        raise RuntimeError(f"commit failed: {code} {r}")
    code, r = _http("POST", f"{API}/scenario-publications",
                    {"scenario_iteration_id": iid, "publication_action": "publish"}, headers=hdr)
    if code not in (200, 201):
        raise RuntimeError(f"publish failed: {code} {r}")
    return scenario_id


def setup(marble_dir):
    access = get_admin_token()
    hdr = {"Authorization": f"Bearer {access}"}
    ensure_data_model(hdr)
    scenario_id = ensure_scenario(hdr)
    (marble_dir / ".scenario_id").write_text(scenario_id)
    print(f"[setup] scenario published: {scenario_id}")
    return scenario_id


# --------------------------------------------------------------------------------------------------
# the engine gate: one decision API call -> safe iff Marble outcome == approve
# --------------------------------------------------------------------------------------------------
class MarbleGate:
    def __init__(self, api_key, scenario_id):
        self.hdr = {"x-api-key": api_key}
        self.scenario_id = scenario_id
        self._n = 0

    def safe(self, provenance, risk):
        self._n += 1
        obj = {"object_id": f"probe-{self._n}", "updated_at": "2024-01-01T00:00:00Z",
               "risk_score": float(risk), "provenance": provenance}
        code, r = _http("POST", f"{API}/v1/decisions",
                        {"scenario_id": self.scenario_id, "trigger_object": obj}, self.hdr)
        if code != 200:
            raise RuntimeError(f"decision failed: {code} {r}")
        data = r.get("data") or []
        if not data:  # trigger not passed (should not happen: trigger is always-true)
            raise RuntimeError(f"decision returned no data (trigger skipped?): {r}")
        outcome = data[0]["outcome"]
        return outcome == "approve"


# --------------------------------------------------------------------------------------------------
# probe / classification (ported from zen_engine_cwitness.py / #9b)
# --------------------------------------------------------------------------------------------------
def _provenance_class(tool):
    return "loose" if pol.is_loose(tool) else "strict"


def _other(cls):
    return "strict" if cls == "loose" else "loose"


def load_records(path=IEEE_PATH, n=None):
    recs = []
    with open(path) as f:
        for line in f:
            o = json.loads(line)
            recs.append({"tool_id": o["tool_id"], "risk_score": float(o["x2"]["risk_score"]),
                         "analytic_category": o.get("category"), "fraud": int(o["meta"]["isFraud"])})
    return recs[:n] if n else recs


def categorize(gate, records, eps):
    out = []
    for r in records:
        cls = _provenance_class(r["tool_id"])
        oth = _other(cls)
        risk = r["risk_score"]
        clean = gate.safe(cls, risk)              # nominal
        disc = gate.safe(oth, risk)               # provenance swap alone (clean risk)
        cont = gate.safe(cls, risk + eps)         # eps move alone (same provenance)
        joint = gate.safe(oth, risk + eps)        # joint swap + eps
        cat = ("U" if not clean else "A" if disc != clean else "B" if cont != clean
               else "C" if joint != clean else "R")
        out.append({"category": cat, "provenance": cls, "swap_to": oth, "risk_score": round(risk, 4),
                    "engine_clean_safe": clean, "engine_swap_only": disc,
                    "engine_eps_only": cont, "engine_joint": joint})
    return out


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--n", type=int, default=800, help="IEEE-CIS transactions to probe (4 decisions each)")
    ap.add_argument("--eps", type=float, default=0.10)
    ap.add_argument("--marble-dir", default=os.environ.get("MARBLE_DIR", "external/marble_src"))
    ap.add_argument("--skip-setup", action="store_true", help="reuse the published scenario + .scenario_id")
    ap.add_argument("--out", default="marble_cwitness")
    args = ap.parse_args()

    marble_dir = Path(args.marble_dir)
    if not IEEE_PATH.exists():
        print(f"[error] IEEE-CIS data not found at {IEEE_PATH}")
        return

    # liveness gate
    code, _ = _http("GET", f"{API}/liveness")
    if code != 200:
        print(f"[error] Marble not live at {API} (got {code}). See HANDOFF_MARBLE_PODMAN.md to bring it up.")
        return

    if args.skip_setup and (marble_dir / ".scenario_id").exists():
        scenario_id = (marble_dir / ".scenario_id").read_text().strip()
        print(f"[setup] reusing scenario {scenario_id}")
    else:
        scenario_id = setup(marble_dir)

    api_key = (marble_dir / ".api_key").read_text().strip()
    gate = MarbleGate(api_key, scenario_id)

    recs = load_records(n=args.n)
    t0 = time.time()
    cats = categorize(gate, recs, args.eps)
    elapsed = time.time() - t0
    dist = Counter(c["category"] for c in cats)
    n = len(recs)

    both = [(c["category"], r["analytic_category"]) for c, r in zip(cats, recs)
            if r["analytic_category"] in ("A", "B", "C", "R", "U")]
    agree = sum(1 for e, a in both if e == a) / max(1, len(both))
    c_eng = {i for i, c in enumerate(cats) if c["category"] == "C"}
    c_ana = {i for i, r in enumerate(recs) if r["analytic_category"] == "C"}
    c_jaccard = len(c_eng & c_ana) / max(1, len(c_eng | c_ana))
    witnesses = [cats[i] for i in list(c_eng)[:5]]

    res = {
        "engine": "Marble (checkmarble/marble) v1.4.0", "engine_type": "purpose-built AML/fraud engine",
        "engine_transport": "decision API (POST /v1/decisions), X-Api-Key", "infra": "rootless podman, host-net",
        "rule": f"safe = risk_score < theta(provenance); theta_strict={THETA}, theta_loose={THETA_LOOSE}",
        "encoding": "score classifier: rule fires (+score) iff risk>=theta(prov); score>=review_threshold => REVIEW(unsafe)",
        "s_semantics": "provenance_upstream (screening-tool / list-source class; pipeline-set)",
        "scenario_id": scenario_id, "n_records": n, "n_decisions": gate._n, "eps": args.eps,
        "seconds": round(elapsed, 1),
        "engine_category_distribution": {k: dist.get(k, 0) for k in ("U", "A", "B", "C", "R")},
        "engine_C_count": dist.get("C", 0), "engine_C_pct": round(100 * dist.get("C", 0) / n, 2),
        "engine_vs_analytic_agreement": round(agree, 4),
        "C_set_jaccard_engine_vs_analytic": round(c_jaccard, 4),
        "witnesses": witnesses,
    }
    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / f"{args.out}.json").write_text(json.dumps(res, indent=2))
    _write_md(OUT / f"{args.out}.md", res, n, args.eps)

    print(json.dumps({k: v for k, v in res.items() if k != "witnesses"}, indent=2))
    print(f"\nwrote {OUT / (args.out + '.json')}\nwrote {OUT / (args.out + '.md')}")
    return res


def _write_md(path, res, n, eps):
    d = res["engine_category_distribution"]
    with open(path, "w") as f:
        f.write("# RUNBOOK closure — engine-verified C-witness inside a REAL purpose-built AML engine (Marble)\n\n")
        f.write(f"Engine: **{res['engine']}** — a {res['engine_type']}, run via its own **{res['engine_transport']}**"
                f" ({res['infra']}). Rule (authored, real IEEE-CIS constants): `{res['rule']}`, encoded as a "
                f"Marble score classifier ({res['encoding']}). `s` = **{res['s_semantics']}**. "
                f"{n} REAL IEEE-CIS transactions × 4 decisions = {res['n_decisions']} engine decisions, "
                f"eps={eps}. Every label is Marble's own decision output.\n\n")
        f.write(f"- engine category distribution: U={d['U']} A={d['A']} B={d['B']} **C={d['C']} "
                f"({res['engine_C_pct']}%)** R={d['R']}\n")
        f.write(f"- Marble-engine vs analytic taxonomy agreement: **{res['engine_vs_analytic_agreement']}** "
                f"(C-set Jaccard {res['C_set_jaccard_engine_vs_analytic']})\n\n")
        f.write("## Engine-verified C-witness traces (each label is Marble's decision outcome)\n\n")
        f.write("| provenance | swap | risk_score | clean | swap-only | +ε-only | **swap+ε (joint)** |\n")
        f.write("|---|---|---:|:--:|:--:|:--:|:--:|\n")
        for w in res["witnesses"]:
            f.write(f"| {w['provenance']} | →{w['swap_to']} | {w['risk_score']} | "
                    f"{'safe' if w['engine_clean_safe'] else 'UNSAFE'} | "
                    f"{'safe' if w['engine_swap_only'] else 'UNSAFE'} | "
                    f"{'safe' if w['engine_eps_only'] else 'UNSAFE'} | "
                    f"**{'safe' if w['engine_joint'] else 'UNSAFE'}** |\n")
        f.write("\n**Reads.** A **purpose-built AML/fraud engine** (Marble) — one rung above the general "
                "engines OPA (#9b) and GoRules ZEN (B2) on domain authenticity — labels real transactions "
                "as Category-C joint-gap witnesses through its own decision API, and reproduces the analytic "
                "taxonomy. `s` is a **provenance / list-source class** (genuinely upstream-set), so the swap "
                "is exactly the #16 `wrong_provenance_binding` fault an agent's pipeline can realize. "
                "Epistemic rank: real AML engine, AUTHORED rule, real data — NOT a claim the idiom was mined "
                "from confidential deployed AML rules (that gap is the regulatory documentary anchor).\n")


if __name__ == "__main__":
    main()
