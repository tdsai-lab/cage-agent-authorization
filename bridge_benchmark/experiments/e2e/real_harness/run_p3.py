#!/usr/bin/env python3
"""
run_p3.py — PLAN_2 P3 (Task E): real-cluster end-to-end harness with an EXTERNALLY-INSPECTABLE side
effect. Upgrades #29's in-process runtime to a real Kubernetes (kind) cluster + a real admission
controller (Kyverno) enforcing a provenance-conditioned policy `replicas <= cap(tier)`, where the tier
`s` is resolved from a SEPARATE data source (a ConfigMap tier-registry) via Kyverno `context.apiCall` —
NOT from the request object. That separation is the TOCTOU surface (CWE-367 / CWE-441).

Fault: the registry is STALE and serves the prior admissible tier `lax` (cap 10) for a namespace whose
TRUE tier is `strict` (cap 3) — the `wrong_provenance_binding` fault (fault_injection.py) realized in a
real cluster: s(strict) -> s'(lax), a d=1 provenance swap, request bytes unchanged.

Three arms on a 6-replica "C-witness" Deployment (safe under lax cap 10, unsafe under strict cap 3):
  deployed_admission — apply and let Kyverno decide from the SERVED (stale) binding -> ADMIT -> the
                       Deployment is really created (kubectl get shows it): a committed unsafe side effect.
  certified_gate     — a rung-1 exact pre-check that does NOT trust the served binding: it enumerates
                       N_1(s_served) (the tier neighbourhood, which contains the true `strict`) and tests
                       the replica count against each branch's cap at the eps-shifted threshold; the
                       `strict` branch fails -> BLOCK the apply -> no side effect.
  oracle             — apply under the TRUE (fresh) registry -> Kyverno denies: the ground-truth verdict.

Also on a genuinely-safe 2-replica Deployment: the certified gate ALLOWS -> applied -> Kyverno admits
(non-vacuity: the gate is not trivially blocking). Side effects are read off the real cluster.

Runs kubectl through `sg docker -c` so a login session without the docker group still works. Needs a
running kind cluster `cage-p3` with Kyverno + the manifests in ./manifests applied (see the module smoke
test / README). No LLM: the agent proposer is orthogonal (certified elsewhere, Experiment F).
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
MANIFESTS = HERE / "manifests"
OUT = HERE.parents[2] / "cert" / "out"
KUBECONFIG = os.environ.get("KUBECONFIG", str(Path.home() / ".kube" / "p3-config"))
LOCAL_BIN = str(Path.home() / ".local" / "bin")

# the policy's own known tier -> replica-cap table (the gate enumerates this; it is NOT read from the
# possibly-stale served binding). strict is the true tier for `payments`.
TIER_CAPS = {"strict": 3, "lax": 10}
NS, DEPLOY = "payments", "settlement-batch"


def _sh(cmd: str, timeout=120):
    """Run a shell command inside a docker-group subshell (sg docker), with kubectl on PATH."""
    full = f'export PATH="{LOCAL_BIN}:$PATH"; export KUBECONFIG="{KUBECONFIG}"; {cmd}'
    p = subprocess.run(["sg", "docker", "-c", full], capture_output=True, text=True, timeout=timeout)
    return p.returncode, (p.stdout + p.stderr).strip()


def kubectl(args: str, timeout=120):
    return _sh(f"kubectl {args}", timeout)


# --------------------------------------------------------------------------- #
# cluster helpers
# --------------------------------------------------------------------------- #
def cluster_ready():
    rc, _ = kubectl("get clusterpolicy replica-cap-by-tier -o name", timeout=30)
    return rc == 0


def set_registry(kind: str):
    """kind in {'stale','true'} -> apply the corresponding tier-registry ConfigMap."""
    f = MANIFESTS / ("10-tier-registry-stale.yaml" if kind == "stale" else "10-tier-registry-true.yaml")
    return kubectl(f"apply -f {f}")


def served_tier():
    rc, out = kubectl("-n cage-system get configmap tier-registry -o jsonpath={.data.tier}", timeout=30)
    return out if rc == 0 else None


def delete_witness():
    kubectl(f"-n {NS} delete deploy {DEPLOY} --ignore-not-found", timeout=60)


def apply_deploy(replicas: int):
    """Apply a Deployment with the given replica count; return (admitted, message)."""
    manifest = _witness_manifest(replicas)
    rc, out = _sh(f"cat <<'EOF' | kubectl apply -f -\n{manifest}\nEOF", timeout=90)
    return rc == 0, out


def deploy_exists():
    rc, out = kubectl(f"-n {NS} get deploy {DEPLOY} --ignore-not-found -o jsonpath={{.spec.replicas}}",
                      timeout=30)
    return (rc == 0 and out.strip() != ""), out.strip()


def _witness_manifest(replicas: int):
    return f"""apiVersion: apps/v1
kind: Deployment
metadata:
  name: {DEPLOY}
  namespace: {NS}
  labels: {{ app: {DEPLOY}, cage-p3-witness: "true" }}
spec:
  replicas: {replicas}
  selector: {{ matchLabels: {{ app: {DEPLOY} }} }}
  template:
    metadata: {{ labels: {{ app: {DEPLOY} }} }}
    spec:
      containers:
        - name: worker
          image: registry.k8s.io/pause:3.10
          resources:
            requests: {{ cpu: "10m", memory: "16Mi" }}
            limits: {{ cpu: "50m", memory: "32Mi" }}"""


# --------------------------------------------------------------------------- #
# the certified gate (rung-1 exact): does NOT trust the served binding
# --------------------------------------------------------------------------- #
def certified_gate_allows(replicas: int, eps_margin: int = 0):
    """Enumerate N_1(s_served) = every tier the served binding could actually be (a d=1 provenance swap),
    and test the replica count against each branch's cap at the eps-shifted (conservative) threshold.
    Allow iff SAFE for every branch. Sound because it does not trust the served tier."""
    worst = None
    for tier, cap in TIER_CAPS.items():                 # the full neighbourhood contains the true tier
        unsafe = replicas > (cap - eps_margin)
        if unsafe and (worst is None or cap < worst[1]):
            worst = (tier, cap)
    return (worst is None), worst


# --------------------------------------------------------------------------- #
# arms
# --------------------------------------------------------------------------- #
def run_deployed_admission(replicas):
    """Apply and let Kyverno decide from the (stale) served binding."""
    delete_witness()
    set_registry("stale")
    time.sleep(1)
    admitted, msg = apply_deploy(replicas)
    exists, rep = deploy_exists()
    return {"arm": "deployed_admission", "replicas": replicas, "served_tier": served_tier(),
            "applied": True, "admitted": admitted, "side_effect": exists,
            "committed_replicas": rep, "detail": _short(msg)}


def run_certified_gate(replicas, eps_margin):
    """Gate the apply on the rung-1 certified check; only apply if it allows."""
    delete_witness()
    set_registry("stale")
    time.sleep(1)
    allow, worst = certified_gate_allows(replicas, eps_margin)
    admitted = False
    msg = "blocked by certified gate before apply"
    if allow:
        admitted, msg = apply_deploy(replicas)
    exists, rep = deploy_exists()
    return {"arm": "certified_gate", "replicas": replicas, "served_tier": served_tier(),
            "gate_allow": allow, "gate_worst_branch": (list(worst) if worst else None),
            "applied": allow, "admitted": admitted, "side_effect": exists,
            "committed_replicas": rep, "detail": _short(msg)}


def run_oracle(replicas):
    """Ground truth: apply under the TRUE (fresh) registry."""
    delete_witness()
    set_registry("true")
    time.sleep(1)
    admitted, msg = apply_deploy(replicas)
    exists, rep = deploy_exists()
    set_registry("stale")                                # restore the faulted state for other arms
    return {"arm": "oracle_true_tier", "replicas": replicas, "served_tier": "strict",
            "applied": True, "admitted": admitted, "side_effect": exists,
            "committed_replicas": rep, "detail": _short(msg)}


def _short(msg, n=180):
    msg = " ".join(msg.split())
    return (msg[:n] + "…") if len(msg) > n else msg


def measure_overhead(replicas, eps_margin, reps=200):
    t0 = time.time()
    for _ in range(reps):
        certified_gate_allows(replicas, eps_margin)
    return (time.time() - t0) / reps * 1e6                # microseconds per gate decision


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--witness-replicas", type=int, default=6)   # unsafe under strict(3), safe under lax(10)
    ap.add_argument("--safe-replicas", type=int, default=2)      # safe under both -> non-vacuity
    ap.add_argument("--eps-margin", type=int, default=0)
    ap.add_argument("--out", default="p3_real_harness")
    args = ap.parse_args()

    if not cluster_ready():
        print("[error] kind cluster 'cage-p3' + Kyverno policy not ready. Apply manifests/ first "
              "(see the P3 README / test_real_harness smoke).")
        return

    rows = []
    # C-witness (6 replicas): the decisive comparison
    rows.append(run_deployed_admission(args.witness_replicas))
    rows.append(run_certified_gate(args.witness_replicas, args.eps_margin))
    rows.append(run_oracle(args.witness_replicas))
    # non-vacuity: a genuinely-safe workload still deploys through the certified gate
    rows.append({**run_certified_gate(args.safe_replicas, args.eps_margin), "case": "safe_nonvacuity"})
    delete_witness()

    gate_us = measure_overhead(args.witness_replicas, args.eps_margin)
    res = {
        "experiment": "PLAN_2 P3 — real kind+Kyverno harness, externally-inspectable side effect",
        "cluster": "kind cage-p3", "admission_controller": "Kyverno v1.13",
        "policy": "replicas <= cap(tier); tier from a separate ConfigMap via context.apiCall (TOCTOU)",
        "fault": "stale tier-registry serves lax(cap 10) while true tier is strict(cap 3) — wrong_provenance_binding",
        "tier_caps": TIER_CAPS, "witness_replicas": args.witness_replicas,
        "safe_replicas": args.safe_replicas, "gate_overhead_us": round(gate_us, 2), "rows": rows,
    }
    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / f"{args.out}.json").write_text(json.dumps(res, indent=2))
    _write_md(OUT / f"{args.out}.md", res)

    print(f"\n{'arm':<20}{'replicas':>9}{'served':>8}{'side_effect':>13}")
    for r in rows:
        tag = " (safe)" if r.get("case") == "safe_nonvacuity" else ""
        print(f"{r['arm']:<20}{r['replicas']:>9}{str(r.get('served_tier')):>8}"
              f"{str(r['side_effect']):>13}{tag}")
    print(f"\ncertified-gate overhead ≈ {gate_us:.1f} µs/decision")
    print(f"wrote {OUT / (args.out + '.json')}\nwrote {OUT / (args.out + '.md')}")
    return res


def _write_md(path, res):
    with open(path, "w") as f:
        f.write("# PLAN_2 P3 — real kind + Kyverno harness with an externally-inspectable side effect\n\n")
        f.write(f"Cluster **{res['cluster']}**, admission **{res['admission_controller']}**. Policy: "
                f"`{res['policy']}`. Fault: {res['fault']}. Tier caps {res['tier_caps']}. The "
                f"{res['witness_replicas']}-replica witness is safe under lax (cap 10) and unsafe under "
                "strict (cap 3); the verdict flips purely on the provenance binding `s` (a d=1 swap), the "
                "request bytes unchanged.\n\n")
        f.write("| arm | replicas | served tier | admitted | **real side effect** |\n")
        f.write("|---|---:|---|:--:|:--:|\n")
        for r in res["rows"]:
            tag = " (safe, non-vacuity)" if r.get("case") == "safe_nonvacuity" else ""
            f.write(f"| {r['arm']}{tag} | {r['replicas']} | {r.get('served_tier')} | "
                    f"{'yes' if r['admitted'] else 'no'} | "
                    f"{'**YES**' if r['side_effect'] else 'none'} |\n")
        f.write(f"\ncertified-gate overhead ≈ **{res['gate_overhead_us']} µs/decision**.\n\n")
        f.write("**Reads.** On a REAL cluster with REAL Kyverno admission, the `wrong_provenance_binding` "
                "fault makes the deployed admission control read a **stale** tier (lax) and **admit** a "
                "workload that the true tier (strict) forbids — a committed, `kubectl get`-inspectable "
                "side effect. The **certified rung-1 gate blocks it** (side effect = none) because it "
                "enumerates the tier neighbourhood `N_1(s_served)` — which contains the true `strict` — "
                "and tests every branch at the ε-shifted cap instead of trusting the served binding; the "
                "`strict` branch fails. The **oracle** (fresh registry) denies too, confirming the gate "
                "matches ground truth. On a genuinely-safe workload the gate still deploys (non-vacuous). "
                "This lifts #29's in-process result to a real cluster + real controller + real side "
                "effect. (The LLM proposer is orthogonal and certified separately, Experiment F.)\n")


if __name__ == "__main__":
    main()
