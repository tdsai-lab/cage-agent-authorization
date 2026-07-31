# P3 — real kind + Kyverno harness (externally-inspectable side effect)

Upgrades #29's in-process runtime to a **real Kubernetes cluster** (kind) + a **real admission
controller** (Kyverno) enforcing a provenance-conditioned policy `replicas <= cap(tier)`, where the tier
`s` is resolved from a **separate data source** (a ConfigMap `tier-registry`) via Kyverno
`context.apiCall` — not from the request object. That separation is the TOCTOU surface (CWE-367/441).

**Result** (`cert/out/p3_real_harness.{json,md}`): under the `wrong_provenance_binding` fault (stale
registry serves tier `lax` cap 10 while the true tier is `strict` cap 3), the deployed admission
**admits** a 6-replica Deployment the true tier forbids → a committed `kubectl get`-inspectable side
effect; the **certified rung-1 gate blocks it** (enumerates `N_1(s_served)` ⊇ true `strict`, tests each
branch at the ε-shifted cap → strict fails), matching the **oracle** (fresh registry denies). A safe
2-replica workload still deploys (non-vacuous). Gate overhead ≈ 0.3 µs/decision.

## Reproduce (Docker required; use `sg docker -c` if your login session lacks the docker group)

```bash
export PATH="$HOME/.local/bin:$PATH"  # kind + kubectl
export KUBECONFIG="$HOME/.kube/p3-config"
M=bridge_benchmark/experiments/e2e/real_harness/manifests

# 1. cluster
sg docker -c "kind create cluster --name cage-p3 --image kindest/node:v1.31.2 --wait 120s"

# 2. Kyverno
sg docker -c "kubectl create -f https://github.com/kyverno/kyverno/releases/download/v1.13.0/install.yaml"
sg docker -c "kubectl -n kyverno rollout status deploy/kyverno-admission-controller --timeout=150s"

# 3. namespaces + STALE registry + policy
sg docker -c "kubectl apply -f $M/00-namespaces.yaml -f $M/10-tier-registry-stale.yaml -f $M/20-policy-replica-by-tier.yaml"

# 4. run the harness (arms: deployed_admission / certified_gate / oracle / safe-non-vacuity)
python bridge_benchmark/experiments/e2e/real_harness/run_p3.py

# teardown
sg docker -c "kind delete cluster --name cage-p3"
```

Tools installed to `~/.local/bin` (no sudo): `kind` v0.25.0, `kubectl` v1.36.2. Kyverno v1.13.0.
Tests: `tests/test_real_harness.py` (gate logic always; cluster arms skip unless `cage-p3` is up).

## Scope / honesty
Real cluster + real controller + real side effect + the certified gate blocking a real
provenance-TOCTOU admission. The LLM/MCP proposer is **orthogonal** and certified separately
(Experiment F); the certified node is the typed admission gate, not the agent. `s`=tier is
upstream-set (resolved from the registry), so the swap is exactly the `wrong_provenance_binding` fault.
This is a discrete provenance-TOCTOU instance (the continuous ε enters as the gate's conservative
threshold margin); it does not add a new soundness claim, it lifts the deployed-substrate rung to a real
cluster.
