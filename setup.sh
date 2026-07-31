#!/usr/bin/env bash
# setup.sh — check (and optionally install) everything REPRODUCE.md asks for.
#
#   bash setup.sh              check the environment, report per capability
#   bash setup.sh --install    pip install -r requirements.txt first, then check
#
# Nothing here is required to run the analytic core: bridge_benchmark/generators/,
# cert/certificate_oracles.py and cert/fragment.py are pure standard library.
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"

OK=0; WARN=0; FAIL=0
ok()   { printf '  \033[32m[ok]\033[0m    %s\n' "$*"; OK=$((OK+1)); }
miss() { printf '  \033[33m[absent]\033[0m %s\n' "$*"; WARN=$((WARN+1)); }
bad()  { printf '  \033[31m[FAIL]\033[0m  %s\n' "$*"; FAIL=$((FAIL+1)); }

if [ "${1:-}" = "--install" ]; then
  echo "== installing core requirements"
  python3 -m pip install -r requirements.txt || bad "pip install -r requirements.txt failed"
  echo
fi

echo "== python"
PYV=$(python3 -c 'import sys; print("%d.%d.%d" % sys.version_info[:3])' 2>/dev/null)
if [ -z "$PYV" ]; then
  bad "python3 not found"
else
  python3 - <<'PY' >/dev/null 2>&1 && ok "python $PYV (>= 3.11)" || bad "python $PYV — 3.11+ required (results produced with 3.12)"
import sys; sys.exit(0 if sys.version_info[:2] >= (3, 11) else 1)
PY
fi

echo
echo "== analytic core (no dependencies) — this must pass"
if python3 bridge_benchmark/generators/test_oracle.py >/tmp/_oracle_check.log 2>&1; then
  ok "oracle unit tests: $(tail -1 /tmp/_oracle_check.log)"
else
  bad "oracle unit tests failed — see /tmp/_oracle_check.log"
fi
rm -f /tmp/_oracle_check.log

echo
echo "== core python packages (requirements.txt)"
for mod in numpy scipy sklearn pandas matplotlib yaml pytest; do
  ver=$(python3 -c "import $mod, sys; print(getattr($mod, '__version__', '?'))" 2>/dev/null)
  if [ -n "$ver" ]; then ok "$mod $ver"; else miss "$mod — 'pip install -r requirements.txt'  (rows tagged 'cpu')"; fi
done

echo
echo "== optional backends (requirements-optional.txt)"
ver=$(python3 -c "import torch; print(torch.__version__)" 2>/dev/null)
if [ -n "$ver" ]; then
  cuda=$(python3 -c "import torch; print('cuda' if torch.cuda.is_available() else 'cpu-only')" 2>/dev/null)
  ok "torch $ver ($cuda)"
else
  miss "torch — the 1-Lipschitz backend (rows tagged 'gpu') will not run"
fi
python3 -c "import orthogonium" 2>/dev/null && ok "orthogonium" || miss "orthogonium — needed with torch for the Lipschitz gate"
python3 -c "import zen_engine" 2>/dev/null && ok "zen-engine" || miss "zen-engine — Experiment B2 (rows tagged 'zen')"

echo
echo "== external tools"
OPA_BIN="bridge_benchmark/experiments/opa_gate/bin/opa"
if [ -x "$OPA_BIN" ]; then
  ok "opa $("$OPA_BIN" version 2>/dev/null | awk '/^Version:/{print $2}') at $OPA_BIN"
else
  miss "opa binary absent (rows tagged 'opa'). Results were produced with OPA 1.17.1:
             mkdir -p $(dirname $OPA_BIN)
             curl -L -o $OPA_BIN https://openpolicyagent.org/downloads/v1.17.1/opa_linux_amd64_static
             chmod +x $OPA_BIN"
fi
command -v ollama >/dev/null 2>&1 \
  && ok "ollama $(ollama --version 2>/dev/null | head -1) — models used: qwen2.5:7b-instruct, qwen2.5:32b, qwen3.6:latest" \
  || miss "ollama absent (rows tagged 'llm'); every LLM row also runs with --llm-backend mock"
command -v kind >/dev/null 2>&1 && ok "kind" || miss "kind/Kubernetes absent (rows tagged 'k8s')"

echo
echo "== data"
IEEE="${IEEE_CIS_DIR:-bridge_benchmark/data/raw/ieee_cis}"
if [ -f "$IEEE/train_transaction.csv" ]; then
  ok "IEEE-CIS at $IEEE"
else
  miss "IEEE-CIS absent (rows tagged 'ieee'). It is licensed competition data and is NOT redistributed:
             python3 scripts/download_ieee_cis.py --out bridge_benchmark/data/raw/ieee_cis
             export IEEE_CIS_DIR=\$PWD/bridge_benchmark/data/raw/ieee_cis"
fi
[ -d bridge_benchmark/data/realdata/nab/data ] \
  && ok "NAB telemetry vendored (MIT) at bridge_benchmark/data/realdata/nab/" \
  || miss "NAB telemetry absent — see bridge_benchmark/data/README.md"
[ -d external/corpora ] \
  && ok "third-party corpora at external/corpora/" \
  || miss "third-party policy corpora absent (rows tagged 'corpora'); each scan prints its upstream URL and expected path"

echo
echo "== frozen detector hashes (pre-registration evidence, see PREREGISTRATION.md)"
python3 - <<'PY'
import hashlib, pathlib
EXPECT = {
 "bridge_benchmark/experiments/detector/idiom_detector.py":
   "4620bb6be4d8911be5c8dd63e83fef770280e86f57a07040045b7263925c23a3",
 "bridge_benchmark/experiments/detector/idiom_rescan.py":
   "2308fd3f9373eb47bd31475300042d2a1d60f11ca262ff7c87be72f7a4588b70",
 "bridge_benchmark/experiments/mcp_substrate/substrate_detector.py":
   "221aa906dca8a79e5ad3d47abfad1756d93a6ea44a825a0a21e241834b9b57f6",
 "bridge_benchmark/experiments/mcp_substrate/openapi_detector.py":
   "466e9dfb8f2da0dacb26be8e21a3c20d5603f5631ef9dd2be1e1427444a329b0",
 "bridge_benchmark/experiments/mcp_substrate/registry_adjudicate.py":
   "b292d38f85f69483fd483cd3b607a77cd3076787146a929775c074579fa06a96",
}
for rel, want in EXPECT.items():
    p = pathlib.Path(rel)
    got = hashlib.sha256(p.read_bytes()).hexdigest() if p.exists() else "MISSING"
    mark = "\033[32m[ok]\033[0m   " if got == want else "\033[31m[FAIL]\033[0m"
    print(f"  {mark} {got[:16]}  {rel}")
PY

echo
echo "== summary"
printf '  %d ok, %d absent (optional), %d failed\n' "$OK" "$WARN" "$FAIL"
echo "  Next: REPRODUCE.md — every row is tagged with the capability it needs."
[ "$FAIL" -eq 0 ]
