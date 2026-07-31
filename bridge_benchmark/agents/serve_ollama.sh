#!/bin/bash
# serve_ollama.sh — start (or confirm) a local Ollama server whose model store lives on the NAS.
# Idempotent: if the server already answers on $OLLAMA_HOST it just reports and exits 0.
#
#   bash bridge_benchmark/agents/serve_ollama.sh            # start/confirm server
#   bash bridge_benchmark/agents/serve_ollama.sh pull qwen2.5:7b-instruct   # also pull a model
#
# Env (override as needed):
#   OLLAMA_HOME    install dir of the no-sudo ollama tarball   (default $OLLAMA_ROOT/install)
#   OLLAMA_MODELS  model store                                 (default $OLLAMA_ROOT/models)
#   OLLAMA_HOST    host:port the server binds                 (default 127.0.0.1:11434)
set -euo pipefail

export OLLAMA_HOME="${OLLAMA_HOME:-${OLLAMA_ROOT:-$PWD/.ollama}/install}"
export OLLAMA_MODELS="${OLLAMA_MODELS:-${OLLAMA_ROOT:-$PWD/.ollama}/models}"
export OLLAMA_HOST="${OLLAMA_HOST:-127.0.0.1:11434}"
BIN="$OLLAMA_HOME/bin/ollama"
LOG_DIR="${LOG_DIR:-${OLLAMA_ROOT:-$PWD/.ollama}/logs}"
mkdir -p "$OLLAMA_MODELS" "$LOG_DIR"

url="http://${OLLAMA_HOST}"
if curl -s --max-time 3 "${url}/api/tags" >/dev/null 2>&1; then
  echo "ollama already up at ${url} (OLLAMA_MODELS=${OLLAMA_MODELS})"
else
  echo "starting ollama (${BIN}) -> ${url}, models in ${OLLAMA_MODELS}"
  nohup "$BIN" serve > "${LOG_DIR}/ollama_serve.log" 2>&1 &
  until curl -s --max-time 2 "${url}/api/tags" >/dev/null 2>&1; do sleep 1; done
  echo "ollama up. GPU line:"
  grep -m1 "inference compute" "${LOG_DIR}/ollama_serve.log" || true
fi

if [[ "${1:-}" == "pull" && -n "${2:-}" ]]; then
  echo "pulling ${2} ..."
  "$BIN" pull "$2"
fi
"$BIN" list
