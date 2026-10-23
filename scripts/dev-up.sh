#!/usr/bin/env bash
# Leaves a local PLR stack running for manual use:
#   near-sandbox (registry deployed, fresh MOCK ROOT) + honest router launched and measured by the mock TDX host.
# Writes .run/stack.env (PLR_ROUTER_URL, PLR_NEAR_RPC, PLR_REGISTRY, PLR_TRUSTED_ROOT, …) for the `plr` CLI:
#   set -a; . .run/stack.env; set +a; node client/dist/cli.js verify
# Stop with scripts/dev-down.sh.
#
# Env: PLR_LLM=llama|mock (default llama: real Qwen 0.5B), PLR_RPC_PORT (default 3030),
#      PLR_ROUTER_PORT (default 18100), PLR_EXTRA=evil-logger,mitm-key,… (extra attack routers),
#      PLR_SKIP_BUILD=1 (skip scripts/build.sh).
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
RUN="$ROOT/.run"
ENV_FILE="$RUN/stack.env"
STOP_FILE="$RUN/stack.stop"
LOG="$RUN/stack.log"

if [[ -f "$ENV_FILE" ]]; then
  echo "a stack is already running ($ENV_FILE exists): scripts/dev-down.sh first" >&2
  echo "(if it crashed, remove the stale file: rm $ENV_FILE)" >&2
  exit 1
fi
[[ "${PLR_SKIP_BUILD:-0}" == 1 ]] || scripts/build.sh
mkdir -p "$RUN"
rm -f "$STOP_FILE"

node e2e/dist/stack-cli.js up \
  --llm "${PLR_LLM:-llama}" \
  --rpc-port "${PLR_RPC_PORT:-3030}" \
  --router-port "${PLR_ROUTER_PORT:-18100}" \
  ${PLR_EXTRA:+--extra "$PLR_EXTRA"} \
  --env-out "$ENV_FILE" --stop-file "$STOP_FILE" </dev/null >"$LOG" 2>&1 &
PID=$!
disown "$PID" 2>/dev/null || true

printf 'starting stack (pid %s, log %s) ' "$PID" "$LOG"
for _ in $(seq 1 1200); do
  if [[ -f "$ENV_FILE" ]]; then
    printf '\n✔ stack ready:\n'; grep -v '^#' "$ENV_FILE" | sed 's/^/    /'
    printf '\n  use it:   set -a; . %s; set +a; node client/dist/cli.js verify\n' "$ENV_FILE"
    printf '  OpenAI:   node client/dist/cli.js proxy   # then point any OpenAI SDK at http://127.0.0.1:18787/v1\n'
    printf '  stop:     scripts/dev-down.sh\n'
    exit 0
  fi
  if grep -q "stack-cli: \(start failed\|stopped\)" "$LOG" 2>/dev/null; then
    printf '\n✘ stack failed to start; last log lines:\n' >&2; tail -n 20 "$LOG" >&2
    exit 1
  fi
  printf '.'; sleep 0.5
done
printf '\n✘ timed out waiting for the stack; see %s (scripts/dev-down.sh to clean up)\n' "$LOG" >&2
exit 1
