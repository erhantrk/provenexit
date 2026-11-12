#!/usr/bin/env bash
# Stops the stack started by scripts/dev-up.sh (VPN exits, mock TDX hosts, near-sandbox) and removes its
# run state. Signal-free: it drops a stop file that the stack process polls.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RUN="$ROOT/.run"
ENV_FILE="$RUN/stack.env"
STOP_FILE="$RUN/stack.stop"
LOG="$RUN/stack.log"
if [[ ! -f "$ENV_FILE" ]]; then echo "no stack running (no $ENV_FILE)"; rm -f "$STOP_FILE"; exit 0; fi
PID="$(sed -n 's/^PLR_STACK_PID=//p' "$ENV_FILE")"
touch "$STOP_FILE"
printf 'stopping stack (pid %s) ' "$PID"
for _ in $(seq 1 90); do
  if grep -q "stack-cli: stopped" "$LOG" 2>/dev/null; then
    rm -f "$STOP_FILE"; printf '\n✔ stack stopped\n'; exit 0
  fi
  printf '.'; sleep 0.5
done
rm -f "$STOP_FILE"
printf '\n✘ the stack did not acknowledge the stop request within 45 s.\n' >&2
printf '  If it crashed, remove the stale state: rm %s\n  If it hangs, terminate pid %s yourself (its children follow automatically).\n' "$ENV_FILE" "$PID" >&2
exit 1
