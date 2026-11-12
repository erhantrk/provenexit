#!/usr/bin/env bash
# Leaves a local ProvenExit stack running for manual use:
#   near-sandbox (the VPN registry deployed, fresh MOCK ROOT) + the honest production VPN exit (PLR-VPN-v1), launched
#   and measured by the mock TDX host and registered on the registry; for two-hop (SPEC-VPN §10) the owner approves
#   operator → org-a and operator2 → org-b, and a second production exit plus a two-hop entry (the loopback-allowing
#   test build: a production entry refuses a loopback exit) are registered by operator2. The test builds' DoH resolver
#   runs on 127.0.0.1:18253 (production builds use the measured public resolvers 1.1.1.1 / 9.9.9.9).
# Writes .run/stack.env (PLR_NEAR_RPC, PLR_VPN_REGISTRY, PLR_TRUSTED_ROOT, PLR_VPN_URL, PLR_VPN_ENTRY_URL,
# PLR_VPN2_URL, PLR_VPN_COMPOSE_HASH, …) for the `plr` CLI:
#   set -a; . .run/stack.env; set +a; node client/dist/cli.js vpn verify
#   node client/dist/cli.js vpn                                      # two-hop (entry → exit), SOCKS5 on :18180
#   PLR_VPN_ENTRY_URL= node client/dist/cli.js vpn                  # one hop (empty = unset), straight to PLR_VPN_URL
# Stop with scripts/dev-down.sh.
#
# Env: PLR_RPC_PORT (default 3030), PLR_EXIT_PORT (default 18200, the VPN exit),
#      PLR_EXTRA=vpn-honest-test,vpn-evil-logger,vpn-mitm-key,… (extra exits),
#      PLR_DESTINATION=1 (also start a local HTTP test destination; port in PLR_DEST_PORT),
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
DEST_ARG=""
[[ "${PLR_DESTINATION:-0}" == 1 ]] && DEST_ARG="--destination"
node e2e/dist/stack-cli.js up \
  --rpc-port "${PLR_RPC_PORT:-3030}" \
  --exit-port "${PLR_EXIT_PORT:-18200}" \
  ${PLR_EXTRA:+--extra "$PLR_EXTRA"} \
  ${DEST_ARG:+"$DEST_ARG"} \
  --env-out "$ENV_FILE" --stop-file "$STOP_FILE" </dev/null >"$LOG" 2>&1 &
PID=$!
disown "$PID" 2>/dev/null || true

printf 'starting stack (pid %s, log %s) ' "$PID" "$LOG"
for _ in $(seq 1 1200); do
  if [[ -f "$ENV_FILE" ]]; then
    printf '\n✔ stack ready:\n'; grep -v '^#' "$ENV_FILE" | sed 's/^/    /'
    printf '\n  use it:   set -a; . %s; set +a; node client/dist/cli.js vpn verify\n' "$ENV_FILE"
    printf '  VPN:      node client/dist/cli.js vpn   # two-hop entry → exit, SOCKS5 socks5h://127.0.0.1:18180\n'
    printf '            PLR_VPN_ENTRY_URL= node client/dist/cli.js vpn                # one hop\n'
    printf '            curl --proxy socks5h://127.0.0.1:18180 https://example.com\n'
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
