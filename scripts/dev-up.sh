#!/usr/bin/env bash
# Leaves a local PLR stack running for manual use:
#   near-sandbox (LLM registry + VPN registry deployed, fresh MOCK ROOT) + honest router and honest production
#   VPN exit (PLR-VPN-v1), both launched and measured by the mock TDX host and registered on their registry;
#   for two-hop (SPEC-VPN §10) the owner approves operator → org-a and operator2 → org-b, and a second production
#   exit plus a two-hop entry (the loopback-allowing test build: a production entry refuses a loopback exit) are
#   registered by operator2. The test builds' DoH resolver runs on 127.0.0.1:18253 (production builds use the
#   measured public resolvers 1.1.1.1 / 9.9.9.9).
# Writes .run/stack.env (PLR_ROUTER_URL, PLR_NEAR_RPC, PLR_REGISTRY, PLR_TRUSTED_ROOT, PLR_VPN_URL,
# PLR_VPN_ENTRY_URL, PLR_VPN2_URL, PLR_VPN_REGISTRY, PLR_VPN_COMPOSE_HASH, …) for the `plr` CLI:
#   set -a; . .run/stack.env; set +a; node client/dist/cli.js verify
#   node client/dist/cli.js vpn verify; node client/dist/cli.js vpn   # two-hop (entry → exit), SOCKS5 on :18180
#   PLR_VPN_ENTRY_URL= node client/dist/cli.js vpn                  # one hop (empty = unset), straight to PLR_VPN_URL
# Stop with scripts/dev-down.sh.
#
# Env: PLR_LLM=llama|mock (default llama: real Qwen 0.5B), PLR_RPC_PORT (default 3030),
#      PLR_ROUTER_PORT (default 18100), PLR_EXIT_PORT (default 18200, the VPN exit),
#      PLR_EXTRA=evil-logger,mitm-key,vpn-honest-test,vpn-evil-logger,vpn-mitm-key,… (extra routers / exits),
#      PLR_DESTINATION=1 (also start a local HTTP test destination; port in PLR_DEST_PORT),
#      PLR_COMBO=1 (SPEC-COMBO, the cheapest deployment: ONE combo TD — LLM + router + VPN exit as three processes,
#        one measurement approved on both registries — instead of the separate router and exits; no two-hop, no
#        PLR_EXTRA. Writes the same PLR_ROUTER_URL / PLR_VPN_URL. PLR_COMBO=combo-test: the loopback-allowing test build),
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
COMBO_ARG=""
case "${PLR_COMBO:-0}" in
  0|"") ;;
  1|combo) COMBO_ARG="combo" ;;
  combo-test) COMBO_ARG="combo-test" ;;
  *) echo "PLR_COMBO must be 1, combo or combo-test" >&2; exit 1 ;;
esac
if [[ -n "$COMBO_ARG" && -n "${PLR_EXTRA:-}" ]]; then echo "PLR_COMBO runs one TD only: unset PLR_EXTRA" >&2; exit 1; fi

node e2e/dist/stack-cli.js up \
  --llm "${PLR_LLM:-llama}" \
  --rpc-port "${PLR_RPC_PORT:-3030}" \
  --router-port "${PLR_ROUTER_PORT:-18100}" \
  --exit-port "${PLR_EXIT_PORT:-18200}" \
  ${PLR_EXTRA:+--extra "$PLR_EXTRA"} \
  ${DEST_ARG:+"$DEST_ARG"} \
  ${COMBO_ARG:+--combo "$COMBO_ARG"} \
  --env-out "$ENV_FILE" --stop-file "$STOP_FILE" </dev/null >"$LOG" 2>&1 &
PID=$!
disown "$PID" 2>/dev/null || true

printf 'starting stack (pid %s, log %s) ' "$PID" "$LOG"
for _ in $(seq 1 1200); do
  if [[ -f "$ENV_FILE" ]]; then
    printf '\n✔ stack ready:\n'; grep -v '^#' "$ENV_FILE" | sed 's/^/    /'
    printf '\n  use it:   set -a; . %s; set +a; node client/dist/cli.js verify\n' "$ENV_FILE"
    printf '  OpenAI:   node client/dist/cli.js proxy   # then point any OpenAI SDK at http://127.0.0.1:18787/v1\n'
    if [[ -n "$COMBO_ARG" ]]; then
      printf '  combo:    one %s TD serves both the router (PLR_ROUTER_URL) and the VPN exit (PLR_VPN_URL)\n' "$COMBO_ARG"
      printf '  VPN:      node client/dist/cli.js vpn verify; node client/dist/cli.js vpn   # one hop, SOCKS5 socks5h://127.0.0.1:18180\n'
    else
      printf '  VPN:      node client/dist/cli.js vpn verify; node client/dist/cli.js vpn   # two-hop entry → exit, SOCKS5 socks5h://127.0.0.1:18180\n'
      printf '            PLR_VPN_ENTRY_URL= node client/dist/cli.js vpn                # one hop\n'
    fi
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
