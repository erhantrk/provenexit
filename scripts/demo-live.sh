#!/usr/bin/env bash
# ProvenExit live demo, one command (verify → browse → revoke → refusal → re-allow), for the video and for judges:
#   env → `plr vpn verify` → `plr vpn` (local SOCKS5) → curl through the attested tunnel → the nearblocks page
#   → YOU revoke the exit's build on NEAR → curl and `plr vpn verify` show the next connection refused
#   → YOU re-allow it on NEAR → curl works again → stop.
#
# This script signs nothing and pays nothing: the two owner transactions are the human's (scripts/owner.sh …).
# Everything it starts is stopped on exit (trap), whatever happens.
#
# Env: deploy/testnet/env.live is loaded first (public identifiers only: PLR_NEAR_RPC, OWNER_ID, VPN_REGISTRY_ID,
#      OPERATOR_ID, INTEL_ROOT, and PLR_VPN_URL once the deploy wrote it). PLR_DEMO_ENV=<file> is loaded after it
#      and wins — e.g. `.run/stack.env` for an S1-F2 local MOCK exit on the local near-sandbox registry.
#      PLR_VPN_URL (required), PLR_VPN_REGISTRY (default: VPN_REGISTRY_ID), PLR_TRUSTED_ROOT (default: INTEL_ROOT),
#      PLR_VPN_SOCKS_PORT (default 18180). PLR_VPN_ENTRY_URL is ignored: the live demo is one hop.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

# ------------------------------------------------------------------------------------------- presentation
if [[ -t 1 && -z "${NO_COLOR:-}" ]]; then
  B=$'\e[1m'; D=$'\e[2m'; R=$'\e[31m'; G=$'\e[32m'; Y=$'\e[33m'; C=$'\e[36m'; X=$'\e[0m'
else
  B=; D=; R=; G=; Y=; C=; X=
fi
STEP=0
step() { STEP=$((STEP + 1)); printf '\n%s━━ %d. %s%s\n' "$B$C" "$STEP" "$*" "$X"; }
info() { printf '%s   %s%s\n' "$D" "$*" "$X"; }
ok()   { printf '%s   ✔ %s%s\n' "$G" "$*" "$X"; }
bad()  { printf '%s   ✘ %s%s\n' "$R" "$*" "$X"; FAILURES=$((FAILURES + 1)); }
run()  { printf '%s   $ %s%s\n' "$Y" "$*" "$X"; }
show() { sed 's/^/   │ /'; }
die()  { printf '\n%s✘ %s%s\n' "$B$R" "$*" "$X" >&2; exit 2; }
FAILURES=0

# ------------------------------------------------------------------------------------------- environment
ENV_LIVE=deploy/testnet/env.live
[[ -f $ENV_LIVE ]] || die "missing $ENV_LIVE (public identifiers only; see deploy/testnet/env.example)"
set -a; . "$ENV_LIVE"; set +a
if [[ -n "${PLR_DEMO_ENV:-}" && "${PLR_DEMO_ENV}" != "$ENV_LIVE" ]]; then
  [[ -f $PLR_DEMO_ENV ]] || die "missing PLR_DEMO_ENV=$PLR_DEMO_ENV"
  set -a; . "$PLR_DEMO_ENV"; set +a
fi
export PLR_VPN_REGISTRY="${PLR_VPN_REGISTRY:-${VPN_REGISTRY_ID:-}}"
export PLR_TRUSTED_ROOT="${PLR_TRUSTED_ROOT:-${INTEL_ROOT:-}}"
export PLR_NEAR_RPC="${PLR_NEAR_RPC:-https://rpc.testnet.fastnear.com}"
[[ -n $PLR_VPN_REGISTRY ]] || die "PLR_VPN_REGISTRY (or VPN_REGISTRY_ID in $ENV_LIVE) is required"
[[ -n $PLR_TRUSTED_ROOT ]] || die "PLR_TRUSTED_ROOT (or INTEL_ROOT in $ENV_LIVE) is required"
[[ -n "${PLR_VPN_URL:-}" ]] || die "PLR_VPN_URL is not set.
  live exit:        add it to $ENV_LIVE (T17 step 2: \`phala cvms get provenexit-exit --json\` → the URL containing -18200.)
  local S1-F2 exit: PLR_DEMO_ENV=.run/stack.env bash scripts/demo-live.sh"
if [[ -n "${PLR_VPN_ENTRY_URL:-}" ]]; then
  info "PLR_VPN_ENTRY_URL is set: the live demo is one hop, ignoring the entry"
  unset PLR_VPN_ENTRY_URL
fi
[[ -f client/dist/cli.js ]] || die "client/dist/cli.js is missing: build first (npx tsc -b && npm run build -w @plr/enclave)"
PORT="${PLR_VPN_SOCKS_PORT:-18180}"
PROXY="socks5h://127.0.0.1:$PORT"
RUN_DIR="$ROOT/.run"
mkdir -p "$RUN_DIR"
ID="demo-live-$$"
VERIFY_LOG="$RUN_DIR/$ID-verify.log"
VPN_LOG="$RUN_DIR/$ID-vpn.log"
STOP_FILE="$RUN_DIR/$ID-vpn.stop"
VPN_PID=""

# ------------------------------------------------------------------------------------------- lifecycle
stop_vpn() {
  [[ -n $VPN_PID ]] || return 0
  touch "$STOP_FILE"
  wait "$VPN_PID" 2>/dev/null || true
  VPN_PID=""
}
cleanup() {
  local code=$?
  trap - EXIT INT TERM
  stop_vpn
  rm -f "$STOP_FILE"
  if [[ $FAILURES -eq 0 ]]; then rm -f "$VERIFY_LOG" "$VPN_LOG"; fi
  exit "$code"
}
trap cleanup EXIT
trap 'exit 130' INT TERM

# The owner command the human runs. This script never runs it (the key stays with its owner).
owner_cmd() { # <method> '<json args>'
  local args='{"hash":"'"$COMPOSE"'"}'
  if [[ "$PLR_NEAR_RPC" == *testnet* ]]; then
    printf "scripts/owner.sh %s '%s'" "$1" "$args"
  else
    printf "node e2e/dist/stack-cli.js owner %s '%s' --vpn --env-out %s" "$1" "$args" "${PLR_DEMO_ENV:-$ENV_LIVE}"
  fi
}
# Waits for the human: the owner step happens in another terminal, between two of ours.
pause() { # <what the human should do>
  printf '\n%s   ⏸  %s%s\n' "$B$Y" "$1" "$X"
  info "the owner transaction is yours; this script signs nothing."
  local _
  IFS= read -r _ || die "stdin closed: cannot wait for the owner step (run it from a terminal)"
}
# curl through the proxy; remote DNS (socks5h), never a direct path around the tunnel.
socks_curl() { curl -sS --max-time 20 --noproxy '' --proxy "$PROXY" "$@"; }

cat <<EOF
${B}ProvenExit live demo${X} — a VPN exit whose no-logs claim your own computer checks, every connection.
${D}exit ${PLR_VPN_URL} · registry ${PLR_VPN_REGISTRY} on ${PLR_NEAR_RPC}
The two NEAR owner steps are yours; this script never signs anything.${X}
EOF

# ------------------------------------------------------------------------------------------- 1. verify
step "Attestation + registry checks: the client verifies the exit before any byte moves"
run "node client/dist/cli.js vpn verify"
set +e
node client/dist/cli.js vpn verify 2>&1 | tee "$VERIFY_LOG" | show
RC=${PIPESTATUS[0]}
set -e
[[ $RC -eq 0 ]] || die "verification failed (exit $RC): nothing would be tunnelled through this exit"
if grep -q 'MOCK ROOT' "$VERIFY_LOG"; then
  info "MOCK ROOT: the offline test root, not Intel (S1-F2: the live exit runs on this machine)"
fi
ok "exit verified: quote chain to the pinned root, measured compose, registered keys, build approved by the registry"
COMPOSE="$(sed -n 's/^ *compose hash: *\([0-9a-f]\{64\}\)$/\1/p' "$VERIFY_LOG" | head -1)"
[[ -n $COMPOSE ]] || die "could not read the compose hash from the verify output"
info "compose approved on the registry: $COMPOSE"
if [[ "$PLR_NEAR_RPC" == *testnet* ]]; then
  info "on NEAR: https://testnet.nearblocks.io/address/$PLR_VPN_REGISTRY"
  info "           (the register_instance_tdx transaction is listed on that page)"
else
  info "registry $PLR_VPN_REGISTRY on $PLR_NEAR_RPC (local near-sandbox: no public explorer page)"
fi

# ------------------------------------------------------------------------------------------- 2. proxy
step "Start the SOCKS5 proxy: plr vpn (background, stopped on exit)"
run "node scripts/plr-bg.mjs --stop-file .run/$ID-vpn.stop -- vpn &"
: >"$VPN_LOG"
node scripts/plr-bg.mjs --stop-file "$STOP_FILE" -- vpn </dev/null >"$VPN_LOG" 2>&1 &
VPN_PID=$!
for _ in $(seq 1 160); do
  grep -q "SOCKS5 proxy" "$VPN_LOG" && break
  jobs -rp | grep -qx "$VPN_PID" || break   # it exited (verification failed or the port is taken)
  sleep 0.25
done
show <"$VPN_LOG"
grep -q "SOCKS5 proxy" "$VPN_LOG" || die "plr vpn did not start (log: $VPN_LOG)"
ok "SOCKS5 proxy on $PROXY"

# ------------------------------------------------------------------------------------------- 3. browse
step "Browse through the attested tunnel"
DIRECT="$(curl -sS --max-time 10 https://api.ipify.org 2>/dev/null || true)"
run "curl --proxy $PROXY https://api.ipify.org"
set +e
VIA="$(socks_curl https://api.ipify.org 2>&1)"
RC=$?
set -e
printf '%s\n' "$VIA" | show
if [[ $RC -ne 0 || -z $VIA ]]; then bad "the fetch through the tunnel failed (curl exit $RC)"; exit 1; fi
ok "your traffic leaves from $VIA"
if [[ -n $DIRECT ]]; then
  if [[ $VIA == "$DIRECT" ]]; then
    info "same as this machine's own address ($DIRECT): this exit runs on this machine (S1-F2 mock exit)"
  else
    ok "and not this machine's address ($DIRECT): the exit relayed it"
  fi
fi

# ------------------------------------------------------------------------------------------- 4. revoke
step "Revoke the exit's build on NEAR — one owner transaction"
info "every new connection re-checks the registry, so the revocation applies to the very next one"
pause "Now revoke on NEAR ($(owner_cmd revoke_compose)), press enter"
run "curl --proxy $PROXY https://api.ipify.org"
set +e
OUT="$(socks_curl https://api.ipify.org 2>&1)"
RC=$?
set -e
printf '%s\n' "$OUT" | show
if [[ ( $RC -eq 97 || ( $RC -eq 7 && "$OUT" == *SOCKS* ) ) ]]; then
  ok "refused before anything was sent (SOCKS5 reply 0x02 \"not allowed by ruleset\")"
else
  bad "the connection was not refused (curl exit $RC) — is the revoke transaction final?"
fi
run "node client/dist/cli.js vpn verify"
set +e
OUT="$(node client/dist/cli.js vpn verify 2>&1)"
RC=$?
set -e
printf '%s\n' "$OUT" | grep -E '✘|REFUSED' | show || printf '%s\n' "$OUT" | show
if [[ $RC -ne 0 && "$OUT" == *E_COMPOSE_NOT_ALLOWED* ]]; then
  ok "the client refuses the revoked build: E_COMPOSE_NOT_ALLOWED"
else
  bad "expected E_COMPOSE_NOT_ALLOWED (exit $RC)"
fi

# ------------------------------------------------------------------------------------------- 5. re-allow
step "Re-allow it on NEAR — the same switch back"
pause "Now re-allow on NEAR ($(owner_cmd allow_compose)), press enter"
run "curl --proxy $PROXY https://api.ipify.org"
set +e
OUT="$(socks_curl https://api.ipify.org 2>&1)"
RC=$?
set -e
printf '%s\n' "$OUT" | show
if [[ $RC -eq 0 && -n $OUT ]]; then
  ok "works again ($OUT): the registry's approval is the switch"
else
  bad "still refused after the re-allow (curl exit $RC) — is the allow transaction final?"
fi

# ------------------------------------------------------------------------------------------- 6. stop
step "Stop"
stop_vpn
ok "SOCKS5 proxy stopped; nothing left running"

printf '\n'
if [[ $FAILURES -eq 0 ]]; then
  printf '%s━━ LIVE DEMO PASSED: verified → browsed → revoked on NEAR (refused) → re-allowed on NEAR (works).%s\n' "$B$G" "$X"
else
  printf '%s━━ LIVE DEMO FAILED: %d check(s) failed.%s\n' "$B$R" "$FAILURES" "$X"
  exit 1
fi
