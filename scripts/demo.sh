#!/usr/bin/env bash
# PLR-v1 + PLR-VPN-v1 end-to-end demo, one command:
#   build → near-sandbox + LLM registry + VPN registry → honest router (real Qwen 0.5B via llama.cpp, launched &
#   measured by the mock TDX host) → `plr verify` + `plr chat` → evil-logger, MITM and on-chain revocation
#   scenarios → VPN: `plr vpn verify`, a fetch through the local SOCKS5 proxy and the attested tunnel, evil exit,
#   MITM, revocation, encrypted DNS inside the exit (DoH: resolver down ⇒ E_DNS, no plaintext fallback), the
#   production egress policy, and (only when online) https://example.com via the exit → two-hop (SPEC-VPN §10):
#   both hops + operator organizations verified, a fetch through entry → exit, same organization refused, a logging
#   entry that sees only the exit's address, and (only when online) https://example.com through two hops →
#   combo (SPEC-COMBO): ONE TD runs the LLM, the router and the VPN exit (one measurement, two keys, two registries):
#   both services verified, chat + tunnel, per-registry revocation, and the production combo's exit cannot reach
#   the router's port → Zcash (SPEC-CHAINS tier C, only when zebrad is installed): a second stack on a zebrad regtest
#   node whose registries are signed OP_RETURN record logs; `plr verify` (tier C: the client checks the registration
#   evidence itself), `plr chat`, and revocation / re-approval via owner records → tier B (SPEC-CHAINS §9-§11, each
#   only when its node tools and built contract are present): EVM (anvil), Stellar (quickstart container), Solana
#   (test validator) — verify, chat, revocation / re-approval by owner transactions.
# Everything it starts is stopped on exit (trap), whatever happens.
#
# Env: PLR_LLM=llama|mock (default llama), PLR_SKIP_BUILD=1, NO_COLOR=1,
#      PLR_DEMO_CHAINS=near|all (default near: the NEAR hackathon path only; "all" also runs the pre-hackathon
#      multi-chain stages from temo: Zcash tier C and EVM/Stellar/Solana tier B),
#      PLR_DEMO_SOCKS_PORT (default 18180; the production-exit proxy uses the next port).
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

# ------------------------------------------------------------------------------------------- presentation
if [[ -t 1 && -z "${NO_COLOR:-}" ]]; then
  B=$'\e[1m'; D=$'\e[2m'; R=$'\e[31m'; G=$'\e[32m'; Y=$'\e[33m'; C=$'\e[36m'; M=$'\e[35m'; X=$'\e[0m'
else
  B=; D=; R=; G=; Y=; C=; M=; X=
fi
STEP=0
step() { STEP=$((STEP + 1)); printf '\n%s━━ %d. %s %s\n' "$B$C" "$STEP" "$1" "$X"; }
info() { printf '%s   %s%s\n' "$D" "$*" "$X"; }
ok()   { printf '%s   ✔ %s%s\n' "$G" "$*" "$X"; }
bad()  { printf '%s   ✘ %s%s\n' "$R" "$*" "$X"; FAILURES=$((FAILURES + 1)); }
show() { sed "s/^/   ${D}│${X} /"; }
run()  { printf '%s   $ %s%s\n' "$Y" "$*" "$X"; }
FAILURES=0

# ------------------------------------------------------------------------------------------- lifecycle
RUN="$ROOT/.run"
ID="demo-$(date +%s)"
ENV_FILE="$RUN/$ID.env"
STACK_LOG="$RUN/$ID.log"
STACK_STARTED=0
STACK_PID=""
STOP_FILE="$RUN/$ID.stop"
DNS_DOWN_FILE="$RUN/$ID.dns-down"   # while it exists, the stack's DoH resolver answers HTTP 503
SOCKS_PIDS=()   # names of the running `plr vpn` instances
SOCKS_JOBS=()   # their background job pids
# Shutdown is signal-free and bounded: dropping $STOP_FILE makes the stack stop every router subtree and the
# chain (group SIGTERM → SIGKILL after 10 s; the stack CLI exits within 20 s whatever happens). If this script
# dies without running its trap, the stack notices via --parent-pid and stops itself.
stop_stack() {
  [[ $STACK_STARTED == 1 ]] || return 0
  STACK_STARTED=0
  touch "$STOP_FILE"
  wait "$STACK_PID" 2>/dev/null || true
  rm -f "$STOP_FILE"
  grep "stack-cli: stop" "$STACK_LOG" 2>/dev/null | show || true
}
# `plr vpn` processes run under scripts/plr-bg.mjs: stopped signal-free by their stop file (or when we are gone).
stop_socks() {
  local p
  for p in "${SOCKS_PIDS[@]+"${SOCKS_PIDS[@]}"}"; do touch "$RUN/$ID-socks-$p.stop"; done
  for p in "${SOCKS_JOBS[@]+"${SOCKS_JOBS[@]}"}"; do wait "$p" 2>/dev/null || true; done
  for p in "${SOCKS_PIDS[@]+"${SOCKS_PIDS[@]}"}"; do rm -f "$RUN/$ID-socks-$p.stop"; done
  SOCKS_PIDS=(); SOCKS_JOBS=()
}
cleanup() {
  local code=$?
  trap - EXIT INT TERM
  stop_socks
  if [[ $STACK_STARTED == 1 ]]; then
    printf '\n%s━━ cleanup%s\n' "$B$C" "$X"
    stop_stack
  fi
  rm -f "$ENV_FILE" "${ENV_FILE%.env}.owner.json" "$RUN/$ID"-socks-*.log "$DNS_DOWN_FILE"
  exit "$code"
}
trap cleanup EXIT
trap 'exit 130' INT TERM

plr() { node "$ROOT/client/dist/cli.js" "$@"; }
owner() { node "$ROOT/e2e/dist/stack-cli.js" owner "$1" "$2" --env-out "$ENV_FILE"; }
vpn_owner() { node "$ROOT/e2e/dist/stack-cli.js" owner "$1" "$2" --vpn --env-out "$ENV_FILE"; }
# Runs `plr` expecting a refusal with code $1; prints the output; checks the code.
expect_refusal() {
  local want=$1; shift
  local out
  set +e; out=$("$@" 2>&1); local rc=$?; set -e
  printf '%s\n' "$out" | show
  if [[ $rc -ne 0 && "$out" == *"$want"* ]]; then ok "refused with ${B}$want${X}${G} — nothing was sent"; else bad "expected refusal $want (exit $rc)"; fi
}

cat <<EOF
${B}PLR-v1 — provably-private LLM router + PLR-VPN-v1 no-logs VPN exit: end-to-end demo${X}
${D}The router runs in a (mock) Intel TDX TD; its code measurement is approved in a NEAR registry contract;
the client verifies a fresh attestation against the chain before it encrypts a single prompt.
Then the same for a VPN exit: \`plr vpn\` only tunnels (SOCKS5, remote DNS) to an exit whose no-logs build is approved
in a second, independent NEAR registry, re-checked on every connection.
${Y}MOCK ROOT:${X}${D} attestation is signed by a local test root, not Intel — see README "What this proves".${X}
EOF

LLM="${PLR_LLM:-llama}"
[[ $LLM == llama || $LLM == mock ]] || { echo "PLR_LLM must be llama or mock" >&2; exit 2; }
export LLM_KIND="$LLM"

# ------------------------------------------------------------------------------------------- 1. build
step "Build (TypeScript, measured router bundles, registry wasm)"
if [[ "${PLR_SKIP_BUILD:-0}" == 1 ]]; then info "skipped (PLR_SKIP_BUILD=1)"; else scripts/build.sh 2>&1 | show; fi
node -e 'const i=require("./enclave/dist/build-info.json"); for (const v of ["honest","evil-logger"]) console.log(`${v.padEnd(16)} bundle ${i.variants[v].bundle_sha256}`); for (const v of ["vpn-honest","vpn-honest-test","vpn-evil-logger"]) console.log(`${v.padEnd(16)} compose ${i.vpn[v].compose.compose_hash}`); for (const v of ["combo","combo-test"]) console.log(`${v.padEnd(16)} compose(${process.env.LLM_KIND}) ${i.combo[v].compose[process.env.LLM_KIND].compose_hash}`)' | show

# ------------------------------------------------------------------------------------------- 2. stack
step "Start near-sandbox, deploy both registries, approve + launch the honest router (llm=$LLM) and VPN exits"
mkdir -p "$RUN"
: >"$STACK_LOG"
rm -f "$STOP_FILE"
node e2e/dist/stack-cli.js up --llm "$LLM" --id "$ID" --extra evil-logger,mitm-key,vpn-honest-test,vpn-evil-logger,vpn-mitm-key,combo-test,combo --destination \
  --evil-entry --dns-down-file "$DNS_DOWN_FILE" \
  --env-out "$ENV_FILE" --stop-file "$STOP_FILE" --parent-pid "$$" </dev/null >"$STACK_LOG" 2>&1 &
STACK_PID=$!
STACK_STARTED=1
SHOWN=0
for _ in $(seq 1 1200); do
  TOTAL=$(wc -l <"$STACK_LOG" | tr -d ' ')
  if [[ $TOTAL -gt $SHOWN ]]; then sed -n "$((SHOWN + 1)),${TOTAL}p" "$STACK_LOG" | show; SHOWN=$TOTAL; fi
  [[ -f "$ENV_FILE" ]] && break
  grep -q "stack-cli: \(start failed\|stopped\)" "$STACK_LOG" && break
  [[ -n "$(jobs -r)" ]] || break   # the stack process died
  sleep 0.5
done
if [[ ! -f "$ENV_FILE" ]]; then sed -n "$((SHOWN + 1)),\$p" "$STACK_LOG" | show; bad "stack failed to start (log: $STACK_LOG)"; exit 1; fi
set -a; . "$ENV_FILE"; set +a
# Two-hop mode is opt-in per command below: the single-hop steps talk to one exit.
TWOHOP_ENTRY_URL="$PLR_VPN_ENTRY_URL"; unset PLR_VPN_ENTRY_URL
ok "stack ready: router $PLR_ROUTER_URL · registry $PLR_REGISTRY @ $PLR_NEAR_RPC"
info "pinned root (PLR_TRUSTED_ROOT): ${PLR_TRUSTED_ROOT:0:32}…"

# ------------------------------------------------------------------------------------------- 3. verify
step "plr verify — every check, against the chain"
run "plr verify"
if plr verify 2>&1 | show; then ok "router verified"; else bad "honest router failed verification"; fi

# ------------------------------------------------------------------------------------------- 4. chat
step "plr chat — encrypted prompt to the attested key, streamed answer, signed receipt"
QUESTION="In one short sentence: why should an AI provider not see my prompts?"
run "plr chat \"$QUESTION\""
set +e; ANSWER=$(plr chat "$QUESTION" 2>&1); RC=$?; set -e
printf '%s\n' "$ANSWER" | show
if [[ $RC -eq 0 ]]; then ok "answer received; receipt signature verified"; else bad "chat failed"; fi
if grep -qF "$QUESTION" "$PLR_STACK_LOG_DIR/honest.log" 2>/dev/null; then bad "prompt found in the honest router's output!"; else ok "honest router output contains no trace of the prompt"; fi
info "waiting for the receipt batch to be anchored on-chain…"
for _ in $(seq 1 30); do grep -q "plr-router: anchored" "$PLR_STACK_LOG_DIR/honest.log" 2>/dev/null && break; sleep 1; done
if grep -m1 "plr-router: anchored" "$PLR_STACK_LOG_DIR/honest.log" | show; then ok "receipts anchored (Merkle root on NEAR, signed by the attested Ed25519 key)"; else bad "no anchor yet"; fi

# ------------------------------------------------------------------------------------------- 5. evil logger
step "Evil router: honest code + a patch that logs prompts (different measurement, not approved)"
SECRET="my bank PIN is 4242 — $(date +%s)"
info "evil compose hash: $(grep -o 'compose_hash=[0-9a-f]*' "$PLR_STACK_LOG_DIR/evil-logger.log" | head -1 | cut -d= -f2)"
info "approved compose:  $PLR_COMPOSE_HASH"
grep -m1 "registration_failed" "$PLR_STACK_LOG_DIR/evil-logger.log" | show || true
run "PLR_ROUTER_URL=\$PLR_EVIL_LOGGER_URL plr chat \"$SECRET\""
expect_refusal E_COMPOSE_NOT_ALLOWED env PLR_ROUTER_URL="$PLR_EVIL_LOGGER_URL" node "$ROOT/client/dist/cli.js" chat "$SECRET"
if grep -qF "$SECRET" "$PLR_STACK_LOG_DIR/evil-logger.log" "$PLR_STACK_RUN_DIR/stolen.log" 2>/dev/null; then bad "the evil router got the secret!"; else ok "the evil router's stdout and stolen.log contain nothing: it never received the prompt"; fi

# ------------------------------------------------------------------------------------------- 6. MITM
step "MITM: the operator's network swaps the router's encryption key in the attestation"
run "PLR_ROUTER_URL=\$PLR_MITM_KEY_URL plr verify"
expect_refusal E_REPORT_DATA_KEYS env PLR_ROUTER_URL="$PLR_MITM_KEY_URL" node "$ROOT/client/dist/cli.js" verify
if grep -q "STOLEN" "$PLR_STACK_LOG_DIR/mitm-key.log" 2>/dev/null; then bad "the MITM decrypted something!"; else ok "the MITM proxy never saw a request it could decrypt"; fi

# ------------------------------------------------------------------------------------------- 7. revocation
step "Revocation: the registry owner revokes the honest build on-chain"
run "owner revoke_compose $PLR_COMPOSE_HASH"
owner revoke_compose "{\"hash\":\"$PLR_COMPOSE_HASH\"}" 2>&1 | show
run "plr chat \"$QUESTION\""
expect_refusal E_COMPOSE_NOT_ALLOWED node "$ROOT/client/dist/cli.js" chat "$QUESTION"
run "owner allow_compose $PLR_COMPOSE_HASH"
owner allow_compose "{\"hash\":\"$PLR_COMPOSE_HASH\"}" 2>&1 | show
run "plr chat \"Say hello in three words.\""
if plr chat "Say hello in three words." 2>&1 | show; then ok "service restored by re-approval"; else bad "chat failed after re-approval"; fi

# =========================================================================================== PLR-VPN-v1
SOCKS_TEST="${PLR_DEMO_SOCKS_PORT:-18180}"
SOCKS_PROD=$((SOCKS_TEST + 1))
MARK="vpn-demo-secret-$(date +%s)-$RANDOM"
# curl through a SOCKS5 proxy with remote DNS (socks5h); `--noproxy ''` keeps NO_PROXY from bypassing it for localhost.
socks_curl() { local port=$1; shift; curl -sS --max-time 20 --noproxy '' --proxy "socks5h://127.0.0.1:$port" "$@"; }
# Starts `plr vpn` against exit $2 on SOCKS port $3 (two-hop through entry $4 when given) in the background;
# waits for its ready line.
start_socks() {
  local name=$1 url=$2 port=$3 entry=${4:-} log="$RUN/$ID-socks-$1.log"
  : >"$log"
  run "${entry:+PLR_VPN_ENTRY_URL=$entry }PLR_VPN_URL=$url PLR_VPN_SOCKS_PORT=$port plr vpn &"
  env ${entry:+PLR_VPN_ENTRY_URL="$entry"} PLR_VPN_URL="$url" PLR_VPN_SOCKS_PORT="$port" node "$ROOT/scripts/plr-bg.mjs" --stop-file "$RUN/$ID-socks-$name.stop" -- vpn </dev/null >"$log" 2>&1 &
  local pid=$!
  SOCKS_PIDS+=("$name"); SOCKS_JOBS+=("$pid")
  for _ in $(seq 1 120); do
    grep -q "SOCKS5 proxy" "$log" && break
    jobs -rp | grep -qx "$pid" || break   # it exited (verification failed or the port is taken)
    sleep 0.25
  done
  show <"$log"
  if grep -q "SOCKS5 proxy" "$log"; then ok "SOCKS5 proxy for the $name exit on socks5h://127.0.0.1:$port"; return 0; fi
  bad "plr vpn ($name) did not start"; return 1
}
# One verified connection with the exact PLR error code (scripts/vpn-probe.mjs): GET <path> to <host>:<port> via exit
# <exit> (two-hop through <entry> unless it is "-"). Expects $1 = "ok" or a refusal code; prints the probe output.
#   expect_probe <ok|E_CODE> <entry|-> <exit> <host> <port> [<path>]
expect_probe() {
  local want=$1 entry=$2 exit=$3; shift 3
  local out rc
  set +e
  if [[ $entry == - ]]; then run "PLR_VPN_URL=$exit vpn-probe $*"; else run "PLR_VPN_ENTRY_URL=$entry PLR_VPN_URL=$exit vpn-probe $*"; fi
  if [[ $entry == - ]]; then out=$(env PLR_VPN_ENTRY_URL= PLR_VPN_URL="$exit" node "$ROOT/scripts/vpn-probe.mjs" "$@" 2>&1 </dev/null); rc=$?
  else out=$(env PLR_VPN_ENTRY_URL="$entry" PLR_VPN_URL="$exit" node "$ROOT/scripts/vpn-probe.mjs" "$@" 2>&1 </dev/null); rc=$?; fi
  set -e
  printf '%s\n' "$out" | show
  if [[ $want == ok ]]; then
    [[ $rc -eq 0 ]] && return 0
    bad "expected a successful connection (exit $rc)"; return 1
  fi
  [[ $rc -ne 0 && "$out" == *"✘ $want"* ]] && return 0
  bad "expected refusal $want (exit $rc)"; return 1
}
# Waits (≤ 10 s) for the stack log to report the DoH resolver state $1 (DOWN|UP).
wait_dns() {
  for _ in $(seq 1 40); do grep -q "stack-cli: DoH resolver $1" "$STACK_LOG" && return 0; sleep 0.25; done
  bad "the DoH resolver did not switch $1"; return 1
}
# Expects a SOCKS5 refusal: curl exit 97 (proxy handshake failed: the CONNECT reply was not "succeeded").
expect_socks_refusal() {
  local what=$1; shift
  local out rc
  set +e; out=$(socks_curl "$@" 2>&1); rc=$?; set -e
  printf '%s\n' "$out" | show
  # curl ≥ 7.73 reports a refused SOCKS5 CONNECT as exit 97 (CURLE_PROXY); older versions as 7 with a SOCKS message.
  if [[ ( $rc -eq 97 || ( $rc -eq 7 && "$out" == *SOCKS* ) ) && "$out" != *dest-ok* ]]; then ok "$what"; else bad "expected a SOCKS5 refusal (curl exit $rc)"; fi
}

step "VPN: plr vpn verify — the production exit, every check against the VPN registry"
info "VPN registry $PLR_VPN_REGISTRY · approved production compose $PLR_VPN_COMPOSE_HASH"
run "plr vpn verify"
if plr vpn verify 2>&1 | show; then ok "production exit verified (same SPEC §9 checks, against the VPN registry)"; else bad "production exit failed verification"; fi

step "VPN: fetch a local destination through the SOCKS5 proxy and the attested tunnel (test build: loopback allowed)"
info "test build compose $PLR_VPN_TEST_COMPOSE_HASH (allow_loopback: true is part of the measurement: never production)"
VPN_TEST_OK=0
if start_socks test "$PLR_VPN_HONEST_TEST_URL" "$SOCKS_TEST"; then
  VPN_TEST_OK=1
  info "$PLR_DEST_HOST exists only in the stack's local DoH resolver (.test never resolves publicly): if it works, the exit resolved it"
  run "curl --proxy socks5h://127.0.0.1:$SOCKS_TEST http://$PLR_DEST_HOST:$PLR_DEST_PORT/$MARK"
  set +e; OUT=$(socks_curl "$SOCKS_TEST" "http://$PLR_DEST_HOST:$PLR_DEST_PORT/$MARK" 2>&1); RC=$?; set -e
  printf '%s\n' "$OUT" | show
  if [[ $RC -eq 0 && "$OUT" == "dest-ok:/$MARK" ]]; then ok "response relayed end-to-end (\"$PLR_DEST_HOST\" was resolved by the exit over DoH, not by the client)"; else bad "fetch through the tunnel failed (curl exit $RC)"; fi
  if grep -qF "$MARK" "$PLR_STACK_LOG_DIR/vpn-honest-test.log" "$PLR_STACK_LOG_DIR/vpn-honest.log" 2>/dev/null; then bad "a destination/payload marker appears in an honest exit's output!"; else ok "the honest exits' output contains no destination, path or payload"; fi
  grep -m3 "plr-vpn: " "$PLR_STACK_LOG_DIR/vpn-honest-test.log" | show || true
fi

step "VPN: evil exit — honest code + a patch that logs destinations (different measurement, not approved)"
info "evil compose hash: $(grep -o 'compose_hash=[0-9a-f]*' "$PLR_STACK_LOG_DIR/vpn-evil-logger.log" | head -1 | cut -d= -f2)"
run "PLR_VPN_URL=\$PLR_VPN_EVIL_LOGGER_URL plr vpn verify"
expect_refusal E_COMPOSE_NOT_ALLOWED env PLR_VPN_URL="$PLR_VPN_EVIL_LOGGER_URL" node "$ROOT/client/dist/cli.js" vpn verify
run "PLR_VPN_URL=\$PLR_VPN_EVIL_LOGGER_URL plr vpn"
expect_refusal E_COMPOSE_NOT_ALLOWED env PLR_VPN_URL="$PLR_VPN_EVIL_LOGGER_URL" PLR_VPN_SOCKS_PORT="$SOCKS_PROD" node "$ROOT/client/dist/cli.js" vpn
if grep -qF "$MARK" "$PLR_STACK_LOG_DIR/vpn-evil-logger.log" 2>/dev/null; then bad "the evil exit saw a destination!"; else ok "the evil exit never received a single connection"; fi

step "VPN: MITM swaps the exit's tunnel key in the attestation"
run "PLR_VPN_URL=\$PLR_VPN_MITM_KEY_URL plr vpn verify"
expect_refusal E_REPORT_DATA_KEYS env PLR_VPN_URL="$PLR_VPN_MITM_KEY_URL" node "$ROOT/client/dist/cli.js" vpn verify

if [[ $VPN_TEST_OK == 1 ]]; then
  step "VPN: revocation — applies to the very next connection, even with a cached attestation"
  run "owner --vpn revoke_compose $PLR_VPN_TEST_COMPOSE_HASH"
  vpn_owner revoke_compose "{\"hash\":\"$PLR_VPN_TEST_COMPOSE_HASH\"}" 2>&1 | show
  run "curl --proxy socks5h://127.0.0.1:$SOCKS_TEST http://$PLR_DEST_HOST:$PLR_DEST_PORT/after-revoke"
  expect_socks_refusal "refused (SOCKS5 reply 0x02 \"not allowed by ruleset\") — the destination was never contacted" "$SOCKS_TEST" "http://$PLR_DEST_HOST:$PLR_DEST_PORT/after-revoke"
  run "owner --vpn allow_compose $PLR_VPN_TEST_COMPOSE_HASH"
  vpn_owner allow_compose "{\"hash\":\"$PLR_VPN_TEST_COMPOSE_HASH\"}" 2>&1 | show
  run "curl --proxy socks5h://127.0.0.1:$SOCKS_TEST http://$PLR_DEST_HOST:$PLR_DEST_PORT/after-reallow"
  set +e; OUT=$(socks_curl "$SOCKS_TEST" "http://$PLR_DEST_HOST:$PLR_DEST_PORT/after-reallow" 2>&1); RC=$?; set -e
  printf '%s\n' "$OUT" | show
  if [[ $RC -eq 0 && "$OUT" == "dest-ok:/after-reallow" ]]; then ok "service restored by re-approval"; else bad "fetch failed after re-approval (curl exit $RC)"; fi
fi

if [[ $VPN_TEST_OK == 1 ]]; then
  step "VPN: encrypted DNS inside the exit — DoH only (RFC 8484), never the host's resolver"
  info "production resolvers (measured in the compose): $(node -e 'console.log(require("./enclave/dist/build-info.json").vpn["vpn-honest"].doh.join(", "))')"
  info "test builds: $PLR_DOH_URL (the stack's local resolver). The resolver sees the query, never your IP;"
  info "the exit's host/ISP sees only TLS to the resolver's IP literal — no plaintext DNS, no bootstrap lookup."
  if expect_probe ok - "$PLR_VPN_HONEST_TEST_URL" "$PLR_DEST_HOST" "$PLR_DEST_PORT" /doh-up; then ok "$PLR_DEST_HOST resolved inside the exit over DoH, then fetched"; fi
  run "touch $DNS_DOWN_FILE   # the DoH resolver now answers HTTP 503"
  touch "$DNS_DOWN_FILE"
  if wait_dns DOWN; then
    if expect_probe E_DNS - "$PLR_VPN_HONEST_TEST_URL" "$PLR_DEST_HOST" "$PLR_DEST_PORT" /doh-down; then ok "resolver down ⇒ E_DNS: no fallback, the destination was never contacted"; fi
    if expect_probe E_DNS - "$PLR_VPN_HONEST_TEST_URL" example.com 80; then ok "example.com ⇒ E_DNS too: the host's resolver could answer it, but the exit never asks it"; fi
    run "curl --proxy socks5h://127.0.0.1:$SOCKS_TEST http://$PLR_DEST_HOST:$PLR_DEST_PORT/doh-down"
    expect_socks_refusal "SOCKS5 reply 0x04 (host unreachable) = E_DNS" "$SOCKS_TEST" "http://$PLR_DEST_HOST:$PLR_DEST_PORT/doh-down"
  fi
  rm -f "$DNS_DOWN_FILE"
  wait_dns UP || true
  if expect_probe E_EGRESS_DENIED - "$PLR_VPN_HONEST_TEST_URL" localhost "$PLR_DEST_PORT"; then ok "\"localhost\" refused before any resolution (RFC 6761), even on the loopback-allowing test build"; fi
fi

step "VPN: the production build refuses loopback and cloud-metadata targets (protects the host's own services)"
if start_socks production "$PLR_VPN_URL" "$SOCKS_PROD"; then
  run "curl --proxy socks5h://127.0.0.1:$SOCKS_PROD http://127.0.0.1:$PLR_DEST_PORT/"
  expect_socks_refusal "127.0.0.1 refused by the exit (E_EGRESS_DENIED → SOCKS5 0x02)" "$SOCKS_PROD" "http://127.0.0.1:$PLR_DEST_PORT/"
  run "curl --proxy socks5h://127.0.0.1:$SOCKS_PROD http://169.254.169.254/latest/meta-data/"
  expect_socks_refusal "169.254.169.254 (cloud metadata) refused by the exit (E_EGRESS_DENIED → SOCKS5 0x02)" "$SOCKS_PROD" "http://169.254.169.254/latest/meta-data/"

  step "VPN: https://example.com through the production exit (only when this machine is online)"
  if curl -sS --max-time 5 -o /dev/null https://example.com 2>/dev/null; then
    run "curl --proxy socks5h://127.0.0.1:$SOCKS_PROD https://example.com"
    set +e; OUT=$(socks_curl "$SOCKS_PROD" https://example.com 2>&1); RC=$?; set -e
    printf '%s\n' "$OUT" | grep -o '<title>[^<]*</title>' | show || true
    if [[ $RC -eq 0 && "$OUT" == *"Example Domain"* ]]; then ok "fetched over TLS through the attested exit (the exit saw only example.com:443 and ciphertext)"; else bad "fetch via the production exit failed (curl exit $RC)"; fi
  else
    info "offline (https://example.com unreachable directly): skipped"
  fi
fi

# =========================================================================================== two-hop (SPEC-VPN §10)
SOCKS_TWO=$((SOCKS_TEST + 2))
SOCKS_TWO_PROD=$((SOCKS_TEST + 3))
MARK2="twohop-demo-secret-$(date +%s)-$RANDOM"
ENTRY_PORT="${TWOHOP_ENTRY_URL##*:}"
twohop_verify() { env PLR_VPN_ENTRY_URL="$1" PLR_VPN_URL="$2" node "$ROOT/client/dist/cli.js" vpn verify; }

step "Two-hop: plr vpn verify — both hops attested, operator organizations from the chain, different orgs"
info "entry $TWOHOP_ENTRY_URL — run by operator2, approved as organization $PLR_VPN_ENTRY_ORG"
info "exit  $PLR_VPN_HONEST_TEST_URL — run by operator, approved as organization $PLR_VPN_ORG (test build: reaches the local destination)"
run "PLR_VPN_ENTRY_URL=\$ENTRY PLR_VPN_URL=\$EXIT plr vpn verify"
set +e; OUT=$(twohop_verify "$TWOHOP_ENTRY_URL" "$PLR_VPN_HONEST_TEST_URL" 2>&1); RC=$?; set -e
printf '%s\n' "$OUT" | show
if [[ $RC -eq 0 && "$OUT" == *"$PLR_VPN_ENTRY_ORG → $PLR_VPN_ORG"* ]]; then ok "both hops verified; organizations $PLR_VPN_ENTRY_ORG ≠ $PLR_VPN_ORG (the exit was attested through the entry, never contacted directly)"; else bad "two-hop verification failed (exit $RC)"; fi

step "Two-hop: fetch through entry ($PLR_VPN_ENTRY_ORG) → exit ($PLR_VPN_ORG) via the SOCKS5 proxy"
if start_socks twohop "$PLR_VPN_HONEST_TEST_URL" "$SOCKS_TWO" "$TWOHOP_ENTRY_URL"; then
  run "curl --proxy socks5h://127.0.0.1:$SOCKS_TWO http://$PLR_DEST_HOST:$PLR_DEST_PORT/$MARK2"
  set +e; OUT=$(socks_curl "$SOCKS_TWO" "http://$PLR_DEST_HOST:$PLR_DEST_PORT/$MARK2" 2>&1); RC=$?; set -e
  printf '%s\n' "$OUT" | show
  if [[ $RC -eq 0 && "$OUT" == "dest-ok:/$MARK2" ]]; then ok "relayed through two nested tunnels (inner one end-to-end encrypted to the exit)"; else bad "two-hop fetch failed (curl exit $RC)"; fi
fi
if expect_probe ok "$TWOHOP_ENTRY_URL" "$PLR_VPN_HONEST_TEST_URL" "$PLR_DEST_HOST" "$PLR_DEST_PORT" "/$MARK2-probe"; then ok "the exit's and the entry's session receipts both verified"; fi
if grep -qF -e "$MARK2" -e "$PLR_DEST_HOST" "$PLR_STACK_LOG_DIR/vpn-entry.log" "$PLR_STACK_LOG_DIR/vpn-honest-test.log" 2>/dev/null; then bad "a destination or payload marker appears in an honest hop's output!"; else ok "neither honest hop's output contains the destination, path or payload"; fi

step "Two-hop: the same organization on both hops is refused"
info "exit #2 $PLR_VPN2_URL (production) is run by operator2 — the entry's own organization ($PLR_VPN_ENTRY_ORG)"
run "PLR_VPN_ENTRY_URL=\$ENTRY PLR_VPN_URL=\$PLR_VPN2_URL plr vpn verify"
expect_refusal E_SAME_OPERATOR twohop_verify "$TWOHOP_ENTRY_URL" "$PLR_VPN2_URL"
if expect_probe E_SAME_OPERATOR "$TWOHOP_ENTRY_URL" "$PLR_VPN2_URL" "$PLR_DEST_HOST" "$PLR_DEST_PORT" /same-org; then ok "connect refused with E_SAME_OPERATOR before any CONNECT to a destination"; fi

if [[ -n "${PLR_VPN_EVIL_ENTRY_URL:-}" ]]; then
  step "Two-hop: even an approved entry that logs everything sees only the exit's address"
  info "⚠️ logging entry $PLR_VPN_EVIL_ENTRY_URL (vpn-evil-logger, run by operator → $PLR_VPN_ORG) prints every destination and the first bytes it relays"
  info "exit: $TWOHOP_ENTRY_URL (test build, $PLR_VPN_ENTRY_ORG). The owner approves the logging build for this step only:"
  run "owner --vpn allow_compose $PLR_VPN_EVIL_COMPOSE_HASH"
  vpn_owner allow_compose "{\"hash\":\"$PLR_VPN_EVIL_COMPOSE_HASH\"}" 2>&1 | show
  MARK3="separation-secret-$(date +%s)-$RANDOM"
  if expect_probe ok "$PLR_VPN_EVIL_ENTRY_URL" "$TWOHOP_ENTRY_URL" "$PLR_DEST_HOST" "$PLR_DEST_PORT" "/$MARK3"; then
    info "everything the logging entry printed:"
    grep "EVIL-VPN-LOGGER" "$PLR_STACK_LOG_DIR/vpn-evil-entry.log" | cut -c1-150 | show || true
    if grep -q "EVIL-VPN-LOGGER destination: .*:$ENTRY_PORT" "$PLR_STACK_LOG_DIR/vpn-evil-entry.log" 2>/dev/null; then ok "it saw the exit's address (127.0.0.1:$ENTRY_PORT) — and that is all it can know"; else bad "the logging entry did not log the exit's address (is the logger working?)"; fi
    if grep -qF -e "$MARK3" -e "$PLR_DEST_HOST" "$PLR_STACK_LOG_DIR/vpn-evil-entry.log" 2>/dev/null; then bad "the logging entry saw the destination or payload!"; else ok "no destination name, path or payload in its output: the inner tunnel is end-to-end encrypted to the exit"; fi
  fi
  run "owner --vpn revoke_compose $PLR_VPN_EVIL_COMPOSE_HASH"
  vpn_owner revoke_compose "{\"hash\":\"$PLR_VPN_EVIL_COMPOSE_HASH\"}" 2>&1 | show
fi

step "Two-hop: https://example.com through two hops (only when this machine is online)"
info "two PRODUCTION hops cannot chain on one machine: a production entry refuses to dial a loopback exit —"
run "PLR_VPN_ENTRY_URL=\$PLR_VPN2_URL PLR_VPN_URL=\$PLR_VPN_URL plr vpn verify   # both production builds"
expect_refusal E_EGRESS_DENIED twohop_verify "$PLR_VPN2_URL" "$PLR_VPN_URL"
info "(in the cloud each hop has a public address.) Locally: test-build entry ($PLR_VPN_ENTRY_ORG) → PRODUCTION exit ($PLR_VPN_ORG, public DoH)."
if curl -sS --max-time 5 -o /dev/null https://example.com 2>/dev/null; then
  if start_socks twohop-production "$PLR_VPN_URL" "$SOCKS_TWO_PROD" "$TWOHOP_ENTRY_URL"; then
    run "curl --proxy socks5h://127.0.0.1:$SOCKS_TWO_PROD https://example.com"
    set +e; OUT=$(socks_curl "$SOCKS_TWO_PROD" https://example.com 2>&1); RC=$?; set -e
    printf '%s\n' "$OUT" | grep -o '<title>[^<]*</title>' | show || true
    if [[ $RC -eq 0 && "$OUT" == *"Example Domain"* ]]; then ok "fetched over TLS through two hops: the entry saw only the exit's address, the production exit resolved example.com over DoH and saw only the entry's IP"; else bad "two-hop fetch via the production exit failed (curl exit $RC)"; fi
  fi
else
  info "offline (https://example.com unreachable directly): skipped"
fi
stop_socks

# =========================================================================================== combo (SPEC-COMBO)
# One TD (one confidential VM in the cloud) runs three processes: the LLM, the router and the VPN exit. One
# measurement covers both programs; each service has its own keys, registry and receipts.
combo_verify_router() { env PLR_ROUTER_URL="$1" node "$ROOT/client/dist/cli.js" verify; }
combo_verify_exit() { env PLR_VPN_ENTRY_URL= PLR_VPN_URL="$1" node "$ROOT/client/dist/cli.js" vpn verify; }
combo_chat() { env PLR_ROUTER_URL="$1" node "$ROOT/client/dist/cli.js" chat "$2"; }
MARK4="combo-demo-secret-$(date +%s)-$RANDOM"
COMBO_Q="Answer in five words: what is a TEE?"

step "Combo: ONE TD runs the router AND the VPN exit — one measurement, two keys, two registries"
info "combo-test TD: router $PLR_COMBO_TEST_ROUTER_URL · exit $PLR_COMBO_TEST_VPN_URL (LLM: a third process, reachable only by the router)"
info "compose (both services) $PLR_COMBO_TEST_COMPOSE_HASH, approved on the LLM registry AND on the VPN registry"
run "PLR_ROUTER_URL=\$PLR_COMBO_TEST_ROUTER_URL plr verify"
set +e; OUT_R=$(combo_verify_router "$PLR_COMBO_TEST_ROUTER_URL" 2>&1); RC_R=$?; set -e
printf '%s\n' "$OUT_R" | grep -E "VERIFIED|REFUSED|compose hash|key hash|operator" | show || true
run "PLR_VPN_URL=\$PLR_COMBO_TEST_VPN_URL plr vpn verify"
set +e; OUT_X=$(combo_verify_exit "$PLR_COMBO_TEST_VPN_URL" 2>&1); RC_X=$?; set -e
printf '%s\n' "$OUT_X" | grep -E "VERIFIED|REFUSED|build:|compose hash|key hash|operator" | show || true
if [[ $RC_R -eq 0 && $RC_X -eq 0 && "$OUT_R" == *"$PLR_COMBO_TEST_COMPOSE_HASH"* && "$OUT_X" == *"$PLR_COMBO_TEST_COMPOSE_HASH"* ]]; then
  ok "both services verified against their own registry, same combo compose"
else bad "combo verification failed (router exit $RC_R, exit exit $RC_X)"; fi
if [[ "$OUT_R" == *"$PLR_COMBO_TEST_ROUTER_KEY_HASH"* && "$OUT_X" == *"$PLR_COMBO_TEST_VPN_KEY_HASH"* && "$PLR_COMBO_TEST_ROUTER_KEY_HASH" != "$PLR_COMBO_TEST_VPN_KEY_HASH" ]]; then
  ok "distinct keys: router ${PLR_COMBO_TEST_ROUTER_KEY_HASH:0:16}… ≠ exit ${PLR_COMBO_TEST_VPN_KEY_HASH:0:16}… (each generated in its own process at boot)"
else bad "the combo services do not show their own distinct keys"; fi

step "Combo: private chat through the combo router + a tunnel through the combo exit"
run "PLR_ROUTER_URL=\$PLR_COMBO_TEST_ROUTER_URL plr chat \"$COMBO_Q\""
set +e; OUT=$(combo_chat "$PLR_COMBO_TEST_ROUTER_URL" "$COMBO_Q" 2>&1); RC=$?; set -e
printf '%s\n' "$OUT" | show
if [[ $RC -eq 0 && "$OUT" == *"compose $PLR_COMBO_TEST_COMPOSE_HASH"* ]]; then ok "answer received; the receipt names the combo compose"; else bad "chat through the combo router failed (exit $RC)"; fi
if expect_probe ok - "$PLR_COMBO_TEST_VPN_URL" "$PLR_DEST_HOST" "$PLR_DEST_PORT" "/$MARK4"; then ok "$PLR_DEST_HOST resolved over DoH inside the combo exit, fetched, session receipt verified"; fi
if grep -qF -e "$MARK4" -e "$COMBO_Q" -e "$PLR_DEST_HOST" "$PLR_STACK_LOG_DIR/combo-test.log" 2>/dev/null; then bad "a prompt, destination or payload appears in the combo TD's output!"; else ok "the combo TD's output (host + LLM + router + exit) has no prompt, destination or payload"; fi

step "Combo: approval is per registry — revoking one role leaves the other serving"
run "owner --vpn revoke_compose $PLR_COMBO_TEST_COMPOSE_HASH   # the VPN registry only"
vpn_owner revoke_compose "{\"hash\":\"$PLR_COMBO_TEST_COMPOSE_HASH\"}" 2>&1 | show
if expect_probe E_COMPOSE_NOT_ALLOWED - "$PLR_COMBO_TEST_VPN_URL" "$PLR_DEST_HOST" "$PLR_DEST_PORT" /combo-revoked; then ok "exit role refused (E_COMPOSE_NOT_ALLOWED)"; fi
run "PLR_ROUTER_URL=\$PLR_COMBO_TEST_ROUTER_URL plr chat \"Say yes.\""
if combo_chat "$PLR_COMBO_TEST_ROUTER_URL" "Say yes." 2>&1 | show; then ok "router role in the same TD still serves (the LLM registry still allows it)"; else bad "the combo router stopped serving after a VPN-registry revocation"; fi
run "owner --vpn allow_compose $PLR_COMBO_TEST_COMPOSE_HASH"
vpn_owner allow_compose "{\"hash\":\"$PLR_COMBO_TEST_COMPOSE_HASH\"}" 2>&1 | show
run "owner revoke_compose $PLR_COMBO_TEST_COMPOSE_HASH   # the LLM registry only"
owner revoke_compose "{\"hash\":\"$PLR_COMBO_TEST_COMPOSE_HASH\"}" 2>&1 | show
run "PLR_ROUTER_URL=\$PLR_COMBO_TEST_ROUTER_URL plr chat \"Say yes.\""
expect_refusal E_COMPOSE_NOT_ALLOWED combo_chat "$PLR_COMBO_TEST_ROUTER_URL" "Say yes."
if expect_probe ok - "$PLR_COMBO_TEST_VPN_URL" "$PLR_DEST_HOST" "$PLR_DEST_PORT" /combo-vpn-still-up; then ok "exit role in the same TD still serves (the VPN registry still allows it)"; fi
run "owner allow_compose $PLR_COMBO_TEST_COMPOSE_HASH"
owner allow_compose "{\"hash\":\"$PLR_COMBO_TEST_COMPOSE_HASH\"}" 2>&1 | show

step "Combo (production build): the exit cannot reach the router or the LLM"
info "production combo TD: router $PLR_COMBO_ROUTER_URL (port $PLR_COMBO_ROUTER_PORT) · exit $PLR_COMBO_VPN_URL · compose $PLR_COMBO_COMPOSE_HASH"
run "PLR_VPN_URL=\$PLR_COMBO_VPN_URL plr vpn verify"
set +e; OUT=$(combo_verify_exit "$PLR_COMBO_VPN_URL" 2>&1); RC=$?; set -e
printf '%s\n' "$OUT" | grep -E "VERIFIED|REFUSED|build:|compose hash" | show || true
if [[ $RC -eq 0 && "$OUT" == *"allow_loopback=false"* ]]; then ok "production combo exit verified: allow_loopback=false is part of the measurement"; else bad "production combo exit failed verification (exit $RC)"; fi
for H in 127.0.0.1 ::1 localhost; do
  if expect_probe E_EGRESS_DENIED - "$PLR_COMBO_VPN_URL" "$H" "$PLR_COMBO_ROUTER_PORT"; then ok "$H:$PLR_COMBO_ROUTER_PORT (the router in the same TD) refused by the exit before any connection"; fi
done
info "the LLM needs the per-boot API key that only the router process receives; separate processes, one memory-encryption domain (SPEC-COMBO §3)"

# ------------------------------------------------------------------------------------------- shutdown
printf '\n%s━━ shutdown%s\n' "$B$C" "$X"
stop_stack                       # stop file → bounded teardown; waits for the stack process
wait                             # (no other background jobs remain)
NEAR_LOG_DIR="$PLR_STACK_LOG_DIR"; NEAR_STACK_LOG="$STACK_LOG"

# =========================================================================================== PLR-CHAINS: Zcash
# A second stack (the first one is stopped: one DoH resolver per machine) on zebrad regtest. The cleanup trap
# follows the reassigned ENV_FILE / STOP_FILE / STACK_PID.
ZEBRAD_BIN="${ZEBRAD_BIN:-$(command -v zebrad || true)}"
[[ -n "$ZEBRAD_BIN" || ! -x "$HOME/.cargo/bin/zebrad" ]] || ZEBRAD_BIN="$HOME/.cargo/bin/zebrad"
ZCASH_RAN=0
DEMO_ALL_CHAINS=0; [[ "${PLR_DEMO_CHAINS:-near}" == all ]] && DEMO_ALL_CHAINS=1
if [[ $DEMO_ALL_CHAINS != 1 ]]; then
  step "Other chains (Zcash, EVM, Stellar, Solana: pre-hackathon temo code): skipped — NEAR only by default; PLR_DEMO_CHAINS=all runs them"
elif [[ -z "$ZEBRAD_BIN" || ! -x "$ZEBRAD_BIN" ]]; then
  step "Zcash (SPEC-CHAINS tier C): skipped — zebrad is not installed (cargo install zebrad)"
else
  export ZEBRAD_BIN
  ZCASH_RAN=1
  ZC_ID="$ID-zcash"
  ENV_FILE="$RUN/$ZC_ID.env"; STACK_LOG="$RUN/$ZC_ID.log"; STOP_FILE="$RUN/$ZC_ID.stop"
  step "Zcash: zebrad regtest — the registries are OP_RETURN record logs of two owner t-addresses (no contracts)"
  info "$("$ZEBRAD_BIN" --version 2>/dev/null | head -1) · owner and operator records are v5 transparent txs signed by their t-address (ZIP-244, ZIP-317)"
  : >"$STACK_LOG"
  rm -f "$STOP_FILE"
  node e2e/dist/stack-cli.js up --chain zcash --llm "$LLM" --id "$ZC_ID" \
    --env-out "$ENV_FILE" --stop-file "$STOP_FILE" --parent-pid "$$" </dev/null >"$STACK_LOG" 2>&1 &
  STACK_PID=$!
  STACK_STARTED=1
  SHOWN=0
  for _ in $(seq 1 1200); do
    TOTAL=$(wc -l <"$STACK_LOG" | tr -d ' ')
    if [[ $TOTAL -gt $SHOWN ]]; then sed -n "$((SHOWN + 1)),${TOTAL}p" "$STACK_LOG" | show; SHOWN=$TOTAL; fi
    [[ -f "$ENV_FILE" ]] && break
    grep -q "stack-cli: \(start failed\|stopped\)" "$STACK_LOG" && break
    [[ -n "$(jobs -r)" ]] || break
    sleep 0.5
  done
  if [[ ! -f "$ENV_FILE" ]]; then
    sed -n "$((SHOWN + 1)),\$p" "$STACK_LOG" | show; bad "Zcash stack failed to start (log: $STACK_LOG)"
  else
    unset PLR_NEAR_RPC
    set -a; . "$ENV_FILE"; set +a
    unset PLR_VPN_ENTRY_URL
    ok "Zcash stack ready: router $PLR_ROUTER_URL · registry $PLR_REGISTRY @ $PLR_ZCASH_RPC"

    step "Zcash: plr verify — tier C, so the client also checks the registration evidence (SPEC-CHAINS §2)"
    run "PLR_CHAIN=zcash plr verify"
    if plr verify 2>&1 | show; then ok "router verified against the Zcash record log"; else bad "honest router failed verification on Zcash"; fi

    step "Zcash: plr chat through the router registered on Zcash"
    run "plr chat \"$QUESTION\""
    if plr chat "$QUESTION" 2>&1 | show; then ok "answer received; receipt signature verified"; else bad "chat failed on Zcash"; fi

    step "Zcash: revocation is an owner record (revoke_compose OP_RETURN); re-approval is another"
    run "owner revoke_compose $PLR_COMPOSE_HASH   # signed by the owner t-address, waits until mined"
    owner revoke_compose "{\"hash\":\"$PLR_COMPOSE_HASH\"}" 2>&1 | show
    run "plr chat \"$QUESTION\""
    expect_refusal E_COMPOSE_NOT_ALLOWED node "$ROOT/client/dist/cli.js" chat "$QUESTION"
    run "owner allow_compose $PLR_COMPOSE_HASH"
    owner allow_compose "{\"hash\":\"$PLR_COMPOSE_HASH\"}" 2>&1 | show
    run "plr chat \"Say hello in three words.\""
    if plr chat "Say hello in three words." 2>&1 | show; then ok "service restored by the re-approval record"; else bad "chat failed after re-approval on Zcash"; fi
  fi
  printf '\n%s━━ Zcash shutdown%s\n' "$B$C" "$X"
  stop_stack
  wait
  ZC_LOG_DIR="${PLR_STACK_LOG_DIR:-}"
  ZC_STACK_LOG="$STACK_LOG"
fi

# =========================================================================================== PLR-CHAINS: tier B
# One short stack per installed tier-B chain (SPEC-CHAINS §9-§11: anvil, a Stellar quickstart container, a Solana
# test validator) whose contract artifact is built: verify (tier B), chat, revocation and re-approval by an owner
# transaction. A chain whose tools or artifact are missing is skipped (never a failure).
TIERB_PASSED=()
SOLANA_DIR="${SOLANA_BIN_DIR:-$HOME/.local/share/solana/install/active_release/bin}"
tierb_ready() {
  case "$1" in
    evm) [[ -f contracts/evm/out/PlrRegistry.sol/PlrRegistry.json ]] && { [[ -n "${ANVIL_BIN:-}" ]] || [[ -x "$HOME/.foundry/bin/anvil" ]] || command -v anvil >/dev/null; } ;;
    stellar) [[ -f contracts/stellar/target/wasm32v1-none/release/plr_stellar_registry.wasm ]] && { [[ -n "${STELLAR_BIN:-}" ]] || command -v stellar >/dev/null || [[ -x /opt/homebrew/bin/stellar ]]; } && docker info >/dev/null 2>&1 ;;
    solana) [[ -f contracts/solana/target/deploy/plr_registry_solana.so && -x "$SOLANA_DIR/solana-test-validator" ]] ;;
  esac
}
TIERB_CHAINS=(); [[ $DEMO_ALL_CHAINS == 1 ]] && TIERB_CHAINS=(evm stellar solana)
for TB in ${TIERB_CHAINS[@]+"${TIERB_CHAINS[@]}"}; do
  if ! tierb_ready "$TB"; then step "$TB (SPEC-CHAINS tier B): skipped — node tools or the built contract are missing (README \"Tier B\")"; continue; fi
  TB_ID="$ID-$TB"
  ENV_FILE="$RUN/$TB_ID.env"; STACK_LOG="$RUN/$TB_ID.log"; STOP_FILE="$RUN/$TB_ID.stop"
  step "$TB: a contract registry (tier B) — the chain stores the registration quote, the client verifies it"
  : >"$STACK_LOG"
  rm -f "$STOP_FILE"
  PATH="$SOLANA_DIR:$PATH" node e2e/dist/stack-cli.js up --chain "$TB" --llm "$LLM" --id "$TB_ID" \
    --env-out "$ENV_FILE" --stop-file "$STOP_FILE" --parent-pid "$$" </dev/null >"$STACK_LOG" 2>&1 &
  STACK_PID=$!
  STACK_STARTED=1
  SHOWN=0
  for _ in $(seq 1 1200); do
    TOTAL=$(wc -l <"$STACK_LOG" | tr -d ' ')
    if [[ $TOTAL -gt $SHOWN ]]; then sed -n "$((SHOWN + 1)),${TOTAL}p" "$STACK_LOG" | show; SHOWN=$TOTAL; fi
    [[ -f "$ENV_FILE" ]] && break
    grep -q "stack-cli: \(start failed\|stopped\)" "$STACK_LOG" && break
    [[ -n "$(jobs -r)" ]] || break
    sleep 0.5
  done
  if [[ ! -f "$ENV_FILE" ]]; then
    sed -n "$((SHOWN + 1)),\$p" "$STACK_LOG" | show; bad "$TB stack failed to start (log: $STACK_LOG)"
  else
    # drop the previous stack's chain settings before loading this one
    unset PLR_NEAR_RPC PLR_ZCASH_RPC PLR_ZCASH_NETWORK PLR_ZCASH_OWNER PLR_ZCASH_START_HEIGHT PLR_EVM_RPC PLR_EVM_CHAIN_ID
    unset PLR_EVM_REGISTRY PLR_EVM_VPN_REGISTRY PLR_STELLAR_RPC PLR_STELLAR_PASSPHRASE PLR_STELLAR_REGISTRY
    unset PLR_STELLAR_VPN_REGISTRY PLR_SOLANA_RPC PLR_SOLANA_PROGRAM PLR_SOLANA_REGISTRY PLR_SOLANA_VPN_REGISTRY
    set -a; . "$ENV_FILE"; set +a
    unset PLR_VPN_ENTRY_URL
    ok "$TB stack ready: router $PLR_ROUTER_URL · registry $PLR_REGISTRY"
    TB_FAIL_BEFORE=$FAILURES
    run "PLR_CHAIN=$TB plr verify"
    if plr verify 2>&1 | show; then ok "router verified against the $TB registry (tier B)"; else bad "honest router failed verification on $TB"; fi
    run "plr chat \"Say hello in three words.\""
    if plr chat "Say hello in three words." 2>&1 | show; then ok "answer received; receipt signature verified"; else bad "chat failed on $TB"; fi
    run "owner revoke_compose $PLR_COMPOSE_HASH   # an owner transaction on $TB"
    owner revoke_compose "{\"hash\":\"$PLR_COMPOSE_HASH\"}" 2>&1 | show
    expect_refusal E_COMPOSE_NOT_ALLOWED node "$ROOT/client/dist/cli.js" chat "Say hello in three words."
    run "owner allow_compose $PLR_COMPOSE_HASH"
    owner allow_compose "{\"hash\":\"$PLR_COMPOSE_HASH\"}" 2>&1 | show
    if plr chat "Say hello in three words." 2>&1 | show; then ok "service restored by the re-approval"; else bad "chat failed after re-approval on $TB"; fi
    [[ $FAILURES -eq $TB_FAIL_BEFORE ]] && TIERB_PASSED+=("$TB")
  fi
  printf '\n%s━━ %s shutdown%s\n' "$B$C" "$TB" "$X"
  stop_stack
  wait
  if [[ $FAILURES -eq 0 ]]; then rm -rf "$STACK_LOG" ${PLR_STACK_LOG_DIR:+"$PLR_STACK_LOG_DIR"}; fi
  rm -f "$ENV_FILE" "${ENV_FILE%.env}.owner.json"
done

# ------------------------------------------------------------------------------------------- summary
printf '\n'
if [[ $FAILURES -eq 0 ]]; then
  rm -rf "$NEAR_LOG_DIR" "$NEAR_STACK_LOG"   # kept only when something failed
  if [[ $ZCASH_RAN == 1 ]]; then rm -rf "$ZC_STACK_LOG" ${ZC_LOG_DIR:+"$ZC_LOG_DIR"}; fi
  printf '%s━━ DEMO PASSED: honest router served privately; evil build, MITM and revoked build were all refused before any prompt left the client.%s\n' "$B$G" "$X"
  printf '%s━━ VPN PASSED: attested exit tunnelled end-to-end with no logs; evil exit, MITM, revoked build and forbidden targets were all refused before any byte reached a destination.%s\n' "$B$G" "$X"
  printf '%s━━ DNS + TWO-HOP PASSED: names resolved only over DoH inside the exit (resolver down ⇒ E_DNS, no fallback); two hops of different organizations verified and chained, same organization refused, a logging entry saw only the exit.%s\n' "$B$G" "$X"
  printf '%s━━ COMBO PASSED: one TD served the attested router and the attested exit (same measurement, own keys, own registries); revoking one role left the other serving; the production exit could not reach the router.%s\n' "$B$G" "$X"
  if [[ ${#TIERB_PASSED[@]} -gt 0 ]]; then
    printf '%s━━ TIER B PASSED (%s): routers registered on contract registries verified (registration quote stored on-chain, checked by the client), served chats, and were refused after the owner revocation.%s\n' "$B$G" "${TIERB_PASSED[*]}" "$X"
  fi
  if [[ $ZCASH_RAN == 1 ]]; then
    printf '%s━━ ZCASH PASSED: a router registered in a Zcash OP_RETURN record log verified (tier C: registration evidence checked by the client), served a private chat, and was refused after the owner revocation record.%s\n' "$B$G" "$X"
  fi
else
  printf '%s━━ DEMO FAILED: %d check(s) failed (stack log: %s)%s\n' "$B$R" "$FAILURES" "$STACK_LOG" "$X"
  exit 1
fi
