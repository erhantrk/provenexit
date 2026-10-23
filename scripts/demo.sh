#!/usr/bin/env bash
# PLR-v1 end-to-end demo, one command:
#   build → near-sandbox + registry → honest router (real Qwen 0.5B via llama.cpp, launched & measured by the
#   mock TDX host) → `plr verify` + `plr chat` → evil-logger, MITM and on-chain revocation scenarios.
# Everything it starts is stopped on exit (trap), whatever happens.
#
# Env: PLR_LLM=llama|mock (default llama), PLR_SKIP_BUILD=1, NO_COLOR=1.
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
cleanup() {
  local code=$?
  trap - EXIT INT TERM
  if [[ $STACK_STARTED == 1 ]]; then
    printf '\n%s━━ cleanup%s\n' "$B$C" "$X"
    stop_stack
  fi
  rm -f "$ENV_FILE" "${ENV_FILE%.env}.owner.json"
  exit "$code"
}
trap cleanup EXIT
trap 'exit 130' INT TERM

plr() { node "$ROOT/client/dist/cli.js" "$@"; }
owner() { node "$ROOT/e2e/dist/stack-cli.js" owner "$1" "$2" --env-out "$ENV_FILE"; }
# Runs `plr` expecting a refusal with code $1; prints the output; checks the code.
expect_refusal() {
  local want=$1; shift
  local out
  set +e; out=$("$@" 2>&1); local rc=$?; set -e
  printf '%s\n' "$out" | show
  if [[ $rc -ne 0 && "$out" == *"$want"* ]]; then ok "refused with ${B}$want${X}${G} — nothing was sent"; else bad "expected refusal $want (exit $rc)"; fi
}

cat <<EOF
${B}PLR-v1 — provably-private LLM router: end-to-end demo${X}
${D}The router runs in a (mock) Intel TDX TD; its code measurement is approved in a NEAR registry contract;
the client verifies a fresh attestation against the chain before it encrypts a single prompt.
${Y}MOCK ROOT:${X}${D} attestation is signed by a local test root, not Intel — see README "What this proves".${X}
EOF

# ------------------------------------------------------------------------------------------- 1. build
step "Build (TypeScript, measured router bundles, registry wasm)"
if [[ "${PLR_SKIP_BUILD:-0}" == 1 ]]; then info "skipped (PLR_SKIP_BUILD=1)"; else scripts/build.sh 2>&1 | show; fi
node -e 'const b=require("./enclave/dist/build-info.json").variants; for (const v of ["honest","evil-logger"]) console.log(`${v.padEnd(12)} bundle ${b[v].bundle_sha256}`)' | show

# ------------------------------------------------------------------------------------------- 2. stack
LLM="${PLR_LLM:-llama}"
step "Start near-sandbox, deploy the registry, approve + launch the honest router (llm=$LLM)"
mkdir -p "$RUN"
: >"$STACK_LOG"
rm -f "$STOP_FILE"
node e2e/dist/stack-cli.js up --llm "$LLM" --id "$ID" --extra evil-logger,mitm-key \
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

# ------------------------------------------------------------------------------------------- shutdown
printf '\n%s━━ shutdown%s\n' "$B$C" "$X"
stop_stack                       # stop file → bounded teardown; waits for the stack process
wait                             # (no other background jobs remain)

# ------------------------------------------------------------------------------------------- summary
printf '\n'
if [[ $FAILURES -eq 0 ]]; then
  rm -rf "$PLR_STACK_LOG_DIR" "$STACK_LOG"   # kept only when something failed
  printf '%s━━ DEMO PASSED: honest router served privately; evil build, MITM and revoked build were all refused before any prompt left the client.%s\n' "$B$G" "$X"
else
  printf '%s━━ DEMO FAILED: %d check(s) failed (stack log: %s)%s\n' "$B$R" "$FAILURES" "$STACK_LOG" "$X"
  exit 1
fi
