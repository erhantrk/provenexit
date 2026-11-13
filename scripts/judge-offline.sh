#!/usr/bin/env bash
# Every check that needs neither the live exit nor NEAR, in one command (Node 22; `npm ci` needs the npm registry
# once). Prints one line per step and ends with "JUDGE-OFFLINE: ALL PASS"; any failure stops it with the step's name.
#   bash scripts/judge-offline.sh            # unit tests, both recorded quotes, the site
#   WITH_CONTRACT=1 bash scripts/judge-offline.sh   # also the NEAR contract tests (needs Rust)
# The live checks (npx provenexit verify) and the image rebuild (scripts/verify-exit-image.sh) are in docs/VERIFY.md.
set -euo pipefail
cd "$(dirname "$0")/.."
LOG="$(mktemp -d)"
trap 'rm -rf "$LOG"' EXIT

step() { # <name> <command...>
  local name=$1; shift
  if "$@" >"$LOG/out" 2>&1; then
    printf '  ✔ %s\n' "$name"
  else
    printf '  ✘ %s\n\n' "$name"; tail -40 "$LOG/out"; printf '\nJUDGE-OFFLINE: FAILED at "%s"\n' "$name"; exit 1
  fi
}

# The live exit's attestation, captured 2026-11-12: every check passes on the recorded collateral and registry state.
replay_live() {
  node client/dist/cli.js vpn verify --fixture fixtures/live-exit | tee "$LOG/live"
  grep -q "VERIFIED (FIXTURE REPLAY" "$LOG/live"
}
# The first real quote (a 2026-11-09 test VM, before the exit existed): Intel's signature holds, but it never bound an
# exit's keys, so the client must refuse it at exactly that check.
replay_spike() {
  set +e; node client/dist/cli.js vpn verify --fixture fixtures/phala-spike/replay >"$LOG/spike" 2>&1; local rc=$?; set -e
  cat "$LOG/spike"
  [ "$rc" -ne 0 ] && grep -q "✔ quote signature chain to root" "$LOG/spike" && grep -q "E_REPORT_DATA_KEYS" "$LOG/spike"
}

echo "ProvenExit offline checks"
step "install (npm ci)" npm ci
step "typecheck and build (tsc -b)" npx tsc -b
step "build the exit bundle" npm run build -w @plr/enclave
step "unit tests (shared, client, enclave, MCP)" npm test
step "replay the live exit's recorded attestation: VERIFIED" replay_live
step "replay the first real quote: refused at the key binding" replay_spike
step "site tests" bash -c "cd site && npm test"
if [ "${WITH_CONTRACT:-}" = 1 ]; then
  step "NEAR registry contract tests (cargo test)" bash -c "cd contracts/near && cargo test --release"
fi
echo "JUDGE-OFFLINE: ALL PASS"
