#!/usr/bin/env bash
# Builds everything the stack needs: TypeScript (shared, enclave, client, e2e), the measured router bundles +
# compose files, and the NEAR registry wasm. Offline-safe (CARGO_NET_OFFLINE=true).
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
echo "• tsc -b"
npx tsc -b
echo "• enclave: reproducible router bundles + app-compose files"
npm run --silent build -w @plr/enclave
echo "• contracts/near: registry wasm"
(cd contracts/near && CARGO_NET_OFFLINE=true cargo near build non-reproducible-wasm --no-abi </dev/null >/dev/null 2>&1) || {
  echo "cargo near build failed; re-run for details: cd contracts/near && CARGO_NET_OFFLINE=true cargo near build non-reproducible-wasm --no-abi" >&2
  exit 1
}
echo "• build OK"
