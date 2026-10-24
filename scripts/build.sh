#!/usr/bin/env bash
# Builds everything the stack needs: TypeScript (shared, enclave, client, e2e), the measured router bundles +
# compose files, and the NEAR registry wasm (+ the tier-B registry of PLR_CHAIN / PLR_BUILD_CHAINS). Offline-safe.
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
# Tier-B registries (SPEC-CHAINS §9-§11): built when PLR_CHAIN selects one, or listed in PLR_BUILD_CHAINS (comma list).
WANT=",${PLR_BUILD_CHAINS:-},${PLR_CHAIN:-},"
if [[ "$WANT" == *,evm,* ]]; then
  echo "• contracts/evm: forge build"
  (cd contracts/evm && forge build --offline >/dev/null) || { echo "forge build failed (cd contracts/evm && forge build)" >&2; exit 1; }
fi
if [[ "$WANT" == *,stellar,* ]]; then
  echo "• contracts/stellar: stellar contract build"
  (cd contracts/stellar && CARGO_NET_OFFLINE=true stellar contract build >/dev/null 2>&1) || { echo "stellar contract build failed (cd contracts/stellar && stellar contract build)" >&2; exit 1; }
fi
if [[ "$WANT" == *,solana,* ]]; then
  echo "• contracts/solana: cargo-build-sbf"
  SOLANA_BIN="${SOLANA_BIN_DIR:-$HOME/.local/share/solana/install/active_release/bin}"
  (cd contracts/solana && PATH="$SOLANA_BIN:$PATH" CARGO_NET_OFFLINE=true cargo-build-sbf >/dev/null 2>&1) || { echo "cargo-build-sbf failed (cd contracts/solana && cargo-build-sbf)" >&2; exit 1; }
fi
echo "• build OK"
