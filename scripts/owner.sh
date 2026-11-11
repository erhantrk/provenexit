#!/usr/bin/env bash
# usage: scripts/owner.sh <method> '<json args>'   (reads deploy/testnet/env.live; signs with OWNER_ID from the near-cli-rs keychain)
set -euo pipefail
cd "$(dirname "$0")/.."; . deploy/testnet/env.live
near contract call-function as-transaction "$VPN_REGISTRY_ID" "$1" json-args "${2:-"{}"}" \
  prepaid-gas '30.0 Tgas' attached-deposit '0 NEAR' sign-as "$OWNER_ID" network-config testnet sign-with-keychain send
