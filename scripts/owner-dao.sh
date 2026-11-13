#!/usr/bin/env bash
# Owner actions through a Sputnik DAO council (the multi-party owner; see deploy/testnet/MULTISIG-OWNER.md).
# Same job as scripts/owner.sh, but an action only runs once enough council members approved it.
#
#   DAO_ID=<dao>.sputnikv2.testnet COUNCIL_ID=<your council account> scripts/owner-dao.sh <command>
#
#   call <method> '<json args>'       propose an owner call on the registry (prints the proposal id)
#   raw '<description>' '<kind json>' propose any other DAO proposal kind (policy change, FactoryInfoUpdate, ...)
#   approve <id>                      vote yes; the vote that reaches the threshold also executes the call
#   show [id]                         print one proposal (or the policy and the number of proposals so far)
#
# Optional: REGISTRY_ID (default: VPN_REGISTRY_ID from deploy/testnet/env.live), PROPOSAL_BOND (default
# "0.1 NEAR", must equal the DAO policy's proposal_bond; it comes back when the proposal is approved),
# NEAR_SIGN (default sign-with-legacy-keychain; e.g. sign-with-keychain or sign-with-ledger).
set -euo pipefail
cd "$(dirname "$0")/.."; . deploy/testnet/env.live
: "${DAO_ID:?set DAO_ID to the DAO account that owns the registry}"
REG=${REGISTRY_ID:-$VPN_REGISTRY_ID}
BOND=${PROPOSAL_BOND:-0.1 NEAR}
SIGN=${NEAR_SIGN:-sign-with-legacy-keychain}
INNER_GAS=30000000000000   # 30 Tgas for the registry call, the same as scripts/owner.sh

b64() { printf '%s' "$1" | base64 | tr -d '\n'; }
send() { # <method> <json args> <gas> <deposit>
  : "${COUNCIL_ID:?set COUNCIL_ID to your council member account}"
  near contract call-function as-transaction "$DAO_ID" "$1" json-args "$2" prepaid-gas "$3" attached-deposit "$4" \
    sign-as "$COUNCIL_ID" network-config testnet "$SIGN" send
}
view() { near contract call-function as-read-only "$DAO_ID" "$1" json-args "$2" network-config testnet now; }
propose() { # <description> <kind json>
  send add_proposal "{\"proposal\":{\"description\":\"$1\",\"kind\":$2}}" '100.0 Tgas' "$BOND"
}

case "${1:-}" in
  call)
    method=${2:?method}; args=${3:-"{}"}
    propose "$REG $method $(printf '%s' "$args" | tr -d '"\\' | cut -c1-120)" \
      "{\"FunctionCall\":{\"receiver_id\":\"$REG\",\"actions\":[{\"method_name\":\"$method\",\"args\":\"$(b64 "$args")\",\"deposit\":\"0\",\"gas\":\"$INNER_GAS\"}]}}"
    ;;
  raw) propose "${2:?description}" "${3:?kind json}" ;;
  approve) send act_proposal "{\"id\":${2:?proposal id},\"action\":\"VoteApprove\"}" '200.0 Tgas' '0 NEAR' ;;
  show)
    if [ -n "${2:-}" ]; then view get_proposal "{\"id\":$2}"; else view get_policy '{}'; view get_last_proposal_id '{}'; fi
    ;;
  *) sed -n '2,15p' "$0"; exit 2 ;;
esac
