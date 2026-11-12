#!/usr/bin/env bash
# Try the live ProvenExit exit (Intel TDX on Phala Cloud, registered on NEAR testnet). Needs: Node 22, `npm ci && npx tsc -b`.
# 1) verifies the exit (every check printed), 2) starts the local SOCKS5 proxy on 127.0.0.1 only, 3) sends one request
# direct and one through the exit and prints both IPs, 4) stops. Changes no system settings, needs no sudo, writes nothing
# outside a temp file. Run in a terminal it keeps the proxy up for a browser until Ctrl-C (TRY_LIVE_KEEP=0: never;
# TRY_LIVE_KEEP=1: always); run by a script or an AI agent (stdin not a terminal) it stops by itself.
set -euo pipefail
cd "$(dirname "$0")/.."
. deploy/testnet/env.live
CLI="node client/dist/cli.js"
[ -f client/dist/cli.js ] || { echo "run first: npm ci && npx tsc -b"; exit 1; }
PORT="${PLR_VPN_SOCKS_PORT:-18180}"
export PLR_VPN_SOCKS_PORT="$PORT"

echo "== 1. verify the exit before any byte leaves"
$CLI vpn verify

echo; echo "== 2. local SOCKS5 proxy on socks5h://127.0.0.1:$PORT"
LOG="$(mktemp -t plr-vpn.XXXXXX)"
$CLI vpn >"$LOG" 2>&1 &
PID=$!
trap 'kill $PID 2>/dev/null || true; rm -f "$LOG"' EXIT
for _ in $(seq 1 60); do grep -q "SOCKS5 proxy on" "$LOG" && break; kill -0 $PID 2>/dev/null || { cat "$LOG"; exit 1; }; sleep 0.5; done
grep -q "SOCKS5 proxy on" "$LOG" || { cat "$LOG"; echo "proxy did not start"; exit 1; }

echo; echo "== 3. one request direct, one through the exit"
echo "your IP:              $(curl -s -m 15 https://ipinfo.io/ip || echo '?')"
echo "IP through the exit:  $(curl -s -m 30 --proxy "socks5h://127.0.0.1:$PORT" https://ipinfo.io/ip)"
echo "  (ipinfo.io sees the Phala machine, not you; only ports 80 and 443 are allowed)"

KEEP="${TRY_LIVE_KEEP:-auto}"
if [ "$KEEP" = "auto" ]; then [ -t 0 ] && KEEP=1 || KEEP=0; fi
[ "$KEEP" = "1" ] || { echo; echo "done (proxy stopped)"; exit 0; }
echo; echo "Proxy stays up: Firefox → Settings → Network → Manual proxy → SOCKS v5 127.0.0.1:$PORT, tick \"Proxy DNS when using SOCKS v5\"."
echo "Ctrl-C to stop."
wait $PID
