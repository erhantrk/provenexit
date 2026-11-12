# @plr/enclave — the VPN exit "inside the TEE" + the mock TDX host

SPEC §4, §5, §6, §8; SPEC-VPN §2–§6; SPEC-TDX §4 (dstack mode). Build: `npm run build -w @plr/enclave` (tsc +
`build.mjs`). Test: `npm test -w @plr/enclave`.

```
src/
  vpn/                the PLR-VPN-v1 exit (SPEC-VPN rev 2): entry, main, exit (HTTP + upgrade), tunnel (state
                      machine, handshake v2), egress (localhost rule → DoH → check every address → dial by
                      IP), doh (RFC 8484 lookup), timers (injectable deadlines), keys, receipts, config
  keys.ts             per-boot X25519 + Ed25519 (secret halves never exposed)
  receipts.ts         receipt log: seq from 0, leaf hashes only, anchored batches, RFC 6962 proofs
  anchor.ts           registration (rev 1.3 operator-bound registration quote) + periodic anchoring + verified resync
  near.ts             NEAR register_instance(_tdx) / anchor_receipts / views (near-api-js)
  registry-writer.ts  the registry operations the anchorer needs (faked in unit tests)
  config.ts           registry selection (PLR_CHAIN: near only) and the NEAR settings
  compose.ts          canonical `plr-vpn` app-compose.json (build) + strict canonical parser (host, exit)
  log.ts              content-free logger (only codes, numbers, hex ids, URLs of loopback listeners)
  boot.ts             boot quote self-check + process guards
  service-routes.ts   /v1/attestation, /v1/receipts/proof, /healthz
  validate.ts, http-util.ts   strict query parsing, content-free JSON responses
  attest/             dstack mode (PLR_ATTESTER=dstack): DstackAttester (guest-agent quotes) + Intel collateral cache
  mock-tdx/host.ts    the mock TDX host (library API, used by the CLI and in-process by harnesses)
  mock-tdx/cli.ts     host CLI
  mock-tdx/runtime.ts runtime closure measurement of node (Mach-O)
  mock-tdx/attester.ts  SocketAttester: what the exit uses to call POST /GetQuote in MOCK mode
evil/                 ⚠️ the evil-logger exit build (logging-dialer.ts)
build.mjs             reproducible esbuild bundles + canonical compose files + build-info.json
```

The LLM router, the mock LLM, the llama.cpp builds and the "combo" build that this package also held before
2026-11-12 are in the baseline commits (root README, "Prior code").

## Build outputs (`dist/`)

| file | what |
|---|---|
| `vpn-exit/<variant>/vpn.bundle.mjs`, `vpn-exit/<variant>/app-compose.json` | VPN exit builds: `vpn-honest` (production), `vpn-honest-test` (`allow_loopback: true`), ⚠️ `vpn-evil-logger` |
| `build-info.json` | `runtime.node_sha256` and every bundle and compose hash (under the `vpn` key) |

The build measures only node (the runtime that runs the exit); it needs no llama.cpp.

## Mock TDX host

```
node dist/mock-tdx/cli.js gen-root --out .run/root.hex           # 0600 secret; prints {"root_p256": "<128 hex>"}
PLR_MOCK_ROOT_SECRET_FILE=.run/root.hex node dist/mock-tdx/cli.js measure --compose dist/vpn-exit/vpn-honest/app-compose.json
PLR_MOCK_ROOT_SECRET_FILE=.run/root.hex PLR_NEAR_RPC=… PLR_VPN_REGISTRY=vpnregistry.… PLR_OPERATOR_ID=… PLR_OPERATOR_KEY=… \
  node dist/mock-tdx/cli.js launch --compose dist/vpn-exit/vpn-honest/app-compose.json [--exit-port 0] [--run-dir .run] [--debug]
```

`launch` options: `--bundle` (default `<compose dir>/vpn.bundle.mjs`), `--exit-port` (default `PLR_VPN_PORT`, else
18200; `0` = ephemeral), `--run-dir` (holds the private socket dir), `--debug` (TD DEBUG attribute). Any other option
is a usage error. Leave the NEAR variables unset for an unregistered instance.

What it does: strict-parses the compose (must already be canonical), hashes the exit bundle, measures the runtime
closure of node (`vpn.node_sha256`) and runs a verified private copy of it, refuses on mismatch
(`plr-host: launch_refused code=E_MEASUREMENT_MISMATCH`, nothing started), builds the boot event log with a fresh
instance-id, creates a per-boot AK certified by the root, serves `POST /GetQuote` on
`<run-dir>/tdx-XXXXXX/q.sock` (dir 0700, socket 0600), then runs **the measured bytes** (copied into the private
dir) with `node --permission --allow-fs-read=<private dir> --disallow-code-generation-from-strings --no-addons` —
i.e. the compose policy `disk: "none"` is enforced (no writes, no child processes; network allowed). If the exit
process exits, the host stops. SIGTERM/SIGINT: clean shutdown, private dir removed — also while the launch is still
in progress: `launchVpn({ signal })` aborts, tears down what it started and rejects with `E_ABORTED`. A host crash
(uncaught exception / unhandled rejection) takes the same teardown path (bounded, 15 s) before exiting 1, and EPIPE
on the host's own output is ignored, so a log reader that goes away (`… | head`) cannot crash the TD or orphan its
children.

Library API (`@plr/enclave/mock-tdx`): `measureVpnBoot`, `launchVpn`, `startQuoteServer`, `loadRootSecret`,
`generateRootSecret`, `freePort`, `exitNodeFlags`, `EXIT_ENV_ALLOWLIST`, `HostError`.

## Integration notes (e2e harness, SPEC-VPN §9.3)

- Library: `import { launchVpn, measureVpnBoot, generateRootSecret, loadRootSecret } from "@plr/enclave/mock-tdx"`
  (workspace-linked; add `{ "path": "../enclave" }` to the e2e tsconfig references for `tsc -b`).
- `attestFor(build, rd)`: `const b = await measureVpnBoot({ composePath, root, debug }); const { quote, eventLog } =
  await b.attester.getQuote(rd);` with `appCompose = new TextDecoder().decode(b.composeBytes)`.
  `approveVpnBuild`: `b.composeHash`, `b.osMeasurement` (or `cli.js measure`).
- Exit URL: parse `plr-vpn: listening url=(\S+)`; registration: wait for `plr-vpn: registered` (or
  `registration_failed code=…`). Use `--exit-port 0` / `exitPort: 0` to avoid fixed ports.
- ⚠️ The host's private dir `<run-dir>/tdx-XXXXXX/` contains a Unix socket. The e2e no-retention test walks
  `S.runDir` and `readFileSync`s every file, which throws on a socket — give the host a run dir **outside**
  `S.runDir` (e.g. `<ROOT>/.run/<id>-host/`). Keep it short: macOS limits socket paths to 104 bytes
  (`E_SOCKET_PATH`); the e2e harness (`hostDirFor`) moves it to a short `plr-<hash>` directory when the run root is
  too long.
- Inside agent Bash sandboxes Unix sockets are refused (EPERM): run host-based tests via `$CONDUCTOR_BIN spawn`.
  `test/host.test.ts` skips its live-launch block (with a warning) when sockets are not permitted.
- Opt-in chain test: `PLR_NEAR_IT=1 npx vitest run test/near.integration.test.ts` (near-sandbox + the built
  contract wasm): the exit registers, anchors a session receipt, and the served proof verifies against `get_anchor`.

## VPN exit (PLR-VPN-v1 rev 2, SPEC-VPN §2–§6)

A `plr-vpn` compose (exact SPEC-VPN §2 schema; `parseVpnCompose` is strict and canonical and refuses any other
document). `vpn.entry` is always `vpn.bundle.mjs`, so each build lives in its own directory:

| variant | files | policy.egress | policy.dns.doh |
|---|---|---|---|
| `vpn-honest` | `dist/vpn-exit/vpn-honest/{app-compose.json,vpn.bundle.mjs}` | `allow_loopback: false` (production) | `https://1.1.1.1/dns-query`, `https://9.9.9.9/dns-query` |
| `vpn-honest-test` | `dist/vpn-exit/vpn-honest-test/…` (same bundle bytes) | `allow_loopback: true` (local tests; different compose hash) | `http://127.0.0.1:18253/dns-query` |
| `vpn-evil-logger` | `dist/vpn-exit/vpn-evil-logger/…` ⚠️ | `allow_loopback: true` | `http://127.0.0.1:18253/dns-query` |

`policy.dns.doh` validation (`dohUrlProblem`): 1–4 unique URLs, each in WHATWG-normalised form (the measured
string is exactly what is fetched), host an IP literal (no bootstrap DNS; `01.1.1.1` / integer / mapped spellings
are refused), no credentials/query/fragment, `https:` to an address the build's egress policy allows (never a
private / link-local / metadata resolver), and plain `http:` only as `http://127.0.0.1:<port>/…` on
`allow_loopback` builds. Resolver order is measured.

`build-info.json` → `"vpn": { "<variant>": { dir, bundle, bundle_sha256, allow_loopback, doh, compose: { file,
compose_hash } } }` (paths relative to `dist/`) and `"runtime": { node_sha256 }`.

```
PLR_MOCK_ROOT_SECRET_FILE=.run/root.hex node dist/mock-tdx/cli.js measure --compose dist/vpn-exit/vpn-honest/app-compose.json
PLR_MOCK_ROOT_SECRET_FILE=.run/root.hex PLR_NEAR_RPC=… PLR_VPN_REGISTRY=vpnregistry.… PLR_OPERATOR_ID=… PLR_OPERATOR_KEY=… \
  node dist/mock-tdx/cli.js launch --compose dist/vpn-exit/vpn-honest/app-compose.json [--exit-port 0] [--run-dir .run] [--debug]
```

Host: measures the compose, the exit bundle and the node runtime closure (`vpn.node_sha256`), refuses on mismatch,
serves quotes on the 0600 socket, and runs the measured bytes on the verified node copy with `exitNodeFlags`
(`--permission --allow-fs-read=<private dir> --disallow-code-generation-from-strings --no-addons`: read-only fs, no
child processes/workers/addons/eval; network allowed). `--exit-port` defaults to `PLR_VPN_PORT`, else 18200.
Forwarded env (allowlist `EXIT_ENV_ALLOWLIST`): `PLR_NEAR_RPC PLR_REGISTRY PLR_VPN_REGISTRY PLR_OPERATOR_ID
PLR_OPERATOR_KEY PLR_REGISTER_DEPOSIT PLR_ANCHOR_DEPOSIT PLR_ANCHOR_INTERVAL_MS PLR_VPN_HOST PLR_VPN_PORT PLR_CHAIN`.
The exit registers on `PLR_VPN_REGISTRY` if set, else `PLR_REGISTRY`; `PLR_CHAIN` may only be `near` (any other
value disables registration). `PLR_VPN_ALLOWED_PORTS` / `PLR_VPN_MAX_TUNNELS` are read by the exit in dstack mode
(they are set in the measured `deploy/phala/docker-compose.yml`); the mock host does not forward them.
Library: `measureVpnBoot` (`composeHash`, `osMeasurement`, `attester`, `composeBytes`, `bundleBytes`, `nodeRuntime`),
`launchVpn` (`exitPort`, `exitEnv`, `output`, `signal`).

Output lines (the exit prints **nothing per connection**):
```
plr-host: measured compose_hash=<hex> os_measurement=<hex> bundle_sha256=<hex> debug=false
plr-host: runtimes_verified node_sha256=<hex>
plr-host: exit_started pid=N
plr-vpn: listening url=http://127.0.0.1:N key_hash=<hex> compose_hash=<hex>
plr-vpn: registered key_hash=<hex>   | plr-vpn: registration_failed code=E_…  | plr-vpn: registration_disabled
plr-vpn: registration_failed code=E_OPERATOR_MISMATCH   (the record names another operator — impossible on a rev 1.3 registry; the exit stops, exit 1)
plr-vpn: anchored anchor_id=N first_seq=N count=N   | plr-vpn: anchor_failed code=E_… first_seq=N count=N
```

Exit behaviour (`src/vpn/`):
- API: `GET /v1/attestation` (SPEC §6.2 bundle, `app_compose` = the VPN compose), `GET /v1/tunnel` with
  `Connection: Upgrade` + `Upgrade: plr-vpn/1` → `101` (any other request there → `400 {"error":"E_BAD_REQUEST"}`),
  `GET /v1/receipts/proof?seq=`, `GET /healthz`. At most 1024 concurrent tunnels (then `503`).
- Quote purposes (SPEC §5 rev 1.3): `/v1/attestation` only ever quotes the **session**
  report_data `key_hash ‖ SHA256("PLR-v1/session-nonce" ‖ nonce)` for any well-formed nonce; the anchorer alone asks
  for the **registration** report_data `key_hash ‖ registration_nonce(PLR_VPN_REGISTRY|PLR_REGISTRY, PLR_OPERATOR_ID)`
  (`SHA256("PLR-v1/register/2" ‖ u8(len c) ‖ c ‖ u8(len o) ‖ o)`), which the contract checks against
  `current_account_id` + `predecessor_account_id`. No session quote can serve as a registration (that would need a
  SHA-256 preimage) and nobody but `PLR_OPERATOR_ID` can submit ours, so the interim refusal of registration-nonce
  values on `/v1/attestation` is gone. Defense in depth kept: after every registration the exit reads
  `get_instance(key).operator` back; if it is not `PLR_OPERATOR_ID`, the exit stops serving and exits 1.
- Handshake v2 (§4.1): on a valid 65-byte hello (version 2) the exit immediately sends `server_hello =
  u8(2) ‖ epk_s` with a fresh ephemeral key per tunnel (`VpnKeys.tunnelAccept` → shared `tunnelServerAccept`, which
  zeroes the ephemeral secret and the DH outputs once the keys are derived). A replayed hello meets a new `epk_s`,
  so every replayed frame fails authentication and nothing is dialled; later compromise of `xs` does not reveal past
  tunnels. A wrong version (incl. the removed v1) or a low-order `epk_c` ⇒ close with nothing sent. No hello state
  is kept (the interim nonce/hello replay guard of rev 1 is gone; `/v1/attestation` serves any well-formed nonce).
- Tunnel (§4.3): hello ≤ 10 s, then CONNECT as c2s frame 0 ≤ 10 s, resolve + dial ≤ 10 s, idle 300 s; any
  protocol/auth error, client EOF before its FIN, or upstream error ⇒ immediate close without FIN/RECEIPT, and
  the upstream connection is aborted with a TCP **RST** (only an authenticated c2s FIN frame becomes a FIN at the
  destination, so a cut/tampered c2s stream is never committed as complete). Frames
  pipelined after CONNECT are queued (≤ 256 KiB) with the socket paused. Backpressure both ways. RECEIPT is sent
  once both FINs are exchanged **and** every relayed c2s byte has been flushed upstream.
- Egress (§6): `validateDestination` → `localhost` / `*.localhost` (RFC 6761) refused `E_EGRESS_DENIED` before any
  resolution, on every policy → DoH lookup (IP literals are not resolved) → `egressAllowed` on
  **every** address — if any is denied the destination is `E_EGRESS_DENIED` (fail closed against mixed answers)
  → also refuse "public" addresses that reach the host itself: Azure WireServer `168.63.129.16` and every address
  of the exit's own interfaces (`os.networkInterfaces()`, per dial; listing failure ⇒ deny), compared in
  canonical form (`egressIdentity`: IPv4-mapped / NAT64 / 6to4 spellings included)
  → dial the first address (IPv4 preferred) **by IP literal** with a lookup function that refuses everything.
  The egress policy is read from the measured compose bytes, never from configuration.
- DNS (§6.1, `doh.ts`): names are resolved **only** by RFC 8484 POSTs (`content-type`/`accept:
  application/dns-message`, A and AAAA in parallel, exact `encodeDnsQuery` bytes with EDNS0 padding) to the
  compose's `policy.dns.doh` resolvers, in order, 5 s per resolver, under the tunnel's dial deadline; responses
  must be `200` + `application/dns-message`, ≤ 65 535 bytes (read incrementally), parsed by `parseDnsResponse`.
  A transport/HTTP/parse failure ⇒ next resolver; NXDOMAIN / no address for both types is an answer ⇒ `E_DNS`;
  all resolvers failing ⇒ `E_DNS`. There is **no fallback**: `egress.ts` has no system-resolver path, `bootExit`
  hands the exit only the DoH lookup built from the measured compose, resolver hosts are IP literals (fetch does
  no lookup) and `net.connect` gets a lookup that refuses. Query/response buffers are zeroed after use; errors are
  the content-free `E_DNS`.
- Deadlines (`timers.ts`): every tunnel timer (hello, CONNECT, idle, linger) comes from an injectable `Timers`
  (Node timers in production); the unit tests drive a manual clock, so no test depends on wall-clock timing.
- Receipts: SPEC-VPN §5 (no destination/port/bytes), `ts_close_ms` clamped ≥ `ts_open_ms`; anchored by the shared
  `Anchorer` (generic over receipt kind: `LeafLog` + `EnclaveKeys`).
- ⚠️ `vpn-evil-logger` = honest source + `evil/logging-dialer.ts` (prints `EVIL-VPN-LOGGER destination: host:port`
  and the first 256 bytes of each direction to stdout). Nothing in `src/` imports it (`test/vpn-host.test.ts`).
