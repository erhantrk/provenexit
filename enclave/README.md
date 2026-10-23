# @plr/enclave — the router and the VPN exit "inside the TEE" + the mock TDX host

SPEC §4, §5, §6, §8, §14; SPEC-VPN §2–§6 (see *VPN exit* below). Build: `npm run build -w @plr/enclave` (tsc + `build.mjs`). Test: `npm test -w @plr/enclave`.

```
src/
  entry.ts            honest bundle entry (→ dist/router.bundle.mjs)
  main.ts             boot: read measured compose, keys in memory, quote self-check, serve, register+anchor
  router.ts           node:http API: /v1/attestation, /v1/private/chat, /v1/receipts/proof, /healthz
  keys.ts             per-boot X25519 + Ed25519 (secret halves never exposed)
  llm.ts, sse.ts      upstream LLM client — 127.0.0.1 only, always stream:true, bounded SSE parser
  validate.ts         strict envelope / plaintext / base64 / query validation
  receipts.ts         receipt log: seq from 0, leaf hashes only, anchored batches, RFC 6962 proofs
  anchor.ts           registration (rev 1.3 operator-bound registration quote) + periodic anchoring + verified resync
  near.ts             NEAR register_instance / anchor_receipts / views (near-api-js)
  compose.ts          canonical app-compose.json (build) + strict canonical parser (host, router)
  log.ts              content-free logger (only codes, numbers, hex ids, routes)
  boot.ts             boot quote self-check + process guards (router and exit)
  service-routes.ts   /v1/attestation, /v1/receipts/proof, /healthz (shared by router and exit)
  vpn/                the PLR-VPN-v1 exit (SPEC-VPN rev 2): entry, main, exit (HTTP + upgrade), tunnel (state
                      machine, handshake v2), egress (localhost rule → DoH → check every address → dial by
                      IP), doh (RFC 8484 lookup), timers (injectable deadlines), keys, receipts, config
  mock-tdx/host.ts    the mock TDX host (library API, used by the CLI and in-process by harnesses)
  mock-tdx/cli.ts     host CLI
  mock-tdx/attester.ts  SocketAttester: what the router uses to call POST /GetQuote
mock-llm/server.mjs   SPEC §14 mock LLM (zero deps; its sha256 is the mock compose's model_sha256)
evil/                 ⚠️ evil-logger demo builds (router: prompt-stealing LLM wrapper; VPN: logging-dialer.ts)
build.mjs             reproducible esbuild bundles + canonical compose files + build-info.json
```

## Build outputs (`dist/`)

| file | what |
|---|---|
| `router.bundle.mjs` | honest router bundle |
| `app-compose.mock.json`, `app-compose.llama.json` | honest compose per llm kind (`app-compose.json` = mock) |
| `evil-logger.bundle.mjs`, `app-compose.evil-logger.{mock,llama}.json` | ⚠️ evil variant |
| `vpn-exit/<variant>/vpn.bundle.mjs`, `vpn-exit/<variant>/app-compose.json` | VPN exit builds: `vpn-honest` (production), `vpn-honest-test` (`allow_loopback: true`), ⚠️ `vpn-evil-logger` |
| `build-info.json` | all bundle and compose hashes (VPN builds under the `vpn` key) |

The llama compose pins `model_sha256` to the SPEC §11 constant; the host refuses to launch if the model file differs.

## Mock TDX host

```
node dist/mock-tdx/cli.js gen-root --out .run/root.hex           # 0600 secret; prints {"root_p256": "<128 hex>"}
PLR_MOCK_ROOT_SECRET_FILE=.run/root.hex node dist/mock-tdx/cli.js measure --compose dist/app-compose.mock.json
PLR_MOCK_ROOT_SECRET_FILE=.run/root.hex \
PLR_NEAR_RPC=http://127.0.0.1:3030 PLR_REGISTRY=registry.sandbox PLR_OPERATOR_ID=operator.sandbox PLR_OPERATOR_KEY=ed25519:... \
  node dist/mock-tdx/cli.js launch --compose dist/app-compose.mock.json [--debug] [--router-port 0] [--run-dir .run]
```

`launch` options: `--bundle` (default `<compose dir>/<router.entry>`), `--llm-file` (default `mock-llm/server.mjs`
or `~/models/qwen2.5-0.5b-instruct-q4_k_m.gguf`), `--llm-port` (default: a free port), `--llama-server`
(default `/opt/homebrew/bin/llama-server`; accepted only if its runtime closure matches `llm.runtime_sha256`), `--router-port` (default 18100; `0` = ephemeral), `--state-dir`
(the run directory announced to the router as `PLR_RUN_DIR`; default `--run-dir`, which holds the socket dir).
Forwarded to the router (allowlist only): `PLR_NEAR_RPC PLR_REGISTRY PLR_OPERATOR_ID PLR_OPERATOR_KEY
PLR_REGISTER_DEPOSIT PLR_ANCHOR_DEPOSIT PLR_ANCHOR_INTERVAL_MS PLR_ROUTER_HOST`. Leave the NEAR variables unset for an
unregistered instance.

What it does: strict-parses the compose (must already be canonical), hashes the bundle and the LLM file, measures
the runtime closures of node (`router.node_sha256`) and llama-server (`llm.runtime_sha256`; see the root README,
*Runtime measurement*) and runs verified private copies of them — likewise the GGUF model: llama-server only ever
gets a 0400 private clone re-hashed against `model_sha256`, never the original path — refuses on mismatch (`plr-host: launch_refused code=E_MEASUREMENT_MISMATCH`), builds the boot event log with a
fresh instance-id, creates a per-boot AK certified by the root, serves `POST /GetQuote` on
`<run-dir>/tdx-XXXXXX/q.sock` (dir 0700, socket 0600), starts the LLM (output discarded; llama-server with
`--log-disable --no-slots --no-webui` and prompt caching off: `--no-cache-prompt --cache-reuse 0 -cram 0
--no-cache-idle-slots -np 1`; the router also sends `cache_prompt: false`; a per-boot API key in the
environment locks the LLM to the router), waits for `/health`, then runs **the measured bytes** (copied into the
private dir) with `node --permission --allow-fs-read=<private dir> --disallow-code-generation-from-strings
--no-addons` — i.e. the compose policy `disk: "none"` is enforced (no writes, no child processes). If a child
exits, the host stops everything. SIGTERM/SIGINT: clean shutdown, private dir removed — also while the launch
is still in progress (e.g. the model is loading): `launch({ signal })` aborts, tears down what it started and
rejects with `E_ABORTED`. A host crash (uncaught exception / unhandled rejection) takes the same teardown path
(bounded, 15 s) before exiting 1, and EPIPE on the host's own output is ignored, so a log reader that goes away
(`… | head`) cannot crash the TD or orphan its children.

Library API (`@plr/enclave/mock-tdx`): `measureBoot`, `launch`, `startQuoteServer`, `loadRootSecret`,
`generateRootSecret`, `freePort`, `HostError`.

### Output lines (machine-readable, content-free)

```
plr-host: measured compose_hash=<hex> os_measurement=<hex> bundle_sha256=<hex> debug=false
plr-host: llm_ready port=N
plr-router: listening url=http://127.0.0.1:N key_hash=<hex> compose_hash=<hex>
plr-router: registered key_hash=<hex>          | plr-router: registration_failed code=E_...
plr-router: registration_disabled              (no NEAR config)
plr-router: anchored anchor_id=N first_seq=N count=N | plr-router: anchor_failed code=E_... first_seq=N count=N
plr-router: request route=/v1/private/chat status=200 ms=N
```

## Router behaviour beyond the letter of the SPEC (security choices)

- A request whose `epk` was already used is refused with `400 E_DECRYPT` (a replay would otherwise make the
  router encrypt a different answer under the same single-use key and frame nonces). The bounded cache
  (1 M entries) fails closed (`503`) when full.
- Unknown fields in the envelope or in the decrypted chat request are refused (`E_BAD_REQUEST`); only `model`,
  `messages[{role,content}]`, `max_tokens`, `temperature` are forwarded (`stream` is accepted and ignored).
- Upstream failure before the first byte → `503 E_UPSTREAM`; after streaming started → encrypted `fin=1`
  `{"type":"error","code":"E_UPSTREAM"}` frame and no receipt (no seq consumed).
- At boot the router asks the host for a quote and checks that its event log measures exactly the compose
  it is about to publish; otherwise it exits (`boot_failed code=E_COMPOSE_MISMATCH`).
- Logs never contain request/response content; uncaught errors print only a code.

## Integration notes (e2e harness, SPEC §13)

- Library: `import { launch, measureBoot, generateRootSecret, loadRootSecret } from "@plr/enclave/mock-tdx"`
  (workspace-linked; add `{ "path": "../enclave" }` to the e2e tsconfig references for `tsc -b`).
- Variants → inputs: `honest` → `dist/app-compose.{mock,llama}.json`; `evil-logger` →
  `dist/app-compose.evil-logger.{mock,llama}.json`; `debug-td` → honest compose + `debug: true` (`--debug`).
  `mitm-key`/`replay-quote`/`truncate-stream`/`tamper-stream` → honest launch behind your proxy.
- `attestFor(variant, rd)`: `const b = await measureBoot({ composePath, root, debug }); const { quote, eventLog } =
  await b.attester.getQuote(rd);` with `appCompose = new TextDecoder().decode(b.composeBytes)`.
  `approveBuild`: `b.composeHash`, `b.osMeasurement` (or `cli.js measure`).
- Router URL: parse `plr-router: listening url=(\S+)`; registration: wait for `plr-router: registered` (or
  `registration_failed code=…`). Use `--router-port 0` / `routerPort: 0` to avoid fixed ports.
- ⚠️ The host's private dir `<run-dir>/tdx-XXXXXX/` contains a Unix socket. e2e test 10 walks `S.runDir` and
  `readFileSync`s every file, which throws on a socket — give the host a run dir **outside** `S.runDir`
  (e.g. `<ROOT>/.run/<id>-host/`). Keep it short: macOS limits socket paths to 104 bytes (`E_SOCKET_PATH`).
- Inside agent Bash sandboxes Unix sockets are refused (EPERM): run host-based tests via `$CONDUCTOR_BIN spawn`.
  `test/host.test.ts` skips its live-launch block (with a warning) when sockets are not permitted.
- Opt-in chain test: `PLR_NEAR_IT=1 npx vitest run test/near.integration.test.ts` (near-sandbox + the built
  contract wasm): registers, anchors, verifies a served proof against `get_anchor`.

## VPN exit (PLR-VPN-v1 rev 2, SPEC-VPN §2–§6)

A second enclave service with **no LLM**: a `plr-vpn` compose (exact SPEC-VPN §2 schema; the compose `name` is the
service discriminator, `composeService()` / `composeServiceOf()`; `parseVpnCompose` is strict and canonical, the
router's `parseCompose` is unchanged and refuses VPN composes and vice versa). `vpn.entry` is always
`vpn.bundle.mjs`, so each build lives in its own directory:

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
compose_hash } } }` (paths relative to `dist/`; the router keys `llm`, `runtime`, `variants` are unchanged).

```
PLR_MOCK_ROOT_SECRET_FILE=.run/root.hex node dist/mock-tdx/cli.js measure --compose dist/vpn-exit/vpn-honest/app-compose.json
PLR_MOCK_ROOT_SECRET_FILE=.run/root.hex PLR_NEAR_RPC=… PLR_VPN_REGISTRY=vpnregistry.… PLR_OPERATOR_ID=… PLR_OPERATOR_KEY=… \
  node dist/mock-tdx/cli.js launch --compose dist/vpn-exit/vpn-honest/app-compose.json [--exit-port 0] [--run-dir .run] [--debug]
```

Host: measures the compose, the exit bundle and the node runtime closure (`vpn.node_sha256`), refuses on mismatch,
serves quotes on the 0600 socket, and runs the measured bytes on the verified node copy with **the router's
isolation flags** (`--permission --allow-fs-read=<private dir> --disallow-code-generation-from-strings
--no-addons`: read-only fs, no child processes/workers/addons/eval; network allowed). LLM options are a usage
error for a VPN compose; `--state-dir` is accepted and ignored; `--router-port` is an alias of `--exit-port`
(default `PLR_VPN_PORT`, else 18200). Forwarded env (allowlist `EXIT_ENV_ALLOWLIST`): `PLR_NEAR_RPC PLR_REGISTRY
PLR_VPN_REGISTRY PLR_OPERATOR_ID PLR_OPERATOR_KEY PLR_REGISTER_DEPOSIT PLR_ANCHOR_DEPOSIT PLR_ANCHOR_INTERVAL_MS
PLR_VPN_HOST PLR_VPN_PORT`. The exit registers on `PLR_VPN_REGISTRY` if set, else `PLR_REGISTRY`.
Library: `measureVpnBoot` (same fields as `measureBoot`: `composeHash`, `osMeasurement`, `attester`,
`composeBytes`), `launchVpn` (`exitPort`, `exitEnv`, `output`, `signal`), `composeServiceOf`.

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
- Quote purposes (SPEC §5 rev 1.3, router and exit alike): `/v1/attestation` only ever quotes the **session**
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

## Combo: LLM router + VPN exit in one TD (SPEC-COMBO)

A `plr-combo` compose (`compose.ts`: `makeComboCompose` / `parseComboCompose`, exact SPEC-COMBO §1 schema; the
`router` half is validated with the router rules, the `vpn` half with the VPN rules, `router.node_sha256 ==
vpn.node_sha256`, canonical bytes required). The router bundle reads its half via `routerLlmKindOf`, the exit via
`vpnPolicyOf` (both strict; they also accept their own single-service compose). Both `/v1/attestation` bundles carry
the same combo `app_compose`.

Builds: `dist/combo/<variant>/<kind>/{app-compose.json,router.bundle.mjs,vpn.bundle.mjs}` for `combo` (production
VPN policy + DoH list) and `combo-test` (`allow_loopback: true`, DoH `http://127.0.0.1:18253/dns-query`), kinds
`mock` | `llama` (the honest bundle bytes). `build-info.json` → `"combo": { "<variant>": { allow_loopback, doh,
router_bundle_sha256, vpn_bundle_sha256, compose: { mock|llama: { dir, file, compose_hash } } } }` (other keys
unchanged).

```
PLR_MOCK_ROOT_SECRET_FILE=.run/root.hex node dist/mock-tdx/cli.js measure --compose dist/combo/combo-test/mock/app-compose.json
PLR_MOCK_ROOT_SECRET_FILE=.run/root.hex PLR_NEAR_RPC=… PLR_REGISTRY=registry.… PLR_VPN_REGISTRY=vpnregistry.… \
PLR_OPERATOR_ID=… PLR_OPERATOR_KEY=… \
  node dist/mock-tdx/cli.js launch --compose dist/combo/combo-test/mock/app-compose.json [--router-port 0] [--exit-port 0] \
       [--llm-port N] [--llm-file F] [--llama-server B] [--run-dir .run] [--state-dir D] [--debug]
```

Host (`measureComboBoot` / `launchCombo`): measures the router bundle, the exit bundle, the model / mock LLM and the
node (+ llama-server) runtime closures, refuses on any mismatch (`launch_refused code=E_MEASUREMENT_MISMATCH`, nothing
started), extends RTMR3 **once** (one boot event log, one quote socket for both services), then runs three
processes: the LLM (per-boot API key, output discarded), the router and the exit, each from its **own** private
directory (`tdx-*/router`, `tdx-*/vpn`, `tdx-*/llm`; `--allow-fs-read` names only that directory) with the usual
isolation flags. Environments come from separate allowlists (`comboProcessEnvs`): the router gets
`PLR_LLM_PORT` + `PLR_LLM_API_KEY` + `ROUTER_ENV_ALLOWLIST` (`PLR_REGISTRY` = LLM registry); the exit gets
`COMBO_EXIT_ENV_ALLOWLIST` (`PLR_VPN_REGISTRY`, no `PLR_REGISTRY` fallback, **no** LLM port or key). `--bundle` is a
usage error (both bundles are read from the compose's directory). If any of the three exits, the host stops the
others (exit 1); SIGTERM/SIGINT stop all three and remove the private dir. Each service generates its own keys,
registers on its own registry (operator-bound, rev 1.3) and anchors its own receipts.

```
plr-host: measured compose_hash=<hex> os_measurement=<hex> router_bundle_sha256=<hex> vpn_bundle_sha256=<hex> debug=false
plr-host: runtimes_verified node_sha256=<hex> llm_runtime_sha256=<hex>
plr-host: llm_ready port=N
plr-host: router_started pid=N
plr-host: exit_started pid=N
plr-router: listening url=http://127.0.0.1:N key_hash=<hex> compose_hash=<combo hex>
plr-vpn: listening url=http://127.0.0.1:N key_hash=<hex> compose_hash=<combo hex>
```
