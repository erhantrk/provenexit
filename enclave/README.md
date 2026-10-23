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
  anchor.ts           registration (registration-nonce quote) + periodic anchoring + verified resync
  near.ts             NEAR register_instance / anchor_receipts / views (near-api-js)
  compose.ts          canonical app-compose.json (build) + strict canonical parser (host, router)
  log.ts              content-free logger (only codes, numbers, hex ids, routes)
  boot.ts             boot quote self-check + process guards (router and exit)
  service-routes.ts   /v1/attestation, /v1/receipts/proof, /healthz (shared by router and exit)
  vpn/                the PLR-VPN-v1 exit (SPEC-VPN): entry, main, exit (HTTP + upgrade), tunnel (state
                      machine), egress (resolve → check every address → dial by IP), replay (hello
                      anti-replay), keys, receipts, config
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
*Runtime measurement*) and runs verified private copies of them, refuses on mismatch (`plr-host: launch_refused code=E_MEASUREMENT_MISMATCH`), builds the boot event log with a
fresh instance-id, creates a per-boot AK certified by the root, serves `POST /GetQuote` on
`<run-dir>/tdx-XXXXXX/q.sock` (dir 0700, socket 0600), starts the LLM (output discarded; llama-server with
`--log-disable --no-slots --no-webui` and prompt caching off: `--no-cache-prompt --cache-reuse 0 -cram 0
--no-cache-idle-slots -np 1`; the router also sends `cache_prompt: false`; a per-boot API key in the
environment locks the LLM to the router), waits for `/health`, then runs **the measured bytes** (copied into the
private dir) with `node --permission --allow-fs-read=<private dir> --disallow-code-generation-from-strings
--no-addons` — i.e. the compose policy `disk: "none"` is enforced (no writes, no child processes). If a child
exits, the host stops everything. SIGTERM/SIGINT: clean shutdown, private dir removed — also while the launch
is still in progress (e.g. the model is loading): `launch({ signal })` aborts, tears down what it started and
rejects with `E_ABORTED`.

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

## VPN exit (PLR-VPN-v1, SPEC-VPN §2–§6)

A second enclave service with **no LLM**: a `plr-vpn` compose (exact SPEC-VPN §2 schema; the compose `name` is the
service discriminator, `composeService()` / `composeServiceOf()`; `parseVpnCompose` is strict and canonical, the
router's `parseCompose` is unchanged and refuses VPN composes and vice versa). `vpn.entry` is always
`vpn.bundle.mjs`, so each build lives in its own directory:

| variant | files | policy.egress |
|---|---|---|
| `vpn-honest` | `dist/vpn-exit/vpn-honest/{app-compose.json,vpn.bundle.mjs}` | `allow_loopback: false` (production) |
| `vpn-honest-test` | `dist/vpn-exit/vpn-honest-test/…` (same bundle bytes) | `allow_loopback: true` (local tests; different compose hash) |
| `vpn-evil-logger` | `dist/vpn-exit/vpn-evil-logger/…` ⚠️ | `allow_loopback: true` |

`build-info.json` → `"vpn": { "<variant>": { dir, bundle, bundle_sha256, allow_loopback, compose: { file,
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
plr-vpn: anchored anchor_id=N first_seq=N count=N   | plr-vpn: anchor_failed code=E_… first_seq=N count=N
```

Exit behaviour (`src/vpn/`):
- API: `GET /v1/attestation` (SPEC §6.2 bundle, `app_compose` = the VPN compose), `GET /v1/tunnel` with
  `Connection: Upgrade` + `Upgrade: plr-vpn/1` → `101` (any other request there → `400 {"error":"E_BAD_REQUEST"}`),
  `GET /v1/receipts/proof?seq=`, `GET /healthz`. At most 1024 concurrent tunnels (then `503`).
- Tunnel (§4.3): hello ≤ 10 s, then CONNECT as c2s frame 0 ≤ 10 s, resolve + dial ≤ 10 s, idle 300 s; any
  protocol/auth error, client EOF before its FIN, or upstream error ⇒ immediate close without FIN/RECEIPT, and
  the upstream connection is aborted with a TCP **RST** (only an authenticated c2s FIN frame becomes a FIN at the
  destination, so a cut/tampered c2s stream is never committed as complete). Frames
  pipelined after CONNECT are queued (≤ 256 KiB) with the socket paused. Backpressure both ways. RECEIPT is sent
  once both FINs are exchanged **and** every relayed c2s byte has been flushed upstream.
- Anti-replay (`replay.ts`; §4.1 has no exit-side randomness in `th`, so a replayed hello would re-derive a
  victim tunnel's keys and nonces): every nonce served by `/v1/attestation` is recorded for 2 h (> the client's
  max `attestTtlMs` of 1 h); a hello must name a live recorded nonce, and each `epk` is admitted once per nonce —
  otherwise the tunnel is closed before any frame. Bounded: ≤ 65 536 live nonces (when full the oldest unused one
  is dropped, else `/v1/attestation` → `503`), ≤ 2^20 remembered hellos (then new tunnels are refused).
- Egress (§6): `validateDestination` → `dns.lookup(all)` (IP literals are not resolved) → `egressAllowed` on
  **every** address — if any is denied the destination is `E_EGRESS_DENIED` (fail closed against mixed answers)
  → also refuse "public" addresses that reach the host itself: Azure WireServer `168.63.129.16` and every address
  of the exit's own interfaces (`os.networkInterfaces()`, per dial; listing failure ⇒ deny), compared in
  canonical form (`egressIdentity`: IPv4-mapped / NAT64 / 6to4 spellings included)
  → dial the first address (IPv4 preferred) **by IP literal** with a lookup function that refuses everything.
  The egress policy is read from the measured compose bytes, never from configuration.
- Receipts: SPEC-VPN §5 (no destination/port/bytes), `ts_close_ms` clamped ≥ `ts_open_ms`; anchored by the shared
  `Anchorer` (generic over receipt kind: `LeafLog` + `EnclaveKeys`).
- ⚠️ `vpn-evil-logger` = honest source + `evil/logging-dialer.ts` (prints `EVIL-VPN-LOGGER destination: host:port`
  and the first 256 bytes of each direction to stdout). Nothing in `src/` imports it (`test/vpn-host.test.ts`).
