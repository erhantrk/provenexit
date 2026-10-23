# @plr/enclave — the router "inside the TEE" + the mock TDX host

SPEC §4, §5, §6, §8, §14. Build: `npm run build -w @plr/enclave` (tsc + `build.mjs`). Test: `npm test -w @plr/enclave`.

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
  mock-tdx/host.ts    the mock TDX host (library API, used by the CLI and in-process by harnesses)
  mock-tdx/cli.ts     host CLI
  mock-tdx/attester.ts  SocketAttester: what the router uses to call POST /GetQuote
mock-llm/server.mjs   SPEC §14 mock LLM (zero deps; its sha256 is the mock compose's model_sha256)
evil/                 ⚠️ evil-logger demo build (honest source + prompt-stealing LLM wrapper)
build.mjs             reproducible esbuild bundles + canonical compose files + build-info.json
```

## Build outputs (`dist/`)

| file | what |
|---|---|
| `router.bundle.mjs` | honest router bundle |
| `app-compose.mock.json`, `app-compose.llama.json` | honest compose per llm kind (`app-compose.json` = mock) |
| `evil-logger.bundle.mjs`, `app-compose.evil-logger.{mock,llama}.json` | ⚠️ evil variant |
| `build-info.json` | all bundle and compose hashes |

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
