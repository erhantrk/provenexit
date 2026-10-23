# PLR-v1 — a provably-private LLM router

An LLM router that runs inside a TEE (Intel TDX, **mocked faithfully** in this milestone), whose approved code
measurement lives in a **NEAR registry contract**. Before a client sends a single prompt it fetches a fresh
attestation, verifies it against the attestation root **and against the chain**, and then encrypts the prompt to
a key that only the measured router code can hold. Every answer comes with a signed receipt that is anchored
on-chain in Merkle batches.

The protocol is specified in [`SPEC.md`](SPEC.md) (frozen, authoritative). This README is the tour.

```
bash scripts/demo.sh        # builds everything, runs the whole story with a real Qwen 0.5B model
```

---

## What this proves — and what it does not

**What the client checks** (SPEC §9, in this order, fail-closed; the first failure aborts and nothing is sent):

| # | check | refusal code |
|---|---|---|
| 1 | fresh 32-byte nonce, well-formed response | `E_BAD_RESPONSE` |
| 2 | TDX v4 quote structure, TEE type | `E_QUOTE_FORMAT`, `E_TEE_TYPE` |
| 3 | signature chain to the pinned root, which must equal the registry's root | `E_ROOT_UNTRUSTED`, `E_QUOTE_SIG` |
| 4 | TD is not in DEBUG mode | `E_DEBUG_TD` |
| 5 | `report_data` binds the router's X25519 + Ed25519 keys and the client's nonce | `E_REPORT_DATA_KEYS`, `E_NONCE` |
| 6 | event log digests + boot sequence replay to RTMR3 | `E_EVENT_LOG`, `E_RTMR3` |
| 7 | the published `app-compose.json` is exactly the measured one | `E_COMPOSE_MISMATCH` |
| 8 | the registry **currently** allows that compose hash and OS measurement | `E_COMPOSE_NOT_ALLOWED`, `E_OS_NOT_ALLOWED` |
| 9 | the registry has a live registration for exactly these keys | `E_INSTANCE_NOT_REGISTERED` |

Given those checks, an operator who controls the host, the network and the router deployment **cannot**:

- run modified router code (e.g. one that logs prompts) and still get prompts — its measurement differs and
  is not on the allowlist (`evil-logger` scenario);
- swap the encryption key in transit — the key is bound into the signed quote (`mitm-key`);
- replay an old attestation — the client's nonce is in the quote (`replay-quote`);
- run the approved code in a debuggable TD (`debug-td`);
- truncate or tamper with the encrypted answer stream undetected (`truncate-stream`, `tamper-stream`);
- keep serving after the registry owner revokes a build — the very next session is refused (`revocation`);
- serve from an instance whose keys were never published on-chain (`unregistered`).

The router itself never writes prompts or answers anywhere (no logs, no disk — the mock host runs it under
Node's permission model with a read-only file system), and the e2e suite checks its output and the whole run
directory for the secret prompt.

**What it does not prove (SPEC §1, out of scope, documented not defended):**

- **MOCK ROOT, not Intel.** In this milestone the quote is signed by a locally generated *MOCK ROOT* through a
  per-boot attestation key, and the "TD" is a Node process supervised by a mock TDX host. The byte layouts,
  hashes, event log and verification logic are the real TDX/dstack ones, but **a MOCK ROOT attests nothing
  about hardware**: whoever holds the mock root secret can forge quotes. The CLI says so on every verify
  (`MOCK ROOT (local test root, NOT Intel)`) and the registry records `root.kind = "MOCK"`.
- TEE vendor compromise, micro-architectural side channels.
- Traffic metadata: timing, sizes, IP addresses.
- Denial of service (the operator can always refuse to serve).
- The registry owner's honesty: the owner decides which builds are allowed (→ multisig / DAO later). The
  client pins the attestation root and the registry contract, not the owner.
- The LLM runtime (llama.cpp), node and the model are measured by hash (see *Runtime measurement*), not audited.
- **Mock host limitations (MOCK only; real TDX removes them).** The mock TDX host is an ordinary process of
  the operator's user, so it is trusted the way the TDX module and dstack guest OS are, but nothing enforces
  that here:
  - *Quote socket.* `POST /GetQuote` listens on a Unix socket (mode 0600, in a 0700 directory) owned by the
    operator's uid. Any process of that uid can connect and get a genuine quote of the approved build for
    **any** `report_data`, i.e. bind its own keys to the honest measurement, register them on-chain and receive
    prompts. In real TDX only code inside the TD can reach the guest agent and the quote is signed by
    hardware; with the MOCK ROOT, socket permissions are the only barrier.
  - *Root secret.* The MOCK ROOT secret is a 0600 file of the same uid (see *MOCK ROOT, not Intel*).
  - *Isolation.* The "TD" is a set of processes: same-uid debugging or memory inspection is not prevented.
  - *Runtime plugins.* Runtimes run from verified private copies, but a **new** ggml backend file dropped
    into `<ggml>/libexec` after measurement would still be found by ggml's directory scan.
- **The registry RPC endpoint is trusted.** NEAR view results carry no state proofs, so whoever answers the
  client's `get_root` / `is_*_allowed` / `get_instance` calls decides checks 3, 8 and 9. The client therefore
  only talks to the registry over `https:`, or plain `http:` to a loopback address (a local node or light
  client); `PLR_NEAR_RPC=http://<remote>` is refused. Pick an RPC provider you trust (or run a node / a light
  client locally); a quorum of independent RPCs or light-client proofs is future work.

---

## Architecture

```
  ┌──────────────── client machine (trusted) ────────────────┐
  │  any OpenAI SDK ──► plr proxy :18787 ──► PrivateClient    │   pins: MOCK/Intel root, registry id
  │                     (OpenAI-compatible)  │  verifyAttestation (SPEC §9)
  └──────────────────────────────────────────┼──────────────────────────┬─────────────────────┘
          1. GET /v1/attestation?nonce=…     │ 3. POST /v1/private/chat │ 2. view calls
             ◄── quote + event log + compose │    X25519 → ChaCha20-     │    get_root, is_allowed,
                 + router keys               │    Poly1305 (SSE frames)  │    get_instance, get_anchor
  ┌──────────────────────────────────────────▼─────────┐     ┌──────────▼──────────────────────────┐
  │ host / operator (UNTRUSTED)                        │     │ NEAR  registry contract (SPEC §7)   │
  │  ┌──────────────────── TDX TD (mock) ───────────┐  │     │  owner allowlist: compose + OS      │
  │  │ mock TDX host  ── measures compose, bundle,  │  │     │  register_instance: verifies the    │
  │  │   (dstack       model → RTMR3; serves quotes │  │────►│    quote ON-CHAIN (P-256, RTMR3,    │
  │  │   stand-in)     on a 0600 unix socket        │  │     │    compose, report_data)            │
  │  │      │ launches exactly the measured bytes   │  │     │  anchor_receipts: Merkle roots      │
  │  │      ▼                                       │  │     │    signed by the attested Ed25519   │
  │  │ router.bundle.mjs  keys in memory only,      │  │     └─────────────────────────────────────┘
  │  │   (node --permission, read-only fs)          │  │
  │  │      │ 127.0.0.1 only                         │  │
  │  │      ▼                                       │  │
  │  │ llama-server (Qwen 0.5B GGUF) | mock LLM     │  │
  │  └──────────────────────────────────────────────┘  │
  └────────────────────────────────────────────────────┘
```

| package | what |
|---|---|
| [`packages/shared`](packages/shared) `@plr/shared` | the protocol: quote parsing, event log, key binding, session crypto, frames, receipts, Merkle, `verifyAttestation` |
| [`contracts/near`](contracts/near) | the registry contract (Rust, near-sdk 5.29): allowlist, on-chain quote verification, anchoring |
| [`enclave`](enclave) `@plr/enclave` | the router bundle, the mock TDX host, the mock LLM, the ⚠️ evil-logger demo build |
| [`client`](client) `@plr/client` | `PrivateClient`, `NearRegistry`, the `plr` CLI and the OpenAI-compatible proxy |
| [`e2e`](e2e) | the SPEC §13 harness (`startStack`), network attackers, the dev-stack CLI, the locked e2e tests |

---

## Quickstart

Requirements (all local, no network needed): Node 22, Rust + `cargo-near` 0.22, `llama-server`
(`/opt/homebrew/bin/llama-server`), the model `~/models/qwen2.5-0.5b-instruct-q4_k_m.gguf`
(sha256 `74a4da8c…a9db`, pinned in the compose), `npm install` already done.

```sh
bash scripts/demo.sh                # the whole story, ~1–2 min; PLR_LLM=mock for the fast mock LLM
```

It builds everything, starts a fresh near-sandbox with the registry, has the owner approve the honest build,
launches the honest router (measured by the mock host, real Qwen) plus an evil-logger build and a MITM proxy,
then runs `plr verify` (every check ✔), `plr chat` (streamed answer + verified receipt + on-chain anchor), and
the refusals: evil build → `E_COMPOSE_NOT_ALLOWED`, MITM → `E_REPORT_DATA_KEYS`, owner revocation →
`E_COMPOSE_NOT_ALLOWED` then service restored by re-approval. Everything is stopped on exit.

A stack to play with:

```sh
scripts/dev-up.sh                   # near-sandbox :3030 + honest router :18100 (PLR_LLM=mock, PLR_EXTRA=evil-logger,…)
set -a; . .run/stack.env; set +a    # PLR_ROUTER_URL, PLR_NEAR_RPC, PLR_REGISTRY, PLR_TRUSTED_ROOT, …
node client/dist/cli.js verify
echo "hello" | node client/dist/cli.js chat     # prompt from stdin (recommended: argv shows up in `ps` and history)
node client/dist/cli.js chat "hello"            # the SPEC §12 argv form also works
scripts/dev-down.sh
```

Tests:

```sh
npx tsc -b && npm run build -w @plr/enclave
(cd contracts/near && cargo near build non-reproducible-wasm --no-abi)
npm test                            # unit tests (shared, enclave, client)
npm run e2e                         # SPEC §13 scenarios + registry conformance on a real near-sandbox
PLR_E2E_LLM=llama npx vitest run test/scenarios.test.ts   # (in e2e/) the same scenarios with real Qwen
```

---

## Use it from any OpenAI SDK

`plr proxy` verifies the router (all checks above) and then serves an OpenAI-compatible API on
`127.0.0.1:18787`: `POST /v1/chat/completions` (streaming and non-streaming) and `GET /v1/models`. Every
request is end-to-end encrypted to the attested key; the receipt is verified before the answer is returned.

```sh
set -a; . .run/stack.env; set +a
node client/dist/cli.js proxy       # ✔ router verified (MOCK ROOT); OpenAI-compatible proxy on http://127.0.0.1:18787/v1
```

```ts
import OpenAI from "openai";
const oa = new OpenAI({ baseURL: "http://127.0.0.1:18787/v1", apiKey: "unused" });
const r = await oa.chat.completions.create({ model: "plr", messages: [{ role: "user", content: "hi" }] });
```

```sh
curl http://127.0.0.1:18787/v1/chat/completions -H 'content-type: application/json' \
  -d '{"model":"plr","messages":[{"role":"user","content":"hi"}]}'
```

`plr chat` reads the prompt from stdin when no argument (or `-`) is given — prefer it for anything sensitive.

If verification fails, the proxy answers `403 {"error":{"type":"plr_verification_failed","code":"E_…"}}` and
forwards nothing. Programmatic use: `new PrivateClient({ routerUrl, registry: new NearRegistry({ rpcUrl,
contractId }), trustedRoot })` from `@plr/client`.

Receipt anchoring: `await client.verifyAnchored(result.receipt)` fetches the router's inclusion proof and checks
it against `get_anchor` on-chain, taking the batch position **from the chain** (`index = seq − first_seq`,
`size = count`, `root`); router values that disagree are refused with `E_ANCHOR_MISMATCH` (`E_NOT_ANCHORED`
until the batch is on-chain).

---

## Runtime measurement (spec revision to SPEC §4)

SPEC §4 has the host hash the router bundle and the model, but the programs that see plaintext — `node`
(router, mock LLM) and `llama-server` — were only a free-form `llm.runtime` label, so an operator could swap
in a prompt-logging llama-server (or node) under the approved compose hash. The compose now pins them:

```json
{ "llm":    { "kind": "...", "model_sha256": "...", "runtime": "...", "runtime_sha256": "<64 hex>" },
  "router": { "bundle_sha256": "...", "entry": "router.bundle.mjs", "node_sha256": "<64 hex>" }, ... }
```

- A runtime digest covers the executable **and its closure**: on macOS both executables are small stubs whose
  code lives in dylibs (`libnode.*.dylib`, `libllama-server-impl.dylib`, ggml, openssl, …), and ggml `dlopen`s
  its backends from `<keg>/libexec`. The host follows `LC_LOAD_DYLIB`/`LC_RPATH` transitively (dyld rules,
  system images under `/usr/lib` and `/System` excluded as OS), adds the libexec plugins, and hashes the
  sorted manifest `"<sha256> <exe|lib> <leaf name>"` (`enclave/src/mock-tdx/runtime.ts`).
- `llm.runtime_sha256` is llama-server's digest for `llama.cpp` composes and equals `router.node_sha256` for
  `mock` composes (the mock LLM is a node script).
- At launch the host clones every closure file into its private 0700 directory, re-hashes the **copies**,
  refuses on any mismatch (`E_MEASUREMENT_MISMATCH`, or `E_RUNTIME_FORMAT` for a non-Mach-O such as a wrapper
  script), and runs the copies (`DYLD_LIBRARY_PATH` points dyld at them). `--llama-server` / `PLR_LLAMA_SERVER`
  is accepted only if it reproduces the pinned digest.
- `enclave/build.mjs` pins the node that runs the build and `PLR_LLAMA_SERVER` (default
  `/opt/homebrew/bin/llama-server`); `approveBuild` and `plr-tdx-host measure` measure exactly like the host.
  Upgrading node or llama.cpp changes the compose hashes, so the owner must approve the new build — by design.
- Real-TDX mapping: dstack's compose pins container image digests, which play this role.

LLM isolation between users: llama-server runs with prompt caching off (`--no-cache-prompt`,
`--cache-reuse 0`, `-cram 0`, `--no-cache-idle-slots`, one slot), and the router sends `cache_prompt: false`,
so one user's prompt prefix can't be probed through `timings.cache_n` or prompt-processing time (verified
live: a request sharing the previous prompt's prefix gets `cache_n = 0`). `--no-cache-prompt` is only a
per-request default, so the LLM is also locked to the router: the host generates a per-boot API key
(`LLAMA_API_KEY` / `PLR_LLM_API_KEY`, via env, never argv) and any other local process gets `401`. Residual
(MOCK limitation): a process of the operator's own uid can read that key from the process environment.
Requests are still served one at a time, so residual queueing latency is in the out-of-scope timing metadata.

Anchor storage: `anchor_receipts` is payable. The storage it adds is paid by the attached deposit (the router
attaches `PLR_ANCHOR_DEPOSIT`, default 0.01 NEAR, and the excess is refunded) or else by the instance's prepaid
anchor credit, which `register_instance` keeps from its deposit (up to 0.05 NEAR, view `get_anchor_credit`).
The contract's own balance never pays, so a registered instance cannot drain it.

---

## Swapping in real TDX (Phala dstack)

The mock is built to the real formats, so the swap is two components, not a redesign:

- **Attester (router side).** The router only talks to `Attester.getQuote(report_data)`; locally that is the
  mock host's `POST /GetQuote` on a Unix socket, which mirrors dstack's guest-agent `GetQuote` (raw 64-byte
  `report_data`, no hashing). In a dstack CVM, `DstackAttester` (`@plr/shared`, stub today) calls the dstack
  SDK; dstack already extends RTMR3 with the same boot events (`system-preparing`, `app-id`, `compose-hash`,
  `instance-id`, `boot-mr-done`) and the same digest rule, so the event-log verification is unchanged. The
  `app-compose.json` becomes the dstack app compose of the CVM.
- **Verifier (client side).** `DcapQvlVerifier` (stub today) verifies real v4 quotes with Intel DCAP
  (`@phala/dcap-qvl`: PCK chain to the pinned Intel root, TCB status `UpToDate`), and returns the same
  `ParsedQuote`. Everything after step 3 of the checks is identical.
- **Registry.** `set_root("INTEL", <Intel root>)`; the OS measurement is then the real MRTD/RTMR0–2 of the
  dstack OS image (`SHA256(mr_td ‖ rtmr0 ‖ rtmr1 ‖ rtmr2)`, SPEC §2.5). On-chain verification of a full Intel
  quote (PCK chain + QE report) is out of scope for milestone 1: with an INTEL root `register_instance` fails
  closed (`E_QUOTE_SIG`); production would verify via a DCAP-verifier contract or an attested relayer.

## Other chains (EVM adapter)

The client depends only on the chain-agnostic `RegistryReader` interface (`getRoot`, `isComposeAllowed`,
`isOsAllowed`, `getInstance`, `getAnchor`, SPEC §10). The registry semantics (SPEC §7) were chosen so every
chain can implement them natively: SHA-256 everywhere (not keccak), P-256 signatures (EVM: the RIP-7212
`P256VERIFY` precompile), Ed25519 anchor signatures. An EVM port is a Solidity contract with the same methods and
error codes plus an `EvmRegistry implements RegistryReader` (e.g. `eth_call` views); `PrivateClient`, the CLI
and the proxy take any `RegistryReader` unchanged. The router side needs the matching writer for
`register_instance` / `anchor_receipts` (today `enclave/src/near.ts`).

---

## Local layout and ports

| what | where |
|---|---|
| llama-server / mock LLM | `127.0.0.1:18080` / `:18081` by SPEC; the mock host picks a free port by default |
| router | `127.0.0.1:18100` (dev-up), ephemeral in tests and the demo |
| client proxy | `127.0.0.1:18787` |
| near-sandbox RPC | `127.0.0.1:3030` (dev-up), ephemeral in tests and the demo |
| run state | `.run/<id>/` (chain home under `near/`), host sockets in `.run/<id>-host/`; removed on stop (`PLR_KEEP_RUN=1` keeps them) |

The harness and the dev stack run every long-lived process under a "lifeline" that leads its own process
group: stop = SIGTERM to the group, SIGKILL after 10 s; and if the controlling process dies in any way, the
lifeline's stdin pipe closes and the subtree is torn down. Nothing is left running.
