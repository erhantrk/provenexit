# How ProvenExit works

The exit is a small Node service in a Docker container inside an Intel TDX confidential VM (Phala Cloud, dstack OS).
The client is a CLI (`provenexit` / `plr`) that runs a local SOCKS5 proxy. A NEAR contract is the allowlist of
approved builds. The byte formats are specified in [`spec/SPEC-TDX.md`](spec/SPEC-TDX.md) (Intel/dstack mode),
[`spec/SPEC.md`](spec/SPEC.md) (quote, event log, key binding, registry, receipts, verification order) and
[`spec/SPEC-VPN.md`](spec/SPEC-VPN.md) (tunnel, DNS, egress policy, two-hop).

## Architecture

```
 ┌──────────────── your machine (trusted) ────────────────────────────┐
 │ browser / curl ──SOCKS5──► provenexit :18180 (VpnClient)           │  pins: Intel root, registry id + code hash
 │                            1. registry code hash (view_account)    │
 │                            2. GET /v1/attestation?nonce            │
 │                            3. fresh Intel collateral (Intel PCS)   │
 │                            4. dcap-qvl verify (Intel chain, TCB)   │
 │                            5. event log → RTMR3, compose policy    │
 │                            6. NEAR views: root, is_compose_allowed,│
 │                               is_os_allowed, get_instance          │
 │                            7. tunnel: X25519+HKDF, ChaCha20-Poly   │
 └──────────────┬──────────────────────────────────────┬──────────────┘
                │ HTTPS (TLS ends at the gateway;      │ HTTPS JSON-RPC (views)
                │ tunnel stays E2E to attested key)    │ https://rpc.testnet.fastnear.com
 ┌──────────────▼──────────────────────────┐   ┌───────▼───────────────────────────────────────┐
 │ Phala Cloud (UNTRUSTED operator/host)   │   │ NEAR testnet: vpnreg.pe-owner-erhan.testnet   │
 │  dstack-gateway  *.phala.network:443    │   │  owner: allow/revoke compose + OS, orgs       │
 │  ┌──────── Intel TDX CVM (dstack OS) ─┐ │   │  register_instance_tdx: dcap-qvl ON-CHAIN,    │
 │  │ guest-agent /var/run/dstack.sock   │ │   │    dstack event log, compose/OS allowlist,    │
 │  │  (quotes, RTMR3 = compose hash)    │ │   │    report_data binds keys+registry+operator   │
 │  │ container "exit" (image@sha256)    │ │──►│  anchor_receipts: Merkle roots, Ed25519 sig   │
 │  │  logging: none, read_only, no caps │ │   │  views: get_root, is_*_allowed, get_instance  │
 │  │  keys in memory only               │ │   └───────────────────────────────────────────────┘
 │  │  DoH 1.1.1.1/9.9.9.9 → dial by IP  │ │             ▲ owner tx (near-cli-rs): the owner's machine
 │  └────────────────────────────────────┘ │
 └───────────────────┬─────────────────────┘
                     ▼ destination (sees the exit's IP)
```

This is the live deployment, the configuration [`deploy/phala/`](../deploy/phala) pins. The local demo stack runs
the same path with a MOCK root in place of Intel (a local test root; `vpn verify` prints `MOCK ROOT (local test root, NOT Intel)`).

## What NEAR does

The registry contract [`vpnreg.pe-owner-erhan.testnet`](https://testnet.nearblocks.io/address/vpnreg.pe-owner-erhan.testnet)
([`contracts/near`](../contracts/near), near-sdk 5.29.1) holds:

- the owner's allowlists: approved compose hashes (the measured docker-compose, so the image digest and its
  settings) and approved OS measurements;
- operator organizations: which NEAR accounts may run exits, grouped by organization (used by two-hop);
- instance records: each exit's keys, registered by the exit itself;
- receipt anchors: Merkle roots of session receipts, signed with the exit's Ed25519 key.

An exit registers with `register_instance_tdx`, which runs Intel DCAP verification **inside the contract**
(`dcap-qvl` 0.7.1) before it lists the exit's keys. Its 13 checks, in order: quote size and hex, collateral parse,
compose size, key format, the stored root is Intel's, quote structure, the DCAP signature chain, the TCB status
(`UpToDate` or `SWHardeningNeeded`), debug off, the dstack event log replays to RTMR3, the compose matches its
measured hash, compose and OS measurement both allowed, and `report_data` binds the keys, the registry and the
calling operator. The full table with error codes is in
[`contracts/near/README.md`](../contracts/near/README.md#intel-mode-register_instance_tdx). The call is payable
(0.1 NEAR) and sent with 300 Tgas; the live exit's registration burnt 186.76 Tgas.

The exit re-registers every 6 hours; records expire after 24 hours. The owner can revoke a compose or OS
measurement at any time. The client reads the registry before every new connection, so a revoked build is refused
on the next connection, even with a cached attestation.

The registry has no access keys, and its code is a reproducible build of this repo; the client pins its code hash
(check 1 below). See [REPRODUCE.md](REPRODUCE.md#the-registry-contract).

## The 20 client checks

`provenexit verify` (or `node client/dist/cli.js vpn verify`) prints them in this order. Before every new connection
the client runs the same checks; an attestation is cached for at most 60 s (`PLR_VPN_ATTEST_TTL_MS`, 0 = attest every
connection), the registry re-check (19) is never cached. The first failure refuses the exit with its code.

| # | check | refused with |
|---|---|---|
| 1 | registry contract code hash matches the pinned build (`view_account.code_hash`) | `E_REGISTRY_CODE_HASH` |
| 2 | response well-formed, fresh 32-byte nonce | `E_BAD_RESPONSE` |
| 3 | quote structure (TDX v4) | `E_QUOTE_FORMAT` |
| 4 | TEE type is TDX | `E_TEE_TYPE` |
| 5 | pinned root == registry root == verifier root | `E_ROOT_UNTRUSTED` |
| 6 | fresh Intel collateral fetched by the client from the PCCS (not the exit's copy) | `E_COLLATERAL_FETCH` |
| 7 | quote signature chain to root | `E_QUOTE_SIG` / `E_COLLATERAL` |
| 8 | Intel TCB status accepted | `E_TCB_STATUS` |
| 9 | TD debug attribute clear | `E_DEBUG_TD` |
| 10 | report_data binds the exit's keys | `E_REPORT_DATA_KEYS` |
| 11 | report_data binds client nonce as a session quote (`SHA256("PLR-v1/session-nonce" ‖ nonce)`) | `E_NONCE` |
| 12 | event log digests and boot sequence | `E_EVENT_LOG` |
| 13 | event log replays to RTMR3 | `E_RTMR3` |
| 14 | app-compose matches measured compose-hash | `E_COMPOSE_MISMATCH` |
| 15 | dstack compose: images pinned by digest, exit logging disabled | `E_COMPOSE_POLICY` |
| 16 | compose hash allowed by registry | `E_COMPOSE_NOT_ALLOWED` |
| 17 | OS measurement allowed by registry | `E_OS_NOT_ALLOWED` |
| 18 | instance registered with matching keys | `E_INSTANCE_NOT_REGISTERED` |
| 19 | registry re-check before each connection (compose, OS, instance) | the code of the failing view |
| 20 | destinations resolved by the exit (remote DNS); the client never resolves them | (property of the proxy) |

An unreadable registry refuses with `E_REGISTRY_UNAVAILABLE`; RPC providers that give different answers refuse with
`E_REGISTRY_RPC_DISAGREE` (the client asks two and both must agree). Checks 1 and 6 are the client's own: the contract
cannot pin its own code hash, and it verifies the collateral the exit hands it at registration time. The offline
fixture replay prints 17 lines: no code-hash line (the registry is a snapshot), check 6 shown as `·` (recorded
collateral), and no lines 19–20 (no connection is made).

In words: the quote's signature chain reaches the pinned Intel SGX Root CA and its TCB status is accepted
(`@phala/dcap-qvl`); `report_data` binds the exit's X25519 and Ed25519 keys and the client's fresh 32-byte nonce;
the dstack event log replays to RTMR3, and its app-id, compose-hash and instance-id payloads are well formed; the
measured docker-compose pins every image by digest, forbids `build` and `privileged`, and sets
`logging.driver: none` on the `exit` service; the NEAR registry, read at that moment, still allows that compose hash
and OS measurement and has a live registration for exactly these keys.

## The connection

Only after the checks does the client open an end-to-end encrypted tunnel to the attested key (X25519 + HKDF,
ChaCha20-Poly1305, with exit ephemeral keys). The operator, the host, Phala's gateway and the network see
ciphertext.

The exit:

- resolves destinations over DNS-over-HTTPS only (resolver down ⇒ `E_DNS`) and dials by IP;
- refuses loopback, private, link-local, metadata and reserved targets (it protects the host's own services);
- dials only ports 80 and 443 (`PLR_VPN_ALLOWED_PORTS`) and serves at most 32 tunnels at once
  (`PLR_VPN_MAX_TUNNELS`); both settings are part of the compose hash the owner approved;
- keeps no destinations, IPs, ports or payloads in logs or receipts; its container logging is off and its keys live
  in memory only.

Session receipts (transcript hash, compose/key hash, sequence number, open and close time, never a destination)
are Merkle-anchored on the same contract with the exit's Ed25519 key.

## Two-hop

With `PLR_VPN_ENTRY_URL` set, traffic goes client → entry exit → exit. The client attests the entry directly, then
fetches and verifies the exit's attestation through a tunnel via the entry; the exit is never contacted directly.
Both hops must be approved builds on the registry, and their operators must belong to two different approved
organizations (`E_OPERATOR_UNAPPROVED`, `E_SAME_OPERATOR`). The entry sees your IP and the exit's address but not
the destination (the inner tunnel is encrypted to the exit); the exit sees the entry's IP, never yours.

Two-hop runs on the local demo stack (`scripts/demo.sh`, MOCK root). The live testnet deployment has one exit, so it
is one hop. Not covered: an adversary watching both hops' networks (timing correlation), and an owner who approves
the same real-world organization under two ids. Spec: [`spec/SPEC-VPN.md`](spec/SPEC-VPN.md) §10.

## Interfaces

- **CLI:** `npx provenexit verify | inspect | connect` (short for `vpn verify`, `vpn inspect`, `vpn`). `inspect`
  shows what the exit attests to (compose hash, OS measurement, key hash, TCB, images): the values the owner approves.
- **MCP server** ([`mcp/README.md`](../mcp/README.md)): tools `verify_exit`, `fetch_via_exit` (refuses unless every
  check passes; fetches only through the attested tunnel) and `registry_status`.
- **Status bundle** ([`status/provenexit-status.mjs`](../status/provenexit-status.mjs)): one self-contained file
  (Node 22, no install). `node provenexit-status.mjs` prints the status JSON of the live deployment: the same ordered
  checks as `vpn verify`, the exit's egress IP fetched through the tunnel, the registry's owner, code hash and event
  history, and the embedded offline replay. The site <https://provenexit.vercel.app> calls `getStatus()` from it.
  Rebuild with `npm run build:status`. [`status/sample-online.json`](../status/sample-online.json) is a live run.

## Repository map

| path | what |
|---|---|
| [`packages/shared`](../packages/shared) `@plr/shared` | protocol: quote parsing (MOCK + INTEL), dstack event log, DCAP verifier, collateral, compose policy, key binding, tunnel crypto, receipts, `verifyAttestation` |
| [`client`](../client) `@plr/client` | `VpnClient` / `TwoHopClient`, `NearRegistry` (with the code-hash pin), the PCCS fetch, the SOCKS5 proxy, `vpn verify`, `vpn inspect`, `vpn verify --fixture`, the status bundle source |
| [`enclave`](../enclave) `@plr/enclave` | the exit bundle, `DstackAttester`, collateral cache, the mock TDX host, the test-only logging exit build |
| [`contracts/near`](../contracts/near) | the registry: allowlists, `register_instance_tdx` (on-chain dcap-qvl), `anchor_receipts`, views |
| [`deploy/phala`](../deploy/phala) | the measured exit compose (image pinned by digest), its Dockerfile, the spike compose |
| [`deploy/testnet/env.live`](../deploy/testnet/env.live) | the live exit URL, registry, code-hash pin and Intel root |
| [`fixtures/live-exit`](../fixtures/live-exit) | the live exit's attestation, nonce and registry snapshot (2026-11-12 20:13 UTC), replayed by `vpn verify --fixture` |
| [`fixtures/phala-spike`](../fixtures/phala-spike) | the real 2026-11-09 TDX dump from a test VM, its parsed parts, and its replay fixture |
| [`mcp`](../mcp), [`status`](../status), [`npm`](../npm), [`site`](../site) | the MCP server, the status bundle, the npm package, the status site |
| [`e2e`](../e2e) | the stack harness (near-sandbox, the registry, the mock TDX host), attacker scenarios, e2e tests |
| [`scripts`](../scripts) | `demo.sh`, `try-live.sh`, `demo-live.sh`, `verify-exit-image.sh`, `build-exit-image.sh`, `owner.sh`, `dev-up.sh` / `dev-down.sh`, `pccs-live-check.mjs` |
| [`docs/spec`](spec) | the three specs |

## Libraries

`@noble/curves`, `@noble/hashes`, `@noble/ciphers`, `near-api-js`, `@phala/dcap-qvl` 0.7.1 (Apache-2.0),
`@phala/dstack-sdk` 0.5.8 (Apache-2.0), `yaml` 2.8.1, `@modelcontextprotocol/sdk`, `zod`, `esbuild`, `vitest`,
`near-sdk` 5.29.1, the `dcap-qvl` 0.7.1 crate (MIT), `sha2`, `p256`, `ed25519-dalek`. Test vectors from dcap-qvl's
`sample/` (MIT). Infrastructure: Phala Cloud (dstack: the live exit and a test CVM), NEAR testnet, FASTNEAR and dRPC RPC,
Phala PCCS (the exit's collateral), Intel PCS (the client's collateral).
