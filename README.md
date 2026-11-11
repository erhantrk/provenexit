# ProvenExit: a VPN exit whose no-logs claim is checked by your client

Built at NEAR HACKATHON (2026-11). Track: Privacy & Private AI.

A VPN exit whose no-logs promise your own computer checks before any byte leaves it: the exit runs in an Intel TDX
confidential VM, and a NEAR contract that verifies Intel's signature on-chain decides which exit builds count.

The judge's one-sentence version: *ProvenExit's client refuses to send traffic unless an Intel-signed TDX quote proves
the exit runs an approved, logging-disabled build listed on a NEAR registry that itself verified that quote on-chain,
and when the owner revokes the build on NEAR, the very next connection is refused.*

This file replaces the October 2026 tour of the pre-hackathon code, which is kept verbatim at
[`docs/PLR-README-2026-10.md`](docs/PLR-README-2026-10.md).

## Status of this snapshot (read this first)

The plan's fallback **S1-F2** applies (maintainer decision, 2026-11-11):
**the VPN exit is not deployed on Phala Cloud.** Phala was used once, on 2026-11-09, for a harmless test CVM that
returned one real TDX quote (kept in [`fixtures/phala-spike/`](fixtures/phala-spike)). What follows from that:

- The **live demo exit in this repository runs on the MOCK root on the local machine** — the plan's pre-existing mode,
  unchanged. It exercises the real protocol, the real SOCKS5 proxy, the real egress policy, the real receipts and the
  real registry/revocation path, but it is not Intel hardware.
- The **real Intel TDX evidence** is that 2026-11-09 quote. It was verified **on-chain** on testnet up to check 13 of
  13 (`report_data`): the spike CVM had asked dstack for `report_data = 64 × 0x42`, not for an exit's keys, so the
  registration was refused with `E_REPORT_DATA`. Checks 1–12 — quote format, Intel root, **DCAP signature
  verification with Intel collateral**, TCB status, DEBUG clear, dstack event log → RTMR3, compose hash, compose and
  OS allowlists — passed **inside the contract**, on chain (tx
  [`9AUTujEQv8p1R1z7SKEpNa5BYFw3a9ZZerkKmpQb5NRB`](https://testnet.nearblocks.io/txns/9AUTujEQv8p1R1z7SKEpNa5BYFw3a9ZZerkKmpQb5NRB),
  186.03 Tgas).
- The offline replay of that quote therefore prints `✔ quote signature chain to root` and
  `✔ Intel TCB status accepted` and then stops at the **expected refusal** `✘ E_REPORT_DATA_KEYS`. A
  `✔ VERIFIED (FIXTURE REPLAY …)` line needs a TDX exit that asked for the exit's key hash and nonce; no such exit
  exists in this snapshot (and none can be manufactured: `report_data` is fixed by Intel at quote time).
- **No exit image was built or published** (T13 was skipped under S1-F2). `deploy/phala/docker-compose.yml` pins a
  documented placeholder digest — it is the exact measured configuration a paid deploy would use, not a live image.

## What it does

- `plr vpn` runs a local SOCKS5 proxy (`socks5h://127.0.0.1:18180`, CONNECT only, remote DNS). Before every new
  connection it verifies the exit, fail-closed:
  1. an Intel TDX v4 quote whose signature chain reaches the pinned Intel SGX Root CA and whose TCB status is
     accepted (`UpToDate` / `SWHardeningNeeded`), checked with `@phala/dcap-qvl`;
  2. `report_data` binds the exit's X25519 + Ed25519 keys and the client's fresh 32-byte nonce;
  3. the dstack event log (IMR3) replays to RTMR3, and the app-id / compose-hash / instance-id payloads are well formed;
  4. the measured docker-compose pins every image by digest, forbids `build` and `privileged`, and disables logging on
     the `exit` service (`logging.driver: none`);
  5. the NEAR registry, read at that moment, still allows that compose hash and OS measurement and has a live
     registration for exactly these keys.
  Only then does it open an end-to-end encrypted tunnel (X25519 + HKDF, ChaCha20-Poly1305) to the attested key. The
  operator, the host and the network see ciphertext; the exit resolves destinations over DNS-over-HTTPS only, refuses
  loopback/private/link-local/metadata targets, and keeps no destinations, IPs, ports or payloads in logs or receipts.
- Revoking a build on NEAR makes every client refuse the **next** connection, even with a cached attestation.
- Session receipts (transcript hash, compose/key hash, sequence, open/close time — never a destination) are
  Merkle-anchored on the same contract with the exit's Ed25519 key.

## NEAR's role (concrete)

- Contract [`pe-vpnreg-erhan.testnet`](https://testnet.nearblocks.io/address/pe-vpnreg-erhan.testnet)
  ([`contracts/near`](contracts/near), near-sdk 5.29.1): owner allowlist (compose hash, OS measurement), operator
  organizations, instance records, receipt anchors, and **on-chain Intel DCAP verification**.
- `register_instance_tdx` runs `dcap-qvl` 0.7.1 inside the contract: thirteen ordered checks (DCAP quote signature and
  TCB status, dstack event log, compose hash, allowlists, `report_data` binding) before an exit's keys are listed. It
  is payable (0.1 NEAR) and called with 300 Tgas. Measured: **179.63 Tgas** to DCAP-verify dcap-qvl's sample quote
  in a near-sandbox spike (test-clock build); the testnet run burnt **186.03 Tgas** and reached check 13, so checks
  1–12 ran on chain for the real quote.
- Deployed wasm: 622 282 bytes, SHA-256 `e2864a9c75f592af91cbdf36ba3918e5793434a949f1daca2b92df40db2b1bdc`.
  Initialization (`new`, owner `pe-owner-erhan.testnet`, root `INTEL`, TTL 86 400 000 ms): tx
  [`FyRSR12vo3KXEwmH8DN7DJQ78SFFHcXoYKeRREUCUWj`](https://testnet.nearblocks.io/txns/FyRSR12vo3KXEwmH8DN7DJQ78SFFHcXoYKeRREUCUWj).
- Operator `pe-op-erhan.testnet` approved as organization `erhan-demo`: tx
  [`G24JXkyLJZQjV8FFHeG9x5ZGy9mNVgwKtSi8p8xEZHL1`](https://testnet.nearblocks.io/txns/G24JXkyLJZQjV8FFHeG9x5ZGy9mNVgwKtSi8p8xEZHL1).
- Allowlists for the **spike** (not an exit) compose `b9823a79…d05f` and OS measurement `821d442f…d323d`: txs
  [`EmWz2Uawni6PicfCqrG8YwkZeZwgkyQMTCbGACQwq6sM`](https://testnet.nearblocks.io/txns/EmWz2Uawni6PicfCqrG8YwkZeZwgkyQMTCbGACQwq6sM)
  and [`E3to6jCjasF37vLqRtsFKLsehLpXL2J1xK7PNFbHnwbX`](https://testnet.nearblocks.io/txns/E3to6jCjasF37vLqRtsFKLsehLpXL2J1xK7PNFbHnwbX).
- Revocation works on testnet: `revoke_compose b9823a79…` tx
  [`3FnZ8bG8k9biUcH5SjtzqpBDmHVU1hmREJGT1vfXh2yz`](https://testnet.nearblocks.io/txns/3FnZ8bG8k9biUcH5SjtzqpBDmHVU1hmREJGT1vfXh2yz),
  re-allow tx [`642fevAQzKKwBFX3xYMZY9edQ3FsxC81HeBjncNzpUpV`](https://testnet.nearblocks.io/txns/642fevAQzKKwBFX3xYMZY9edQ3FsxC81HeBjncNzpUpV).
  (`anchor_count` is 0: no exit runs on testnet in this snapshot.)

## Try it (pick one)

1. **Offline, ~2 minutes, no accounts** — the whole story on a local near-sandbox with the MOCK root:

   ```sh
   npm ci && npx near-sandbox --version && npx tsc -b && npm run build -w @plr/enclave && (cd contracts/near && cargo near build non-reproducible-wasm --no-abi) && PLR_LLM=mock bash scripts/demo.sh
   ```

   - see: `✔ VERIFIED` (router and VPN exit), a fetch through the SOCKS5 proxy and the attested tunnel, the evil
     builds refused with `E_COMPOSE_NOT_ALLOWED`, the MITM refused with `E_REPORT_DATA_KEYS`, owner revocation then
     `refused with E_COMPOSE_NOT_ALLOWED` and a restore, and the final `✔ DEMO PASSED`, `✔ VPN PASSED`,
     `✔ DNS + TWO-HOP PASSED`, `✔ COMBO PASSED`.
   - nothing is left running afterwards. Requires Node 22, Rust + `cargo-near`, and the npm lockfile's dependencies.
     The `npx near-sandbox --version` step is needed once per install: it downloads NEAR's sandbox binary (~70 MB)
     into `node_modules`, which the stack then runs (set `NEAR_SANDBOX_BIN_PATH` to reuse an existing binary).
   - long checkout paths: the stack keeps Unix sockets under a run root limited to 60 bytes, so set
     `PLR_RUN_ROOT=<short dir>` if your clone path is longer than that.

2. **Replay the real Intel attestation offline** — needs only `npm ci` and the TypeScript build:

   ```sh
   npm ci && npx tsc -b && node client/dist/cli.js vpn verify --fixture fixtures/phala-spike/replay
   ```

   - see: `✔ quote signature chain to root`, `✔ Intel TCB status accepted`, then the expected refusal
     `✘ E_REPORT_DATA_KEYS` — the recorded 2026-11-09 Phala CVM asked dstack for `report_data = 64 × 0x42`, so it
     never bound an exit's keys. That is the same point at which the on-chain registration stopped (tx
     `9AUTujEQ…`, check 13 of 13, after checks 1–12 passed). No network is used; the DCAP check runs at the capture
     time.

3. **Live exit:** there is none in this snapshot (S1-F2). [`scripts/demo-live.sh`](scripts/demo-live.sh) drives the
   PLAN §10.1 sequence (`vpn verify` → browse → owner revoke → refusal → re-allow) against a deployed exit, reading
   `deploy/testnet/env.live`; it signs nothing itself.

## How to verify each claim

| claim | command / evidence | expected |
|---|---|---|
| the exit is genuine Intel TDX | `node client/dist/cli.js vpn verify --fixture fixtures/phala-spike/replay` | `✔ quote signature chain to root`, `✔ Intel TCB status accepted` |
| NEAR verified Intel's signature itself | registration tx `9AUTujEQ…` on nearblocks | failure at check 13 `E_REPORT_DATA` — checks 1–12 (DCAP, TCB, event log, compose, allowlists) passed in the contract |
| the exit image is pinned and logging is off | `deploy/phala/docker-compose.yml`; `checkDstackComposePolicy` in [`packages/shared/src/attest/compose-policy.ts`](packages/shared/src/attest/compose-policy.ts) | image by digest, `logging.driver: none`; the same check rejects the real 2026-11-09 spike compose (`E_COMPOSE_POLICY`) |
| image = this source | not shown in this snapshot: no image was built (T13 skipped) | stated, not claimed |
| revocation works | option 1 (MOCK stack) or the testnet revoke/re-allow txs above | `refused with E_COMPOSE_NOT_ALLOWED`, then restored by re-approval |
| no destination in receipts | [`SPEC-VPN.md`](SPEC-VPN.md) §5; e2e scans the exits' output and run directory | only hashes, sequence numbers and timestamps |

## What it does not prove

- **The exit sees your destinations.** Any VPN exit must know the host/port it connects to and relays the
  bytes. ProvenExit proves the approved code does not *keep* them — not that it never sees them.
- **"No logs" covers the attested code, not the operator's network.** DNS is no longer exposed: the exit's
  host and ISP see only TLS to the resolver's IP, and the **resolver** sees the names the exit asks for, but
  never your IP (only the exit's). The exit still dials over a NIC the host controls, so the **operator** — not
  only the exit's ISP — can observe the upstream leg without touching the measured code: destination IP:port,
  timing, the TLS SNI, and every byte of plain-HTTP traffic. ProvenExit proves the approved exit code retains
  nothing; it does not stop the operator's host from watching the exit's own traffic to destinations. Use
  HTTPS (ideally with ECH) for anything sensitive, and two-hop so that operator does not also know
  who you are.
- **TLS is still needed for content.** For `https://` the exit relays TLS ciphertext; for plain `http://` the
  exit code processes the plaintext (it never stores it). The destination sees the exit's IP.
- **Metadata.** Timing and sizes of tunnelled traffic are visible to the operator and the network (DATA is not
  padded, no cover traffic; only the CONNECT / CONNECT_ERR payloads have fixed sizes). With one hop, your own IP is visible to the exit operator's network.
- **Proxy mode only.** Only what you send through the SOCKS5 proxy is protected: TCP CONNECT, no UDP (no QUIC,
  no WebRTC media, no system-wide tunnel). Use `socks5h` (or "proxy DNS") so names are not resolved locally.
- **MOCK ROOT, not Intel, for the demo exit in this snapshot.** Its quote is signed by a locally generated test root
  through a per-boot attestation key, and the "TD" is a Node process supervised by a mock TDX host. The byte layouts,
  hashes, event log and verification logic are the real TDX/dstack ones, but **a MOCK root attests nothing about
  hardware**: whoever holds the mock root secret can forge quotes. The CLI says so on every verify
  (`MOCK ROOT (local test root, NOT Intel)`). Mock-host limits, which real TDX removes: the quote socket is a 0600
  Unix socket of the operator's uid (any same-uid process can obtain a genuine quote for **any** `report_data`), the
  root secret is a 0600 file of the same uid, the TD is a set of same-uid processes, and a new ggml plugin file dropped
  into a measured directory after measurement would still be found by its scan.
- **Collateral freshness window (R7).** The exit serves the Intel collateral (PCK CRL, TCB info, QE identity) it
  fetched from a PCCS. `dcap-qvl` checks it against the client's clock, so it cannot be expired — but an exit can
  serve a CRL that is *stale yet unexpired* and hide a freshly revoked platform. Setting `PLR_PCCS_URL` on the client
  makes the client fetch fresh collateral itself (T24); the residual window is the CRL's own update interval.
- **The OS measurement was observed, not reproduced (T26 not done).** The allowlisted value `821d442f…d323d` is the
  `SHA256(mr_td ‖ rtmr0 ‖ rtmr1 ‖ rtmr2)` of the dstack OS image that booted, read from the quote. It was not
  re-derived with `dstack-mr` from the dstack release. The owner approves the value they saw, not one computed from
  source.
- **A single owner key decides the allowlist (R12).** `pe-owner-erhan.testnet` is one NEAR account: whoever holds that
  key can allow or revoke builds and operators. The client pins the Intel root and the registry contract, not the
  owner. Multisig / a DAO (e.g. Sputnik) is future work.
- **In a cloud deployment, Phala's dstack-gateway terminates TLS.** HTTPS to the exit ends at the gateway
  (`https://<app-id>-18200.<gateway-domain>`), which then speaks to the container; the tunnel inside is end-to-end
  encrypted to the attested key, so the gateway sees only ciphertext, cannot impersonate the exit (its key is inside
  the signed quote) and cannot read or forge tunnel content. It can still observe connection timing and volume, and
  it is a liveness dependency ("refuse to serve" is always possible). In this snapshot no exit runs behind it.
- **The registry owner's honesty** (see above) and **the registry RPC endpoint is trusted**: NEAR view results carry
  no state proofs, so whoever answers the client's `get_root` / `is_*_allowed` / `get_instance` calls decides checks
  3, 5 and the allowlist. The client therefore only talks to the registry over `https:`, or plain `http:` to a
  loopback address; `PLR_NEAR_RPC=http://<remote>` is refused. Pick an RPC provider you trust (the demos use
  `https://rpc.testnet.fastnear.com`); a quorum of independent RPCs or light-client proofs is future work.
- **TEE vendor trust and side channels** are out of scope: Intel, the dstack OS image and the TDX module are trusted
  roots; micro-architectural side channels are not defended.

## Architecture

```
 ┌──────────────── user's laptop (trusted) ───────────────────────────┐
 │ browser / curl ──SOCKS5──► plr vpn :18180 (VpnClient)              │  pins: INTEL_ROOT_P256, registry account id
 │                            1. GET /v1/attestation?nonce            │
 │                            2. dcap-qvl verify (Intel chain, TCB)   │
 │                            3. event log → RTMR3, compose policy    │
 │                            4. NEAR views: root, is_compose_allowed,│
 │                               is_os_allowed, get_instance          │
 │                            5. tunnel: X25519+HKDF, ChaCha20-Poly   │
 └──────────────┬──────────────────────────────────────┬──────────────┘
                │ HTTPS (TLS ends at the gateway;      │ HTTPS JSON-RPC (views)
                │ tunnel stays E2E to attested key)    │ https://rpc.testnet.fastnear.com
 ┌──────────────▼──────────────────────────┐   ┌───────▼───────────────────────────────────────┐
 │ Phala Cloud (UNTRUSTED operator/host)   │   │ NEAR testnet: pe-vpnreg-erhan.testnet         │
 │  dstack-gateway  *.phala.network:443    │   │  owner: allow/revoke compose + OS, orgs       │
 │  ┌──────── Intel TDX CVM (dstack OS) ─┐ │   │  register_instance_tdx: dcap-qvl ON-CHAIN,    │
 │  │ guest-agent /var/run/dstack.sock   │ │   │    dstack event log, compose/OS allowlist,    │
 │  │  (quotes, RTMR3 = compose hash)    │ │   │    report_data binds keys+registry+operator   │
 │  │ container "exit" (image@sha256)    │ │──►│  anchor_receipts: Merkle roots, Ed25519 sig   │
 │  │  logging: none, read_only, no caps │ │   │  views: get_root, is_*_allowed, get_instance  │
 │  │  keys in memory only               │ │   └───────────────────────────────────────────────┘
 │  │  DoH 1.1.1.1/9.9.9.9 → dial by IP  │ │             ▲ owner tx (near-cli-rs): Erhan's laptop
 │  └────────────────────────────────────┘ │
 └───────────────────┬─────────────────────┘
                     ▼ destination (sees the exit's IP)
```

Under S1-F2 the demo exit runs in this repository on the MOCK root; the diagram is the INTEL deployment the code is
written for (and the configuration `deploy/phala/` pins).

## Repository map

| path | what |
|---|---|
| [`packages/shared`](packages/shared) `@plr/shared` | protocol: quote parsing (MOCK + INTEL), dstack event log, DCAP verifier, collateral, compose policy, key binding, tunnel crypto, receipts, `verifyAttestation` |
| [`client`](client) `@plr/client`, `plr` / `provenexit` CLI | `VpnClient` / `TwoHopClient`, `NearRegistry`, the SOCKS5 proxy, `vpn verify`, `vpn inspect`, `vpn verify --fixture` |
| [`enclave`](enclave) `@plr/enclave` | exit bundle, `DstackAttester`, collateral cache, the mock TDX host, mock LLM, test-only logging builds |
| [`contracts/near`](contracts/near) | the registry: allowlists, `register_instance_tdx` (on-chain dcap-qvl), `anchor_receipts`, views |
| [`SPEC-TDX.md`](SPEC-TDX.md) | the frozen INTEL/dstack byte formats and the contract/client additions this code implements |
| [`deploy/phala`](deploy/phala) | the measured exit compose (placeholder image digest; see its README) and the spike compose |
| [`fixtures/phala-spike`](fixtures/phala-spike) | the real 2026-11-09 TDX dump, its parsed parts, and the INTERFACES §3.3 replay fixture |
| [`e2e`](e2e) | the stack harness (near-sandbox, zebrad, anvil, Stellar, Solana), attacker scenarios, locked e2e tests |
| [`scripts`](scripts) | `demo.sh` (option 1), `demo-live.sh`, `dev-up.sh` / `dev-down.sh`, `owner.sh`, `pccs-live-check.mjs` |

Elsewhere in the repo, not part of the NEAR submission (mentioned once, as the plan asks): the private LLM router
(PLR-v1, `plr verify` / `plr chat` / `plr proxy`, still exercised by `scripts/demo.sh`) and the multi-chain registries
([`SPEC-CHAINS.md`](SPEC-CHAINS.md): EVM/Monad, Stellar, Solana in `contracts/{evm,stellar,solana}`, Zcash record
logs in `client/src/zcash-registry.ts`).

## Prior code and hackathon window (rules Q-001/Q-003/Q-004)

- First commit `58c5ea9` on 2026-10-23, after the hackathon announcement (2026-10-19), so all code in this repo was
  written inside the window. There is no pre-hackathon baseline.
- Commits 2026-10-23…2026-10-24 built the mock-root protocol, the NEAR registry and the multi-chain registries. Work
  from 2026-11-09 on built the real Intel TDX path (`4fb2f08` is the last commit before it).
- Diffs: [4fb2f08...main](https://github.com/erhantrk/provenexit/compare/4fb2f08...main) (the real-TDX work;
  `4fb2f08` is the last pre-2026-11-09 commit) and [the full history](https://github.com/erhantrk/provenexit/commits/main).
- The design record is in [`docs/plan/`](docs/plan) (plan, tasks, frozen interfaces, sources), with the decisions and
  findings in [`NOTES-DECISIONS.md`](NOTES-DECISIONS.md).

## AI use

Large parts of the code, specs and tests were written with AI coding assistants, directed and reviewed by Erhan
Türker (design decisions, review, accounts, keys, deployment, submission). The planning documents in `docs/plan/`
(PLAN, TASKS, INTERFACES, SOURCES) were generated by Claude. Details, including which assistant did what:
[`AI_USE.md`](AI_USE.md).

## Libraries

`@noble/curves`, `@noble/hashes`, `@noble/ciphers`, `near-api-js`, `@phala/dcap-qvl` 0.7.1 (Apache-2.0),
`@phala/dstack-sdk` 0.5.8 (Apache-2.0), `yaml` 2.8.1, `viem`, `@solana/web3.js`, `@stellar/stellar-sdk`, `esbuild`,
`vitest`, `near-sdk` 5.29.1, the `dcap-qvl` 0.7.1 crate (MIT), `sha2`, `p256`, `ed25519-dalek`, `forge-std`.
Test vectors from dcap-qvl's `sample/` (MIT). Infrastructure: Phala Cloud (dstack, test CVM only), NEAR testnet,
FASTNEAR RPC, Phala PCCS.

## License

MIT, see [`LICENSE`](LICENSE).
