# ProvenExit

**NEAR verifies Intel's TDX attestation on chain, and uses it as an allowlist for VPN exits. When the owner revokes a build on NEAR, the next connection is refused.**

Every VPN says "no logs". ProvenExit's client checks, before it sends a byte, that the exit runs an approved build with logging off. The proof is an Intel-signed quote, checked against a NEAR registry. Built at NEAR HACKATHON (2026-11).

> **Status:** a live exit runs on Intel TDX hardware (Phala Cloud, production OS `dstack-0.6.1`). The NEAR contract verified its quote on chain, all 13 checks, before listing its keys ([tx `HSQqnRMu…`](https://testnet.nearblocks.io/txns/HSQqnRMupfLQeSi47h4dHv2K47WmDMBkT4CpuZuDpZR8)). The full local demo (option 1) uses a mock root. Limits: [Limits and trust](#limits-and-trust).

Demo video: (link added at submission)

## Try it in 2 minutes

Live exit (Node 22, network, no accounts):

```sh
npm ci && npx tsc -b && scripts/try-live.sh
```

It prints every check of the live exit (`✔ VERIFIED`), starts a local SOCKS5 proxy on `127.0.0.1:18180`, and shows your IP next to the IP a website sees through the exit (the Phala machine). It changes no system settings, needs no sudo, and nothing else on the machine uses the proxy. Run non-interactively (CI, an AI agent) it stops by itself; in a terminal the proxy stays up for a browser until Ctrl-C.

Offline (no network): the same exit's quote and registry state, captured 2026-11-12, replayed:

```sh
npm ci && npx tsc -b && node client/dist/cli.js vpn verify --fixture fixtures/live-exit
```

You see 16 `✔` lines and `✔ VERIFIED (FIXTURE REPLAY …)`. The full local demo with revocation (needs Rust) is [option 1](#try-it-all-options).

## Numbers

- **188.08 Tgas:** one NEAR transaction verified the live exit's real Intel TDX quote inside the contract, **all 13 checks** (DCAP signature, TCB, event log, compose, allowlists, key binding), then listed its keys ([tx `HSQqnRMu…`](https://testnet.nearblocks.io/txns/HSQqnRMupfLQeSi47h4dHv2K47WmDMBkT4CpuZuDpZR8)).
- **1 live exit** on Intel TDX: TCB `UpToDate`, debug off, image pinned by digest, container logging off, only ports 80 and 443, at most 32 tunnels.
- **298 client tests (1 skipped) and 60 contract tests** pass (see [`NOTES-DECISIONS.md`](NOTES-DECISIONS.md), [`contracts/near/README.md`](contracts/near/README.md)).
- **Owner revoke and re-allow** transactions ran on the NEAR testnet registry (on the test compose; a client refusing right after a revocation is shown on the local demo stack) ([revoke tx](https://testnet.nearblocks.io/txns/3FnZ8bG8k9biUcH5SjtzqpBDmHVU1hmREJGT1vfXh2yz), [re-allow tx](https://testnet.nearblocks.io/txns/642fevAQzKKwBFX3xYMZY9edQ3FsxC81HeBjncNzpUpV)).

## Tracks

Proposed (Erhan confirms at submission): **Privacy & Private AI** (primary) · AI Security & Defense

## What NEAR does here

A NEAR contract on testnet ([`pe-vpnreg-erhan.testnet`](https://testnet.nearblocks.io/address/pe-vpnreg-erhan.testnet)) runs Intel DCAP verification itself, with `dcap-qvl` inside the contract. It also checks the dstack event log, the compose hash and the OS allowlists before it lists an exit's keys. The owner can revoke a build on chain. The client reads the registry before every new connection, so a revoked build is refused on the next connection, even with a cached attestation. The same contract anchors Merkle roots of session receipts.

[Judge path](#how-to-verify-each-claim) · [Limits and trust](#limits-and-trust) · [AI use](#ai-use) · [Prior code](#prior-code-and-hackathon-window-rules-q-001q-003q-004) · [History](docs/HISTORY.md)

---

## The judge's one-sentence version

*ProvenExit's client refuses to send traffic unless an Intel-signed TDX quote proves the exit runs an approved, logging-disabled build listed on a NEAR registry that itself verified that quote on-chain, and when the owner revokes the build on NEAR, the very next connection is refused.* The live exit on Phala runs exactly this path; the local demo stack runs it on a mock root.

## How to verify each claim

| claim | command / evidence | expected |
|---|---|---|
| the live exit is real Intel TDX, approved and registered | `scripts/try-live.sh` (or `vpn verify` with `deploy/testnet/env.live`) | every check `✔`, `✔ VERIFIED`, then a different IP through the exit |
| the same, without network | `node client/dist/cli.js vpn verify --fixture fixtures/live-exit` | `✔ VERIFIED (FIXTURE REPLAY …)` |
| NEAR verified Intel's signature itself | registration tx [`HSQqnRMu…`](https://testnet.nearblocks.io/txns/HSQqnRMupfLQeSi47h4dHv2K47WmDMBkT4CpuZuDpZR8) | success, 188.08 Tgas: all 13 checks ran in the contract |
| the exit image is pinned and logging is off | `deploy/phala/docker-compose.yml`; `checkDstackComposePolicy` in [`packages/shared/src/attest/compose-policy.ts`](packages/shared/src/attest/compose-policy.ts) | image by digest, `logging.driver: none`; the same check rejects the real 2026-11-09 spike compose (`E_COMPOSE_POLICY`) |
| image = this source | [`scripts/build-exit-image.sh`](scripts/build-exit-image.sh) builds it from the `vpn-honest` bundle and [`deploy/phala/Dockerfile`](deploy/phala/Dockerfile) | not reproducible yet: a rebuild is not shown to give the same digest (no build provenance) |
| revocation works | option 1 (MOCK stack) or the testnet revoke/re-allow txs above | `refused with E_COMPOSE_NOT_ALLOWED`, then restored by re-approval |
| no destination in receipts | [`SPEC-VPN.md`](SPEC-VPN.md) §5; e2e scans the exits' output and run directory | only hashes, sequence numbers and timestamps |

## Try it (all options)

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
   - long checkout paths: macOS limits Unix socket paths to 104 bytes, so when `<run root>/<id>-host/…` would not
     fit, the stack puts its host sockets in a short `<run root>/plr-<hash>` directory, or, if even that is too long, under
     `os.tmpdir()` (or `/tmp`). Any clone path works; `PLR_RUN_ROOT` is only needed to move the (non-socket) run state elsewhere.

2. **Replay the live exit's attestation offline** — needs only `npm ci` and the TypeScript build:

   ```sh
   npm ci && npx tsc -b && node client/dist/cli.js vpn verify --fixture fixtures/live-exit
   ```

   - see: every check `✔`, then `✔ VERIFIED (FIXTURE REPLAY …)` with the registration tx. No network is used; the
     DCAP check runs at the capture time (2026-11-12).
   - the older test-VM quote (2026-11-09, before the exit existed) is kept too:
     `node client/dist/cli.js vpn verify --fixture fixtures/phala-spike/replay`. It shows `✔ quote signature chain to root`, `✔ Intel TCB status accepted`, then the expected refusal
     `✘ E_REPORT_DATA_KEYS` — the recorded 2026-11-09 Phala CVM asked dstack for `report_data = 64 × 0x42`, so it
     never bound an exit's keys. That is the same point at which the on-chain registration stopped (tx
     `9AUTujEQ…`, check 13 of 13, after checks 1–12 passed). No network is used; the DCAP check runs at the capture
     time.

3. **Live exit:** `scripts/try-live.sh` (above). The exit URL, registry and Intel root are in
   [`deploy/testnet/env.live`](deploy/testnet/env.live). [`scripts/demo-live.sh`](scripts/demo-live.sh) drives the
   demo sequence (`vpn verify` → browse → owner revoke → refusal → re-allow) against it; it signs nothing itself.
   The exit is paid by the hour, so it runs during judging but may be stopped afterwards; option 2 needs no exit.

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

## NEAR contract details

- Contract [`pe-vpnreg-erhan.testnet`](https://testnet.nearblocks.io/address/pe-vpnreg-erhan.testnet)
  ([`contracts/near`](contracts/near), near-sdk 5.29.1): owner allowlist (compose hash, OS measurement), operator
  organizations, instance records, receipt anchors, and **on-chain Intel DCAP verification**.
- `register_instance_tdx` runs `dcap-qvl` 0.7.1 inside the contract: thirteen ordered checks (DCAP quote signature and
  TCB status, dstack event log, compose hash, allowlists, `report_data` binding) before an exit's keys are listed. It
  is payable (0.1 NEAR) and called with 300 Tgas. Measured: **179.63 Tgas** to DCAP-verify dcap-qvl's sample quote
  in a near-sandbox spike (test-clock build); on testnet, the live exit's registration passed all 13 checks for
  **188.08 Tgas** ([tx `HSQqnRMu…`](https://testnet.nearblocks.io/txns/HSQqnRMupfLQeSi47h4dHv2K47WmDMBkT4CpuZuDpZR8)). An earlier run on the 2026-11-09 test-VM quote burnt 186.03 Tgas and stopped,
  as designed, at check 13 (that VM never bound an exit's keys).
- Deployed wasm: 622 282 bytes, SHA-256 `e2864a9c75f592af91cbdf36ba3918e5793434a949f1daca2b92df40db2b1bdc`.
  Initialization (`new`, owner `pe-owner-erhan.testnet`, root `INTEL`, TTL 86 400 000 ms): tx
  [`FyRSR12vo3KXEwmH8DN7DJQ78SFFHcXoYKeRREUCUWj`](https://testnet.nearblocks.io/txns/FyRSR12vo3KXEwmH8DN7DJQ78SFFHcXoYKeRREUCUWj).
- Operator `pe-op-erhan.testnet` approved as organization `erhan-demo`: tx
  [`G24JXkyLJZQjV8FFHeG9x5ZGy9mNVgwKtSi8p8xEZHL1`](https://testnet.nearblocks.io/txns/G24JXkyLJZQjV8FFHeG9x5ZGy9mNVgwKtSi8p8xEZHL1).
- The live exit's compose hash `6b56436b…e2c0` was allowed by the owner in tx
  [`8fU3ScGVptLev9qdGbBsW72kJDcye9CzKTLpQzaKh8dm`](https://testnet.nearblocks.io/txns/8fU3ScGVptLev9qdGbBsW72kJDcye9CzKTLpQzaKh8dm); its OS measurement is the same `821d442f…d323d`
  (production `dstack-0.6.1`). The exit then registered itself: tx
  [`HSQqnRMupfLQeSi47h4dHv2K47WmDMBkT4CpuZuDpZR8`](https://testnet.nearblocks.io/txns/HSQqnRMupfLQeSi47h4dHv2K47WmDMBkT4CpuZuDpZR8). It re-registers every 6 h (records expire after 24 h)
  and anchors receipt roots on the same contract.
- Allowlists for the **spike** (not an exit) compose `b9823a79…d05f` and OS measurement `821d442f…d323d`. They are
  allowed on the INTEL registry **only to demonstrate checks 1–12**; the client refuses that compose with
  `E_COMPOSE_POLICY` (no `exit` service, unpinned image), but the registry itself would list a registration under it,
  so the owner should `revoke_compose b9823a79…` once the demo video is recorded (not done here): txs
  [`EmWz2Uawni6PicfCqrG8YwkZeZwgkyQMTCbGACQwq6sM`](https://testnet.nearblocks.io/txns/EmWz2Uawni6PicfCqrG8YwkZeZwgkyQMTCbGACQwq6sM)
  and [`E3to6jCjasF37vLqRtsFKLsehLpXL2J1xK7PNFbHnwbX`](https://testnet.nearblocks.io/txns/E3to6jCjasF37vLqRtsFKLsehLpXL2J1xK7PNFbHnwbX).
- Revocation works on testnet: `revoke_compose b9823a79…` tx
  [`3FnZ8bG8k9biUcH5SjtzqpBDmHVU1hmREJGT1vfXh2yz`](https://testnet.nearblocks.io/txns/3FnZ8bG8k9biUcH5SjtzqpBDmHVU1hmREJGT1vfXh2yz),
  re-allow tx [`642fevAQzKKwBFX3xYMZY9edQ3FsxC81HeBjncNzpUpV`](https://testnet.nearblocks.io/txns/642fevAQzKKwBFX3xYMZY9edQ3FsxC81HeBjncNzpUpV).

## Limits and trust

Every limit and disclosure from the earlier README is kept here.

### Status of this snapshot

- **The live exit runs on Intel TDX** on Phala Cloud (instance `tdx.small`, production OS `dstack-0.6.1`, not the
  SSH-enabled dev OS), from the image `ghcr.io/erhantrk/provenexit-exit@sha256:7e53f383…1ad5` pinned in
  [`deploy/phala/docker-compose.yml`](deploy/phala/docker-compose.yml). The NEAR contract verified its quote on chain
  (all 13 checks) before listing its keys ([tx `HSQqnRMu…`](https://testnet.nearblocks.io/txns/HSQqnRMupfLQeSi47h4dHv2K47WmDMBkT4CpuZuDpZR8)). It is paid by the hour on Phala; it runs through
  judging and may be stopped afterwards. [`fixtures/live-exit/`](fixtures/live-exit) keeps a replayable capture.
- **Safeguards in the measured compose:** the exit dials only ports 80 and 443 (`PLR_VPN_ALLOWED_PORTS`) and serves at
  most 32 tunnels at once (`PLR_VPN_MAX_TUNNELS`). Both are part of the compose hash the owner approved.
- **The local demo stack (option 1) runs on the MOCK root** — the pre-existing mode, unchanged. It exercises the real
  protocol, SOCKS5 proxy, egress policy, receipts and registry/revocation path, but it is not Intel hardware.
- **History:** until 2026-11-12 the plan's fallback S1-F2 applied (no exit on Phala); the only real quote was a
  2026-11-09 test VM ([`fixtures/phala-spike/`](fixtures/phala-spike)), which passed checks 1–12 on chain (tx
  [`9AUTujEQ…`](https://testnet.nearblocks.io/txns/9AUTujEQv8p1R1z7SKEpNa5BYFw3a9ZZerkKmpQb5NRB)) and stopped at
  check 13 because it never bound an exit's keys. On 2026-11-12 the exit image was built (T13) and deployed.

### What it does not prove

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
- **MOCK ROOT, not Intel, for the local demo stack (option 1).** Its quote is signed by a locally generated test root
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
- **A second trust root: the contract account's own key.** The final review found one **FullAccess** key still on
  `pe-vpnreg-erhan.testnet` (`view_access_key_list`); it was not removed. Whoever holds it can deploy a different
  wasm that answers `is_compose_allowed` with `true` and invents `get_instance` records while `get_root` stays
  `INTEL`; the client pins only the contract id, so it would trust those answers, and "NEAR verified Intel's
  signature" would then hold for nothing. The deployed wasm is also not reproducible: it was built with
  `non-reproducible-wasm`, and a rebuild from this source on the reviewer's machine gave SHA-256 `3bab2448…`, not the
  deployed `e2864a9c…`, so a reader cannot tie the deployed code to this source. Fix, not done here (needs a
  redeploy and a human with the key): `cargo near build reproducible-wasm`, redeploy, delete the full-access key (or
  route upgrades through the owner/DAO), and optionally pin `view_account.code_hash` in the client.
- **In a cloud deployment, Phala's dstack-gateway terminates TLS.** HTTPS to the exit ends at the gateway
  (`https://<app-id>-18200.<gateway-domain>`), which then speaks to the container; the tunnel inside is end-to-end
  encrypted to the attested key, so the gateway sees only ciphertext, cannot impersonate the exit (its key is inside
  the signed quote) and cannot read or forge tunnel content. It can still observe connection timing and volume, and
  it is a liveness dependency ("refuse to serve" is always possible). The live exit runs behind it.
- **The registry owner's honesty** (see above) and **the registry RPC endpoint is trusted**: NEAR view results carry
  no state proofs, so whoever answers the client's `get_root` / `is_*_allowed` / `get_instance` calls decides checks
  3, 5 and the allowlist. The client therefore only talks to the registry over `https:`, or plain `http:` to a
  loopback address; `PLR_NEAR_RPC=http://<remote>` is refused. Pick an RPC provider you trust (the demos use
  `https://rpc.testnet.fastnear.com`); a quorum of independent RPCs or light-client proofs is future work.
- **TEE vendor trust and side channels** are out of scope: Intel, the dstack OS image and the TDX module are trusted
  roots; micro-architectural side channels are not defended.

## Prior code and hackathon window (rules Q-001/Q-003/Q-004)

- **Disclosed baseline:** commits `c2a35e4`..`9bd402e` (2026-10-23/24 — after the 2026-10-19 announcement, before the
  2026-11-01 start) built the mock-root protocol, the NEAR registry, the VPN exit and the multi-chain registries. They
  are prior work and are not claimed as hackathon-window work.
- **Judged work:** `9bd402e`..`hackathon-submission` (from 2026-11-09): the real Intel TDX path (dstack event log,
  DCAP in the client and on-chain in the contract, compose policy, the Phala spike, the local stack, the exit image
  and the live TDX exit).
- Branches and tags: all of this work is on `main` (the same commits as the branch `provenexit`). The tags
  `window-start` (`c2a35e4`), `real-tdx-start` (`9bd402e`) and `hackathon-submission` (final HEAD) are to be created by
  the maintainers; none exists in this snapshot, so the links use `main`.
- Diffs: [9bd402e...main](https://github.com/erhantrk/provenexit/compare/9bd402e...main) (the real-TDX
  work) and [the full history](https://github.com/erhantrk/provenexit/commits/main).
- The design record is [`docs/plan/INTERFACES.md`](docs/plan/INTERFACES.md) (frozen interfaces), with the decisions and
  findings in [`NOTES-DECISIONS.md`](NOTES-DECISIONS.md). The internal plan and task list it cites (PLAN, TASKS) are not published.
- This file replaces the October 2026 tour of the pre-hackathon code, which is kept verbatim at [`docs/PLR-README-2026-10.md`](docs/PLR-README-2026-10.md). Older history: [`docs/HISTORY.md`](docs/HISTORY.md).

## AI use

Large parts of the code, specs and tests were written with AI coding assistants, directed and reviewed by Erhan
Türker (design decisions, review, accounts, keys, deployment, submission). The planning documents (a plan, a task list, and the
frozen interfaces in `docs/plan/INTERFACES.md`) were generated by Claude; only the interfaces are published. Details, including which assistant did what:
[`AI_USE.md`](AI_USE.md).

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

This is the live deployment (the configuration `deploy/phala/` pins). The local demo stack runs the same path with a
MOCK root in place of Intel.

## Repository map

| path | what |
|---|---|
| [`packages/shared`](packages/shared) `@plr/shared` | protocol: quote parsing (MOCK + INTEL), dstack event log, DCAP verifier, collateral, compose policy, key binding, tunnel crypto, receipts, `verifyAttestation` |
| [`client`](client) `@plr/client`, `plr` / `provenexit` CLI | `VpnClient` / `TwoHopClient`, `NearRegistry`, the SOCKS5 proxy, `vpn verify`, `vpn inspect`, `vpn verify --fixture` |
| [`enclave`](enclave) `@plr/enclave` | exit bundle, `DstackAttester`, collateral cache, the mock TDX host, mock LLM, test-only logging builds |
| [`contracts/near`](contracts/near) | the registry: allowlists, `register_instance_tdx` (on-chain dcap-qvl), `anchor_receipts`, views |
| [`SPEC-TDX.md`](SPEC-TDX.md) | the frozen INTEL/dstack byte formats and the contract/client additions this code implements |
| [`deploy/phala`](deploy/phala) | the measured exit compose (the live image, pinned by digest), its Dockerfile, and the spike compose |
| [`fixtures/live-exit`](fixtures/live-exit) | the live exit's attestation bundle, nonce and registry snapshot (2026-11-12), replayed by `vpn verify --fixture` |
| [`fixtures/phala-spike`](fixtures/phala-spike) | the real 2026-11-09 TDX dump, its parsed parts, and the INTERFACES §3.3 replay fixture |
| [`e2e`](e2e) | the stack harness (near-sandbox, zebrad, anvil, Stellar, Solana), attacker scenarios, locked e2e tests |
| [`scripts`](scripts) | `demo.sh` (option 1), `demo-live.sh`, `dev-up.sh` / `dev-down.sh`, `owner.sh`, `pccs-live-check.mjs` |

Elsewhere in the repo, not part of the NEAR submission (mentioned once, as the plan asks): the private LLM router
(PLR-v1, `plr verify` / `plr chat` / `plr proxy`, still exercised by `scripts/demo.sh`) and the multi-chain registries
([`SPEC-CHAINS.md`](SPEC-CHAINS.md): EVM/Monad, Stellar, Solana in `contracts/{evm,stellar,solana}`, Zcash record
logs in `client/src/zcash-registry.ts`). They are pre-hackathon temo code (October 2026). `scripts/demo.sh` runs the
NEAR path only by default; `PLR_DEMO_CHAINS=all PLR_LLM=mock bash scripts/demo.sh` also runs those older chain stages
(each only when its node tools are installed).

Older history (commit timeline, multi-chain work, the October tour): [`docs/HISTORY.md`](docs/HISTORY.md).

## Libraries

`@noble/curves`, `@noble/hashes`, `@noble/ciphers`, `near-api-js`, `@phala/dcap-qvl` 0.7.1 (Apache-2.0),
`@phala/dstack-sdk` 0.5.8 (Apache-2.0), `yaml` 2.8.1, `viem`, `@solana/web3.js`, `@stellar/stellar-sdk`, `esbuild`,
`vitest`, `near-sdk` 5.29.1, the `dcap-qvl` 0.7.1 crate (MIT), `sha2`, `p256`, `ed25519-dalek`, `forge-std`.
Test vectors from dcap-qvl's `sample/` (MIT). Infrastructure: Phala Cloud (dstack: the live exit and a test CVM), NEAR testnet,
FASTNEAR RPC, Phala PCCS.

## Other project by the same submitter (rule Q-015)

Erhan also submits **ZeroInit**, an independent project that shares no code with this one (repository link added at
submission).

## License

MIT, see [`LICENSE`](LICENSE).
