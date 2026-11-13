# Verify each claim

Every claim ProvenExit makes, the command or transaction that checks it, and what you should see. Commands run from
a clone of this repo with Node 22 unless they start with `npx`. Build once with `npm ci && npx tsc -b`.

## The claims

| claim | how to check | expected |
|---|---|---|
| The live exit is real Intel TDX, runs the approved build with logging off, and is registered | `npx provenexit verify` (or `scripts/try-live.sh` from the repo) | 20 `✔` lines and `✔ VERIFIED`; `tcb: UpToDate`; `image: ghcr.io/erhantrk/provenexit-exit@sha256:74c6d1c5…2785`; `compose hash: 2f4100e6…dabf`; `OS measurement: 821d442f…d323d` |
| The same, without network | `node client/dist/cli.js vpn verify --fixture fixtures/live-exit` | 16 `✔` lines, one `·` line, `✔ VERIFIED (FIXTURE REPLAY of https://d2c65be0…-18200.dstack-pha1-prod9.phala.network, captured 2026-11-12T20:13:49.641Z; …; registration tx 6yBT47ij…)` |
| NEAR verified Intel's signature itself, on chain | registration tx [`6yBT47ij…`](https://testnet.nearblocks.io/txns/6yBT47ijg4AgqpYGUk6dUw9tdD3kRFw4iScL7aaSBCp) | success, 186.76 Tgas: `register_instance_tdx` ran all 13 checks in the contract and emitted `instance_registered` with `"root_kind":"INTEL"`, `"tcb_status":"UpToDate"` |
| The registry's code cannot change and is this repo's code | nearblocks: [`vpnreg.pe-owner-erhan.testnet`](https://testnet.nearblocks.io/address/vpnreg.pe-owner-erhan.testnet) has no access keys (key deleted in [`58sZ72Aa…`](https://testnet.nearblocks.io/txns/58sZ72Aa7aAtCFjYQnKxxkcZ2PbGoS6D1yhBam343kiz)); rebuild in [REPRODUCE.md](REPRODUCE.md#the-registry-contract), or `near contract verify deployed-at vpnreg.pe-owner-erhan.testnet network-config testnet now` (rebuilds from the source link in the contract's own metadata, in Docker); SourceScan verified the same build ([contract tab](https://testnet.nearblocks.io/address/vpnreg.pe-owner-erhan.testnet?tab=contract), `v2-verifier.sourcescan.testnet`) | code hash `C1hvenbrzHKN1n1f2z63Duburr8YXLAKBescrEvarCGM`, the same as the rebuild; check 1 of `verify` passes |
| The client refuses a registry running other code | pin a different code hash: `PLR_VPN_REGISTRY_CODE_HASH=C1hvenbrzHKN1n1f2z63Duburr8YXLAKBescrEvarCGN npx provenexit verify` (last character changed) | `✘ registry contract code hash matches the pinned build … [E_REGISTRY_CODE_HASH]`, `✘ REFUSED — E_REGISTRY_CODE_HASH` |
| The exit image is pinned and logging is off | [`deploy/phala/docker-compose.yml`](../deploy/phala/docker-compose.yml); `checkDstackComposePolicy` in [`packages/shared/src/attest/compose-policy.ts`](../packages/shared/src/attest/compose-policy.ts) | image by digest, `logging.driver: none` on `exit`; the same check rejects the 2026-11-09 spike compose (`E_COMPOSE_POLICY`) |
| The running image is exactly what this source builds | `scripts/verify-exit-image.sh` in a clean checkout (git and Docker with buildx) | last line `MATCH`; `built` and `pinned` both `sha256:74c6d1c52e2ce72698fb238e52e27d03eefe1770af00a1dae3405d3474f22785` |
| … also on a second machine | the [verify exit image](https://github.com/erhantrk/provenexit/actions/workflows/verify-exit-image.yml) workflow (GitHub-hosted ubuntu, `linux/amd64`) | `MATCH` in the step log and job summary, e.g. run [43319605400](https://github.com/erhantrk/provenexit/actions/runs/43319605400) on `47d9794` |
| Revocation refuses the next connection | [`scripts/demo-live.sh`](../scripts/demo-live.sh) against the live exit with the owner's two transactions (run on 2026-11-13: [`2JJdbyoG…`](https://testnet.nearblocks.io/txns/2JJdbyoGGr5GewNMDd9aeGrDSDjQ33xDoAWWovR8s1u2), [`tdQDjQkF…`](https://testnet.nearblocks.io/txns/tdQDjQkF6ZBVcsxuebHwuvykLEDJ9CvuuVSkicY57LW)), or the local demo stack (below) | `refused with E_COMPOSE_NOT_ALLOWED` after `revoke_compose`, `VERIFIED` again after `allow_compose` |
| A logging build or a man in the middle is refused | local demo stack (below) | evil logging exit refused with `E_COMPOSE_NOT_ALLOWED`, MITM refused with `E_REPORT_DATA_KEYS` |
| No destination in receipts | [`spec/SPEC-VPN.md`](spec/SPEC-VPN.md) §5; the e2e tests scan the exits' output and run directory | only hashes, sequence numbers and timestamps |
| Fresh Intel collateral is fetched by the client, never taken from the exit | `npx provenexit verify`; then `PLR_PCCS_URL=https://127.0.0.1:1 npx provenexit verify` (a PCCS that cannot be reached) | header `collateral: fetched fresh by this client from https://api.trustedservices.intel.com` and check 6 `✔`; with the unreachable PCCS: `✘ fresh Intel collateral … [E_COLLATERAL_FETCH]`, `✘ REFUSED — E_COLLATERAL_FETCH` |

What the exit attests to, without the registry: `npx provenexit inspect` prints the compose hash, OS measurement,
key hash, TCB and images, the values the owner approves with `allow_compose` / `allow_os`.

Check the registry directly over NEAR RPC (no tools needed beyond `curl`):

```sh
curl -s https://rpc.testnet.fastnear.com -H 'content-type: application/json' -d '{"jsonrpc":"2.0","id":1,"method":"query","params":{"request_type":"view_access_key_list","finality":"final","account_id":"vpnreg.pe-owner-erhan.testnet"}}'
# … "keys":[] …
curl -s https://rpc.testnet.fastnear.com -H 'content-type: application/json' -d '{"jsonrpc":"2.0","id":1,"method":"query","params":{"request_type":"view_account","finality":"final","account_id":"vpnreg.pe-owner-erhan.testnet"}}'
# … "code_hash":"C1hvenbrzHKN1n1f2z63Duburr8YXLAKBescrEvarCGM" …
```

## Ways to run it

1. **Live exit, one command:** `npx provenexit verify`, then `npx provenexit connect` for a local SOCKS5 proxy on
   `127.0.0.1:18180` (use `socks5h://`, e.g. `curl -x socks5h://127.0.0.1:18180 https://ifconfig.me`).

2. **Live exit from the repo:** `npm ci && npx tsc -b && scripts/try-live.sh`. It prints every check, starts the
   local proxy on `127.0.0.1:18180`, and shows your IP next to the IP a website sees through the exit (the Phala
   machine). It changes no system settings, needs no sudo, and nothing else on the machine uses the proxy. Run
   non-interactively (CI, an AI agent) it stops by itself; in a terminal the proxy stays up for a browser until
   Ctrl-C. The exit URL, registry, code-hash pin and Intel root are in [`deploy/testnet/env.live`](../deploy/testnet/env.live).

3. **Offline replay of the live exit:** `node client/dist/cli.js vpn verify --fixture fixtures/live-exit`. No
   network: the DCAP check runs at the capture time (2026-11-12 20:13 UTC) on the recorded collateral, so the line a
   live run adds (`fresh Intel collateral fetched by the client from the PCCS`) is printed as `·`, not checked.

4. **Offline replay of the first real quote:** `node client/dist/cli.js vpn verify --fixture fixtures/phala-spike/replay`.
   This is a 2026-11-09 test VM on Phala, before the exit existed, which asked dstack for `report_data = 64 × 0x42`.
   It shows `✔ quote signature chain to root`, `✔ Intel TCB status accepted`, `✔ TD debug attribute clear`, then
   the expected refusal `✘ report_data binds the exit's keys [E_REPORT_DATA_KEYS]` and `✘ REFUSED`: it never bound an
   exit's keys. The on-chain registration of that quote stopped at the same point (tx
   [`9AUTujEQ…`](https://testnet.nearblocks.io/txns/9AUTujEQv8p1R1z7SKEpNa5BYFw3a9ZZerkKmpQb5NRB), check 13 of 13,
   after checks 1–12 passed).

5. **The full local demo, with revocation** (no accounts; needs Rust and `cargo-near`):

   ```sh
   npm ci && npx near-sandbox --version && npx tsc -b && npm run build -w @plr/enclave && (cd contracts/near && cargo near build non-reproducible-wasm --no-abi) && bash scripts/demo.sh
   ```

   It runs on a local near-sandbox with the MOCK root (a local test root, not Intel). You see `✔ VERIFIED`, a fetch through the SOCKS5
   proxy and the attested tunnel, the evil exit refused with `E_COMPOSE_NOT_ALLOWED`, the MITM refused with
   `E_REPORT_DATA_KEYS`, owner revocation then a refused connection and a restore, DoH-only DNS (resolver down ⇒
   `E_DNS`), two-hop, and the final lines `━━ VPN PASSED`, `━━ DNS + TWO-HOP PASSED`, `━━ DEMO PASSED`. Nothing is left
   running afterwards.
   - `npx near-sandbox --version` is needed once per install: it downloads NEAR's sandbox binary (about 70 MB) into
     `node_modules` (set `NEAR_SANDBOX_BIN_PATH` to reuse an existing binary).
   - Long checkout paths: macOS limits Unix socket paths to 104 bytes, so when `<run root>/<id>-host/…` would not
     fit, the stack puts its host sockets in a short `<run root>/plr-<hash>` directory, or, if even that is too long,
     under the OS temp dir. Any clone path works; `PLR_RUN_ROOT` only moves the (non-socket) run state.

6. **Live demo sequence:** [`scripts/demo-live.sh`](../scripts/demo-live.sh) drives verify → browse → owner revoke →
   refusal → re-allow against the live exit. It signs nothing itself; the two owner transactions are run by the
   owner with [`scripts/owner.sh`](../scripts/owner.sh).

7. **Status bundle:** `node status/provenexit-status.mjs` prints the live status JSON (no install); the site
   <https://provenexit.vercel.app> shows the same. [`status/sample-online.json`](../status/sample-online.json) is a
   live run (verdict `VERIFIED`, 20 checks); [`status/sample-offline.json`](../status/sample-offline.json) is a run
   with the exit made unreachable for that process (the exit itself stayed up; chain data is live), recorded
   2026-11-12 20:15 UTC, before the client had its two newest checks, so it lists 18 checks and `E_BAD_RESPONSE`.

8. **MCP server:** `claude mcp add provenexit -- npx -y -p provenexit provenexit-mcp`, then ask the agent to verify
   the exit or fetch a page through it. From the repo: `claude mcp add provenexit -- node /path/to/mcp/dist/provenexit-mcp.mjs`.

## Tests

Counted 2026-11-13 on the owner's machine, all passing:

| suite | command | tests |
|---|---|---|
| shared, client, enclave, MCP | `npx tsc -b && npm run build -w @plr/enclave && npm test` | 260, 201, 155 (+1 skipped), 9 |
| contract | `cd contracts/near && cargo test --release` | 60 |
| e2e (near-sandbox, MOCK root) | `npm run e2e` (after the near-sandbox and contract build steps of option 5) | 58 |
| site | `cd site && npm test` | 24 |

CI ([tests](https://github.com/erhantrk/provenexit/actions/workflows/tests.yml)) runs the unit suites, the offline
replay and the contract tests on every push to `main`.

## The on-chain record

All on NEAR testnet. Owner `pe-owner-erhan.testnet` until 2026-11-13, then the 2-of-3 council `pe-owners.sputnikv2.testnet`; operator `pe-op-erhan.testnet` (organization `erhan-demo`).

**The live registry `vpnreg.pe-owner-erhan.testnet`** (keyless, reproducible build):

| what | tx |
|---|---|
| account created | [`DnEwrCy4…`](https://testnet.nearblocks.io/txns/DnEwrCy4FNs9AybgXwWnVm9TJy9Spveoio7EWJ5VLPKT) |
| deployed and initialized (`new`, owner `pe-owner-erhan.testnet`, root `INTEL`, TTL 86 400 000 ms) | [`HLKDypfv…`](https://testnet.nearblocks.io/txns/HLKDypfvxYKi55j5RnS7pxfwVbTrNNtRWgmTVhvZBg5L) |
| its only access key deleted: the code can never change | [`58sZ72Aa…`](https://testnet.nearblocks.io/txns/58sZ72Aa7aAtCFjYQnKxxkcZ2PbGoS6D1yhBam343kiz) |
| operator `pe-op-erhan.testnet` approved as organization `erhan-demo` | [`4Jxoaw46…`](https://testnet.nearblocks.io/txns/4Jxoaw46DokBTCHWXTsToD2ZiFRSaqXCzefkKuo1Ajox) |
| OS measurement `821d442f…d323d` (production `dstack-0.6.1`) allowed | [`61pQhJr3…`](https://testnet.nearblocks.io/txns/61pQhJr3dbHZTmk9NVquB5yKu6xz18mLWRTD5iRYf722) |
| first exit compose `9411d0f7…c85c` (image `7e53f383…`) allowed | [`HeP6W5LM…`](https://testnet.nearblocks.io/txns/HeP6W5LMo9bnGAi9mTF4aoeEQSJrxJvdmcybE6cBRdFx) |
| that exit registered itself, 13/13, 186.34 Tgas | [`EZDveHx5…`](https://testnet.nearblocks.io/txns/EZDveHx5571sdsm72MrbC7xayf4rhhpp8BTa6MFcUruN) |
| 2026-11-12 20:05:57 UTC: current compose `2f4100e6…dabf` (image `74c6d1c5…2785`) allowed | [`GdY61VR2…`](https://testnet.nearblocks.io/txns/GdY61VR2ZBFR9SpgwVCmb7e6AN7Mx5PRt59XmKio9HhD) |
| 20:06:19 UTC: the exit registered itself, 13/13, 186.76 Tgas, key hash `9f7434d4…bba8f` | [`6yBT47ij…`](https://testnet.nearblocks.io/txns/6yBT47ijg4AgqpYGUk6dUw9tdD3kRFw4iScL7aaSBCp) |
| 20:06:50 UTC: old compose `9411d0f7…` revoked | [`9HhvupZA…`](https://testnet.nearblocks.io/txns/9HhvupZAQWnrdFtXDMUuA4w6sVYfzHPF8Mtk4VXuhNVx) |
| 2026-11-13 08:28 UTC, live demo: current compose revoked, the next connection refused (`E_COMPOSE_NOT_ALLOWED`) | [`2JJdbyoG…`](https://testnet.nearblocks.io/txns/2JJdbyoGGr5GewNMDd9aeGrDSDjQ33xDoAWWovR8s1u2) |
| seconds later: re-allowed, the next connection works again | [`tdQDjQkF…`](https://testnet.nearblocks.io/txns/tdQDjQkF6ZBVcsxuebHwuvykLEDJ9CvuuVSkicY57LW) |
| 2026-11-13: council DAO `pe-owners.sputnikv2.testnet` created (3 members, threshold 2, no access keys) | [`3ywCUrJW…`](https://testnet.nearblocks.io/txns/3ywCUrJWrLMRsSPe3bRP8rURxHzqf7T9rkmb9PtKW2n4) |
| factory auto-update turned off by a 2-of-3 proposal | [`CMK9GzuD…`](https://testnet.nearblocks.io/txns/CMK9GzuDo8hnpY2sfgNHAsaABHPTSa8NpgRTko4zjGeW), [`BPWDHNp6…`](https://testnet.nearblocks.io/txns/BPWDHNp6S3oYPJhLBBRM9goThesGRB2Pe4supzhNNQAx), [`8DkW2KYg…`](https://testnet.nearblocks.io/txns/8DkW2KYgWgKtnobeCvgxjmHd2YdvoYeLAbYd6PyBVY9b) |
| the single owner names the DAO as next owner (`propose_owner`) | [`BLaRVAn1…`](https://testnet.nearblocks.io/txns/BLaRVAn19UAjboeJEJQ9Xqc5nN7f2Yn1N9AeqYV1ao3K) |
| DAO proposal `accept_owner`: first approval (nothing runs), second approval (owner = DAO) | [`8w4hSwiy…`](https://testnet.nearblocks.io/txns/8w4hSwiybzMod8Jj8UU9MGJE1RN7PPNeMs3YV6w5AgWv), [`AG21wQyc…`](https://testnet.nearblocks.io/txns/AG21wQycaDwUC31kHHjP6Wm9SfvfE5evubKAKcBtwAi4), [`HzsVd6XC…`](https://testnet.nearblocks.io/txns/HzsVd6XCWaB3JCxKfhktTAvP7htxKtNESsqczxHfPgsq) |

Only the live exit's compose is allowed there. The exit re-registers every 6 hours (records expire after 24 hours)
and anchors receipt roots on the same contract.

**The first registry `pe-vpnreg-erhan.testnet`** (retired 2026-11-12; same code, but a non-reproducible build of
622 282 bytes, SHA-256 `e2864a9c…`, with a full-access key left on it; the client no longer uses it):

| what | tx |
|---|---|
| init | [`FyRSR12v…`](https://testnet.nearblocks.io/txns/FyRSR12vo3KXEwmH8DN7DJQ78SFFHcXoYKeRREUCUWj) |
| operator approval | [`G24JXkyL…`](https://testnet.nearblocks.io/txns/G24JXkyLJZQjV8FFHeG9x5ZGy9mNVgwKtSi8p8xEZHL1) |
| spike compose `b9823a79…d05f` and OS measurement `821d442f…d323d` allowed, only to show checks 1–12 on a real quote | [`EmWz2Uaw…`](https://testnet.nearblocks.io/txns/EmWz2Uawni6PicfCqrG8YwkZeZwgkyQMTCbGACQwq6sM), [`E3to6jCj…`](https://testnet.nearblocks.io/txns/E3to6jCjasF37vLqRtsFKLsehLpXL2J1xK7PNFbHnwbX) |
| the spike quote's registration: checks 1–12 pass, stops at 13 (`report_data`) | [`9AUTujEQ…`](https://testnet.nearblocks.io/txns/9AUTujEQv8p1R1z7SKEpNa5BYFw3a9ZZerkKmpQb5NRB) |
| owner revoke of the spike compose, then re-allow | [`3FnZ8bG8…`](https://testnet.nearblocks.io/txns/3FnZ8bG8k9biUcH5SjtzqpBDmHVU1hmREJGT1vfXh2yz), [`642fevAQ…`](https://testnet.nearblocks.io/txns/642fevAQzKKwBFX3xYMZY9edQ3FsxC81HeBjncNzpUpV) |
| the live exit's first 13/13 registration, 188.08 Tgas | [`HSQqnRMu…`](https://testnet.nearblocks.io/txns/HSQqnRMupfLQeSi47h4dHv2K47WmDMBkT4CpuZuDpZR8) |
| spike compose revoked for good (2026-11-12) | [`3DmY4Rqr…`](https://testnet.nearblocks.io/txns/3DmY4RqrDAVknLov5pDYMgAQvjmMpM354eeGZdWifh7n) |

For scale: DCAP-verifying dcap-qvl's sample quote in a near-sandbox spike (test-clock build) took 179.63 Tgas.
