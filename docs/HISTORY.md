# ProvenExit history

Dated events, oldest first. Times are UTC. The current state is in the [README](../README.md); the transactions are
listed in [VERIFY.md](VERIFY.md#the-on-chain-record).

## Prior code and the hackathon window

- **Disclosed baseline:** commits `c2a35e4`..`9bd402e` (2026-10-23/24: after the hackathon's 2026-10-19
  announcement, before its 2026-11-01 start) built the mock-root protocol, the NEAR registry, the VPN exit, a private
  LLM router and registries on other chains. They are prior work and are not claimed as hackathon work. Their README
  is [the baseline README at `9bd402e`](https://github.com/erhantrk/provenexit/blob/9bd402e70b0f909c07f88244d363913f29cc1096/README.md);
  it describes code that is no longer in the tree, and its commands do not run on the current tree.
- **Hackathon work:** everything after `9bd402e` (commits from 2026-11-11; the first real quote is from 2026-11-09): the real Intel TDX path (dstack event log, DCAP in
  the client and on chain in the contract, compose policy, the Phala spike, the local stack, the exit image and the
  live TDX exit), the reproducible image, the keyless registry, the npm package, the MCP server and the status site.
  Diff: [9bd402e...main](https://github.com/erhantrk/provenexit/compare/9bd402e...main); full history:
  [commits](https://github.com/erhantrk/provenexit/commits/main).
- **Branches and tags:** all of this work is on `main` (the same commits as the branch `provenexit`). This snapshot
  has no tags; the boundaries are the commits `c2a35e4` (first baseline commit) and `9bd402e` (last baseline commit).
- The design record is [`spec/SPEC-TDX.md`](spec/SPEC-TDX.md), the frozen Intel/dstack spec. The internal plan, task
  list and build log that some code comments cite are not published.

## Commit timeline

From `git log` (commit dates, converted to UTC).

| date | commits | what |
|---|---|---|
| 2026-10-23 | `c2a35e4`..`de44d25` | PLR-v1 spec and build (NEAR registry, TEE router, client SDK, e2e, demo); PLR-VPN-v1 (SOCKS5 proxy, no-logs exit); VPN milestone 2 (forward-secret tunnel v2, DoH-only exit DNS, two-hop with on-chain operator organizations); the combo milestone (LLM router and VPN exit in one TD) and the multi-chain spec |
| 2026-10-24 | `4172f40`..`9bd402e` | Registries on other chains: a Zcash record log, EVM/Monad (Solidity), Stellar (Soroban), Solana |
| 2026-11-11 | `fdecb3c`..`a1f69b9` | the 2026-11-09 Phala spike fixture, then the Intel/dstack path task by task (DCAP in the contract, compose policy, testnet registry, client fixture replay), review fixes, README and AI_USE |
| 2026-11-12 | `1c60ead`.. | VPN-only cleanup (below), the live exit, the keyless registry, the reproducible image, the status site, the npm package, the code-hash pin and fresh collateral |

## 2026-11-09: the first real quote

Before any exit ran on Phala, a test CVM (the "spike", [`deploy/phala/spike/docker-compose.yml`](../deploy/phala/spike/docker-compose.yml):
a quote dump, never a VPN exit) produced the real TDX evidence in [`fixtures/phala-spike/`](../fixtures/phala-spike).
It asked dstack for `report_data = 64 × 0x42`, so it never bound an exit's keys. On the first testnet registry
`pe-vpnreg-erhan.testnet` its quote passed the on-chain checks 1–12 and stopped at check 13 (tx `9AUTujEQ…`). Until
2026-11-12 the project's fallback applied: no exit on Phala, the local stack on a MOCK root, and this quote as the
only real-hardware evidence.

## 2026-11-12: VPN-only cleanup (pre-hackathon code removed, kept in the baseline commits)

To keep the submission VPN-only, this code was removed from the tree. It remains in the baseline commits
`c2a35e4`..`9bd402e` and in the history up to the removal:

- **The private LLM router (PLR-v1):** the router enclave service, the mock LLM and the llama.cpp builds (the enclave
  build measured `llama-server`), the "combo" build running the router and the VPN exit in one TD (`SPEC-COMBO.md`),
  the router evil build, the client's `plr verify` / `plr chat` / `plr proxy` and the router e2e scenarios.
- **The registries on other chains:** EVM/Monad, Stellar and Solana in `contracts/{evm,stellar,solana}`, the Zcash
  record log, their client readers, enclave writers and e2e drivers, `SPEC-CHAINS.md` and the registration-evidence
  step for chains that do not verify quotes, and the local tool notes.

[`spec/SPEC.md`](spec/SPEC.md) keeps the base the VPN exit uses (quote format, event log, compose rules, key binding,
registry, receipt anchoring, verification order) with unchanged section numbers; the router-only sections are
one-line notes. Some code still carries names from that time (the `plr` CLI name, the `PLR_*` environment
variables, the `@plr/*` packages).

## 2026-11-12: the live exit

The exit image was built on the host (image `sha256:7e53f383…`, not reproducible) and deployed on Phala Cloud
(`tdx.small`, production OS `dstack-0.6.1`). On the first registry the owner allowed it and it registered 13/13
(tx `HSQqnRMu…`, 188.08 Tgas).

## 2026-11-12: keyless, reproducible registry

The registry was redeployed as `vpnreg.pe-owner-erhan.testnet` from a `cargo near build reproducible-wasm` build of
commit `dcd37e6` (SHA-256 `a39ed48c…`, code hash `C1hvenbr…`) and its only access key was deleted, closing the
"full-access key / non-reproducible build" limit of `pe-vpnreg-erhan.testnet`. The live exit's compose (now naming
the new registry) was allowed and the exit registered 13/13 again (tx `EZDveHx5…`, 186.34 Tgas). The first registry
is retired.

## 2026-11-12, 20:05: the exit redeployed from a reproducible image

The exit image build was made reproducible (commit `6740b3f`: multi-stage Dockerfile, constant `SOURCE_DATE_EPOCH`,
pinned BuildKit v0.34.2). Two fresh clones built the same digest, `sha256:74c6d1c5…2785`; it was pushed, pinned in
`deploy/phala/docker-compose.yml` (`9b3571d`) and the Phala CVM (same app id and URL) was updated to it. New compose
hash `2f4100e6…dabf` allowed (tx `GdY61VR2…`), the exit registered 13/13 with new keys (tx `6yBT47ij…`, 186.76 Tgas),
and the previous compose `9411d0f7…` (image `7e53f383…`, registration `EZDveHx5…`) was revoked (tx `9HhvupZA…`).
`fixtures/live-exit`, the status and MCP bundles and the status samples were re-recorded from the new exit at
20:13–20:15; the earlier capture is in git history before `d47bbe8`.

## 2026-11-12, evening: second-machine rebuild, code-hash pin, fresh collateral

- The "verify exit image" workflow (commit `d675a32`) rebuilds the image on a GitHub-hosted `linux/amd64` runner on
  every push to `main`; it prints `MATCH`.
- The npm package `provenexit` (CLI and MCP server, defaults from `deploy/testnet/env.live`) was added, and the
  status site <https://provenexit.vercel.app> went live.
- The client pins the registry contract's code hash (`E_REGISTRY_CODE_HASH`) and fetches fresh Intel collateral
  itself by default (`E_COLLATERAL_FETCH`). Both are client-only; the exit image did not change. The client went from
  18 to 20 checks; `provenexit@0.1.1` ships both.
- The spike compose `b9823a79…` was revoked on the retired registry (tx `3DmY4Rqr…`).

## 2026-11-12/13: docs

The README was shortened; the judge path, limits, architecture and rebuild steps moved to `docs/`, and the three specs
to `docs/spec/`. The verbatim copy of the October README that was kept in `docs/` was removed; it is the
[baseline README at `9bd402e`](https://github.com/erhantrk/provenexit/blob/9bd402e70b0f909c07f88244d363913f29cc1096/README.md)
(the copy had two later notes: the client's `PLR_PCCS_URL` setting and the short socket directory for long paths;
both are described in the current docs).
