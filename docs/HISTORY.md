# ProvenExit history

Older work that is not needed to judge the NEAR HACKATHON submission. The current story is in the
[README](../README.md).

## The October 2026 tour (pre-hackathon)

The README of the pre-hackathon code (the private LLM router PLR-v1, the VPN milestones, the multi-chain registries)
is kept verbatim at [`PLR-README-2026-10.md`](PLR-README-2026-10.md). It describes code that is no longer in the tree
(see "Removed on 2026-11-12" below); its commands do not run on the current tree.

## Commit timeline

From `git log` (dates are commit dates).

| date | commits | what |
|---|---|---|
| 2026-10-23 | `c2a35e4`..`977c648` | PLR-v1 spec and build (NEAR registry, TEE router, client SDK, e2e, demo); PLR-VPN-v1 (SOCKS5 proxy, no-logs exit); VPN milestone 2 (forward-secret tunnel v2, DoH-only exit DNS, two-hop with on-chain operator orgs) |
| 2026-10-24 | `34900ba`..`9bd402e` | Combo milestone (LLM router and VPN exit in one TD); multi-chain registries: Zcash record log, EVM/Monad (Solidity), Stellar (Soroban), Solana |
| 2026-11-11 | `fdecb3c`.. | The 2026-11-09 Phala spike fixture, then tasks T01..T24 (Intel/dstack path, DCAP in the contract, compose policy, testnet registry, client fixture replay), review fixes, README and AI_USE |
| 2026-11-12 | after `00c910f` | VPN-only cleanup: the LLM router and the non-NEAR registries removed from the tree (below) |

The first group is the disclosed baseline; see "Prior code and hackathon window" in the README.

## Removed on 2026-11-12 (pre-hackathon code, kept in the baseline commits)

To keep the submission VPN-only, this code was removed from the tree on 2026-11-12. It remains in the baseline
commits `c2a35e4`..`9bd402e` and in the history up to the removal:

- **The private LLM router (PLR-v1):** the router enclave service, the mock LLM and the llama.cpp builds (the
  enclave build measured `llama-server`), the "combo" build running the router and the VPN exit in one TD
  (`SPEC-COMBO.md`), the router evil build, the client's `plr verify` / `plr chat` / `plr proxy` and the router
  e2e scenarios.
- **The multi-chain registries:** EVM/Monad, Stellar and Solana in `contracts/{evm,stellar,solana}`, the Zcash
  record log, their client readers, enclave writers and e2e drivers, `SPEC-CHAINS.md` and the registration-evidence
  step for chains that do not verify quotes, and the local tool notes (`docs/solana-local.md`,
  `docs/stellar-local.md`, `docs/zcash/`).

`SPEC.md` keeps the base the VPN exit uses (quote format, event log, compose rules, key binding, registry, receipt
anchoring, verification order) with unchanged section numbers; the router-only sections are one-line notes.

## Deployments and checkpoints in this repository

- Testnet registry `pe-vpnreg-erhan.testnet`: init, operator approval, spike allowlist, revoke and re-allow txs are
  listed in the README section "NEAR contract details".

## 2026-11-12: keyless, reproducible registry

The registry was redeployed as `vpnreg.pe-owner-erhan.testnet` from a `cargo near build reproducible-wasm` build
(SHA-256 `a39ed48c…`, code hash `C1hvenbr…`) and its only access key was deleted, closing the "full-access key /
non-reproducible build" limit of `pe-vpnreg-erhan.testnet`. The live exit's compose (now naming the new registry)
was allowed and the exit registered 13/13 again (tx `EZDveHx5…`). The first registry is retired.

## 2026-11-12, 20:05 UTC: the exit redeployed from a reproducible image

The exit image build was made reproducible (commit `6740b3f`: multi-stage Dockerfile, constant `SOURCE_DATE_EPOCH`,
pinned BuildKit v0.34.2). Two fresh clones built the same digest, `sha256:74c6d1c5…2785`; it was pushed, pinned in
`deploy/phala/docker-compose.yml` (`9b3571d`) and the Phala CVM (same app id and URL) was updated to it. New compose
hash `2f4100e6…dabf` allowed (tx `GdY61VR2…`), the exit registered 13/13 with new keys (tx `6yBT47ij…`, 186.76 Tgas),
and the previous compose `9411d0f7…` (image `7e53f383…`, registration `EZDveHx5…`) was revoked (tx `9HhvupZA…`).
`fixtures/live-exit`, the status and MCP bundles and the status samples were re-recorded from the new exit at
20:13–20:15 UTC; the earlier capture is in git history before `d47bbe8`.
