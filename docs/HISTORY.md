# ProvenExit history

Older work that is not needed to judge the NEAR HACKATHON submission. The current story is in the
[README](../README.md).

## The October 2026 tour (pre-hackathon)

The README of the pre-hackathon code (the private LLM router PLR-v1, the VPN milestones, the multi-chain registries)
is kept verbatim at [`PLR-README-2026-10.md`](PLR-README-2026-10.md).

## Commit timeline

From `git log` (dates are commit dates).

| date | commits | what |
|---|---|---|
| 2026-10-23 | `c2a35e4`..`977c648` | PLR-v1 spec and build (NEAR registry, TEE router, client SDK, e2e, demo); PLR-VPN-v1 (SOCKS5 proxy, no-logs exit); VPN milestone 2 (forward-secret tunnel v2, DoH-only exit DNS, two-hop with on-chain operator orgs) |
| 2026-10-24 | `34900ba`..`9bd402e` | Combo milestone (LLM router and VPN exit in one TD); multi-chain registries: Zcash record log, EVM/Monad (Solidity), Stellar (Soroban), Solana |
| 2026-11-11 | `4692b17`.. | The hackathon plan in `docs/plan/`, the 2026-11-09 Phala spike fixture, then tasks T01..T24 (Intel/dstack path, DCAP in the contract, compose policy, testnet registry, client fixture replay), review fixes, README and AI_USE |

The first group is the disclosed baseline; see "Prior code and hackathon window" in the README.

## Multi-chain registries (pre-hackathon, not part of the NEAR submission)

- [`SPEC-CHAINS.md`](../SPEC-CHAINS.md): EVM/Monad, Stellar, Solana in `contracts/{evm,stellar,solana}`, Zcash record
  logs in `client/src/zcash-registry.ts`. They are pre-hackathon code from October 2026.
- `scripts/demo.sh` runs the NEAR path only by default. `PLR_DEMO_CHAINS=all PLR_LLM=mock bash scripts/demo.sh` also
  runs those older chain stages (each only when its node tools are installed).
- Local notes for the tools: [`solana-local.md`](solana-local.md), [`stellar-local.md`](stellar-local.md),
  [`zcash/`](zcash).

## The private LLM router (pre-hackathon)

PLR-v1 (`plr verify` / `plr chat` / `plr proxy`) is still exercised by `scripts/demo.sh`. It is not part of the NEAR
submission.

## Deployments and checkpoints in this repository

- Testnet registry `pe-vpnreg-erhan.testnet`: init, operator approval, spike allowlist, revoke and re-allow txs are
  listed in the README section "NEAR contract details".
- Decisions and findings per task (S1 Phala spike, S2 dcap-qvl in a contract, T03..T24): [`NOTES-DECISIONS.md`](../NOTES-DECISIONS.md).
