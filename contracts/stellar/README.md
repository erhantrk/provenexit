# PLR registry — Stellar Soroban (tier B, SPEC-CHAINS §10)

`src/lib.rs` is the registry contract (soroban-sdk `=29.0.1`): owner policy (compose / OS allowlists, MOCK|INTEL
root, operator orgs, two-step ownership), registration only by owner-approved operators that `require_auth()` the
call, on-chain quote format + `report_data` checks (`keyHash ‖ registrationNonce("stellar:" + C…, G…)`), the
registration quote stored on-chain, and contiguous anchors (with their Ed25519 `sig`, verified by clients) posted only
by the instance's operator while its build is allowed. Errors are `#[contracterror]` codes 1–9 named after the PLR
codes. Every write extends the TTL of the entries it wrote and of the read-path entries (≥ instance TTL).

```sh
cargo test                 # rule-by-rule tests (src/test.rs) with @plr/shared vectors (src/vectors.rs)
stellar contract build     # → target/wasm32v1-none/release/plr_stellar_registry.wasm
node fixtures/gen.mjs      # (repo root: node contracts/stellar/fixtures/gen.mjs) regenerates src/vectors.rs
```

JS: writer `enclave/src/chains/stellar.ts` (`PLR_STELLAR_RPC`, `PLR_STELLAR_PASSPHRASE`, `PLR_STELLAR_REGISTRY` /
`PLR_STELLAR_VPN_REGISTRY`, `PLR_STELLAR_KEY`), reader `client/src/chains/stellar.ts` (`StellarRegistry`, views via
`simulateTransaction`), e2e driver `e2e/src/chains/stellar.ts` (one quickstart container per stack, docs/stellar-local.md).
