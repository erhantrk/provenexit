# PLR registry — Solana (tier B, SPEC-CHAINS §11)

Native program (`solana-program =5.1.0`, no Anchor). One deployed program serves any number of registries; a
registry is a **state account** created by `Init` and its `contractId` is `solana:<state base58>`.

```sh
cargo test                                   # native unit tests (encoding, layouts, rules, full instruction flows)
PATH=$HOME/.local/share/solana/install/active_release/bin:$PATH cargo-build-sbf   # → target/deploy/plr_registry_solana.so
```

## Instructions (`u8 tag ‖ fields`, little-endian, strings `u8 len ‖ bytes`)

| tag | instruction | accounts (`s` signer, `w` writable) |
|---|---|---|
| 0 | `Init{owner[32], root_kind u8, root_p256[64], ttl_ms u64}` | state (s,w) — pre-allocated (147 bytes) and owned by the program, same tx as `CreateAccount` |
| 1–4 | `AllowCompose` / `RevokeCompose` / `AllowOs` / `RevokeOs` `{h[32]}` | state, owner (s,w), item PDA (w), system program |
| 5 | `SetRoot{kind u8, p256[64]}` | state (w), owner (s) |
| 6 | `ApproveOperator{op[32], org}` | state, owner (s,w), op PDA (w), system program |
| 7 | `RevokeOperator{op[32]}` | state, owner (s), op PDA (w) |
| 8 / 9 | `ProposeOwner{next[32]}` / `AcceptOwner` | state (w), owner / proposed owner (s) |
| 10 | `RegisterInstance{x[32], ed[32], compose[32], os[32], quote[828]}` | state, operator (s,w), op PDA, inst PDA (w), system program |
| 11 | `AnchorReceipts{key_hash[32], root[32], first_seq u64, count u64, sig[64]}` | state (w), operator (s,w), inst PDA (w), anchor PDA (w), compose PDA, os PDA, system program |

PDAs: `["compose", state, hash]`, `["os", state, hash]`, `["op", state, operator]`, `["inst", state, key_hash]`,
`["anchor", state, u64le(id)]`. Account layouts are documented in `src/state.rs` (readers decode those offsets).

`RegisterInstance` data is 957 bytes, so with its five accounts a legacy transaction exceeds the 1232-byte packet
limit: the TypeScript writer (`enclave/src/chains/solana.ts`) sends it as a v0 transaction through a per-key
address lookup table.

Rules are those of the EVM registry (SPEC-CHAINS §9): operator approved (`E_OPERATOR_UNAPPROVED`), quote format
(828 bytes, v4, att key type 2, tee type 0x81 → `E_QUOTE_FORMAT`), `report_data = key_hash ‖ registrationNonce(contractId,
operator base58)` (`E_REPORT_DATA`), first registrant owns the key while the owner approves it (`E_UNAUTHORIZED`; once that operator is revoked another
approved operator may take the key over as a fresh record — the writer passes the holder's op PDA as optional
account 5 so the program can check the revocation), refresh keeps `next_seq`;
anchors by the instance's operator only, unexpired, compose/OS still allowed, contiguous, `1 ≤ count ≤ 10 000`.
Time = Clock `unix_timestamp * 1000`. Errors: `ProgramError::Custom(n)` with the §10 numbering
(`E_UNAUTHORIZED = 1 … E_COMPOSE_NOT_ALLOWED = 9`). The quote signature is not verified on-chain: clients verify it.
