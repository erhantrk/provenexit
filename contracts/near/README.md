# plr-registry — PLR-v1 NEAR registry contract (SPEC §7)

Owner-governed allowlist of compose hashes and OS measurements, **on-chain verification of MOCK TDX
registration quotes**, and Ed25519-authorised Merkle anchoring of receipts.

## Build and test (the gate)

```sh
cd contracts/near
cargo near build non-reproducible-wasm --no-abi   # → target/near/plr_registry.wasm (~210 KB)
cargo test --release                              # 29 tests, incl. 64 TS-generated registration vectors
```

Without network, add `CARGO_NET_OFFLINE=true`.

## Deploying (important for harnesses)

* `new(owner_id, root_kind, root_p256, instance_ttl_ms?)` is `#[private]`: it **must be called by the
  contract account itself** (e.g. `contractAccount.callFunction({ contractId: contractAccount.accountId, methodName: "new", ... })`,
  or in the same batch as the deploy). This blocks front-running the init. `instance_ttl_ms` defaults to 86 400 000.
* `root_kind` is `"MOCK"` or `"INTEL"`; `root_p256` is a valid P-256 point as 128 lowercase hex chars (`x‖y`).
  An `INTEL` root cannot verify quotes on-chain in milestone 1, so `register_instance` fails with `E_QUOTE_SIG`.
* Change methods reject unknown JSON arguments.

## Methods

| method | who | notes |
|---|---|---|
| `allow_compose(hash)` / `revoke_compose(hash)` / `allow_os(hash)` / `revoke_os(hash)` | owner | idempotent; events `compose_allowed`… |
| `set_root(kind, p256)` | owner | event `root_set` |
| `propose_owner(id)` / `accept_owner()` | owner / pending owner | events `owner_proposed`, `owner_accepted` |
| `register_instance(quote, event_log, app_compose, x25519, ed25519) → key_hash` | anyone, `#[payable]` | SPEC §7 steps 1-7; storage deposit required (≈0.0035 NEAR used; ≈6.5 Tgas); excess becomes anchor credit (≤ 0.05 NEAR), the rest is refunded |
| `anchor_receipts(key_hash, root, first_seq, count, sig) → anchor_id` | anyone, `#[payable]` | storage paid by the attached deposit (excess refunded) or the instance's prepaid anchor credit, else `E_DEPOSIT`; event `receipts_anchored` |
| `get_anchor_credit(key_hash) → string` | view | remaining prepaid anchor storage (yoctoNEAR); `register_instance` keeps up to 0.05 NEAR of its excess deposit as credit, refunds the rest |
| views | | `is_allowed(compose_hash, os_measurement)`, `is_compose_allowed(hash)`, `is_os_allowed(hash)`, `get_instance(key_hash)` (null if unknown/expired), `get_root()`, `get_anchor(id)`, `anchor_count()`, `get_owner()`, `get_pending_owner()`, `get_instance_ttl_ms()` |

Views never panic on malformed input: a malformed or all-zero hash is simply "not allowed" / `null`.

Re-registering the same keys refreshes `expires_at_ms` (and compose/OS) but keeps `operator`, `registered_at_ms` and
`next_seq`. It adds no storage, so it needs no deposit; a deposit attached to a refresh tops up the anchor credit.

## Error codes (panic message = `CODE` or `CODE: static detail`; caller input is never echoed)

`E_BAD_HEX`, `E_ZERO_HASH`, `E_BAD_INPUT`, `E_UNAUTHORIZED`, `E_DEPOSIT`, `E_QUOTE_FORMAT` (any structural quote
problem incl. TEE type, bad hex, > 4096 hex chars), `E_QUOTE_SIG`, `E_DEBUG_TD`, `E_EVENT_LOG`, `E_RTMR3`,
`E_COMPOSE_MISMATCH`, `E_COMPOSE_NOT_ALLOWED`, `E_OS_NOT_ALLOWED`, `E_REPORT_DATA`, `E_INSTANCE_NOT_REGISTERED`,
`E_SEQ`, `E_ANCHOR_SIG`.

## Layout

| file | role |
|---|---|
| `src/lib.rs` | contract state, methods, argument validation, storage deposit/refund |
| `src/verify.rs` | `register_instance` pipeline (SPEC §7 steps 1-7, in order) |
| `src/quote.rs` | MOCK quote parsing (SPEC §2) |
| `src/ecdsa.rs` | P-256: low-S + range checks, on-curve check, compression, host `p256_verify` |
| `src/eventlog.rs` | event-log verification and RTMR3 replay (SPEC §3), same rules as `@plr/shared` |
| `src/binding.rs` | key hash, registration nonce, AK-cert and anchor message layouts |
| `src/bytes.rs`, `src/hash.rs`, `src/errors.rs`, `src/events.rs`, `src/ctx.rs` | strict hex + constant-time helpers, hashes, codes, NEP-297, context seam |
| `src/test_host.rs`, `src/tests.rs` | native NEAR host for unit tests, contract tests |
| `fixtures/gen.mjs` → `fixtures/vectors.json` | cross-implementation vectors produced with `@plr/shared` |
| `scripts/sandbox-smoke.mjs` | optional smoke test of the wasm on a real near-sandbox |

### Why a custom test host

near-sdk's `unit-testing` feature (`testing_env!`) needs `near-vm-runner`, which this offline build cannot fetch.
The tests therefore link `src/test_host.rs`, a native implementation of the `near_sys` host functions the contract
uses. It models registers, storage with NEAR's 40-byte per-record overhead, logs, transfers, and P-256/Ed25519
verification. Like the real host, its `p256_verify` accepts high-S signatures. near-sdk only compiles off-wasm under
a few cfgs, so `.cargo/config.toml` sets `--cfg clippy` for non-wasm targets only. In this dependency tree, only
near-sdk's two build guards read that cfg. The real host behaviour (high-S accepted by the host, rejected by the
contract; Ed25519; storage refund; gas) is checked by `scripts/sandbox-smoke.mjs` on near-sandbox 2.13.4.

### Regenerating fixtures

```sh
npx tsc -b packages/shared && node contracts/near/fixtures/gen.mjs
```

The generator computes each case's expected code with a TS transcription of SPEC §7 built on `@plr/shared`. It
refuses to write if that code differs from the code the case was designed to hit.
