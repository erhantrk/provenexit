# plr-registry — PLR-v1 NEAR registry contract (SPEC §7)

Owner-governed allowlist of compose hashes and OS measurements, **on-chain verification of MOCK TDX
registration quotes**, **on-chain Intel DCAP verification of real TDX quotes** (`register_instance_tdx`, INTEL mode,
SPEC-TDX §2.3), and Ed25519-authorised Merkle anchoring of receipts.

## Build and test (the gate)

```sh
cd contracts/near
cargo near build reproducible-wasm                 # the deployed build, from commit dcd37e6 (Docker, pinned image): SHA-256 a39ed48c…, code hash C1hvenbr…
cargo near build non-reproducible-wasm --no-abi   # → target/near/plr_registry.wasm (~230 KB, no dcap-qvl)
cargo test --release                              # 60 tests, incl. the TS-generated vectors and the INTEL checks 1-4/8-13
cargo test --release --features tdx-test-clock    # 61 tests: + TV-Q1 through the real dcap pipeline (fixed clock)
```

`tdx-test-clock` pins the verification clock to `1_750_377_600` (2025-06-20T00:00:00Z) so TV-Q1's collateral
(valid 2025-06-19 … 2025-07-19) verifies forever. **Never deploy a build with it.**

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
| `approve_operator(account_id, org_id)` / `revoke_operator(account_id)` | owner | SPEC §7 rev 1.2 operator organizations. `org_id` must match `^[a-z0-9][a-z0-9._-]{0,63}$` (ASCII), else `E_BAD_INPUT`. Re-approving changes the org. Revoking an unapproved account is a no-op. Events `operator_approved` `{account_id, org_id, previous_org_id}` / `operator_revoked` `{account_id, previous_org_id}`. Not payable: like the other owner methods, the entry's storage (≈ 110-240 bytes, ≤ 0.0024 NEAR) is paid from the contract balance and released on revoke. Owner-only, so it is not a drain vector |
| `get_operator(account_id) → org_id \| null` | view | `null` if not approved or `account_id` is malformed |
| `register_instance(quote, event_log, app_compose, x25519, ed25519) → key_hash` | anyone, `#[payable]` | SPEC §7 steps 1-7; storage deposit required (≈0.0035 NEAR used; ≈6.5 Tgas); excess becomes anchor credit (≤ 0.05 NEAR), the rest is refunded |
| `register_instance_tdx(quote, collateral, event_log, app_compose, x25519, ed25519) → key_hash` | anyone, `#[payable]` | INTEL mode (SPEC-TDX §2.3): on-chain Intel DCAP + dstack event log; 13 ordered checks below; same deposit/refund rules as `register_instance` (attach 0.1 NEAR, 300 Tgas) |
| `get_tdx_policy() → {intel_root_p256, accepted_tcb_statuses, dcap_qvl_version}` | view | SPEC-TDX §2.4; never panics |
| `anchor_receipts(key_hash, root, first_seq, count, sig) → anchor_id` | anyone, `#[payable]` | storage paid by the attached deposit (excess refunded) or the instance's prepaid anchor credit, else `E_DEPOSIT`; event `receipts_anchored` |
| `migrate()` | contract account (`#[private]`) | rev 1.3 one-time upgrade of a rev 1.2 state; **empties the compose allowlist** (see below); event `compose_allowlist_reset` `{state_rev}` |
| `get_state_rev() → u8` | view | `3` for the rev 1.3 layout |
| `get_anchor_credit(key_hash) → string` | view | remaining prepaid anchor storage (yoctoNEAR); `register_instance` keeps up to 0.05 NEAR of its excess deposit as credit, refunds the rest |
| views | | `is_allowed(compose_hash, os_measurement)`, `is_compose_allowed(hash)`, `is_os_allowed(hash)`, `get_instance(key_hash)` (null if unknown/expired; includes `org_id`, the registering operator's org looked up live at read time, or null), `get_root()`, `get_anchor(id)`, `anchor_count()`, `get_owner()`, `get_pending_owner()`, `get_instance_ttl_ms()` |

Views never panic on malformed input: a malformed or all-zero hash is simply "not allowed" / `null`.

**Operator-bound registration (SPEC §5/§7 rev 1.3).** Check 7 requires
`report_data == key_hash(x25519, ed25519) ‖ SHA256("PLR-v1/register/2" ‖ u8(len c) ‖ c ‖ u8(len o) ‖ o)` with
`c = current_account_id` and `o = predecessor_account_id`. A registration quote therefore registers only on this
registry and only when submitted by the operator account the enclave bound it to (its `PLR_OPERATOR_ID`); anyone else
gets `E_REPORT_DATA`. Session quotes (`key_hash ‖ SHA256("PLR-v1/session-nonce" ‖ nonce)`) and rev 1.2 registration
nonces (`SHA256("PLR-v1/register" ‖ c)`) never match. Account ids outside 1..=64 bytes fail closed (`E_REPORT_DATA`).

Re-registering the same keys refreshes `expires_at_ms` (and compose/OS) but keeps `operator`, `registered_at_ms` and
`next_seq`; since the quote is operator-bound, only that operator can refresh. It adds no storage, so it needs no
deposit; a deposit attached to a refresh tops up the anchor credit.

Organizations are metadata for clients (two-hop routing requires `entry.org_id != exit.org_id`, SPEC-VPN). They do
not gate `register_instance` or `anchor_receipts`: an unapproved account can still register, and its instances report
`org_id: null`.

**Upgrading a rev 1.2 registry to rev 1.3 (fail closed).** A pre-rev-1.3 router or exit puts the *raw* client
nonce into its `/v1/attestation` quotes. Anyone can therefore ask an old instance for a "session" quote over
`registration_nonce(registry, attacker)` and register that instance's keys under their own account (so the attacker
becomes its `operator`, and for exits its organization, permanently). The rev 1.3 check cannot tell which build
produced a quote, so **no pre-rev-1.3 compose hash may stay on the allowlist of a rev 1.3 registry**. The contract
enforces this:

* The rev 1.3 state has a trailing `state_rev` field and the compose allowlist lives under a new storage prefix.
  Deploying rev 1.3 code over a rev 1.2 state therefore makes *every* method (including `register_instance` and the
  views) fail with `Cannot deserialize the contract state` until the migration runs.
* `migrate()` must be called by the contract account itself, in the same batch as the code deploy (deploy +
  `migrate` as one transaction, so there is no window). It keeps owner, root, OS allowlist, instances, anchors,
  credits, TTL and operator organizations, and **starts with an empty compose allowlist**. It fails with
  `E_BAD_INPUT` on anything but a rev 1.2 state (so it cannot run twice). The old allowlist entries stay in storage
  under the old prefix and are never read again.
* The owner then re-approves **only rev 1.3 builds** (`allow_compose`). Instances of old builds stay readable but
  their compose is no longer allowed: clients reject them and they cannot anchor. Never re-approve a pre-rev-1.3
  compose hash on a rev 1.3 registry. Deploying a fresh registry account works too.

**State layout (rev 1.2):** the `operators` map was added as the last field of the contract state and the last
`StorageKey` variant. A contract deployed before rev 1.2 cannot be upgraded in place by code redeploy alone, because
the borsh state would not deserialize. Redeploy it fresh, or add a migration. There is no migration method, since no
pre-rev-1.2 deployment exists outside local sandboxes.

## INTEL mode (`register_instance_tdx`)

`register_instance` only accepts MOCK quotes and fails closed (`E_QUOTE_SIG`) under an `INTEL` root.
`register_instance_tdx` is the real-TDX path: the quote's Intel signature chain is verified **on chain** by
`dcap-qvl` 0.7.1 (the same pure-Rust verifier the enclave and client use off chain, so the wasm carries no
crypto host-function dependency), the dstack RTMR3 event log is replayed, and the result is recorded exactly like a
MOCK registration (same storage deposit, anchor credit and refund rules; attach `0.1 NEAR` and `300 Tgas`, expect
120-250 Tgas burnt). A registry with root kind `INTEL` whose `root_p256` is not the Intel SGX Root CA below rejects
every TDX quote (`E_QUOTE_SIG`), so pinning the root is what enables the mode.

Arguments (checks 1-4 concern them):

| argument | type | rule |
|---|---|---|
| `quote` | lowercase hex string | TDX quote v4, ≤ 16 384 hex chars (8 192 bytes; real quotes ≈ 5 006) |
| `collateral` | string | canonical collateral JSON (SPEC-TDX §1.2), ≤ 32 768 bytes |
| `event_log` | JSON array | dstack IMR3 events, 5-64 entries (SPEC-TDX §1.3, V1 digests only) |
| `app_compose` | string | the measured dstack app-compose text, 1-32 768 bytes |
| `x25519`, `ed25519` | 32-byte lowercase hex | non-zero |

Checks, in this order (the first failure panics with the code, as everywhere else):

| # | check | code |
|---|---|---|
| 1 | `quote.len() ≤ 16384`, lowercase hex | `E_QUOTE_FORMAT` |
| 2 | `collateral.len() ≤ 32768`, parses as `dcap_qvl::QuoteCollateralV3` via `near_sdk::serde_json::from_str` | `E_COLLATERAL` |
| 3 | `1 ≤ app_compose.len() ≤ 32768` | `E_BAD_INPUT` |
| 4 | keys: 32-byte hex, not all-zero (existing `key32_arg`) | `E_BAD_HEX` / `E_BAD_INPUT` |
| 5 | stored root kind is `INTEL` **and** stored `root_p256 == INTEL_ROOT_P256` | `E_QUOTE_SIG` |
| 6 | INTEL structural parse (§1.1 table: version, tee, vendor id, sig_data_len, zero padding, `mr_signer_seam`). There is no `E_TEE_TYPE` on chain: like `parse_mock`, a wrong TEE type is `E_QUOTE_FORMAT` (the TS client keeps `E_TEE_TYPE`) | `E_QUOTE_FORMAT` |
| 7 | `QuoteVerifier::new_prod().verify(&quote, &collateral, now_secs)` is `Ok(report)`; `now_secs = env::block_timestamp_ms() / 1000` (or `1_750_377_600` under `tdx-test-clock`) | `E_QUOTE_SIG` |
| 8 | `report.status` ∈ `ACCEPTED_TCB_STATUSES` (`UpToDate`, `SWHardeningNeeded`) | `E_TCB_STATUS` |
| 9 | DEBUG bit clear (byte 168) | `E_DEBUG_TD` |
| 10 | `verify_event_log_dstack(event_log, rtmr3)` (SPEC-TDX §1.3) | `E_EVENT_LOG` / `E_RTMR3` |
| 11 | `sha256(app_compose) == compose-hash payload` | `E_COMPOSE_MISMATCH` |
| 12 | compose allowed, then OS measurement allowed (`os_measurement = SHA256(mr_td ‖ rtmr0 ‖ rtmr1 ‖ rtmr2)`) | `E_COMPOSE_NOT_ALLOWED` / `E_OS_NOT_ALLOWED` |
| 13 | `report_data == key_hash(x25519, ed25519) ‖ registration_nonce(current_account_id, predecessor_account_id)` (the rev 1.3 binding: only the operator the enclave named can register) | `E_REPORT_DATA` |

It then does the same record/refresh/deposit/refund work as `register_instance` (`record_instance`) and emits
`instance_registered` with the MOCK data fields **plus** `"root_kind":"INTEL"` and `"tcb_status":"<status>"`:

```
EVENT_JSON:{"standard":"plr","version":"1.0.0","event":"instance_registered","data":[{"key_hash":"5f…","compose_hash":"8f…","os_measurement":"34…","x25519":"…","ed25519":"…","operator":"pe-op-erhan.testnet","expires_at_ms":1794182400000,"refreshed":false,"root_kind":"INTEL","tcb_status":"UpToDate"}]}
```

`get_tdx_policy()` reports what the code enforces, whatever the stored root is:

```json
{"intel_root_p256":"0ba9c4c0…ae7394","accepted_tcb_statuses":["UpToDate","SWHardeningNeeded"],"dcap_qvl_version":"0.7.1"}
```

`INTEL_ROOT_P256` is the public key of `CN=Intel SGX Root CA` (x‖y, extracted from `dcap-qvl`'s `TrustedRootCA.der`),
`ACCEPTED_TCB_STATUSES` is `["UpToDate","SWHardeningNeeded"]`, and `dcap_qvl` is pinned to `=0.7.1`.

Tests: the default `cargo test --release` covers the INTEL argument checks (1-4), checks 8-13 on a hand-built
INTEL-format quote (TCB, DEBUG, event log, compose hash, both allowlists, and report_data bound to the keys, the registry
and the predecessor), the accepted TCB status list, and the INTEL deposit/refund/`instance_registered` path.
`--features tdx-test-clock` adds TV-Q1 (the `dcap-qvl` sample quote, 5 006 bytes) pushed through the real dcap
pipeline under the fixed 2025-06-20 clock: with the Intel root and empty allowlists it gets past dcap (status
`UpToDate`), the TCB and DEBUG checks and stops at check 10 with `E_EVENT_LOG` on an empty log. A MOCK root (or any
non-Intel P-256 key) fails at check 5 with `E_QUOTE_SIG`; `"{}"`/oversized collateral is `E_COLLATERAL`, a
16 386-char quote is `E_QUOTE_FORMAT`, and `get_tdx_policy` returns the three fields.

## Error codes (panic message = `CODE` or `CODE: static detail`; caller input is never echoed)

`E_BAD_HEX`, `E_ZERO_HASH`, `E_BAD_INPUT`, `E_UNAUTHORIZED`, `E_DEPOSIT`, `E_QUOTE_FORMAT` (any structural quote
problem incl. TEE type, bad hex, > 4096 hex chars in MOCK mode / > 16 384 in INTEL mode), `E_QUOTE_SIG`, `E_DEBUG_TD`,
`E_EVENT_LOG`, `E_RTMR3`, `E_COMPOSE_MISMATCH`, `E_COMPOSE_NOT_ALLOWED`, `E_OS_NOT_ALLOWED`, `E_REPORT_DATA`,
`E_TCB_STATUS`, `E_COLLATERAL`, `E_INSTANCE_NOT_REGISTERED`, `E_SEQ`, `E_ANCHOR_SIG`.

## Layout

| file | role |
|---|---|
| `src/lib.rs` | contract state, methods, argument validation, storage deposit/refund |
| `src/verify.rs` | `register_instance` pipeline (SPEC §7 steps 1-7, in order) |
| `src/verify_tdx.rs` | `register_instance_tdx` pipeline (SPEC-TDX §2.3 checks 5-13, in order) |
| `src/quote.rs` | MOCK quote parsing (SPEC §2) and INTEL quote parsing (SPEC-TDX §1.1) |
| `src/ecdsa.rs` | P-256: low-S + range checks, on-curve check, compression, host `p256_verify` |
| `src/eventlog.rs` | event-log verification and RTMR3 replay (SPEC §3), same rules as `@plr/shared` |
| `src/binding.rs` | key hash, operator-bound registration nonce (rev 1.3), AK-cert and anchor message layouts |
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
