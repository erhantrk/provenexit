# ProvenExit: SPEC-TDX (INTEL/dstack mode)

Status: FROZEN rev 1 (2026-11-10), INTEL/dstack mode.

This document specifies the INTEL/dstack mode next to the existing MOCK mode of [`SPEC.md`](SPEC.md) and
[`SPEC-VPN.md`](SPEC-VPN.md). The byte formats here are the ones `packages/shared` and `contracts/near` implement;
the measured deployment files are in [`deploy/phala/`](deploy/phala).

Notation as in SPEC.md: `‖` = concatenation, hex = lowercase, no `0x`, even length.

---

## 0. Constants (copy them verbatim)

| name | value | source |
|---|---|---|
| `INTEL_ROOT_P256` | `0ba9c4c0c0c86193a3fe23d6b02cda10a8bbd4e88e48b4458561a36e705525f567918e2edc88e40d860bd0cc4ee26aacc988e505a953558c453f6b0904ae7394` | public key (x‖y) of `CN=Intel SGX Root CA` (notAfter 2049-12-31), extracted with `openssl` from `dcap-qvl-0.7.1/src/TrustedRootCA.der` |
| `INTEL_QE_VENDOR_ID` | `939a7233f79c4ca9940a0db3957f0607` | SPEC.md §2.1 (already in `packages/shared/src/tdx/quote.ts`) |
| `DSTACK_EVENT_TYPE` | `0x08000001` (= 134217729) | dstack `cc-eventlog/src/runtime_events.rs` |
| `ACCEPTED_TCB_STATUSES` | `["UpToDate", "SWHardeningNeeded"]` | project decision. Day-0 spike S1 may require adding `"OutOfDate"`, but only with the human's OK |
| `MAX_TDX_QUOTE_BYTES` | `8192` (hex: 16384 chars) | project decision. Real quotes are about 5 006 bytes |
| `MAX_COLLATERAL_JSON_BYTES` | `32768` | project decision. The sample collateral is 16 072 bytes |
| `MAX_DSTACK_COMPOSE_BYTES` | `32768` | project decision. Phala's `app-compose.json` may embed a pre-launch script |
| `MAX_DSTACK_EVENT_PAYLOAD` | `4096` bytes | project decision. The `key-provider` payload is JSON |
| `MAX_EVENTS` | `64` | unchanged (SPEC §3) |
| `PCCS_URL` | `https://pccs.phala.network` | `dcap-qvl` default (`PHALA_PCCS_URL`) |
| `DSTACK_SOCKET` | `/var/run/dstack.sock` | `@phala/dstack-sdk` 0.5.8 default socket path |

Error codes **added** to `packages/shared/src/errors.ts` `ERROR_CODES` and to `contracts/near/src/errors.rs`:
`E_TCB_STATUS`, `E_COMPOSE_POLICY`, `E_COLLATERAL`.

---

## 1. Byte formats

### 1.1 INTEL-mode quote (TDX quote v4, real Intel signature)

Same header/body layout as SPEC.md §2.1/§2.2 (absolute offsets unchanged: `td_attributes` @168, `mr_td` @184,
`rtmr0..3` @376/424/472/520, `report_data` @568). Differences from MOCK mode:

| check | rule | error |
|---|---|---|
| length | `636 ≤ len ≤ 8192` | `E_QUOTE_FORMAT` |
| version / att_key_type / tee_type / reserved | `4` / `2` / `0x81` / zero (as SPEC §2.1) | `E_QUOTE_FORMAT` / `E_TEE_TYPE` |
| qe_vendor_id | `== INTEL_QE_VENDOR_ID` | `E_QUOTE_FORMAT` |
| `sig_data_len` (u32le @632) | `1 ≤ sig_data_len ≤ len − 636` | `E_QUOTE_FORMAT` |
| trailing bytes `quote[636 + sig_data_len ..]` | **all `0x00`** (zero padding is normal: both dcap-qvl sample quotes, including the one produced by dstack's tappd, carry 70 zero bytes) | `E_QUOTE_FORMAT` |
| `mr_signer_seam` (48 bytes @112) | all zero (Intel-signed TDX module; dstack's verifier makes the same check) | `E_QUOTE_FORMAT` |
| DEBUG | bit 0 of byte 168 clear | `E_DEBUG_TD` |
| signature | `dcap-qvl` verify with Intel prod root, collateral, `now` | `E_QUOTE_SIG` |
| TCB status | `status ∈ ACCEPTED_TCB_STATUSES` | `E_TCB_STATUS` |

`os_measurement = SHA256(mr_td ‖ rtmr0 ‖ rtmr1 ‖ rtmr2)` (unchanged, SPEC §2.5).

**Test vector TV-Q1** (from `dcap-qvl` 0.7.1 crate, file `sample/tdx_quote`, 5 006 bytes, collateral
`sample/tdx_quote_collateral.json`, 16 072 bytes). Checked on 2026-11-08 with `@phala/dcap-qvl@0.7.1` `verify()`:

| field | value |
|---|---|
| `sha256(quote)` | `c42f9164325024bca2757bc8819b11879a0a369132ea4e2b7c85df4805ea72db` |
| `sig_data_len` / bytes after offset 636 | `4300` / `4370` (70 trailing zero bytes) |
| `verify(q, c, 1750377600)` (2025-06-20T00:00:00Z) | `status = "UpToDate"`, `advisory_ids = []`, `report.type = "td10"` |
| `verify(q, c, 1794096000)` (2026-11-08T00:00:00Z) | throws `"TCBInfo expired"` |
| `mr_td` | `91eb2b44d141d4ece09f0c75c2c53d247a3c68edd7fafe8a3520c942a604a407de03ae6dc5f87f27428b2538873118b7` |
| `td_attributes` | `0000001000000000` (DEBUG clear) |
| `rtmr3` | 48 zero bytes (not a dstack quote, so TV-Q1 has no event log) |
| `report_data` | `9a9d48e7f6799642d3d1b34e1e5e1742d4bb02dd6ddd551862c1211d35c304f9eca3efdbb481601c163cf52493d6e44aed55d51ec39b7e518fadb92c2b523f20` |
| `os_measurement` | `345469a462dafe286b728237091da824ce7508ebf14b390a47b1766c9c22cd65` |

Copy both files into the repo as `packages/shared/test/vectors/dcap/tdx_quote.bin` and
`packages/shared/test/vectors/dcap/tdx_quote_collateral.json` (MIT-licensed, credit in README §Libraries).
Source: `https://crates.io/api/v1/crates/dcap-qvl/0.7.1/download` → `dcap-qvl-0.7.1/sample/`.

### 1.2 Collateral JSON (canonical wire form)

The JSON object that `dcap-qvl` (Rust `QuoteCollateralV3`, JS `verify()`) accepts. **Canonical form = binary fields
as lowercase hex strings**: that is the form of the dcap-qvl sample file, which the Rust tests deserialize and
the JS `verify()` accepts (tested 2026-11-08). The JS `getCollateral()` returns these four fields as **number
arrays**, so the exit MUST convert them with `canonicalCollateral()` (§4.3) before sending them anywhere.

```json
{
  "pck_crl_issuer_chain": "-----BEGIN CERTIFICATE-----\nMIIC...\n-----END CERTIFICATE-----\n...",
  "root_ca_crl": "308201203081c8020101300a06082a8648ce3d0403023068311a30180603...",
  "pck_crl": "30820a6330820a08020101300a06082a8648ce3d04030230703122302006...",
  "tcb_info_issuer_chain": "-----BEGIN CERTIFICATE-----\n...",
  "tcb_info": "{\"id\":\"TDX\",\"version\":3,\"issueDate\":\"2025-06-19T10:16:03Z\",\"nextUpdate\":\"2025-07-19T10:16:03Z\",\"fmspc\":\"B0C06F000000\",...}",
  "tcb_info_signature": "027ef6ca41bac64e61edbbd672b1c97eb0b2997400c5018eee002e66421b...",
  "qe_identity_issuer_chain": "-----BEGIN CERTIFICATE-----\n...",
  "qe_identity": "{\"id\":\"TD_QE\",\"version\":2,\"issueDate\":\"2025-06-19T10:32:27Z\",...}",
  "qe_identity_signature": "d6d709840544c26e2ab3d680067d04b6160551f78aa23062cc79ab1be2ff...",
  "pck_certificate_chain": "-----BEGIN CERTIFICATE-----\n... (optional; present when the PCCS client extracted it)"
}
```

Field types: every field is a JSON string. Binary fields (`root_ca_crl`, `pck_crl`, `tcb_info_signature`,
`qe_identity_signature`) are lowercase hex. `pck_certificate_chain` is optional (omit if absent). No other keys.

### 1.3 dstack RTMR3 event log (INTEL mode)

Event JSON shape is identical to SPEC §3 (`{"imr":3,"event_type":134217729,"digest":"<96 hex>","event":"<name>","event_payload":"<hex>"}`),
the same shape `@phala/dstack-sdk` 0.5.8 declares (`interface EventLog { imr; event_type; digest; event; event_payload }`).

Digest rule **V1 only** (dstack `RuntimeEvent::preimage`, `EventLogVersion::V1`):
`digest = SHA384(u32le(0x08000001) ‖ ":" ‖ utf8(event) ‖ ":" ‖ payload)`. The CVM is deployed with
`--event-log-version 1`. A V2 (JCS JSON) digest fails with `E_EVENT_LOG` ("digest mismatch").

`verifyEventLogDstack(events, rtmr3)` (TS) / `verify_event_log_dstack(events, rtmr3)` (Rust). The rules, in order:

1. `events` is an array, `5 ≤ length ≤ 64` → else `E_EVENT_LOG`.
2. Every entry: exactly the 5 keys above; `imr == 3`; `event_type == 134217729`; `event` matches
   `^[\x21-\x39\x3b-\x7e]{1,128}$`; `digest` is 96 hex chars; `event_payload` is hex with ≤ 4096 bytes;
   recomputed V1 digest == `digest` → else `E_EVENT_LOG`.
3. The five names `system-preparing`, `app-id`, `compose-hash`, `instance-id`, `boot-mr-done` each occur
   **exactly once**, at strictly increasing indices in that order → else `E_EVENT_LOG` ("boot sequence").
   Any **other** event name may appear anywhere: dstack emits `key-provider`, `os-image-hash`,
   `init-script-hash`, `storage-fs`, `storage-encrypted`, `system-ready`, …, and their effect is pinned by the
   compose hash and OS measurement anyway.
4. Payload sizes: `system-preparing` 0, `app-id` 20, `compose-hash` 32, `instance-id` 20, `boot-mr-done` 0 →
   else `E_EVENT_LOG`. **No** `app-id == compose_hash[0:20]` rule. On Phala Cloud the app-id comes from the
   KMS / deployment (dstack source: "app_id is the deploy-time instance_info.app_id").
5. Replay: `rt = 0^48; for each event: rt = SHA384(rt ‖ digest)`; `rt == rtmr3` → else `E_RTMR3`.
6. Return `{ composeHash, appId, instanceId }` (payloads of the three events).

**Test vector TV-E1** (V1 digests, computed 2026-11-08 with Python hashlib):
- `digest("app-id", deadbeef)` = `67b4be4efed0893cfa2bb1d35dca209ad8348b4c97f980807bcde8b9a0f26398dd0923d6eccb5aa2096d98046da8740f`
  (same input as dstack's own unit test `v1_digest_unchanged`).
- `digest("system-preparing", <empty>)` = `f9974020ef507068183313d0ca808e0d1ca9b2d1ad0c61f5784e7157c362c06536f5ddacdad4451693f48fcc72fff624`
- RTMR3 after only that event = `6a9a63f48733aba50d6892c873d838f97351040ddb0b497dcbdb0571ad78d0c1f1b8b3e87a9719706604b6cc5faedee0`

**Test vector TV-E2** (real dstack log): written by spike S1 to `fixtures/phala-spike/event_log.json`, together with
`quote.hex` (rtmr3 inside). Until S1 has run, the unit test uses a synthetic log built with `makeEvent`:
`[key-provider("{}"), system-preparing, app-id(20×0x11), compose-hash(sha256(compose)), instance-id(20×0x22), boot-mr-done, system-ready]`.

### 1.4 dstack `app-compose.json` and the compose policy (INTEL mode only)

The measured document in INTEL mode is **the dstack app-compose** (the string `DstackClient.info().tcb_info.app_compose`),
not the SPEC-VPN §2 compose. `compose_hash = SHA256(utf8(app_compose))` and it must equal the `compose-hash`
event (unchanged rule SPEC §9 step 7). Example (abbreviated, values illustrative; the real one comes from S1/T14):

```json
{
  "manifest_version": 2,
  "name": "provenexit-exit",
  "runner": "docker-compose",
  "docker_compose_file": "services:\n  exit:\n    image: ghcr.io/erhantrk/provenexit-exit@sha256:<64 hex>\n    logging:\n      driver: none\n    ...",
  "kms_enabled": true,
  "gateway_enabled": true,
  "public_logs": false,
  "public_sysinfo": false,
  "allowed_envs": ["PLR_OPERATOR_KEY"],
  "no_instance_id": false,
  "secure_time": false
}
```

`checkDstackComposePolicy(appComposeText: string): { images: string[] }` (TS, client only). Fail with
`E_COMPOSE_POLICY` unless **all** of these hold:
1. `JSON.parse` succeeds and gives an object; `runner === "docker-compose"`; `docker_compose_file` is a string.
2. `yaml.parse(docker_compose_file)` (package `yaml@2.8.1`) gives an object with an object `services`.
3. Every service has `image` matching `^[a-z0-9./_:-]+@sha256:[0-9a-f]{64}$` (pinned by digest) and **no**
   `build` key and **no** `privileged: true`.
4. A service named `exit` exists and has `logging.driver === "none"`. Its stdout and stderr go nowhere, so
   "no logs" is a measured property of the compose itself.
Return the list of image references, which `plr vpn verify` prints.

### 1.5 Attestation bundle (`GET /v1/attestation?nonce=<64 hex>`), INTEL mode

SPEC §6.2 shape plus one field. `root_kind` becomes `"INTEL"`, `app_compose` is the dstack app-compose, and
`collateral` is **required** in INTEL mode (and ignored or absent in MOCK mode):

```json
{
  "v": "PLR-v1",
  "root_kind": "INTEL",
  "quote": "040002008100000000000000939a7233f79c4ca9940a0db3957f0607...",
  "event_log": [
    {"imr":3,"event_type":134217729,"digest":"f9974020…f624","event":"system-preparing","event_payload":""},
    {"imr":3,"event_type":134217729,"digest":"…","event":"app-id","event_payload":"<40 hex>"},
    {"imr":3,"event_type":134217729,"digest":"…","event":"compose-hash","event_payload":"<64 hex>"},
    {"imr":3,"event_type":134217729,"digest":"…","event":"instance-id","event_payload":"<40 hex>"},
    {"imr":3,"event_type":134217729,"digest":"…","event":"boot-mr-done","event_payload":""}
  ],
  "app_compose": "{\"manifest_version\":2,\"name\":\"provenexit-exit\",...}",
  "x25519": "<64 hex>",
  "ed25519": "<64 hex>",
  "collateral": { "pck_crl_issuer_chain": "...", "root_ca_crl": "<hex>", "...": "... (§1.2)" },
  "registration_quote": "<hex, optional, unchanged SPEC-CHAINS §4>"
}
```

Client rules: missing `collateral`, or `collateral` not a plain object of strings, gives `E_BAD_RESPONSE`.
`app_compose` up to 32 768 bytes. The collateral is Intel-signed and freshness-checked against the client's
clock, so taking it from the (untrusted) exit is safe. The residual risk (an exit can serve a CRL that is stale
but not yet expired) is listed in the README's limits.

---

## 2. NEAR registry contract additions (`contracts/near`, near-sdk `=5.29.1`)

Everything in SPEC §7 and `contracts/near/README.md` stays. **One new change method, one new view, two new
constants, three new error codes.** The state layout (borsh) is **unchanged**, so no migration is needed; we
deploy fresh testnet accounts anyway.

### 2.1 Cargo additions (`contracts/near/Cargo.toml`)

```toml
[dependencies]
near-sdk = "=5.29.1"
sha2 = { version = "0.10.9", default-features = false }
p256 = { version = "0.13.2", default-features = false, features = ["arithmetic"] }
dcap-qvl = { version = "=0.7.1", default-features = false, features = ["contract", "std", "default-x509", "rustcrypto"] }

[target.'cfg(target_arch = "wasm32")'.dependencies]
getrandom = { version = "0.2.16", features = ["custom"] }

[features]
# Test-only fixed clock for the TV-Q1 vector (collateral valid 2025-06-19..2025-07-19). NEVER deploy a build with it.
tdx-test-clock = []
```

The feature set is the one dcap-qvl's own NEAR gas benchmark uses (`tests/near/contracts/gas-test/Cargo.toml`), with `rustcrypto` added. That benchmark measured ~98 TGas at `opt-level=3`, and dcap-qvl's docs say ~169 TGas at `opt-level="z"`.

### 2.2 New constants (`src/lib.rs`)

```rust
/// Intel SGX Root CA public key, x‖y (SPEC-TDX §0). A registry with root_kind INTEL must store exactly this.
pub const INTEL_ROOT_P256_HEX: &str = "0ba9c4c0c0c86193a3fe23d6b02cda10a8bbd4e88e48b4458561a36e705525f567918e2edc88e40d860bd0cc4ee26aacc988e505a953558c453f6b0904ae7394";
pub const MAX_TDX_QUOTE_HEX_LEN: usize = 16_384;
pub const MAX_COLLATERAL_LEN: usize = 32_768;
pub const MAX_DSTACK_COMPOSE_LEN: usize = 32_768;
pub const ACCEPTED_TCB_STATUSES: [&str; 2] = ["UpToDate", "SWHardeningNeeded"];
```

### 2.3 `register_instance_tdx` (new, change method, payable)

```rust
#[payable]
#[deny_unknown_arguments]
pub fn register_instance_tdx(
    &mut self,
    quote: String,       // lowercase hex, ≤ 16 384 chars
    collateral: String,  // canonical collateral JSON text (§1.2), ≤ 32 768 bytes
    event_log: Value,    // array of IMR3 events (§1.3)
    app_compose: String, // exact dstack app-compose text, 1..=32 768 bytes
    x25519: String,      // 64 hex
    ed25519: String,     // 64 hex
) -> String              // key_hash, 64 hex
```

**Access:** anyone may call it, but SPEC §5 rev 1.3 binding means only the operator account that the enclave
bound into `report_data` succeeds (`predecessor_account_id`). **Deposit:** same rules as `register_instance`
(storage deposit, excess → anchor credit ≤ 0.05 NEAR, rest refunded). Callers attach `0.1 NEAR`. **Gas:**
attach `300 Tgas`. Expected burn is 120–250 Tgas (measured in spike S2).

Checks, in this order (the first failure panics with the code as the message prefix, like the existing methods):

| # | check | code |
|---|---|---|
| 1 | `quote.len() ≤ 16384`, lowercase hex | `E_QUOTE_FORMAT` |
| 2 | `collateral.len() ≤ 32768`, parses as `dcap_qvl::QuoteCollateralV3` via `near_sdk::serde_json::from_str` | `E_COLLATERAL` |
| 3 | `1 ≤ app_compose.len() ≤ 32768` | `E_BAD_INPUT` |
| 4 | keys: 32-byte hex, not all-zero (existing `key32_arg`) | `E_BAD_HEX` / `E_BAD_INPUT` |
| 5 | stored root kind is `INTEL` **and** stored `root_p256 == INTEL_ROOT_P256` | `E_QUOTE_SIG` |
| 6 | INTEL structural parse (§1.1 table: version, tee, vendor id, sig_data_len, zero padding, mr_signer_seam). The contract has no `E_TEE_TYPE`: like `parse_mock`, a wrong TEE type is `E_QUOTE_FORMAT` (the TS client keeps `E_TEE_TYPE`) | `E_QUOTE_FORMAT` |
| 7 | `QuoteVerifier::new_prod().verify(&quote, &collateral, now_secs)` is `Ok(report)`; `now_secs = env::block_timestamp_ms() / 1000` (or `1_750_377_600` under feature `tdx-test-clock`) | `E_QUOTE_SIG` |
| 8 | `report.status` ∈ `ACCEPTED_TCB_STATUSES` | `E_TCB_STATUS` |
| 9 | DEBUG bit clear (byte 168) | `E_DEBUG_TD` |
| 10 | `verify_event_log_dstack(event_log, rtmr3)` (§1.3) | `E_EVENT_LOG` / `E_RTMR3` |
| 11 | `sha256(app_compose) == compose-hash payload` | `E_COMPOSE_MISMATCH` |
| 12 | compose allowed, then OS measurement allowed | `E_COMPOSE_NOT_ALLOWED` / `E_OS_NOT_ALLOWED` |
| 13 | `report_data == key_hash(x25519, ed25519) ‖ registration_nonce(current_account_id, predecessor_account_id)` (existing `registration_report_data`) | `E_REPORT_DATA` |

Then it does **exactly the same record/refresh/deposit/refund logic as `register_instance`**. Refactor that block
into `fn record_instance(&mut self, v: Verified, xp: [u8;32], ep: [u8;32], operator: AccountId) -> (u64 /*expires_at_ms*/, bool /*refreshed*/)`
and call it from both methods. **Event** (NEP-297, standard `plr`, version `1.0.0`): `instance_registered`
with the existing data fields **plus** `"root_kind":"INTEL"` and `"tcb_status":"<status>"`. Example log line:

```
EVENT_JSON:{"standard":"plr","version":"1.0.0","event":"instance_registered","data":[{"key_hash":"5f…","compose_hash":"8f…","os_measurement":"34…","x25519":"…","ed25519":"…","operator":"pe-op-erhan.testnet","expires_at_ms":1794182400000,"refreshed":false,"root_kind":"INTEL","tcb_status":"UpToDate"}]}
```

(Check the exact existing `data` shape in `src/events.rs` and keep it: add the two keys, don't rename anything.)

Unchanged behaviour of the old method: `register_instance` with an INTEL root still fails closed with
`E_QUOTE_SIG` (MOCK quotes only).

### 2.4 `get_tdx_policy` (new, view)

```rust
pub fn get_tdx_policy(&self) -> TdxPolicyView
#[near(serializers = [json])] pub struct TdxPolicyView { pub intel_root_p256: String, pub accepted_tcb_statuses: Vec<String>, pub dcap_qvl_version: String }
```
Returns `{"intel_root_p256":"0ba9…7394","accepted_tcb_statuses":["UpToDate","SWHardeningNeeded"],"dcap_qvl_version":"0.7.1"}`.
Never panics.

### 2.5 Rust skeleton for the new verification (`src/verify_tdx.rs`, new file)

```rust
//! INTEL-mode registration: on-chain Intel DCAP verification (dcap-qvl) + dstack event log (SPEC-TDX §2.3).
use dcap_qvl::{verify::QuoteVerifier, QuoteCollateralV3};
use near_sdk::serde_json::Value;
use crate::binding::{key_hash, registration_report_data};
use crate::bytes::ct_eq;
use crate::errors::*;
use crate::eventlog::{compose_matches, verify_event_log_dstack};
use crate::verify::{Policy, RootKind, Verified};

pub struct TdxRegistration<'a> {
    pub quote: &'a [u8],
    pub collateral: &'a QuoteCollateralV3,
    pub event_log: &'a Value,
    pub app_compose: &'a [u8],
    pub x25519: &'a [u8; 32],
    pub ed25519: &'a [u8; 32],
}

pub fn now_secs() -> u64 {
    #[cfg(feature = "tdx-test-clock")]
    { 1_750_377_600 }
    #[cfg(not(feature = "tdx-test-clock"))]
    { near_sdk::env::block_timestamp_ms() / 1_000 }
}

/// Returns (Verified, tcb_status).
pub fn verify_registration_tdx(
    reg: &TdxRegistration<'_>, policy: &impl Policy, contract_id: &str, operator_id: &str, now: u64,
) -> Result<(Verified, String), Error> {
    let (kind, root) = policy.root();
    if kind != RootKind::Intel || crate::bytes::encode_hex(&root) != crate::INTEL_ROOT_P256_HEX {
        return Err(Error::new(E_QUOTE_SIG, "registry root is not the Intel root"));
    }
    let q = crate::quote::parse_intel(reg.quote)?;                 // §1.1 structural rules
    let report = QuoteVerifier::new_prod()
        .verify(reg.quote, reg.collateral, now)
        .map_err(|_| Error::new(E_QUOTE_SIG, "dcap"))?;
    if !crate::ACCEPTED_TCB_STATUSES.contains(&report.status.as_str()) {
        return Err(Error::new(E_TCB_STATUS, ""));
    }
    if q.is_debug() { return Err(Error::new(E_DEBUG_TD, "")); }
    let boot = verify_event_log_dstack(reg.event_log, &q.rtmr(3))?;
    if !compose_matches(reg.app_compose, &boot.compose_hash) { return Err(Error::new(E_COMPOSE_MISMATCH, "")); }
    let os_measurement = q.os_measurement();
    if !policy.compose_allowed(&boot.compose_hash) { return Err(Error::new(E_COMPOSE_NOT_ALLOWED, "")); }
    if !policy.os_allowed(&os_measurement) { return Err(Error::new(E_OS_NOT_ALLOWED, "")); }
    let expected = registration_report_data(reg.x25519, reg.ed25519, contract_id, operator_id)
        .ok_or_else(|| Error::new(E_REPORT_DATA, "account id length"))?;
    if !ct_eq(&q.report_data(), &expected) { return Err(Error::new(E_REPORT_DATA, "")); }
    Ok((Verified { key_hash: key_hash(reg.x25519, reg.ed25519), compose_hash: boot.compose_hash, os_measurement }, report.status))
}
```

Names that may not exist yet and must be created: `crate::quote::parse_intel` (returns the same view type as
`parse_mock`, with `rtmr()`, `report_data()`, `is_debug()`, `os_measurement()`), `crate::bytes::encode_hex`
(use whatever hex encoder `lib.rs` already uses), and `verify_event_log_dstack`. If `Error::new` takes
`&'static str`, keep the details static as shown.

**getrandom shim** (add to `src/lib.rs`; harmless if unused):

```rust
#[cfg(target_arch = "wasm32")]
fn plr_no_getrandom(_buf: &mut [u8]) -> Result<(), getrandom::Error> { Err(getrandom::Error::UNSUPPORTED) }
#[cfg(target_arch = "wasm32")]
getrandom::register_custom_getrandom!(plr_no_getrandom);
```

---

## 3. Client and shared library additions (TypeScript)

### 3.1 `@plr/shared`

```ts
// packages/shared/src/attest/types.ts — CHANGED (backwards compatible: ctx optional, MockVerifier ignores it)
export interface VerifyContext { collateral?: unknown; nowSecs?: number }
export interface QuoteVerifier {
  readonly rootKind: RootKind;
  readonly rootPublicKey: Uint8Array;
  verify(quote: Uint8Array, ctx?: VerifyContext): ParsedQuote;     // synchronous (dcap-qvl JS verify is sync)
}

// packages/shared/src/attest/intel.ts — NEW
export const INTEL_ROOT_P256: Uint8Array;                     // fromHex(SPEC-TDX §0)
export const ACCEPTED_TCB_STATUSES: readonly string[];        // ["UpToDate","SWHardeningNeeded"]
export class DcapQvlVerifier implements QuoteVerifier {       // replaces the stub in attest/stubs.ts (delete the stub class; re-export from index.ts)
  readonly rootKind: "INTEL";
  constructor(rootPub?: Uint8Array /* default INTEL_ROOT_P256; anything else ⇒ PlrError E_ROOT_UNTRUSTED */,
              o?: { acceptedStatuses?: readonly string[]; clock?: () => number /* ms, default Date.now */ });
  get rootPublicKey(): Uint8Array;
  /** parseQuote(quote,"INTEL") structure first; then dcap verify(quote, ctx.collateral, ctx.nowSecs ?? floor(clock()/1000));
   *  dcap throw ⇒ E_QUOTE_SIG; status not accepted ⇒ E_TCB_STATUS; missing/non-object collateral ⇒ E_COLLATERAL.
   *  Returns parseQuote(quote, "INTEL"). Also exposes the last status: */
  verify(quote: Uint8Array, ctx?: VerifyContext): ParsedQuote;
  readonly lastStatus: string | undefined;
}
export function isIntelRoot(root: Uint8Array): boolean;     // equalBytes(root, INTEL_ROOT_P256)

// packages/shared/src/tdx/eventlog-dstack.ts — NEW (§1.3)
export function verifyEventLogDstack(events: TdxEvent[], rtmr3: Uint8Array): { composeHash: Uint8Array; appId: Uint8Array; instanceId: Uint8Array };

// packages/shared/src/attest/compose-policy.ts — NEW (§1.4)
export function checkDstackComposePolicy(appCompose: string): { images: string[] };   // E_COMPOSE_POLICY

// packages/shared/src/attest/collateral.ts — NEW
export type CollateralJson = Record<string, string>;
export function canonicalCollateral(c: unknown): CollateralJson;   // number[] / Uint8Array → lowercase hex; strings kept; unknown keys dropped; E_COLLATERAL on bad input
export function isCollateralJson(c: unknown): c is CollateralJson;
```

`parseQuote(q, "INTEL")` in `tdx/quote.ts` changes to the §1.1 rules: allow trailing zero padding and require
`mr_signer_seam == 0`. MOCK mode is unchanged.

`verifyAttestation` (`policy.ts`) changes. Nothing else in it changes:
- `parseBundle`: when `expectedKind === "INTEL"`, require `isCollateralJson(b.collateral)` (else `E_BAD_RESPONSE`
  "collateral") and allow `app_compose` ≤ 32 768 bytes. MOCK mode keeps 8 192.
- Step 3: `verifier.verify(b.quote, { collateral: b.collateral, nowSecs: Math.floor((p.now ?? Date.now()) / 1000) })`.
  Add `"E_TCB_STATUS"` and `"E_COLLATERAL"` to the allowed codes of that `guard`.
- Step 6: `rootKind === "INTEL" ? verifyEventLogDstack(...) : verifyEventLog(...)`.
- New step 7b (INTEL only, right after the compose check): `checkDstackComposePolicy(app_compose)` →
  push `CHECKS.COMPOSE_POLICY = "dstack compose: images pinned by digest, exit logging disabled"`.
- New check name (INTEL only, pushed right after `QUOTE_SIG`): `CHECKS.TCB = "Intel TCB status accepted"`.
- `VerifiedRouter` gains optional `tcbStatus?: string` and `images?: string[]` (INTEL only).

### 3.2 `@plr/client`

- Default verifier selection in `client/src/client.ts` (line ~126) and `client/src/vpn/hop.ts` (line ~126):
  `o.verifier ?? (isIntelRoot(trustedRoot) ? new DcapQvlVerifier(trustedRoot) : new MockVerifier(trustedRoot))`.
  **Pinning the Intel root is what selects INTEL mode.** There is no new env var.
- CLI `plr vpn verify` output: for INTEL it prints `root: INTEL ROOT (Intel SGX Root CA)`, `tcb: <status>`,
  `image: <ref>` per image, and `explorer: https://testnet.nearblocks.io/address/<registry>` when `PLR_NEAR_RPC`
  contains `testnet`.
- New CLI flag: `plr vpn verify --fixture <dir>` (§3.3).
- `client/package.json`: add `"bin": { "plr": "./dist/cli.js", "provenexit": "./dist/cli.js" }`.

### 3.3 Fixture / replay format (`fixtures/<name>/`)

```
fixtures/phala-2026-11-12/
  meta.json        {"captured_at_ms":1794460000000,"exit_url":"https://<app-id>-18200.<gw>.phala.network",
                    "network":"testnet","registry":"vpnreg.pe-owner-erhan.testnet","registration_tx":"<tx hash>",
                    "revocation_tx":"<tx hash or null>","note":"captured by scripts/capture-fixture.mjs"}
  nonce.hex        64 hex chars (the nonce the capture used)
  bundle.json      the exact /v1/attestation response body (§1.5)
  registry.json    {"root":{"kind":"INTEL","p256":"0ba9…7394"},"compose":["<hex>"],"os":["<hex>"],
                    "instances":{"<key_hash>":{…InstanceRecord as returned by get_instance…}}}
```

`plr vpn verify --fixture <dir>` = `verifyAttestation({ bundle, nonce, verifier: new DcapQvlVerifier(INTEL_ROOT_P256,
{ clock: () => meta.captured_at_ms }), registry: new MemoryRegistry({ ...registry.json, chain: "near",
contractId: meta.registry, verifiesOnChain: true, now: () => meta.captured_at_ms }), trustedRoot: INTEL_ROOT_P256,
now: meta.captured_at_ms })`. It prints every check and a final line
`✔ VERIFIED (FIXTURE REPLAY of <exit_url>, captured <ISO date>; registry snapshot of <registry>; registration tx <hash>)`.
It needs **no network**. The DCAP check runs at `captured_at` time, so a fixture verifies forever. The README states this
honestly ("proves the recorded exit was genuine at capture time").

Mock-mode fixture: none needed. `bash scripts/demo.sh` with `PLR_LLM=mock` is the fully offline judge path.

---

## 4. Exit (enclave) additions

### 4.1 Environment variables (exit container, INTEL mode)

| var | value | measured? |
|---|---|---|
| `PLR_ATTESTER` | `dstack` (new; default `mock` = existing `PLR_TDX_SOCKET` path) | yes (literal in compose) |
| `PLR_VPN_POLICY_PATH` | `/app/vpn-policy.json` (new; the SPEC-VPN §2 compose JSON baked in the image, used only for `policy`) | yes (file in image) |
| `PLR_VPN_HOST` / `PLR_VPN_PORT` | `0.0.0.0` / `18200` | yes |
| `PLR_CHAIN` | `near` | yes |
| `PLR_NEAR_RPC` | `https://test.rpc.fastnear.com` | yes |
| `PLR_VPN_REGISTRY` | `<VPN_REGISTRY_ID>` e.g. `vpnreg.pe-owner-erhan.testnet` | yes |
| `PLR_OPERATOR_ID` | `<OPERATOR_ID>` e.g. `pe-op-erhan.testnet` | yes |
| `PLR_OPERATOR_KEY` | `ed25519:<base58>` (`NEAR_KEY_RE` in `enclave/src/near.ts`) | **no**: sealed env (`phala deploy -e`), the only secret |
| `PLR_ANCHOR_INTERVAL_MS` | `60000` | yes |
| `PLR_REGISTER_DEPOSIT` | `100000000000000000000000` (0.1 NEAR) | yes |
| `PLR_PCCS_URL` | `https://pccs.phala.network` | yes |

Rule: **every security-relevant setting is a literal in the measured docker-compose.** Only the operator key is
sealed. Changing the key changes who signs and pays, not what the code does.

### 4.2 `DstackAttester` (`enclave/src/attest/dstack-attester.ts`, new)

```ts
import { DstackClient } from "@phala/dstack-sdk";           // pin "@phala/dstack-sdk": "0.5.8"
import { fromHex, PlrError, type Attester, type TdxEvent } from "@plr/shared";
export class DstackAttester implements Attester {
  readonly #c: DstackClient;
  constructor(endpoint = "/var/run/dstack.sock") { this.#c = new DstackClient(endpoint); }
  async getQuote(reportData: Uint8Array): Promise<{ quote: Uint8Array; eventLog: TdxEvent[] }> {
    if (!(reportData instanceof Uint8Array) || reportData.length !== 64) throw new PlrError("E_BAD_INPUT", "report_data");
    const r = await this.#c.getQuote(reportData);           // raw 64 bytes, no hashing (sdk: hex.length ≤ 128)
    const quote = fromHex(String(r.quote).replace(/^0x/, ""));
    const all = JSON.parse(r.event_log) as Array<Record<string, unknown>>;
    const eventLog = all.filter((e) => e.imr === 3).map((e) => ({
      imr: 3, event_type: e.event_type as number, digest: String(e.digest), event: String(e.event), event_payload: String(e.event_payload),
    }));
    return { quote, eventLog };
  }
  /** The measured dstack app-compose, exactly as dstack hashed it. */
  async appCompose(): Promise<string> { const i = await this.#c.info(); return i.tcb_info.app_compose; }
}
```
**UNVERIFIED until S1:** whether `r.quote` carries a `0x` prefix (handled either way), and whether `digest` and
`event_payload` in `event_log` are lowercase hex without `0x`. If not, normalise them in the map
(`.replace(/^0x/,"").toLowerCase()`) and note it in SPEC-TDX as an S1 finding.

### 4.3 `CollateralCache` (`enclave/src/attest/collateral-cache.ts`, new)

```ts
import dcap from "@phala/dcap-qvl";                        // CJS package: default import, then destructure
import { canonicalCollateral, type CollateralJson } from "@plr/shared";
export class CollateralCache {
  #v: CollateralJson | null = null; #at = 0;
  constructor(readonly pccsUrl: string, readonly ttlMs = 3_600_000, readonly clock = Date.now) {}
  async get(quote: Uint8Array): Promise<CollateralJson> {
    if (this.#v && this.clock() - this.#at < this.ttlMs) return this.#v;
    const raw = await dcap.getCollateral(this.pccsUrl, Buffer.from(quote));
    this.#v = canonicalCollateral(raw); this.#at = this.clock(); return this.#v;
  }
}
```
One platform has one FMSPC, so caching a single value per process is correct.

### 4.4 Wiring changes (exact)

- `enclave/src/vpn/config.ts`: `ExitConfig` gains `attester: "mock" | "dstack"`, `policyPath: string | null`,
  `pccsUrl: string`. In `dstack` mode `PLR_TDX_SOCKET` / `PLR_APP_COMPOSE_PATH` are **not** required and
  `PLR_VPN_POLICY_PATH` **is**.
- `enclave/src/vpn/main.ts` `bootExit`: when `cfg.attester === "dstack"`, set `attester = new DstackAttester()`,
  `composeText = await attester.appCompose()`, `composeBytes = utf8(composeText)`, and
  `policy = vpnPolicyOf(readCompose(cfg.policyPath))`. Otherwise keep the existing code.
  `selfCheckQuote(attester, keys, composeHash, rootKind)` passes `rootKind` through to `parseQuote` and picks
  `verifyEventLogDstack` for INTEL.
- `enclave/src/service-routes.ts`: `CommonRoutesOptions` gains `rootKind: RootKind` and
  `collateral?: (quote: Uint8Array) => Promise<CollateralJson>`. The bundle uses `root_kind: o.rootKind`
  (replaces the hard-coded `"MOCK"`) and, when `o.collateral` is set, `collateral: await o.collateral(quote)`
  (failure → `503 E_UPSTREAM`).
- `enclave/src/registry-writer.ts` `RegisterArgs` gains `collateral?: string` (JSON text).
  `enclave/src/near.ts` `registerInstance`: `args.collateral ? "register_instance_tdx" : "register_instance"`.
- `enclave/src/anchor.ts` `register()`: in INTEL mode, add `collateral: JSON.stringify(await cache.get(quote))`.

### 4.5 Exit HTTP API

Unchanged (SPEC-VPN §3): `GET /v1/attestation`, `GET /v1/tunnel` (Upgrade `plr-vpn/1`), `GET /v1/receipts/proof`,
`GET /healthz`. Public URL on Phala: `https://<app-id>-18200.<gateway-domain>` (TLS terminated by the dstack
gateway; the tunnel inside is end-to-end encrypted to the attested key, so the gateway sees only ciphertext).
Fallback if the gateway breaks the Upgrade (spike S1 step 6): `https://<app-id>-18443s.<gateway-domain>` (TLS passthrough),
with the exit terminating TLS itself using a boot-time self-signed cert and the client env `PLR_VPN_TLS_VERIFY=0`.
This is safe because nothing relies on TLS for authenticity.

---

## 5. Docker image and dstack compose

The measured files are [`deploy/phala/Dockerfile`](deploy/phala/Dockerfile) and
[`deploy/phala/docker-compose.yml`](deploy/phala/docker-compose.yml); the live values and deploy steps are in
[`deploy/phala/README.md`](deploy/phala/README.md). Any change to the compose gives a new compose hash, which the owner
must approve again (`allow_compose`).

---

## 6. CLI commands the demo uses (frozen output keywords)

| command | must print (grep-able) |
|---|---|
| `node client/dist/cli.js vpn verify` (INTEL) | `✔ quote signature chain to root`, `✔ Intel TCB status accepted`, `✔ dstack compose: images pinned by digest, exit logging disabled`, `✔ compose hash allowed by registry`, `✔ instance registered with matching keys`, `✔ VERIFIED` |
| same, after `revoke_compose` | `✘ E_COMPOSE_NOT_ALLOWED` |
| `node client/dist/cli.js vpn verify --fixture fixtures/<name>` | `FIXTURE REPLAY`, `✔ VERIFIED` |
| `node client/dist/cli.js vpn` | `✔ SOCKS5 proxy on socks5h://127.0.0.1:18180` |
| `curl --proxy socks5h://127.0.0.1:18180 https://api.ipify.org` | an IP address that is **not** the laptop's |
