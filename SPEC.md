# PLR-v1 — Attestation, registry and receipt base protocol

Status: **FROZEN** for milestone 1 (rev 1.1, 2026-10-23: runtime measurement in §4, from security review; rev 1.2: operator organizations in §7; rev 1.3: quote-purpose domain separation + operator-bound registration in §5/§7). Changes require an explicit spec revision; implementations and the
locked tests (`packages/shared/test`, `e2e/test`) are written against this document.

**Scope (2026-11-12).** PLR-v1 was written for a private LLM router; the VPN exit ([`SPEC-VPN.md`](SPEC-VPN.md)) reuses
its quote format, event log, compose rules, key binding, registry, receipt anchoring and verification order. The
router was removed from this repository on 2026-11-12, so this file now keeps only that shared base. The
router-only parts (the encrypted chat endpoint §6.3, the router's compose schema, receipt and SDK, the ports and model of
§11, the client SDK §12, the router harness §13 and the mock LLM §14) are in the baseline commits
`c2a35e4`..`9bd402e`. Section numbers are unchanged because code comments and the deployed contract's source cite
them; removed sections keep a one-line note. No byte format changed.

Notation: `‖` = byte concatenation. `u16le/u32le` little-endian, `u64be` big-endian. `utf8(s)` = UTF-8 bytes.
Hex on the wire is **lowercase, no `0x` prefix, even length**; parsers MUST reject anything else.
`DOMAIN = utf8("PLR-v1")`.

---

## 1. Threat model and guarantees

The operator of an attested instance (the VPN exit), the cloud host and the network are untrusted. The client
trusts: (a) the attestation root (Intel in production, SPEC-TDX; the **MOCK ROOT** in the local stack), (b) the
registry contract's owner policy, (c) its own code.

The client uses an instance only if ALL of the following hold, checked fresh per session:
1. A quote signed (via an attestation key certified by the root) describes a non-debug TDX TD.
2. The quote's `report_data` binds the instance's X25519 + Ed25519 public keys and the client's fresh nonce.
3. The event log replays to the quote's RTMR3 and contains exactly one `compose-hash` that equals
   `sha256(app_compose_bytes)` of the published `app-compose.json`.
4. The registry contract currently allows that compose hash and the OS measurement, and has a live
   registration for that key pair.

Traffic is encrypted to the attested X25519 key (the VPN tunnel, SPEC-VPN §4); signed receipts are anchored
on-chain in Merkle batches (§8).

Out of scope (documented, not defended): TEE vendor compromise, micro-architectural side channels,
traffic metadata (timing, sizes, IP), denial of service, the owner key's honesty (→ multisig later).

---

## 2. Quote format (Intel TDX Quote v4 layout)

### 2.1 Header (48 bytes, offset 0)
| off | len | field | required value |
|---|---|---|---|
| 0 | 2 | version (u16le) | 4 |
| 2 | 2 | att_key_type (u16le) | 2 (ECDSA-P256) |
| 4 | 4 | tee_type (u32le) | 0x00000081 (TDX) |
| 8 | 4 | reserved | zero |
| 12 | 16 | qe_vendor_id | MOCK: `utf8("PLR-MOCK-QE-0001")`; Intel: `939a7233f79c4ca9940a0db3957f0607` |
| 28 | 20 | user_data | any (mock: zero) |

### 2.2 TD Report body (584 bytes, offset 48). Offsets below are **absolute** (from quote start).
| abs off | len | field |
|---|---|---|
| 48 | 16 | tee_tcb_svn |
| 64 | 48 | mr_seam |
| 112 | 48 | mr_signer_seam |
| 160 | 8 | seam_attributes |
| 168 | 8 | td_attributes — bit 0 of byte 168 = **DEBUG** |
| 176 | 8 | xfam |
| 184 | 48 | mr_td |
| 232 | 48 | mr_config_id |
| 280 | 48 | mr_owner |
| 328 | 48 | mr_owner_config |
| 376 | 48 | rtmr0 |
| 424 | 48 | rtmr1 |
| 472 | 48 | rtmr2 |
| 520 | 48 | rtmr3 |
| 568 | 64 | report_data |

`signed_bytes = quote[0:632]`.

### 2.3 Signature section (offset 632)
`u32le sig_data_len` followed by `sig_data`.

**MOCK sig_data** (exactly 192 bytes ⇒ total quote length **828**):
| off (in sig_data) | len | field |
|---|---|---|
| 0 | 64 | `quote_sig` = ECDSA-P256-SHA256(AK, signed_bytes), `r‖s`, low-S |
| 64 | 64 | `ak_pub` = attestation key, uncompressed point **without** the 0x04 prefix (`x‖y`) |
| 128 | 64 | `ak_cert_sig` = ECDSA-P256-SHA256(ROOT, `utf8("PLR-MOCK-AK-v1") ‖ ak_pub`), `r‖s`, low-S |

The ROOT public key is published as 64-byte `x‖y` hex. Mock verification: `ak_cert_sig` verifies under
ROOT, then `quote_sig` verifies under `ak_pub`. (Intel mode: sig_data is the real v4 ECDSA quote
signature data with QE report + PCK chain, verified by dcap-qvl; out of scope for milestone 1.)

Parsers MUST reject: wrong length for the declared mode, `sig_data_len` mismatch, version ≠ 4,
att_key_type ≠ 2, tee_type ≠ 0x81, non-zero reserved bytes.

### 2.4 Mock measurement values (deterministic)
`mr_td = SHA384(utf8("PLR-MOCK-OS-v1:MRTD"))`, `rtmrN = SHA384(utf8("PLR-MOCK-OS-v1:RTMR" + N))` for N=0,1,2.
Other 48-byte fields zero; tee_tcb_svn zero; td_attributes zero (debug = byte 168 |= 0x01).

### 2.5 OS measurement
`os_measurement = SHA256(mr_td ‖ rtmr0 ‖ rtmr1 ‖ rtmr2)` (32 bytes). SHA-256 is used (not keccak) so every
target chain can compute it natively.

---

## 3. Event log and RTMR3 (dstack-compatible)

Event JSON object:
```json
{ "imr": 3, "event_type": 134217729, "digest": "<96 hex>", "event": "<name>", "event_payload": "<hex>" }
```
`event_type` MUST be `0x08000001` (134217729). Only `imr == 3` events are accepted.

`digest = SHA384(u32le(event_type) ‖ utf8(":") ‖ utf8(event) ‖ utf8(":") ‖ event_payload_bytes)`

Replay: `rt = 0x00 * 48`; for each event in order: `rt = SHA384(rt ‖ digest)`. Result MUST equal quote rtmr3.
Verifiers MUST recompute each digest and reject if it differs from the provided `digest`.

Required boot sequence (exact names, in this order, each exactly once; other events MAY appear only
**after** `boot-mr-done`, and MUST NOT reuse a reserved name):
1. `system-preparing` — empty payload
2. `app-id` — 20 bytes = `SHA256(compose_bytes)[0:20]`
3. `compose-hash` — 32 bytes = `SHA256(compose_bytes)`
4. `instance-id` — 20 random bytes
5. `boot-mr-done` — empty payload

Reserved names: the five above. Max events: 64. Max payload: 256 bytes.

---

## 4. App compose (the measured "what code is running" document)

`app-compose.json` is the exact byte string measured into RTMR3. It is published with every attestation.
`compose_hash = SHA256(compose_bytes)`. Canonical form produced by the build: keys sorted recursively,
`JSON.stringify(obj, null, 2) + "\n"`. Verifiers hash the **bytes received**, never a re-serialisation.
The schema of the VPN exit's compose is SPEC-VPN §2 (`name: "plr-vpn"`); in INTEL/dstack mode the measured document
is the dstack app-compose (SPEC-TDX §1.4).

**rev 1.1 — runtime measurement.** The compose pins the executable that sees plaintext (`node_sha256`, for the VPN
exit `vpn.node_sha256`). Because node can be a thin launcher, the digest is SHA-256 over a sorted manifest of the
executable, every non-system dylib it links (transitively) and runtime-loaded plugins. The host refuses to launch on
mismatch (`E_MEASUREMENT_MISMATCH`) and runs private re-hashed copies. Verifiers still hash the compose bytes as received.

The **mock TDX host** (the local stand-in for the dstack guest OS) is the only component that measures:
it reads `app-compose.json`, hashes the bundle file and the runtime, refuses to launch if any hash differs from the
compose, extends RTMR3 with the boot sequence, then launches the bundle as a child process. The instance obtains
quotes only through the host's quote endpoint (§6.1); it never holds the ROOT or AK private keys.

---

## 5. Key binding

The instance generates at boot, in memory only: X25519 keypair `(xs, xp)`, Ed25519 keypair `(es, ep)`.

`key_hash = SHA256(DOMAIN ‖ xp(32) ‖ ep(32))`

**rev 1.3 — every quote states its purpose**, so no quote can serve another purpose:
```
session:       report_data = key_hash ‖ SHA256(utf8("PLR-v1/session-nonce") ‖ client_nonce(32))
registration:  report_data = key_hash ‖ registration_nonce
               registration_nonce = SHA256(utf8("PLR-v1/register/2") ‖ u8(len c) ‖ c ‖ u8(len o) ‖ o)
               c = utf8(registry contract account id), o = utf8(operator account id), both ≤ 64 bytes (NEAR limit)
```
Instances only ever produce session report_data for `/v1/attestation`; the raw client nonce never appears in a
quote. Producing a registration quote from a session request would need a SHA-256 preimage. Binding the operator means a
registration quote can only be submitted by the operator account the enclave chose (its configured `PLR_OPERATOR_ID`).

---

## 6. Instance HTTP API (the VPN exit: default `127.0.0.1:18200`, SPEC-VPN §3)

### 6.1 Mock TDX host quote endpoint (internal, not exposed to clients)
`POST /GetQuote` body `{"report_data":"<128 hex>"}` → `{"quote":"<hex>","event_log":[...]}`.
Listens on a Unix socket under the run directory (mode 0600); path given to the instance via
`PLR_TDX_SOCKET`. Mirrors dstack's `GetQuote` (no hashing of report_data).

### 6.2 `GET /v1/attestation?nonce=<64 hex>`
→ `200`
```json
{
  "v": "PLR-v1",
  "root_kind": "MOCK",
  "quote": "<hex>",
  "event_log": [ ... ],
  "app_compose": "<exact compose file contents as a JSON string>",
  "x25519": "<64 hex>",
  "ed25519": "<64 hex>"
}
```
Bad/missing nonce → `400 {"error":"E_BAD_REQUEST"}`.
Optional fields: `registration_quote` (hex) — the quote of the instance's latest successful registration (§5), served
once registered; a NEAR registry verified it on-chain, so clients accept and ignore it. `collateral` — INTEL mode
only (SPEC-TDX §1.5).

### 6.3 (removed 2026-11-12)
The LLM router's encrypted chat endpoint `POST /v1/private/chat` and its request/frame key schedule. The VPN exit's
encrypted channel is the tunnel of SPEC-VPN §4.

### 6.4 `GET /v1/receipts/proof?seq=<n>`
→ `{"anchor_id":<u64>,"first_seq":<u64>,"count":<u64>,"index":<u64>,"root":"<64 hex>","proof":["<64 hex>",...]}`
or `404 {"error":"E_NOT_ANCHORED"}` if not yet anchored.

### 6.5 `GET /healthz` → `{"ok":true}`.

**No-retention rules (enforced by review + tests):** no traffic plaintext or ciphertext in stdout/stderr, error
messages, files, or env; no disk writes; receipts store only hashes (SPEC-VPN §1, §5).

---

## 7. Registry (NEAR contract, `contracts/near`)

State:
- `owner`, `pending_owner`
- `root`: `{ kind: "MOCK"|"INTEL", p256: "<128 hex>" }`
- `allowed_compose: set<hex32>`, `allowed_os: set<hex32>`
- `instances: map<key_hash → Instance>`
  `Instance = { compose_hash, os_measurement, x25519, ed25519, operator, registered_at_ms, expires_at_ms, next_seq }`
- `anchors: vec<Anchor>`; `Anchor = { id, key_hash, root, first_seq, count, at_ms }`
- `instance_ttl_ms` (default 86_400_000)
- `operators: map<account → org_id>` (rev 1.2; `org_id` matches `^[a-z0-9][a-z0-9._-]{0,63}$`)

Methods (NEAR: JSON args, hex strings; zero hash `00…00` always rejected):
| method | who | effect |
|---|---|---|
| `new(owner_id, root_kind, root_p256, instance_ttl_ms)` | init | |
| `allow_compose(hash)` / `revoke_compose(hash)` | owner | event `compose_allowed` / `compose_revoked` |
| `allow_os(hash)` / `revoke_os(hash)` | owner | event `os_allowed` / `os_revoked` |
| `set_root(kind, p256)` | owner | event `root_set` |
| `propose_owner(id)` / `accept_owner()` | owner / pending | two-step transfer |
| `approve_operator(account_id, org_id)` / `revoke_operator(account_id)` | owner | rev 1.2; event `operator_approved` / `operator_revoked`; bad org_id ⇒ `E_BAD_INPUT` |
| `get_operator(account_id) → org_id \| null` | view | rev 1.2 |
| `register_instance(quote, event_log, app_compose, x25519, ed25519)` | anyone (operator), payable for storage | verifies on-chain (below); event `instance_registered` |
| `anchor_receipts(key_hash, root, first_seq, count, sig)` | anyone | event `receipts_anchored` |
| `is_allowed(compose_hash, os_measurement) → bool` | view | |
| `get_instance(key_hash) → Instance \| null` | view | returns null if expired; rev 1.2: includes `org_id` (live lookup of the operator's org, or null) |
| `get_root() → {kind,p256}` | view | |
| `get_anchor(id) → Anchor \| null`, `anchor_count() → u64` | view | |

`register_instance` MUST verify, failing with the listed code in the panic message:
1. quote parses per §2 in MOCK mode, `E_QUOTE_FORMAT`
2. root/AK signatures valid under stored root, `E_QUOTE_SIG`
3. DEBUG bit clear, `E_DEBUG_TD`
4. event log replays to rtmr3 and has a valid boot sequence, `E_EVENT_LOG` / `E_RTMR3`
5. `SHA256(app_compose) == compose-hash event`, `E_COMPOSE_MISMATCH`
6. compose and OS measurement allowed, `E_COMPOSE_NOT_ALLOWED` / `E_OS_NOT_ALLOWED`
7. `report_data == SHA256(DOMAIN‖x25519‖ed25519) ‖ registration_nonce(current_account_id, predecessor_account_id)` (§5 rev 1.3), `E_REPORT_DATA`

Re-registering the same key_hash refreshes `expires_at_ms` and keeps `next_seq` and `operator` (only the bound operator
can submit it, rev 1.3). Replaying a registration quote can only re-register the same keys under the same operator.

`anchor_receipts`: instance exists, is unexpired, its compose and OS are still allowed; `first_seq == next_seq`;
`1 ≤ count ≤ 10_000`; `sig` = Ed25519(instance ed25519,
`utf8("PLR-v1/anchor") ‖ utf8(contract_account_id) ‖ key_hash ‖ root ‖ u64be(first_seq) ‖ u64be(count)`).
Then `next_seq += count`. Codes: `E_INSTANCE_NOT_REGISTERED`, `E_SEQ`, `E_ANCHOR_SIG`, `E_COMPOSE_NOT_ALLOWED`.

NEAR implementation notes (verified by spike on near-sandbox 2.13.4, near-sdk 5.29.1):
`env::p256_verify(sig[64], sha256_digest[32], compressed_pubkey[33])` — the host **accepts high-S signatures**,
so the contract MUST itself reject `s > n/2` (n = P-256 order) for both `quote_sig` and `ak_cert_sig`, and
compress the 64-byte `x‖y` keys (prefix 0x02/0x03 by y parity). SHA-384 via the `sha2` crate (no host fn).
Caller-supplied JSON is bounded: quote ≤ 4 KiB hex, event_log ≤ 64 events, app_compose ≤ 8 KiB.

Events: NEP-297 `EVENT_JSON:{"standard":"plr","version":"1.0.0","event":"<name>","data":[...]}`.

---

## 8. Receipts and Merkle anchoring

Every session yields an Ed25519-signed receipt (the VPN session receipt of SPEC-VPN §5: `receipt_msg`, `sig` under the
instance's attested `ep`, `leaf = SHA256(0x00 ‖ receipt_msg)`). `seq` is a per-instance counter from 0, contiguous.

Merkle tree: RFC 6962 §2.1 (`node = SHA256(0x01 ‖ L ‖ R)`, split at largest power of two < n). Proofs are
RFC 6962 audit paths. A batch covers receipts `[first_seq, first_seq+count)` and is anchored with
`anchor_receipts` (§7, `anchorMessage`).

The client verifies the receipt's signature under the attested `ep` and its fields against its own values
(SPEC-VPN §5). Later it MAY fetch the proof (§6.4) and check it against `get_anchor(anchor_id)` on-chain; the batch
position (`first_seq`, `count`) and the root are taken from the chain, never from the instance.

---

## 9. Client verification order (`verifyAttestation`) and error codes

Fail closed. The first failing check throws `PlrError(code)`; nothing is sent.
1. nonce fresh 32 random bytes; response fields well-formed — `E_BAD_RESPONSE`
2. quote structure — `E_QUOTE_FORMAT`; tee type — `E_TEE_TYPE`
3. signature chain to trusted root (root from config, MUST equal registry `get_root`) — `E_ROOT_UNTRUSTED` / `E_QUOTE_SIG`
4. DEBUG bit clear — `E_DEBUG_TD`
5. `report_data[0:32] == key_hash(x25519, ed25519)` — `E_REPORT_DATA_KEYS`; `report_data[32:64] == SHA256("PLR-v1/session-nonce" ‖ nonce)` — `E_NONCE` (rev 1.3)
6. event log digests + boot sequence — `E_EVENT_LOG`; replay == rtmr3 — `E_RTMR3`
7. `SHA256(app_compose bytes) == compose-hash` — `E_COMPOSE_MISMATCH`
8. registry `is_allowed(compose, os)` — `E_COMPOSE_NOT_ALLOWED` / `E_OS_NOT_ALLOWED` (each checked separately)
9. registry `get_instance(key_hash)` non-null, keys/compose/os match — `E_INSTANCE_NOT_REGISTERED`
10. registry unreachable at any step — `E_REGISTRY_UNAVAILABLE`

Tunnel and receipts: SPEC-VPN §8.

---

## 10. TypeScript module contract (`@plr/shared`)

Locked tests import exactly these names from `@plr/shared`. All byte values are `Uint8Array`; hex strings
only at JSON boundaries.

```ts
// errors & encoding
class PlrError extends Error { code: string }
toHex(b: Uint8Array): string; fromHex(h: string, expectedLen?: number): Uint8Array   // throws PlrError E_BAD_HEX
concatBytes(...a: Uint8Array[]): Uint8Array
DOMAIN: Uint8Array

// tdx
const QUOTE: { HEADER_LEN: 48, BODY_LEN: 584, SIGNED_LEN: 632, MOCK_LEN: 828, OFF: { MR_TD:184, RTMR0:376, RTMR3:520, REPORT_DATA:568, TD_ATTRIBUTES:168 } }
MOCK_QE_VENDOR_ID: Uint8Array
interface TdReport { teeTcbSvn, mrSeam, mrSignerSeam, seamAttributes, tdAttributes, xfam, mrTd, mrConfigId,
                     mrOwner, mrOwnerConfig, rtmr: [Uint8Array,Uint8Array,Uint8Array,Uint8Array], reportData }
interface ParsedQuote { version: number; attKeyType: number; teeType: number; qeVendorId: Uint8Array;
                        userData: Uint8Array; report: TdReport; signedBytes: Uint8Array; sigData: Uint8Array }
encodeQuote(header: {qeVendorId: Uint8Array; userData?: Uint8Array}, report: TdReport, sigData: Uint8Array): Uint8Array
parseQuote(q: Uint8Array): ParsedQuote                          // §2 checks; E_QUOTE_FORMAT / E_TEE_TYPE
isDebug(report: TdReport): boolean
osMeasurement(report: TdReport): Uint8Array
mockOsReport(opts?: { debug?: boolean }): TdReport               // §2.4 values, rtmr3 & reportData zero

// event log
interface TdxEvent { imr: number; event_type: number; digest: string; event: string; event_payload: string }
EVENT_TYPE: 0x08000001
makeEvent(name: string, payload: Uint8Array): TdxEvent
replayRtmr3(events: TdxEvent[]): Uint8Array
verifyEventLog(events: TdxEvent[], rtmr3: Uint8Array): { composeHash: Uint8Array; appId: Uint8Array; instanceId: Uint8Array }
bootEvents(composeBytes: Uint8Array, instanceId: Uint8Array): TdxEvent[]

// key binding
keyHash(x25519: Uint8Array, ed25519: Uint8Array): Uint8Array
reportData(x25519, ed25519, clientNonce): Uint8Array                  // rev 1.3: key_hash ‖ SHA256("PLR-v1/session-nonce" ‖ nonce)
registrationNonce(contractId: string, operatorId: string): Uint8Array   // rev 1.3 (§5)
registrationReportData(x25519, ed25519, contractId: string, operatorId: string): Uint8Array

// attestation
interface Attester { getQuote(reportData: Uint8Array): Promise<{ quote: Uint8Array; eventLog: TdxEvent[] }> }
interface QuoteVerifier { readonly rootKind: "MOCK" | "INTEL"; verify(quote: Uint8Array): ParsedQuote }
class MockRoot { static generate(): MockRoot; static fromSecret(sk: Uint8Array): MockRoot; readonly publicKey: Uint8Array /*64*/; readonly secretKey: Uint8Array
                 certifyAk(akPub: Uint8Array): Uint8Array }
class MockTdxAttester implements Attester {
  constructor(opts: { root: MockRoot; composeBytes: Uint8Array; instanceId?: Uint8Array; debug?: boolean }) }
class MockVerifier implements QuoteVerifier { constructor(rootPub: Uint8Array) }

// receipts (the VPN session receipt itself: SPEC-VPN §9.1)
merkleRoot(leaves: Uint8Array[]): Uint8Array
merkleProof(leaves: Uint8Array[], index: number): Uint8Array[]
verifyMerkleProof(leaf: Uint8Array, index: number, size: number, proof: Uint8Array[], root: Uint8Array): boolean
anchorMessage(p: { contractId: string; keyHash: Uint8Array; root: Uint8Array; firstSeq: bigint; count: bigint }): Uint8Array

// registry (chain-agnostic)
interface InstanceRecord { compose_hash: string; os_measurement: string; x25519: string; ed25519: string;
                           operator: string; org_id: string | null; registered_at_ms: number; expires_at_ms: number; next_seq: number }
interface RegistryReader {
  readonly chain: string; readonly contractId: string;
  getRoot(): Promise<{ kind: "MOCK" | "INTEL"; p256: string }>;
  isComposeAllowed(h: string): Promise<boolean>;  isOsAllowed(h: string): Promise<boolean>;
  getInstance(keyHash: string): Promise<InstanceRecord | null>;
  getAnchor(id: number): Promise<{ id: number; key_hash: string; root: string; first_seq: number; count: number; at_ms: number } | null>;
}

// policy
interface AttestationBundle { v: "PLR-v1"; root_kind: "MOCK" | "INTEL"; quote: string; event_log: TdxEvent[];
                              app_compose: string; x25519: string; ed25519: string;
                              registration_quote?: string /* accepted, ignored (§6.2) */; collateral?: object /* INTEL */ }
interface VerifiedRouter { x25519: Uint8Array; ed25519: Uint8Array; keyHash: Uint8Array; composeHash: Uint8Array;
                           osMeasurement: Uint8Array; rootKind: "MOCK" | "INTEL"; checks: string[] }
verifyAttestation(p: { bundle: AttestationBundle; nonce: Uint8Array; verifier: QuoteVerifier;
                       registry: RegistryReader; trustedRoot: Uint8Array }): Promise<VerifiedRouter>
```
`isComposeAllowed`/`isOsAllowed` map to the contract's `is_allowed` semantics; NEAR exposes them as
`is_compose_allowed(hash)` and `is_os_allowed(hash)` views in addition to `is_allowed`.

Registry reader implementations: `NearRegistry` (`client`), `MemoryRegistry` (`@plr/shared`, tests only;
`new MemoryRegistry({ root, compose: string[], os: string[], instances: Record<string, InstanceRecord> })`).

---

## 11. Ports and local layout
VPN exit `127.0.0.1:18200` (SPEC-VPN §3) · client SOCKS5 proxy `127.0.0.1:18180` · test builds' DoH resolver
`127.0.0.1:18253` (SPEC-VPN §2) · near-sandbox RPC `127.0.0.1:3030` · run state in `./.run/`.

---

## 12. (removed 2026-11-12)
The LLM router's client SDK and CLI (`PrivateClient`, `plr verify` / `plr chat` / `plr proxy`). The VPN client SDK and
CLI are SPEC-VPN §9.2; the NEAR registry reader `NearRegistry({ rpcUrl, contractId })` (in `@plr/client`) is unchanged.

## 13. (removed 2026-11-12)
The router e2e harness. The harness of this repository is SPEC-VPN §9.3.

## 14. (removed 2026-11-12)
The mock LLM.
