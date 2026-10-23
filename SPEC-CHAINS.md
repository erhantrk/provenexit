# PLR-CHAINS — one protocol, many registries

Status: **FROZEN** (2026-10-24), rev 1. Builds on `SPEC.md` rev 1.3, `SPEC-VPN.md` rev 2, `SPEC-COMBO.md`. Defines how the PLR
registry (SPEC §7) is realised on chains other than NEAR, and the one client rule that makes every chain equally safe.

## 1. Tiers

| tier | chains | what the chain enforces | what the client additionally verifies |
|---|---|---|---|
| A | NEAR | full quote verification at registration (SPEC §7), owner policy, operator orgs, anchors (Ed25519-checked) | — |
| B | EVM (any EVM incl. Monad), Stellar (Soroban), Solana | owner policy, operator orgs, registration only by **owner-approved operators** with `operator = tx signer`, the **registration quote stored on-chain**, anchors with contiguous `first_seq` posted only by the instance's operator | the stored registration quote (§2) and each anchor's Ed25519 signature |
| C | Zcash (no contracts) | ordering + authenticity of owner/operator records written as transparent `OP_RETURN` data (§5); nothing is validated by consensus beyond the transaction signature | everything in tier B, from records it parses itself (§5), with the registration quote hash-committed on-chain and the quote served by the instance |

Tier B/C accept instance records only from operators the owner has approved (`approve_operator`, evaluated live): without
on-chain quote checks this stops unapproved accounts from front-running or spamming registrations. A chain may move up a tier later (e.g. Stellar has `secp256r1_verify`); clients must not depend on the tier for safety.

## 2. Registration evidence (the client rule, `SPEC.md` §9 step 9b, rev 1.4)
`RegistryReader` gains `readonly verifiesOnChain: boolean` (true only for tier A) and
`getRegistrationQuote(keyHash: string, offered?: Uint8Array): Promise<Uint8Array | null>` (tier B: the quote stored on-chain,
`offered` ignored; tier C: returns `offered` only if its SHA-256 equals the on-chain `reg_quote` commitment, else null; tier A
may return null). The attestation bundle (SPEC §6.2) gains an optional `registration_quote` hex field that routers and exits
include once registered; the client passes it as `offered`.

When `verifiesOnChain` is false, after SPEC §9 step 9 the client MUST, failing with `E_REGISTRATION_EVIDENCE`:
1. obtain `rq = getRegistrationQuote(key_hash, bundle.registration_quote)` (null ⇒ fail);
2. `verifier.verify(rq)` (same pinned root as the session quote), DEBUG clear;
3. `rq.report_data == registrationReportData(x25519, ed25519, registry.contractId, record.operator)` (SPEC §5 rev 1.3);
4. `rq.mr_td, rtmr0, rtmr1, rtmr2, rtmr3` all equal the session quote's — the same TD boot, so the already-verified event log,
   compose hash and OS measurement apply to it.
Tier A readers return `verifiesOnChain = true` and the step is skipped (the contract did it). `MemoryRegistry` gains an option
`verifiesOnChain` (default true) and `registrationQuotes: Record<keyHash, hex>`.

Anchors on tier B/C: `verifyAnchored` additionally checks the anchor's stored `sig` against the instance's attested Ed25519 key
over SPEC §7 `anchorMessage` (with `contractId` per §3). Bad or missing sig ⇒ `E_ANCHOR_SIG`. `AnchorRecord` gains `sig?: string`.

## 3. Identifiers (all ≤ 64 bytes, used verbatim in `registrationNonce` / `anchorMessage`)
| chain | `contractId` | operator id |
|---|---|---|
| NEAR | registry account id (unchanged) | NEAR account id |
| EVM / Monad | `evm:<chainId>:<0x-lowercase-address>` | `0x` + 40 lowercase hex (tx sender) |
| Stellar | `stellar:<C… contract strkey>` | `G…` account strkey (tx source / `require_auth` address) |
| Solana | `solana:<registry state account base58>` | signer pubkey base58 |
| Zcash | `zcash:<network>:<owner t-address>` (`network` = `regtest`/`testnet`/`mainnet`) | t-address of the record's signer |

## 4. Instance-side changes (router and exit; also inside combo)
- `PLR_CHAIN` = `near` (default) | `evm` | `stellar` | `solana` | `zcash` selects the registry writer; chain settings come from
  `PLR_<CHAIN>_*` env (listed per chain below). The host forwards them in its env allowlists.
- Registration always uses `registrationReportData(registry contractId, own operator id)`. Tier B writers submit the quote bytes
  with the record; tier C writers commit `SHA256(quote)`.
- `/v1/attestation` responses include `registration_quote` (hex) once the instance has registered (public data; reveals nothing
  new). Malformed ⇒ the client treats it as absent.
- Anchoring: same batching; tier B/C writers submit `(key_hash, root, first_seq, count, sig)`.

## 5. Zcash record log (tier C)
Registry = all confirmed transparent transactions whose **every input** is signed (P2PKH `scriptSig`) by one key, and that carry
exactly one `OP_RETURN` output whose data starts with `utf8("PLR1")`. The signer's t-address (hash160 of the `scriptSig` pubkey)
is the record's author. Records are ordered by (block height, tx index). Only records from the **owner** address (the one in
`contractId`, or a later owner set by an owner record) are policy; instance records must come from the operator they name.

Payload = `"PLR1" ‖ u8(type) ‖ body` (≤ 80 bytes total):
| type | name | author | body |
|---|---|---|---|
| 0x01 | allow_compose | owner | hash32 |
| 0x02 | revoke_compose | owner | hash32 |
| 0x03 | allow_os | owner | hash32 |
| 0x04 | revoke_os | owner | hash32 |
| 0x05 | set_root | owner | u8(kind: 1=MOCK, 2=INTEL) ‖ p256 x‖y (64) |
| 0x06 | approve_operator | owner | hash160 of operator (20) ‖ u8(len) ‖ org_id (≤ 48 bytes, SPEC §7 charset) |
| 0x07 | revoke_operator | owner | hash160 (20) |
| 0x08 | transfer_owner | owner | hash160 of the new owner (20) |
| 0x10 | reg_keys | operator | x25519 (32) ‖ ed25519 (32) |
| 0x11 | reg_measure | operator | key_hash (32) ‖ compose_hash (32) |
| 0x12 | reg_os | operator | key_hash (32) ‖ os_measurement (32) |
| 0x13 | reg_quote | operator | key_hash (32) ‖ SHA256(registration quote) (32) |
| 0x20 | anchor | operator | key_hash (32) ‖ root (32) ‖ u32be(first_seq) ‖ u16be(count) |
| 0x21 | anchor_sig | operator | key_hash[0:8] ‖ sig (64) — the Ed25519 anchor signature for the operator's latest unsigned anchor of that key |

Semantics (reader-side, deterministic): a registration of key K by operator O is complete when 0x10 (whose keys hash to K),
0x11, 0x12 and 0x13 for K all exist from O. `getInstance(K)` returns the **earliest completed** registration whose operator is
**currently approved** (else null); `registered_at` = block time of its completing record; expiry = `registered_at + 86 400 000 ms`, refreshed by a repeated 0x13. Anchors must be contiguous
(`first_seq == next_seq`, `1 ≤ count ≤ 10 000`) and from the instance's operator, else ignored; an anchor without a valid 0x21
within the next 10 blocks is ignored. Unknown types and malformed bodies are ignored. `isComposeAllowed` etc. reflect the
latest owner record. Malformed transactions never throw; they are skipped.

Reader source: a Zcash node JSON-RPC (Zebra) — `getblockcount`, `getblockhash`, `getblock <hash> 2`; it scans from
`PLR_ZCASH_START_HEIGHT`. Writers build and sign v5 transparent transactions themselves (ZIP-244 sighash, P2PKH, ZIP-317 fee)
and submit with `sendrawtransaction`. Env: `PLR_ZCASH_RPC`, `PLR_ZCASH_NETWORK`, `PLR_ZCASH_OWNER` (t-address = contractId part),
`PLR_ZCASH_KEY` (operator WIF/hex secret, writer only), `PLR_ZCASH_START_HEIGHT`.

## 6. Harness (`e2e/src/harness.ts`) — chain-agnostic admin
```ts
type Chain = "near" | "evm" | "stellar" | "solana" | "zcash";
startStack(o: { llm; chain?: Chain; … })                       // default "near" (existing tests unchanged)
interface Stack { …
  chain: Chain;
  admin: ChainAdmin;       // owner of the LLM registry
  vpnAdmin: ChainAdmin;    // owner of the VPN registry
  asStranger(a: ChainAdmin): ChainAdmin;  // same API signed by the stranger account (must be refused / ignored)
}
interface ChainAdmin {
  allowCompose(h: string): Promise<void>; revokeCompose(h: string): Promise<void>;
  allowOs(h: string): Promise<void>; revokeOs(h: string): Promise<void>;
  approveOperator(account: "operator" | "operator2", orgId: string): Promise<void>;
  revokeOperator(account: "operator" | "operator2"): Promise<void>;
}
```
`approveBuild`, `approveVpnBuild`, `approveOperator`, `startRouter`, `startExit`, `registry`, `vpnRegistry` work on every chain.
`startRouter` / `startExit` with `register: true` resolve only once `registry` / `vpnRegistry` `.getInstance(keyHash)` is non-null
(on tier B/C the router's operator must have been approved on that registry first; tests do so).
For tier B/C, a refused admin call either rejects or has no effect on the reader (tests accept both). Every chain driver runs a
local node (NEAR sandbox, anvil, Stellar quickstart, solana-test-validator, zebrad regtest) and stops it in `stop()`.

## 7. `@plr/shared` additions (locked tests import these names)
```ts
// rev 1.4 client rule
interface RegistryReader { …; readonly verifiesOnChain: boolean; getRegistrationQuote(keyHash: string, offered?: Uint8Array): Promise<Uint8Array | null> }
MemoryRegistryOptions += { verifiesOnChain?: boolean /* default true */; registrationQuotes?: Record<string, string> /* keyHash → quote hex */ }
// MemoryRegistry.getRegistrationQuote returns the configured quote for keyHash (ignores offered), or null.
AttestationBundle += { registration_quote?: string }
AnchorRecord += { sig?: string }
// error code added: E_REGISTRATION_EVIDENCE

// Zcash transactions (ZIP-225 v5, ZIP-244 digests; docs/zcash/ has the ZIP texts)
SIGHASH: { ALL: 1; NONE: 2; SINGLE: 3; ANYONECANPAY: 0x80 }
zcashTxid(tx: Uint8Array): Uint8Array                       // byte order exactly as the "txid" field of packages/shared/test/vectors/zip_0244.json
zcashSighash(tx: Uint8Array, p: { inputIndex: number | null; hashType: number; amounts: bigint[]; scriptPubKeys: Uint8Array[] }): Uint8Array
    // inputIndex null ⇒ the "sighash_shielded" value; otherwise ZIP-244 §S.2 for that transparent input
buildSignedTransparentTx(p: { branchId: number; expiryHeight: number; lockTime?: number;
    inputs: { txid: Uint8Array; vout: number; amount: bigint; secretKey: Uint8Array }[];   // P2PKH, compressed pubkey
    outputs: { amount: bigint; script: Uint8Array }[] }): Uint8Array                       // SIGHASH_ALL, low-S DER + 0x01
hash160(b: Uint8Array): Uint8Array
p2pkhScript(h160: Uint8Array): Uint8Array; opReturnScript(data: Uint8Array): Uint8Array   // data ≤ 80 bytes else E_BAD_INPUT
tAddress(h160: Uint8Array, network: "regtest" | "testnet" | "mainnet"): string          // Base58Check; regtest/testnet prefix 1d25, mainnet 1cb8
parseTAddress(a: string): { network: "test" | "mainnet"; hash160: Uint8Array }          // P2PKH only; E_BAD_INPUT
zip317Fee(p: { inputs: number; outputScripts: Uint8Array[] }): bigint
    // 5000n × max(2, max(ceil(inputs·150 / 150), ceil(Σ(8 + compactSize(len) + len) / 34)))

// Zcash record log (§5)
type ZcashRecord =
  | { type: "allow_compose" | "revoke_compose" | "allow_os" | "revoke_os"; hash: string }
  | { type: "set_root"; kind: "MOCK" | "INTEL"; p256: string }
  | { type: "approve_operator"; hash160: string; org_id: string }
  | { type: "revoke_operator" | "transfer_owner"; hash160: string }
  | { type: "reg_keys"; x25519: string; ed25519: string }
  | { type: "reg_measure"; key_hash: string; compose_hash: string }
  | { type: "reg_os"; key_hash: string; os_measurement: string }
  | { type: "reg_quote"; key_hash: string; quote_sha256: string }
  | { type: "anchor"; key_hash: string; root: string; first_seq: number; count: number }
  | { type: "anchor_sig"; key_prefix: string /* 16 hex */; sig: string };
encodeZcashRecord(r: ZcashRecord): Uint8Array                // the OP_RETURN payload ("PLR1" ‖ type ‖ body); E_BAD_INPUT
decodeZcashRecord(payload: Uint8Array): ZcashRecord | null    // never throws
interface ZcashBlock { height: number; time: number;           // the subset of Zebra `getblock <hash> 2` used
  tx: { txid: string; vin: { coinbase?: string; scriptSig?: { hex: string } }[]; vout: { scriptPubKey: { hex: string } }[] }[] }
class ZcashLog {
  constructor(o: { network: "regtest" | "testnet" | "mainnet"; owner: string /* t-address */; ttlMs?: number /* 86_400_000 */ });
  readonly contractId: string;                                 // "zcash:<network>:<owner>"
  apply(b: ZcashBlock): void;                                  // blocks in increasing height; re-applying a height already applied is a no-op
  readonly height: number; readonly time: number;              // last applied block (time in seconds, as Zebra reports)
  getRoot(): { kind: "MOCK" | "INTEL"; p256: string } | null;
  isComposeAllowed(h: string): boolean; isOsAllowed(h: string): boolean;
  getInstance(keyHash: string): InstanceRecord | null;         // operator = t-address; org_id live; null if expired at `time`
  registrationQuoteHash(keyHash: string): string | null;
  getAnchor(id: number): AnchorRecord | null; anchorCount(): number;   // ids in acceptance order from 0; sig set from 0x21
}
```
A transaction is a record only if: no coinbase input; ≥ 1 input; every input's scriptSig is exactly two pushes (sig, 33-byte
compressed pubkey) with the same pubkey; exactly one output script starts with `0x6a`, whose single push decodes as a record.

## 8. Local Zcash node facts (verified 2026-10-24 on this machine, zebrad 7.0.0 at ~/.cargo/bin/zebrad)
Config that works (one node per stack; ports chosen by the harness):
```toml
[network]
network = "Regtest"
listen_addr = "127.0.0.1:0"
cache_dir = false
[network.testnet_parameters.activation_heights]
Canopy = 1
NU5 = 1
NU6 = 1
"NU6.1" = 1
[mining]
miner_address = "tm…"          # harness faucet P2PKH address
[state]
ephemeral = true
[rpc]
listen_addr = "127.0.0.1:<port>"
enable_cookie_auth = false
[tracing]
filter = "warn"
```
- Without the activation-heights table only up to Canopy is active (no v5). With it: NU5/NU6/NU6.1 active from height 1;
  `getblockchaininfo.consensus.nextblock` = `4dec4df0` (NU6.1 branch id 0x4DEC4DF0). Writers read the branch id from there.
- `generate N` works (returns block hashes); coinbase is a v5 tx with one P2PKH output of 625 000 000 zats to `miner_address`.
- `getaddressutxos {"addresses":[…]}` and `getaddressbalance` work (built-in index, coinbase included). UTXO objects:
  `{address, txid, outputIndex, script, satoshis, height}`. RPC txids are hex strings in RPC display order — writers must check
  the byte order against their own `zcashTxid` (Bitcoin-style reversal) when spending outputs.
- Consensus coinbase maturity applies (spend coinbase only after 100 confirmations: mine ≥ 101 blocks first).
- Mempool standardness: `max_datacarrier_bytes = 83` (80-byte payload), one OP_RETURN per tx.
- Harness: one zebrad per stack (ephemeral), a faucet key mines 101+ blocks, then funds owner / operator / operator2 / stranger
  with ≥ 30 separate UTXOs each (so writers can submit several records without waiting); a background miner calls
  `generate 1` every 1 s while the stack runs. Readers poll `getblockcount` and apply new blocks on each query.
