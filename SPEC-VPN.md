# PLR-VPN-v1 — Provably No-Logs VPN Exit: Protocol Specification

Status: **FROZEN** for the VPN milestone. Builds on `SPEC.md` (PLR-v1, rev 1.1): quote format (§2), event log (§3),
compose measurement rules (§4), key binding (§5), registry contract (§7, deployed a second time, unchanged),
receipt anchoring (§7/§8 Merkle + `anchor_receipts`), client verification order (§9). Notation as SPEC.md.
`VDOMAIN = utf8("PLR-VPN-v1")`.

---

## 1. Guarantees and non-guarantees

A VPN exit must see the destination host/port and the bytes it relays (TLS ciphertext for HTTPS; plaintext for
plain HTTP). PLR-VPN does **not** hide those from the exit code. It proves, before any byte leaves the client:
1. the exit is the approved, measured `plr-vpn` build in a non-debug TD (same checks as SPEC §9 1–9, against the
   **VPN registry**);
2. the tunnel is end-to-end encrypted to the attested X25519 key, so the operator, host and network see only
   ciphertext and cannot read, modify, reorder, truncate or reflect tunnel data undetected;
3. the approved code retains nothing: no destination, DNS name, IP, byte count or payload is logged, written,
   or included in receipts or on-chain data;
4. destinations are resolved by the exit (remote DNS) — the client never resolves them;
5. the exit refuses to reach loopback/private/link-local/metadata/reserved addresses (protects the host's own
   services: quote socket, RPC, LLM ports, cloud metadata).

Out of scope: traffic analysis (timing, sizes), the destination seeing the exit's IP, the exit's ISP seeing
destinations, content of non-TLS traffic as seen by the exit code (it is processed, never stored), TEE vendor trust.

---

## 2. Compose (VPN schema)

Canonical form and hashing exactly as SPEC §4 (keys sorted recursively, `JSON.stringify(obj, null, 2) + "\n"`,
verifiers hash bytes received). Schema (exact keys, no extras):
```json
{
  "manifest_version": 1,
  "name": "plr-vpn",
  "policy": { "disk": "none", "egress": { "allow_loopback": false, "deny_private": true }, "logs": "none" },
  "vpn": { "bundle_sha256": "<64 hex>", "entry": "vpn.bundle.mjs", "node_sha256": "<64 hex>" }
}
```
`node_sha256` is the runtime measurement of SPEC §4 rev 1.1. `deny_private` MUST be `true`. `allow_loopback: true`
exists only for local test builds; it changes the compose hash, so a test build can never pass as production.
The mock TDX host launches a `plr-vpn` compose with **no LLM**, same isolation as the router (read-only fs, no child
processes, no addons, no code generation from strings); network is allowed (it is an exit).

Builds (by `enclave/build.mjs`): `vpn-honest` (production policy), `vpn-honest-test` (`allow_loopback: true`),
`vpn-evil-logger` (honest source + patch that prints destinations and the first relayed bytes to stdout; test policy).

---

## 3. Exit HTTP API (one port, default `127.0.0.1:18200`)

- `GET /v1/attestation?nonce=<64 hex>` → the SPEC §6.2 bundle (same JSON shape, `app_compose` = VPN compose).
- `GET /v1/tunnel` with `Connection: Upgrade`, `Upgrade: plr-vpn/1` → `101 Switching Protocols`, then the raw
  socket carries §4. Any other request on `/v1/tunnel` → `400 {"error":"E_BAD_REQUEST"}`.
- `GET /v1/receipts/proof?seq=<n>` → as SPEC §6.4 (VPN receipts).
- `GET /healthz` → `{"ok":true}`.

---

## 4. Tunnel protocol (one tunnel per proxied TCP connection)

### 4.1 Hello and keys
Client → exit, first 65 bytes after the upgrade: `hello = u8(1) ‖ att_nonce(32) ‖ epk(32)`
(`att_nonce` = the nonce of the client's verified attestation; `epk` = fresh ephemeral X25519 public key).
```
shared = X25519(client_eph_sk, xp)                 (exit: X25519(xs, epk); all-zero ⇒ close, E_DECRYPT)
th     = SHA256(utf8("PLR-VPN-v1/tunnel") ‖ att_nonce ‖ epk ‖ xp ‖ ep)
okm    = HKDF-SHA256(ikm=shared, salt=th, info=utf8("PLR-VPN-v1/keys"), L=64)
k_c2s  = okm[0:32]     k_s2c = okm[32:64]
```

### 4.2 Frames (both directions)
Wire: `u32be(len) ‖ ct`, `17 ≤ len ≤ 16 + 1 + 16384` (tag + type byte + max payload). A length outside this range
⇒ `E_TUNNEL_PROTOCOL`.
`ct = ChaCha20-Poly1305(k_dir, nonce = u32be(dir) ‖ u64be(seq), aad = th ‖ u8(dir), pt)`,
`pt = u8(type) ‖ payload`, `dir` = 1 (c2s, key k_c2s) or 2 (s2c, key k_s2c), `seq` per direction from 0, strictly
increasing by 1. A frame that fails authentication ⇒ `E_DECRYPT`; the receiver closes the tunnel and MUST NOT
deliver any part of it. An unknown type ⇒ `E_TUNNEL_PROTOCOL`.

| type | name | dir | payload |
|---|---|---|---|
| 1 | CONNECT | c2s | JSON `{"host":"<domain or IP literal>","port":<1..65535>}` (≤ 512 bytes) |
| 2 | CONNECT_OK | s2c | empty |
| 3 | CONNECT_ERR | s2c | JSON `{"code":"E_..."}` |
| 4 | DATA | both | 1..16384 bytes |
| 5 | FIN | both | empty — sender will send no more DATA (half-close) |
| 6 | RECEIPT | s2c | JSON `{"receipt":{…§5},"sig":"<128 hex>"}` |

### 4.3 State machine
Exit:
1. Receive hello within 10 s, then exactly one CONNECT as c2s frame 0 within 10 s; anything else ⇒ close.
2. Validate destination (§6), resolve (exit-side DNS), check **every** resolved address against egress (§6),
   dial the first allowed address **by IP** (no second resolution). Timeout 10 s.
   Errors ⇒ CONNECT_ERR `E_BAD_INPUT` | `E_DNS` | `E_EGRESS_DENIED` | `E_CONNECT_FAILED`, then close.
3. CONNECT_OK (s2c frame 0). Relay: c2s DATA → upstream; upstream bytes → s2c DATA (≤ 16384 per frame).
   c2s FIN ⇒ half-close upstream write. Upstream EOF ⇒ s2c FIN.
4. When both directions are FIN'd: s2c RECEIPT, then close. Upstream error or client protocol error ⇒ close
   immediately without FIN/RECEIPT.
5. Idle limit 300 s with no frames in either direction ⇒ close.

Client:
- Sends hello + CONNECT, waits for CONNECT_OK (else surfaces the CONNECT_ERR code).
- Delivers DATA to the application in order. s2c FIN ⇒ application EOF (FIN is authenticated, so a clean EOF
  is never forged). Socket end/close **before** s2c FIN ⇒ `E_TRUNCATED`: the application stream is destroyed
  with an error (never a clean EOF).
- Application end ⇒ c2s FIN. After both FINs, waits ≤ 10 s for RECEIPT and verifies it (§5); missing ⇒ the
  receipt promise rejects `E_TRUNCATED` (data already delivered remains valid: it was authenticated).

---

## 5. Session receipts (no metadata)
```json
{ "v":1, "th":"<64>", "compose_hash":"<64>", "key_hash":"<64>", "seq":<u64>, "ts_open_ms":<u64>, "ts_close_ms":<u64> }
```
```
vpn_receipt_msg = utf8("PLR-VPN-v1/receipt") ‖ th ‖ compose_hash ‖ key_hash ‖ u64be(seq) ‖ u64be(ts_open_ms) ‖ u64be(ts_close_ms)
sig  = Ed25519(es, vpn_receipt_msg)          leaf = SHA256(0x00 ‖ vpn_receipt_msg)
```
`seq` per exit instance from 0, contiguous; batches anchored with the unchanged `anchor_receipts` on the VPN registry
(SPEC §7 `anchorMessage`). Client verifies: sig under attested `ep`; `th`, `compose_hash`, `key_hash` equal its own;
`ts_open_ms ≤ ts_close_ms`. No destination, address, port, byte count or client IP appears in receipts, logs or chain.

---

## 6. Destination validation and egress policy

`validateDestination(host, port)`: `port` integer 1..65535; `host` is an IPv4 dotted-quad literal (4 decimal octets,
no leading zeros), an IPv6 literal (without brackets), or a DNS name: total ≤ 253 chars, labels 1..63 of
`[a-z0-9-]` (case-insensitive ASCII), not starting/ending with `-`, optional single trailing dot, and the last label
not all-digits (so `01.2.3.4` or `2130706433` can never be smuggled as a "name"). Else `E_BAD_INPUT`.

`classifyIp(ip)` → one of:
| class | IPv4 | IPv6 |
|---|---|---|
| `unspecified` | 0.0.0.0/8 | `::` |
| `loopback` | 127.0.0.0/8 | `::1` |
| `private` | 10/8, 172.16/12, 192.168/16 | fc00::/7 |
| `link-local` | 169.254/16 | fe80::/10 |
| `cgnat` | 100.64/10 | — |
| `multicast` | 224/4 | ff00::/8 |
| `reserved` | 192.0.0/24, 192.0.2/24, 198.18/15, 198.51.100/24, 203.0.113/24, 240/4 (incl. 255.255.255.255) | 2001:db8::/32, 100::/64 |
| `public` | everything else | everything else (global unicast) |
| `invalid` | not an IP literal | |
IPv6 forms embedding IPv4 — IPv4-mapped `::ffff:a.b.c.d` / `::ffff:XXXX:XXXX`, IPv4-compatible `::a.b.c.d`,
NAT64 `64:ff9b::/96`, 6to4 `2002:AABB:CCDD::/48` — are classified by the **embedded IPv4** address.

`egressAllowed(ip, policy)` is true iff class is `public`, or class is `loopback` and `policy.allow_loopback`.
Everything else (including `invalid`) is denied.

---

## 7. Client verification for each new connection
1. Attestation (SPEC §9 checks 1–10) against the **VPN registry**; a verified attestation MAY be reused for
   ≤ `attestTtlMs` (default 60 000; 0 = always fresh).
2. **On every new connection, even with a cached attestation:** `isComposeAllowed`, `isOsAllowed`, `getInstance`
   (keys/compose/os match) are re-checked — revocation applies to the very next connection.
3. Only then is the tunnel opened. Verification failure ⇒ the destination is never contacted.
The client performs **no DNS resolution of destinations**; its only own lookups are for the exit URL and the RPC URL.

---

## 8. Error codes (added to the PLR set)
`E_EGRESS_DENIED`, `E_DNS`, `E_CONNECT_FAILED`, `E_TUNNEL_PROTOCOL` (plus reuse of `E_BAD_INPUT`, `E_DECRYPT`,
`E_TRUNCATED`, `E_RECEIPT_SIG`, `E_RECEIPT_MISMATCH`, `E_NOT_ANCHORED`, `E_ANCHOR_MISMATCH` and all §9 codes).

SOCKS5 reply mapping (RFC 1928 REP): success 0x00; any SPEC §9 verification code, `E_EGRESS_DENIED` → 0x02
(not allowed by ruleset); `E_DNS` → 0x04 (host unreachable); `E_CONNECT_FAILED` → 0x05 (connection refused);
unsupported command → 0x07; unsupported address type → 0x08; anything else → 0x01.

---

## 9. TypeScript module contract

### 9.1 `@plr/shared` (pure, locked tests import these names)
```ts
const TUNNEL: { VERSION: 1; HELLO_LEN: 65; MAX_PAYLOAD: 16384; MIN_FRAME_LEN: 17; MAX_FRAME_LEN: 16401; DIR_C2S: 1; DIR_S2C: 2 }
const FRAME: { CONNECT: 1; CONNECT_OK: 2; CONNECT_ERR: 3; DATA: 4; FIN: 5; RECEIPT: 6 }
deriveTunnel(p: { shared; attNonce; epk; xp; ep }): { th: Uint8Array; kC2s: Uint8Array; kS2c: Uint8Array }
encodeHello(attNonce: Uint8Array, epk: Uint8Array): Uint8Array
parseHello(b: Uint8Array): { attNonce: Uint8Array; epk: Uint8Array }                 // E_TUNNEL_PROTOCOL
tunnelClientInit(p: { xp; ep; attNonce }): { hello: Uint8Array; th; kC2s; kS2c }      // fresh ephemeral each call
tunnelServerInit(p: { xs; xp; ep; hello: Uint8Array }): { attNonce; th; kC2s; kS2c }  // E_TUNNEL_PROTOCOL / E_DECRYPT
class TunnelWriter { constructor(key: Uint8Array, th: Uint8Array, dir: 1 | 2); seal(type: number, payload: Uint8Array): Uint8Array /* wire bytes incl. length */ }
class TunnelReader { constructor(key: Uint8Array, th: Uint8Array, dir: 1 | 2);
                     push(chunk: Uint8Array): Array<{ type: number; payload: Uint8Array }>  // any chunking; E_DECRYPT / E_TUNNEL_PROTOCOL; poisoned after an error
                     end(): void /* E_TRUNCATED if a partial frame is buffered */ }
interface VpnReceipt { v: 1; th: string; compose_hash: string; key_hash: string; seq: number; ts_open_ms: number; ts_close_ms: number }
vpnReceiptMessage(r): Uint8Array; signVpnReceipt(r, edSecret): string; verifyVpnReceipt(r, sigHex, edPub): boolean; vpnReceiptLeaf(r): Uint8Array
validateDestination(host: string, port: number): void                                 // E_BAD_INPUT
classifyIp(ip: string): "public"|"loopback"|"private"|"link-local"|"cgnat"|"multicast"|"unspecified"|"reserved"|"invalid"
egressAllowed(ip: string, policy: { allow_loopback: boolean; deny_private: boolean }): boolean
// SOCKS5 (RFC 1928, server side, CONNECT + no-auth only)
parseSocksGreeting(b: Uint8Array): { consumed: number; methods: number[] } | null      // null = need more bytes; E_BAD_INPUT
parseSocksRequest(b: Uint8Array): { consumed: number; cmd: number; atyp: "ipv4"|"domain"|"ipv6"; host: string; port: number } | null
encodeSocksReply(rep: number): Uint8Array                                              // VER 5, BND 0.0.0.0:0 (10 bytes)
socksReplyFor(code: string | null): number                                             // §8 mapping
```
Malformed SOCKS input (wrong VER, NMETHODS 0, RSV ≠ 0, domain length 0, unknown ATYP) ⇒ `E_BAD_INPUT`, except unknown
ATYP is reported as `{atyp}`-less error code `E_BAD_INPUT` too (server replies 0x08). IPv6 hosts are returned in
RFC 5952 compressed lowercase form; domain hosts verbatim.

### 9.2 `@plr/client`
```ts
class VpnClient {
  constructor(o: { exitUrl: string; registry: RegistryReader; trustedRoot: Uint8Array; verifier?: QuoteVerifier;
                   attestTtlMs?: number; lookup?: typeof import("node:dns").lookup });
  attest(): Promise<VerifiedRouter>;                                 // fresh nonce; SPEC §9
  connect(host: string, port: number): Promise<VpnStream>;           // §7 checks then tunnel; rejects PlrError
  verifyAnchored(r: VpnReceipt): Promise<boolean>;                   // as PrivateClient.verifyAnchored (E_NOT_ANCHORED / E_ANCHOR_MISMATCH)
}
interface VpnStream extends import("node:stream").Duplex {
  receipt(): Promise<{ receipt: VpnReceipt; sig: string }>;          // verified per §5; E_TRUNCATED / E_RECEIPT_SIG / E_RECEIPT_MISMATCH
}
// Stream errors are PlrError (E_DECRYPT, E_TRUNCATED, E_TUNNEL_PROTOCOL) emitted via 'error'.
startVpn(o: { port: number; host?: string; client: VpnClient }): Promise<{ url: string /* socks5h://127.0.0.1:<port> */; port: number; close(): Promise<void> }>
```
All lookups the client itself performs go through `o.lookup` when given. CLI: `plr vpn` (SOCKS5 on `127.0.0.1:18180`,
env `PLR_VPN_URL`, `PLR_VPN_REGISTRY`, `PLR_NEAR_RPC`, `PLR_TRUSTED_ROOT`), `plr vpn verify` (prints every check).

### 9.3 E2E harness additions (`e2e/src/harness.ts`, `Stack` gains)
```ts
type VpnVariant = "vpn-honest" | "vpn-honest-test" | "vpn-evil-logger" | "vpn-mitm-key" | "vpn-replay-quote" | "vpn-tamper-stream" | "vpn-truncate-stream";
interface Stack { …existing…
  vpnContractId: string;                     // a second registry deployment (same wasm, same MOCK root), e.g. vpnregistry.<root>
  vpnRegistry: RegistryReader;
  callVpn(signer: Signer, method: string, args: object, o?: { deposit?: string; gas?: string }): Promise<unknown>;
  approveVpnBuild(v: "vpn-honest" | "vpn-honest-test" | "vpn-evil-logger"): Promise<{ composeHash: string; osMeasurement: string }>;
  startExit(v: VpnVariant, o?: { register?: boolean }): Promise<ExitHandle>;   // register defaults true (on the VPN registry)
  startDestination(): Promise<Destination>;
}
interface ExitHandle { url: string; composeHash: string; keyHash: string; output(): string; stop(): Promise<void> }
interface Destination { host: "127.0.0.1"; port: number; hits(): number; received(): string; close(): Promise<void> }
```
`startDestination`: HTTP/1.1 server on 127.0.0.1; every request increments `hits`; `received()` = all raw request
bytes so far (latin1); response `200` with body `dest-ok:<path>` and `Connection: close`; `POST` echoes the body
after the prefix.
Network-attack variants are the approved **`vpn-honest-test`** build behind a malicious TCP/HTTP proxy:
`vpn-mitm-key` rewrites `x25519` in attestation responses; `vpn-replay-quote` replays its first attestation
response for every nonce; `vpn-tamper-stream` flips one byte in the ciphertext of the first s2c **DATA** frame;
`vpn-truncate-stream` forwards CONNECT_OK and the first s2c DATA frame, then closes the client socket (no FIN).
The attacker proxy parses only frame lengths. `ExitHandle.url` points at the proxy for these variants.
`stop()` of the stack also stops all exits and destinations.
