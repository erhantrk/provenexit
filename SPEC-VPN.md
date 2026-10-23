# PLR-VPN-v1 — Provably No-Logs VPN Exit: Protocol Specification

Status: **FROZEN**, rev 2 (2026-10-23): tunnel handshake v2 with exit ephemeral keys (§4.1), encrypted DNS (§2, §6.1),
two-hop routing with on-chain operator organizations (§10). Rev 1 handshake and the interim hello replay guard are removed. Builds on `SPEC.md` (PLR-v1, rev 1.1): quote format (§2), event log (§3),
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
  "policy": { "disk": "none", "dns": { "doh": ["https://1.1.1.1/dns-query", "https://9.9.9.9/dns-query"] },
              "egress": { "allow_loopback": false, "deny_private": true }, "logs": "none" },
  "vpn": { "bundle_sha256": "<64 hex>", "entry": "vpn.bundle.mjs", "node_sha256": "<64 hex>" }
}
```
`node_sha256` is the runtime measurement of SPEC §4 rev 1.1. `policy.dns.doh` is a non-empty list (≤ 4) of RFC 8484
resolver URLs whose host is an **IP literal** (no bootstrap DNS); `https:` is required, except that `http://127.0.0.1:<port>/…`
is allowed only when `allow_loopback` is true (test builds). `deny_private` MUST be `true`. `allow_loopback: true`
exists only for local test builds; it changes the compose hash, so a test build can never pass as production.
The mock TDX host launches a `plr-vpn` compose with **no LLM**, same isolation as the router (read-only fs, no child
processes, no addons, no code generation from strings); network is allowed (it is an exit).

Builds (by `enclave/build.mjs`): `vpn-honest` (production policy), `vpn-honest-test` (`allow_loopback: true`),
`vpn-evil-logger` (honest source + patch that prints destinations and the first relayed bytes to stdout; test policy).
Test-policy builds use `"dns": {"doh": ["http://127.0.0.1:18253/dns-query"]}`; `vpn-honest` uses the production list above.

---

## 3. Exit HTTP API (one port, default `127.0.0.1:18200`)

- `GET /v1/attestation?nonce=<64 hex>` → the SPEC §6.2 bundle (same JSON shape, `app_compose` = VPN compose).
- `GET /v1/tunnel` with `Connection: Upgrade`, `Upgrade: plr-vpn/1` → `101 Switching Protocols`, then the raw
  socket carries §4. Any other request on `/v1/tunnel` → `400 {"error":"E_BAD_REQUEST"}`.
- `GET /v1/receipts/proof?seq=<n>` → as SPEC §6.4 (VPN receipts).
- `GET /healthz` → `{"ok":true}`.

---

## 4. Tunnel protocol (one tunnel per proxied TCP connection)

### 4.1 Handshake v2 (exit ephemeral key ⇒ replay protection + forward secrecy)
Client → exit, first 65 bytes after the upgrade: `hello = u8(2) ‖ att_nonce(32) ‖ epk_c(32)`
(`att_nonce` = the nonce of the client's verified attestation; `epk_c` = fresh ephemeral X25519 public key).
Exit → client, immediately after a valid hello: `server_hello = u8(2) ‖ epk_s(32)` (fresh ephemeral per tunnel).
```
dh1    = X25519(e_c, xp)      (exit: X25519(xs, epk_c))      — authenticates the attested exit
dh2    = X25519(e_c, epk_s)   (exit: X25519(e_s, epk_c))     — per-tunnel freshness, forward secrecy
         either all-zero ⇒ close, E_DECRYPT
th     = SHA256(utf8("PLR-VPN-v2/tunnel") ‖ att_nonce ‖ epk_c ‖ epk_s ‖ xp ‖ ep)
okm    = HKDF-SHA256(ikm = dh1 ‖ dh2, salt = th, info = utf8("PLR-VPN-v2/keys"), L = 64)
k_c2s  = okm[0:32]     k_s2c = okm[32:64]
```
Both ephemeral secrets are zeroed once keys are derived. A replayed client hello meets a new `epk_s`, so replayed
frames fail authentication; later compromise of `xs` does not reveal past tunnels. The client sends CONNECT only after
it has received and processed `server_hello` (which may arrive in the same read as the `101` response). A wrong
version byte or length in either hello ⇒ `E_TUNNEL_PROTOCOL`.

### 4.2 Frames (both directions)
Wire: `u32be(len) ‖ ct`, `17 ≤ len ≤ 16 + 1 + 16384` (tag + type byte + max payload). A length outside this range
⇒ `E_TUNNEL_PROTOCOL`.
`ct = ChaCha20-Poly1305(k_dir, nonce = u32be(dir) ‖ u64be(seq), aad = th ‖ u8(dir), pt)`,
`pt = u8(type) ‖ payload`, `dir` = 1 (c2s, key k_c2s) or 2 (s2c, key k_s2c), `seq` per direction from 0, strictly
increasing by 1. A frame that fails authentication ⇒ `E_DECRYPT`; the receiver closes the tunnel and MUST NOT
deliver any part of it. An unknown type ⇒ `E_TUNNEL_PROTOCOL`.

| type | name | dir | payload |
|---|---|---|---|
| 1 | CONNECT | c2s | JSON `{"host":"<domain or IP literal>","port":<1..65535>}` (≤ 512 bytes; senders pad with trailing spaces to exactly 512) |
| 2 | CONNECT_OK | s2c | empty |
| 3 | CONNECT_ERR | s2c | JSON `{"code":"E_..."}` (senders pad with trailing spaces to exactly 32 bytes) |
| 4 | DATA | both | 1..16384 bytes |
| 5 | FIN | both | empty — sender will send no more DATA (half-close) |
| 6 | RECEIPT | s2c | JSON `{"receipt":{…§5},"sig":"<128 hex>"}` |

### 4.3 State machine
Exit:
1. Receive hello within 10 s, then exactly one CONNECT as c2s frame 0 within 10 s; anything else ⇒ close.
2. Validate destination (§6), resolve via DoH (§6.1), check **every** resolved address against egress (§6),
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

Names `localhost` and `*.localhost` (any case, optional trailing dot; RFC 6761) are refused with `E_EGRESS_DENIED`
before any resolution.

`egressAllowed(ip, policy)` is true iff class is `public`, or class is `loopback` and `policy.allow_loopback`.
Everything else (including `invalid`) is denied.

---

### 6.1 Encrypted DNS (RFC 8484) — no plaintext fallback
The exit resolves names only through the compose's `policy.dns.doh` resolvers: `POST <url>` with
`content-type: application/dns-message`, `accept: application/dns-message`, A and AAAA queries in parallel, 5 s timeout per
resolver, resolvers tried in order. It never uses the host's resolver. All resolvers failing ⇒ `E_DNS`; NXDOMAIN or no
addresses for both types ⇒ `E_DNS`. Every returned address is then egress-checked as above.

`encodeDnsQuery(name, type)` — `name` must be a DNS name per §6 (not an IP literal), else `E_BAD_INPUT`; exact bytes (big-endian):
```
header   = u16(0) id ‖ u16(0x0100) RD ‖ u16(1) QD ‖ u16(0) AN ‖ u16(0) NS ‖ u16(1) AR
question = qname ‖ u16(qtype) ‖ u16(1)            qtype: A = 1, AAAA = 28
           qname = labels of lowercase(name without trailing dot), each u8(len) ‖ bytes, then u8(0)
opt_rr   = u8(0) ‖ u16(41) ‖ u16(4096) ‖ u32(0) ‖ u16(4 + P) ‖ u16(12) ‖ u16(P) ‖ 0x00 * P     (EDNS0 + padding, RFC 8467)
P        = smallest value ≥ 0 such that the whole message length is a multiple of 128
```
`parseDnsResponse(bytes, name, type)` → address strings (IPv4 dotted quad; IPv6 RFC 5952 compressed lowercase).
`E_DNS` unless: length ≥ 12; id = 0; QR = 1; opcode = 0; TC = 0; QDCOUNT = 1 and the question equals (name, type, IN)
case-insensitively; RCODE 0 (RCODE 3 NXDOMAIN ⇒ returns `[]`; others ⇒ `E_DNS`); ANCOUNT ≤ 32; every name decodes with
compression pointers that point strictly backwards, ≤ 16 pointer hops, total ≤ 255 bytes, labels ≤ 63; every RR fits in the
message. Answers: start at the question name, follow CNAME records (class IN) owned by the current name, ≤ 8 hops; return
the A (rdlength 4) / AAAA (rdlength 16) records of the requested type owned by any name in that chain. A record of the
requested type with a wrong rdlength ⇒ `E_DNS`. Records of other types/classes are ignored. Trailing bytes after the
counted sections are ignored.

## 7. Client verification for each new connection
1. Attestation (SPEC §9 checks 1–10) against the **VPN registry**; a verified attestation MAY be reused for
   ≤ `attestTtlMs` (default 60 000; 0 = always fresh).
2. **On every new connection, even with a cached attestation:** `isComposeAllowed`, `isOsAllowed`, `getInstance`
   (keys/compose/os match) are re-checked — revocation applies to the very next connection.
3. Only then is the tunnel opened. Verification failure ⇒ the destination is never contacted.
The client performs **no DNS resolution of destinations**; its only own lookups are for the exit URL and the RPC URL.

---

## 8. Error codes (added to the PLR set)
`E_EGRESS_DENIED`, `E_DNS`, `E_CONNECT_FAILED`, `E_TUNNEL_PROTOCOL`, `E_OPERATOR_UNAPPROVED`, `E_SAME_OPERATOR` (plus reuse of `E_BAD_INPUT`, `E_DECRYPT`,
`E_TRUNCATED`, `E_RECEIPT_SIG`, `E_RECEIPT_MISMATCH`, `E_NOT_ANCHORED`, `E_ANCHOR_MISMATCH` and all §9 codes).

SOCKS5 reply mapping (RFC 1928 REP): success 0x00; any SPEC §9 verification code, `E_EGRESS_DENIED`,
`E_OPERATOR_UNAPPROVED`, `E_SAME_OPERATOR` → 0x02
(not allowed by ruleset); `E_DNS` → 0x04 (host unreachable); `E_CONNECT_FAILED` → 0x05 (connection refused);
unsupported command → 0x07; unsupported address type → 0x08; anything else → 0x01.

---

## 9. TypeScript module contract

### 9.1 `@plr/shared` (pure, locked tests import these names)
```ts
const TUNNEL: { VERSION: 2; HELLO_LEN: 65; SERVER_HELLO_LEN: 33; MAX_PAYLOAD: 16384; MIN_FRAME_LEN: 17; MAX_FRAME_LEN: 16401; DIR_C2S: 1; DIR_S2C: 2 }
const FRAME: { CONNECT: 1; CONNECT_OK: 2; CONNECT_ERR: 3; DATA: 4; FIN: 5; RECEIPT: 6 }
deriveTunnel(p: { dh1; dh2; attNonce; epkC; epkS; xp; ep }): { th: Uint8Array; kC2s: Uint8Array; kS2c: Uint8Array }  // E_DECRYPT if dh1/dh2 all-zero
encodeHello(attNonce: Uint8Array, epkC: Uint8Array): Uint8Array
parseHello(b: Uint8Array): { attNonce: Uint8Array; epkC: Uint8Array }                 // E_TUNNEL_PROTOCOL
encodeServerHello(epkS: Uint8Array): Uint8Array
parseServerHello(b: Uint8Array): { epkS: Uint8Array }                                // E_TUNNEL_PROTOCOL
tunnelClientStart(p: { xp; ep; attNonce }): { hello: Uint8Array; finish(serverHello: Uint8Array): { th; kC2s; kS2c } }  // fresh ephemeral; finish at most once (E_TUNNEL_PROTOCOL)
tunnelServerAccept(p: { xs; xp; ep; hello: Uint8Array }): { serverHello: Uint8Array; attNonce; th; kC2s; kS2c }        // fresh ephemeral; E_TUNNEL_PROTOCOL / E_DECRYPT
class TunnelWriter { constructor(key: Uint8Array, th: Uint8Array, dir: 1 | 2); seal(type: number, payload: Uint8Array): Uint8Array /* wire bytes incl. length */ }
class TunnelReader { constructor(key: Uint8Array, th: Uint8Array, dir: 1 | 2);
                     push(chunk: Uint8Array): Array<{ type: number; payload: Uint8Array }>  // any chunking; E_DECRYPT / E_TUNNEL_PROTOCOL; poisoned after an error
                     end(): void /* E_TRUNCATED if a partial frame is buffered */ }
interface VpnReceipt { v: 1; th: string; compose_hash: string; key_hash: string; seq: number; ts_open_ms: number; ts_close_ms: number }
vpnReceiptMessage(r): Uint8Array; signVpnReceipt(r, edSecret): string; verifyVpnReceipt(r, sigHex, edPub): boolean; vpnReceiptLeaf(r): Uint8Array
validateDestination(host: string, port: number): void                                 // E_BAD_INPUT
classifyIp(ip: string): "public"|"loopback"|"private"|"link-local"|"cgnat"|"multicast"|"unspecified"|"reserved"|"invalid"
egressAllowed(ip: string, policy: { allow_loopback: boolean; deny_private: boolean }): boolean
isLocalhostName(host: string): boolean                                               // §6 RFC 6761 names
encodeDnsQuery(name: string, type: "A" | "AAAA"): Uint8Array                          // §6.1 exact bytes
parseDnsResponse(b: Uint8Array, name: string, type: "A" | "AAAA"): string[]           // §6.1; E_DNS
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
class TwoHopClient {
  constructor(o: { entryUrl: string; exitUrl: string; registry: RegistryReader; trustedRoot: Uint8Array;
                   verifier?: QuoteVerifier; attestTtlMs?: number; lookup?: typeof import("node:dns").lookup });
  attest(): Promise<{ entry: VerifiedRouter; exit: VerifiedRouter; entryOrg: string; exitOrg: string }>;   // §10
  connect(host: string, port: number): Promise<TwoHopStream>;
}
interface TwoHopStream extends VpnStream { entryReceipt(): Promise<{ receipt: VpnReceipt; sig: string }> }   // receipt() = exit's
```
`startVpn` accepts any `client` with `connect(host, port): Promise<VpnStream>` (so also a `TwoHopClient`).
All lookups the client itself performs go through `o.lookup` when given. CLI: `plr vpn` (SOCKS5 on `127.0.0.1:18180`,
env `PLR_VPN_URL`, `PLR_VPN_REGISTRY`, `PLR_NEAR_RPC`, `PLR_TRUSTED_ROOT`; with `PLR_VPN_ENTRY_URL` set it runs two-hop
with `PLR_VPN_URL` as the exit), `plr vpn verify` (prints every check, both hops and the operator check in two-hop mode).

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
interface Stack { …
  accounts: { owner; operator; operator2; stranger };          // Signer gains "operator2"
  approveOperator(account: "operator" | "operator2", orgId: string): Promise<void>;   // owner → approve_operator on the VPN registry
  revokeOperator(account: "operator" | "operator2"): Promise<void>;
  dns: { set(name: string, addrs: string[]): void; hits(): number; setDown(down: boolean): void };
}
startExit(v, o?: { register?: boolean; operator?: "operator" | "operator2" })   // operator account that registers it (default "operator")
interface ExitHandle { url: string; composeHash: string; keyHash: string; output(): string; stop(): Promise<void> }
interface Destination { host: "127.0.0.1"; port: number; hits(): number; received(): string; close(): Promise<void> }
```
`dns`: the stack always runs the local RFC 8484 resolver of the test builds on `127.0.0.1:18253` (POST `/dns-query`),
answering from `set()` records (A/AAAA by address family; unknown names ⇒ NXDOMAIN; `setDown(true)` ⇒ HTTP 503);
`hits()` counts queries. `startDestination`: HTTP/1.1 server on 127.0.0.1; every request increments `hits`; `received()` = all raw request
bytes so far (latin1); response `200` with body `dest-ok:<path>` and `Connection: close`; `POST` echoes the body
after the prefix.
Network-attack variants are the approved **`vpn-honest-test`** build behind a malicious TCP/HTTP proxy:
`vpn-mitm-key` rewrites `x25519` in attestation responses; `vpn-replay-quote` replays its first attestation
response for every nonce; `vpn-tamper-stream` flips one byte in the ciphertext of the first s2c **DATA** frame;
`vpn-truncate-stream` forwards CONNECT_OK and the first s2c DATA frame, then closes the client socket (no FIN).
The attacker proxy parses only frame lengths. `ExitHandle.url` points at the proxy for these variants.
`stop()` of the stack also stops all exits and destinations.

---

## 10. Two-hop routing with operator organizations

Goal: no single party learns both who the client is and where it connects. The client tunnels to an **entry** exit,
and through that tunnel opens a second, nested tunnel to an **exit** exit, which reaches the destination.
- The entry sees the client's IP and the exit's address, never the destination, DNS names or payload (inner tunnel is
  end-to-end encrypted to the exit). The exit sees the entry's IP, never the client's.
- Both hops are `plr-vpn` instances on the **VPN registry** with approved compose + OS measurement (any approved build).
- **Operator organizations (registry, SPEC §7 rev 1.2):** the owner maps operator accounts to an `org_id`;
  `get_instance` returns the live `org_id` of the instance's operator (null if unapproved).

Client procedure (`TwoHopClient`):
1. Attest the entry directly (§7). Its instance must have a non-null `org_id`, else `E_OPERATOR_UNAPPROVED`.
2. Open an entry tunnel with CONNECT to the exit's host:port (taken from `exitUrl`). Over that stream, fetch the exit's
   `/v1/attestation` (fresh nonce, HTTP/1.1) and verify it (§7). The exit's `org_id` must be non-null
   (`E_OPERATOR_UNAPPROVED`) and differ from the entry's (`E_SAME_OPERATOR`). The exit is never contacted directly.
3. Each `connect(host, port)`: re-check both hops' registry state (compose, OS, instance, and org rules above — revocation
   or an org change applies to the next connection), open a new entry tunnel to the exit, upgrade `/v1/tunnel` over it,
   run the §4 handshake with the exit, and CONNECT to the destination **inside** the inner tunnel.
4. The returned stream carries the exit's receipt (`receipt()`); the entry tunnel's receipt is verified too
   (`entryReceipt()`).
Out of scope: an adversary observing both the entry's and the exit's networks (timing correlation), and an owner that
approves the same real-world organization under two `org_id`s (owner trust; multisig/staking later).
