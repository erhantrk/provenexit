# PLR-v1 — a provably-private LLM router

An LLM router that runs inside a TEE (Intel TDX, **mocked faithfully** in this milestone), whose approved code
measurement lives in a **NEAR registry contract**. Before a client sends a single prompt it fetches a fresh
attestation, verifies it against the attestation root **and against the chain**, and then encrypts the prompt to
a key that only the measured router code can hold. Every answer comes with a signed receipt that is anchored
on-chain in Merkle batches.

The protocol is specified in [`SPEC.md`](SPEC.md) (frozen, authoritative). This README is the tour.

The same machinery also runs a **provably no-logs VPN exit** (PLR-VPN-v1, [`SPEC-VPN.md`](SPEC-VPN.md)): a SOCKS5
proxy on your machine that only tunnels to an exit whose measured code is approved in a second NEAR registry —
see [*PLR-VPN*](#plr-vpn--a-provably-no-logs-vpn-exit-proxy-mode). Both services can also run together in **one**
TD (one confidential VM, [`SPEC-COMBO.md`](SPEC-COMBO.md)) — see
[*Cheapest demo deployment: one VM*](#cheapest-demo-deployment-one-vm).

```
bash scripts/demo.sh        # builds everything, runs the whole story with a real Qwen 0.5B model (+ the VPN story)
```

---

## What this proves — and what it does not

**What the client checks** (SPEC §9, in this order, fail-closed; the first failure aborts and nothing is sent):

| # | check | refusal code |
|---|---|---|
| 1 | fresh 32-byte nonce, well-formed response | `E_BAD_RESPONSE` |
| 2 | TDX v4 quote structure, TEE type | `E_QUOTE_FORMAT`, `E_TEE_TYPE` |
| 3 | signature chain to the pinned root, which must equal the registry's root | `E_ROOT_UNTRUSTED`, `E_QUOTE_SIG` |
| 4 | TD is not in DEBUG mode | `E_DEBUG_TD` |
| 5 | `report_data` binds the router's X25519 + Ed25519 keys and the client's nonce | `E_REPORT_DATA_KEYS`, `E_NONCE` |
| 6 | event log digests + boot sequence replay to RTMR3 | `E_EVENT_LOG`, `E_RTMR3` |
| 7 | the published `app-compose.json` is exactly the measured one | `E_COMPOSE_MISMATCH` |
| 8 | the registry **currently** allows that compose hash and OS measurement | `E_COMPOSE_NOT_ALLOWED`, `E_OS_NOT_ALLOWED` |
| 9 | the registry has a live registration for exactly these keys | `E_INSTANCE_NOT_REGISTERED` |

Given those checks, an operator who controls the host, the network and the router deployment **cannot**:

- run modified router code (e.g. one that logs prompts) and still get prompts — its measurement differs and
  is not on the allowlist (`evil-logger` scenario);
- swap the encryption key in transit — the key is bound into the signed quote (`mitm-key`);
- replay an old attestation — the client's nonce is in the quote (`replay-quote`);
- run the approved code in a debuggable TD (`debug-td`);
- truncate or tamper with the encrypted answer stream undetected (`truncate-stream`, `tamper-stream`);
- keep serving after the registry owner revokes a build — the very next session is refused (`revocation`);
- serve from an instance whose keys were never published on-chain (`unregistered`).

The router itself never writes prompts or answers anywhere (no logs, no disk — the mock host runs it under
Node's permission model with a read-only file system), and the e2e suite checks its output and the whole run
directory for the secret prompt.

**What it does not prove (SPEC §1, out of scope, documented not defended):**

- **MOCK ROOT, not Intel.** In this milestone the quote is signed by a locally generated *MOCK ROOT* through a
  per-boot attestation key, and the "TD" is a Node process supervised by a mock TDX host. The byte layouts,
  hashes, event log and verification logic are the real TDX/dstack ones, but **a MOCK ROOT attests nothing
  about hardware**: whoever holds the mock root secret can forge quotes. The CLI says so on every verify
  (`MOCK ROOT (local test root, NOT Intel)`) and the registry records `root.kind = "MOCK"`.
- TEE vendor compromise, micro-architectural side channels.
- Traffic metadata: timing, sizes, IP addresses.
- Denial of service (the operator can always refuse to serve).
- The registry owner's honesty: the owner decides which builds are allowed (→ multisig / DAO later). The
  client pins the attestation root and the registry contract, not the owner.
- The LLM runtime (llama.cpp), node and the model are measured by hash (see *Runtime measurement*), not audited.
- **Mock host limitations (MOCK only; real TDX removes them).** The mock TDX host is an ordinary process of
  the operator's user, so it is trusted the way the TDX module and dstack guest OS are, but nothing enforces
  that here:
  - *Quote socket.* `POST /GetQuote` listens on a Unix socket (mode 0600, in a 0700 directory) owned by the
    operator's uid. Any process of that uid can connect and get a genuine quote of the approved build for
    **any** `report_data`, i.e. bind its own keys to the honest measurement, register them on-chain and receive
    prompts. In real TDX only code inside the TD can reach the guest agent and the quote is signed by
    hardware; with the MOCK ROOT, socket permissions are the only barrier.
  - *Root secret.* The MOCK ROOT secret is a 0600 file of the same uid (see *MOCK ROOT, not Intel*).
  - *Isolation.* The "TD" is a set of processes: same-uid debugging or memory inspection is not prevented.
  - *Runtime plugins.* Runtimes run from verified private copies, but a **new** ggml backend file dropped
    into `<ggml>/libexec` after measurement would still be found by ggml's directory scan.
- **The registry RPC endpoint is trusted.** NEAR view results carry no state proofs, so whoever answers the
  client's `get_root` / `is_*_allowed` / `get_instance` calls decides checks 3, 8 and 9. The client therefore
  only talks to the registry over `https:`, or plain `http:` to a loopback address (a local node or light
  client); `PLR_NEAR_RPC=http://<remote>` is refused. Pick an RPC provider you trust (or run a node / a light
  client locally); a quorum of independent RPCs or light-client proofs is future work.
- **Zcash registry (tier C, `SPEC-CHAINS.md`).** `PLR_CHAIN=zcash` makes the client read the registry from a
  Zebra node (`PLR_ZCASH_RPC`, same https/loopback rule; `PLR_ZCASH_NETWORK`, `PLR_ZCASH_OWNER` or
  `PLR_REGISTRY=zcash:<network>:<owner>`, `PLR_ZCASH_START_HEIGHT`). Zcash checks nothing beyond tx signatures,
  so the client also verifies the registration quote (same boot, bound to registry + operator) and each anchor's
  Ed25519 signature itself; `plr verify` prints the tier and this extra check. The node is trusted like the NEAR
  RPC (no SPV proofs). Expiry is decided in chain time; the reader rebases block times to the local clock (Zebra
  regtest blocks carry 2011 timestamps).
- **EVM / Monad, Stellar, Solana registries (tier B, `SPEC-CHAINS.md` §9-§11).** `PLR_CHAIN=evm|stellar|solana`
  reads a contract registry (`PLR_EVM_RPC` / `PLR_STELLAR_RPC` + `PLR_STELLAR_PASSPHRASE` / `PLR_SOLANA_RPC` +
  `PLR_SOLANA_PROGRAM`, same https/loopback rule; `PLR_REGISTRY=evm:<chainId>:<0x…>` / `stellar:C…` /
  `solana:<state>`). The chain stores the registration quote but does not verify it, so the client does the same
  extra checks as on Zcash (see "Multi-chain registries").

---

## Architecture

```
  ┌──────────────── client machine (trusted) ────────────────┐
  │  any OpenAI SDK ──► plr proxy :18787 ──► PrivateClient    │   pins: MOCK/Intel root, registry id
  │                     (OpenAI-compatible)  │  verifyAttestation (SPEC §9)
  └──────────────────────────────────────────┼──────────────────────────┬─────────────────────┘
          1. GET /v1/attestation?nonce=…     │ 3. POST /v1/private/chat │ 2. view calls
             ◄── quote + event log + compose │    X25519 → ChaCha20-     │    get_root, is_allowed,
                 + router keys               │    Poly1305 (SSE frames)  │    get_instance, get_anchor
  ┌──────────────────────────────────────────▼─────────┐     ┌──────────▼──────────────────────────┐
  │ host / operator (UNTRUSTED)                        │     │ NEAR  registry contract (SPEC §7)   │
  │  ┌──────────────────── TDX TD (mock) ───────────┐  │     │  owner allowlist: compose + OS      │
  │  │ mock TDX host  ── measures compose, bundle,  │  │     │  register_instance: verifies the    │
  │  │   (dstack       model → RTMR3; serves quotes │  │────►│    quote ON-CHAIN (P-256, RTMR3,    │
  │  │   stand-in)     on a 0600 unix socket        │  │     │    compose, report_data)            │
  │  │      │ launches exactly the measured bytes   │  │     │  anchor_receipts: Merkle roots      │
  │  │      ▼                                       │  │     │    signed by the attested Ed25519   │
  │  │ router.bundle.mjs  keys in memory only,      │  │     └─────────────────────────────────────┘
  │  │   (node --permission, read-only fs)          │  │
  │  │      │ 127.0.0.1 only                         │  │
  │  │      ▼                                       │  │
  │  │ llama-server (Qwen 0.5B GGUF) | mock LLM     │  │
  │  └──────────────────────────────────────────────┘  │
  └────────────────────────────────────────────────────┘
```

| package | what |
|---|---|
| [`packages/shared`](packages/shared) `@plr/shared` | the protocol: quote parsing, event log, key binding, session crypto, frames, receipts, Merkle, `verifyAttestation` |
| [`contracts/near`](contracts/near) | the registry contract (Rust, near-sdk 5.29): allowlist, on-chain quote verification, anchoring |
| [`enclave`](enclave) `@plr/enclave` | the router bundle, the VPN exit bundles, the mock TDX host, the mock LLM, the ⚠️ evil-logger demo builds |
| [`client`](client) `@plr/client` | `PrivateClient`, `VpnClient`, `NearRegistry`, the `plr` CLI, the OpenAI-compatible proxy and the SOCKS5 proxy |
| [`e2e`](e2e) | the SPEC §13 / SPEC-VPN §9.3 harness (`startStack`), network attackers, the dev-stack CLI, the locked e2e tests |

---

## Quickstart

Requirements (all local, no network needed): Node 22, Rust + `cargo-near` 0.22, `llama-server`
(`/opt/homebrew/bin/llama-server`), the model `~/models/qwen2.5-0.5b-instruct-q4_k_m.gguf`
(sha256 `74a4da8c…a9db`, pinned in the compose), `npm install` already done.

```sh
bash scripts/demo.sh                # the whole story, ~1–2 min; PLR_LLM=mock for the fast mock LLM
```

It builds everything, starts a fresh near-sandbox with the registry, has the owner approve the honest build,
launches the honest router (measured by the mock host, real Qwen) plus an evil-logger build and a MITM proxy,
then runs `plr verify` (every check ✔), `plr chat` (streamed answer + verified receipt + on-chain anchor), and
the refusals: evil build → `E_COMPOSE_NOT_ALLOWED`, MITM → `E_REPORT_DATA_KEYS`, owner revocation →
`E_COMPOSE_NOT_ALLOWED` then service restored by re-approval. It then runs the VPN story: `plr vpn verify`
against the VPN registry, a fetch through the SOCKS5 proxy and the attested tunnel to a local destination (test
build), evil exit and MITM refused, revocation, the production exit refusing `127.0.0.1` and
`169.254.169.254`, and — only if the machine is online — `https://example.com` through the production exit.
After the two-hop story it runs the combo story (SPEC-COMBO): one TD serving both the router and the exit, both
verified (same compose hash, distinct keys), a chat and a tunnel through it, per-registry revocation (revoking the
combo on the VPN registry stops only the exit role and vice versa), and the production combo's exit refusing
`127.0.0.1` / `::1` / `localhost` on the router's own port. Everything is stopped on exit.

A stack to play with:

```sh
scripts/dev-up.sh                   # near-sandbox :3030 + honest router :18100 (PLR_LLM=mock, PLR_EXTRA=evil-logger,…)
                                    # PLR_COMBO=1: ONE combo TD (router :18100 + VPN exit :18200), same env vars
set -a; . .run/stack.env; set +a    # PLR_ROUTER_URL, PLR_NEAR_RPC, PLR_REGISTRY, PLR_TRUSTED_ROOT, …
node client/dist/cli.js verify
echo "hello" | node client/dist/cli.js chat     # prompt from stdin (recommended: argv shows up in `ps` and history)
node client/dist/cli.js chat "hello"            # the SPEC §12 argv form also works
scripts/dev-down.sh
```

Tests:

```sh
npx tsc -b && npm run build -w @plr/enclave
(cd contracts/near && cargo near build non-reproducible-wasm --no-abi)
npm test                            # unit tests (shared, enclave, client)
npm run e2e                         # SPEC §13 scenarios, registry conformance, VPN, two-hop and combo on a real near-sandbox
PLR_E2E_LLM=llama npx vitest run test/scenarios.test.ts   # (in e2e/) the same scenarios with real Qwen
```

---

## Use it from any OpenAI SDK

`plr proxy` verifies the router (all checks above) and then serves an OpenAI-compatible API on
`127.0.0.1:18787`: `POST /v1/chat/completions` (streaming and non-streaming) and `GET /v1/models`. Every
request is end-to-end encrypted to the attested key; the receipt is verified before the answer is returned.

```sh
set -a; . .run/stack.env; set +a
node client/dist/cli.js proxy       # ✔ router verified (MOCK ROOT); OpenAI-compatible proxy on http://127.0.0.1:18787/v1
```

```ts
import OpenAI from "openai";
const oa = new OpenAI({ baseURL: "http://127.0.0.1:18787/v1", apiKey: "unused" });
const r = await oa.chat.completions.create({ model: "plr", messages: [{ role: "user", content: "hi" }] });
```

```sh
curl http://127.0.0.1:18787/v1/chat/completions -H 'content-type: application/json' \
  -d '{"model":"plr","messages":[{"role":"user","content":"hi"}]}'
```

`plr chat` reads the prompt from stdin when no argument (or `-`) is given — prefer it for anything sensitive.

If verification fails, the proxy answers `403 {"error":{"type":"plr_verification_failed","code":"E_…"}}` and
forwards nothing. Programmatic use: `new PrivateClient({ routerUrl, registry: new NearRegistry({ rpcUrl,
contractId }), trustedRoot })` from `@plr/client`.

Receipt anchoring: `await client.verifyAnchored(result.receipt)` fetches the router's inclusion proof and checks
it against `get_anchor` on-chain, taking the batch position **from the chain** (`index = seq − first_seq`,
`size = count`, `root`); router values that disagree are refused with `E_ANCHOR_MISMATCH` (`E_NOT_ANCHORED`
until the batch is on-chain).

---

## PLR-VPN — a provably no-logs VPN exit (proxy mode)

`plr vpn` runs a local SOCKS5 proxy (`socks5h://127.0.0.1:18180`, CONNECT only, remote DNS). For **every new
connection** it checks the exit against a second, independent NEAR registry (the *VPN registry*: same contract,
same root, its own allowlist) and only then opens an end-to-end encrypted tunnel to the exit's attested key. The
exit (`plr-vpn` build, `127.0.0.1:18200` by default) runs under the same mock TDX host as the router, with no LLM.

```
  app ──SOCKS5──► plr vpn :18180 ──── per connection: attestation (cached ≤ 60 s) + registry re-check ────┐
  (curl, browser)  VpnClient          GET /v1/tunnel (Upgrade: plr-vpn/1)                                 │
                     │  hello(att_nonce, epk_c) ⇄ server_hello(epk_s) → 2×X25519 + HKDF → ChaCha20-Poly1305  │
                     ▼                                                                                     ▼
  host / network (UNTRUSTED): sees only ciphertext ─────► TD: plr-vpn exit ── DoH lookup, dials by IP ──► destination
                                                              egress policy, no logs, signed session receipts
```

### What it proves

Before a single byte leaves your machine (SPEC-VPN §1, §7):

1. the exit is the **approved, measured `plr-vpn` build** in a non-debug TD — the same SPEC §9 checks as the
   router (table above), against the **VPN registry**; a router build is not a VPN build and vice versa;
2. the tunnel is end-to-end encrypted to the attested X25519 key: the operator, host and network see only
   ciphertext and cannot read, modify, reorder, truncate or reflect it undetected (`E_DECRYPT`, `E_TRUNCATED`:
   a cut stream is never a clean EOF — in either direction: if the client→exit stream is cut or tampered, the
   exit aborts the destination connection with a TCP RST, never a FIN). **Handshake v2 (SPEC-VPN §4.1):** the
   exit answers every hello with a fresh ephemeral X25519 key, and the tunnel keys mix both the attested static
   key (`dh1`, authenticates the exit) and the two ephemerals (`dh2`). So a recorded tunnel cannot be replayed —
   the replayed hello meets a new `epk_s`, every replayed frame fails authentication and nothing reaches a
   destination — and it has **forward secrecy**: both ephemeral secrets are zeroed once the keys are derived, so
   a later leak of the exit's static key does not decrypt past tunnels;
3. the approved code **retains nothing**: no destination, DNS name, IP, port, byte count or payload is logged,
   written, put in a receipt or on-chain. Session receipts carry only the transcript hash, compose/key hash,
   a sequence number and open/close timestamps, and are anchored on the VPN registry in Merkle batches;
4. destinations are resolved **by the exit** (remote DNS) — the client never looks them up — and the exit
   resolves them **only over encrypted DNS** (RFC 8484 DoH, SPEC-VPN §6.1) to the resolvers measured in its
   compose (`https://1.1.1.1/dns-query`, `https://9.9.9.9/dns-query`: IP literals, so no bootstrap lookup).
   There is no plaintext fallback: if every resolver fails, the connection fails with `E_DNS` (SOCKS5 `0x04`)
   and the host's resolver is never asked;
5. the exit refuses loopback, private, link-local (incl. `169.254.169.254` cloud metadata), CGNAT, multicast
   and reserved targets — every resolved address is checked, IPv4 embedded in IPv6 included — and the names
   `localhost` / `*.localhost` before any resolution (RFC 6761), so it cannot be
   turned against the host's own services (`E_EGRESS_DENIED`). Beyond the SPEC-VPN §6 table it also refuses
   host-only services that sit in public address space (Azure WireServer `168.63.129.16`) and the exit's own
   interface addresses, in any spelling;
6. revocation on-chain applies to the **very next connection**, even while an attestation is cached.

The e2e suite (`e2e/test/vpn.test.ts`) runs each of these against a real near-sandbox: honest exit (receipts
verified and anchored), evil exit that logs destinations (`E_COMPOSE_NOT_ALLOWED`, destination never contacted),
MITM key swap (`E_REPORT_DATA_KEYS`), replayed attestation (`E_NONCE`), tampered / truncated tunnel, revocation,
production egress policy, unregistered instance, DoH (names only the local resolver knows, NXDOMAIN, resolver
down ⇒ `E_DNS`, localhost names, a name resolving to a private address), and a scan of the exit's output and the
run directory for the destination and payload. `e2e/test/twohop.test.ts` covers two-hop (below).

### What it does not prove

- **The exit sees your destinations.** Any VPN exit must know the host/port it connects to and relays the
  bytes. PLR-VPN proves the approved code does not *keep* them — not that it never sees them.
- **"No logs" covers the attested code, not the operator's network.** DNS is no longer exposed: the exit's
  host and ISP see only TLS to the resolver's IP, and the **resolver** sees the names the exit asks for, but
  never your IP (only the exit's). The exit still dials over a NIC the host controls, so the **operator** — not
  only the exit's ISP — can observe the upstream leg without touching the measured code: destination IP:port,
  timing, the TLS SNI, and every byte of plain-HTTP traffic. PLR-VPN proves the approved exit code retains
  nothing; it does not stop the operator's host from watching the exit's own traffic to destinations. Use
  HTTPS (ideally with ECH) for anything sensitive, and two-hop (below) so that operator does not also know
  who you are.
- **TLS is still needed for content.** For `https://` the exit relays TLS ciphertext; for plain `http://` the
  exit code processes the plaintext (it never stores it). The destination sees the exit's IP.
- **Metadata.** Timing and sizes of tunnelled traffic are visible to the operator and the network (DATA is not
  padded, no cover traffic; only the CONNECT / CONNECT_ERR payloads have fixed sizes). With one hop, your own IP is visible to the exit operator's network.
- **Proxy mode only.** Only what you send through the SOCKS5 proxy is protected: TCP CONNECT, no UDP (no QUIC,
  no WebRTC media, no system-wide tunnel). Use `socks5h` (or "proxy DNS") so names are not resolved locally.
- Everything listed for the router applies too: **MOCK ROOT, not Intel** in this milestone; the registry owner
  decides which builds are approved; the RPC endpoint is trusted; mock-host limitations.

### Quickstart

```sh
PLR_LLM=mock scripts/dev-up.sh          # chain + both registries + honest router :18100 + production VPN exit :18200
set -a; . .run/stack.env; set +a        # adds PLR_VPN_URL, PLR_VPN_REGISTRY, PLR_VPN_COMPOSE_HASH, PLR_VPN_ENTRY_URL
unset PLR_VPN_ENTRY_URL                 # one hop (with it set, `plr vpn` is two-hop — see below)
node client/dist/cli.js vpn verify      # every check, ✔/✘, against the VPN registry
node client/dist/cli.js vpn             # ✔ VPN exit verified …  ✔ SOCKS5 proxy on socks5h://127.0.0.1:18180
curl --proxy socks5h://127.0.0.1:18180 https://example.com     # (another terminal; needs the machine online)
scripts/dev-down.sh
```

Client env: `PLR_VPN_URL` (default `http://127.0.0.1:18200`), `PLR_VPN_REGISTRY`, `PLR_NEAR_RPC`,
`PLR_TRUSTED_ROOT`, `PLR_VPN_SOCKS_PORT` (default 18180), `PLR_VPN_ATTEST_TTL_MS` (default 60000; 0 = a fresh
attestation for every connection — the registry is re-checked on every connection regardless), and
`PLR_PCCS_URL` (INTEL mode only, e.g. `https://pccs.phala.network`): fetch fresh Intel collateral (PCK CRL, TCB
info, QE identity) from that PCCS with `getCollateral` instead of trusting the exit's copy, before verification.
`PLR_PCCS_URL=https://pccs.phala.network node scripts/pccs-live-check.mjs` shows it against the recorded real TDX
quote (build first: `npx tsc -b`).

Browser / app settings — SOCKS v5 host `127.0.0.1`, port `18180`, **remote DNS**:

- **Firefox**: Settings → Network Settings → *Manual proxy configuration* → SOCKS Host `127.0.0.1` Port
  `18180`, *SOCKS v5*, tick **Proxy DNS when using SOCKS v5**; set `media.peerconnection.enabled = false` in
  `about:config` (WebRTC/UDP bypasses any SOCKS proxy).
- **Chrome / Chromium**: `--proxy-server="socks5://127.0.0.1:18180"` (Chrome always resolves names through a
  SOCKS5 proxy); add `--host-resolver-rules="MAP * ~NOTFOUND, EXCLUDE 127.0.0.1"` to make any local lookup fail.
- **curl**: `--proxy socks5h://127.0.0.1:18180` (`socks5://` without the `h` would resolve locally);
  **git**: `git config --global http.proxy socks5h://127.0.0.1:18180`; most CLIs honour
  `ALL_PROXY=socks5h://127.0.0.1:18180`.

If the exit fails verification, `plr vpn` does not start (and `plr vpn verify` prints the failing check); if a
later connection fails the registry re-check, that connection gets SOCKS5 reply `0x02` and nothing is sent.
Programmatic use: `new VpnClient({ exitUrl, registry: new NearRegistry({ rpcUrl, contractId }), trustedRoot })`,
`await client.connect(host, port)` → a `Duplex` with `receipt()`; `startVpn({ port, client })` for the proxy.

For two hops (entry → exit, different operator organizations) set `PLR_VPN_ENTRY_URL` — see
[Two-hop routing](#two-hop-routing-and-operator-organizations-spec-vpn-10) below.

Builds (`enclave/build.mjs`): `vpn-honest` (production: `allow_loopback: false`, the public DoH resolvers),
`vpn-honest-test` (loopback allowed and the local test resolver `http://127.0.0.1:18253/dns-query`, so tests and
the demo can reach a local destination — a different compose hash, so it can never pass as production), and ⚠️
`vpn-evil-logger` (prints destinations and the first relayed bytes; test policy; never approved).

### Two-hop routing and operator organizations (SPEC-VPN §10)

One exit always knows two things about you at once: your IP (it accepts your connection) and your destinations
(it dials them). Two-hop splits them across two attested `plr-vpn` instances run by **different organizations**:

```
  you ──tunnel A (to the entry's attested key)──► ENTRY ──CONNECT exit:port──► EXIT ──DoH, dial──► destination
       └──── tunnel B (nested inside A, end-to-end to the EXIT's attested key) ────┘
```

`TwoHopClient` (and `plr vpn` with `PLR_VPN_ENTRY_URL` set) attests the entry directly, then fetches the exit's
attestation *through* a tunnel to the entry — the client never contacts or resolves the exit itself. Both hops
must be approved `plr-vpn` builds on the VPN registry, and both operators must be mapped to an organization by
the registry owner (`approve_operator(account_id, org_id)`, SPEC §7 rev 1.2; `get_instance` returns the
operator's **live** `org_id`). The orgs must differ: `E_OPERATOR_UNAPPROVED` / `E_SAME_OPERATOR` (SOCKS5
`0x02`). Every new connection re-checks both hops' compose, OS, instance and org rules, so a revocation or an
org change applies to the very next connection, even with cached attestations. Each connection returns two
verified session receipts: `receipt()` from the exit and `entryReceipt()` from the entry.

Who knows what:

| party | your IP | exit's address | destination host:port | DNS names | payload |
|---|---|---|---|---|---|
| your network / ISP | ✔ | ✔ | — | — | — (ciphertext) |
| entry (operator org A) and its host | ✔ | ✔ | — | — | — (inner tunnel is end-to-end to the exit) |
| network between the hops | entry's IP | ✔ | — | — | — |
| exit (operator org B) and its host | — (sees the entry's IP) | — | ✔ | — (host sees only TLS to the resolver) | TLS ciphertext (plaintext for `http://`) |
| exit's DoH resolver | — | — | — | ✔ (asked by the exit) | — |
| destination | — (sees the exit's IP) | — | ✔ | — | ✔ |

The e2e suite (`e2e/test/twohop.test.ts`) proves the operator rules on a real chain and that even an approved
entry that **logs everything** (the evil build, approved for the test) records only the exit's address — never
the destination name, path or payload.

Remaining limits:

- **Timing correlation across both hops.** An adversary that watches the entry's and the exit's networks (or
  both operators colluding) can match flows by timing and size — no padding or cover traffic.
- **Owner trust for org approvals.** The registry owner decides which accounts belong to which organization. An
  owner that approves one real-world company under two `org_id`s defeats the separation (later: multisig /
  staking-backed org registration). Clients see the org ids that `plr vpn verify` prints.
- **Who registers a key decides its org — and only the enclave's chosen operator can (SPEC §5/§7 rev 1.3).** The
  contract records as `operator` whoever lands the first `register_instance` for a key. Every quote now states its
  purpose: `/v1/attestation` only quotes `key_hash ‖ SHA256("PLR-v1/session-nonce" ‖ nonce)`, while a registration
  quote binds `registration_nonce(contract, operator)` (length-prefixed, operator = the instance's `PLR_OPERATOR_ID`),
  which the contract checks against `current_account_id` + `predecessor_account_id`. A session quote can never pass as
  a registration (that needs a SHA-256 preimage), and a registration quote is useless to anyone but the bound
  operator, so a front-run cannot claim the key. Defense in depth: after each registration the exit still reads the
  record back and, if the operator is not its own account, logs `registration_failed code=E_OPERATOR_MISMATCH`, stops
  serving and exits non-zero (a restart produces new keys).
- **Frame sizes.** CONNECT payloads are always 512 bytes and CONNECT_ERR payloads 32 bytes (space-padded JSON). The
  entry, which sees the inner frames' lengths, therefore cannot learn the destination name's length or which
  error the exit returned. Later DATA frames still have their natural sizes (TLS records).
- The single-hop limits above still apply to the exit's upstream leg (destination IP:port, SNI, plain HTTP).

Run it locally — `scripts/dev-up.sh` approves `operator` as `org-a` and `operator2` as `org-b`, and starts the
production exit (`PLR_VPN_URL`, org-a), a second production exit (`PLR_VPN2_URL`, org-b) and a two-hop entry
(`PLR_VPN_ENTRY_URL`, org-b). The entry is the approved **test** build: a production entry refuses to dial a
loopback exit (its own egress policy), so on one machine only a loopback-allowing entry can reach the exit; in the
cloud both hops are production builds with public addresses.

```sh
PLR_LLM=mock scripts/dev-up.sh
set -a; . .run/stack.env; set +a        # PLR_VPN_ENTRY_URL set ⇒ `plr vpn` is two-hop
node client/dist/cli.js vpn verify      # entry hop + exit hop (fetched through the entry) + organizations
node client/dist/cli.js vpn             # ✔ two-hop VPN verified … entry (org-b) → exit (org-a) … SOCKS5 on :18180
curl --proxy socks5h://127.0.0.1:18180 https://example.com     # online: entry → production exit → example.com
PLR_VPN_URL=$PLR_VPN2_URL node client/dist/cli.js vpn verify   # same org on both hops ⇒ ✘ E_SAME_OPERATOR
PLR_VPN_ENTRY_URL= node client/dist/cli.js vpn                 # one hop again (empty = unset)
scripts/dev-down.sh
```

Programmatic: `new TwoHopClient({ entryUrl, exitUrl, registry, trustedRoot })`; `startVpn({ port, client })`
accepts it like a `VpnClient`. Owner actions on the dev stack:
`node e2e/dist/stack-cli.js owner approve_operator '{"account_id":"…","org_id":"org-c"}' --vpn`
(also `revoke_operator`).

### Running it in the cloud — costs and where to put the exit

Phala Cloud (managed dstack CVMs) instance prices, as published (Oct 2026):

| item | cost |
|---|---|
| Phala Cloud `tdx.small` | $0.06/h (≈ $44/month) |
| Phala Cloud `tdx.medium` (e.g. the LLM router + Qwen 0.5B) | $0.12/h (≈ $88/month) |
| Phala Cloud `tdx.large` | $0.23/h |
| Phala Cloud egress | **no published per-GB price or quota** ("each machine includes bandwidth based on its size" — ask sales) |
| Azure DCesv5 / ECesv5 (Intel TDX VMs, public IP) egress | first 100 GB/month free, then $0.087/GB |
| GCP C3 Confidential VMs (TDX) egress | roughly $0.085–0.12/GB (unverified) |
| NEAR storage per registry deployment (≈ 217 KB wasm + state, 1 NEAR / 100 KB staked, refundable) | ≈ 2–3 NEAR locked |
| NEAR gas: `register_instance` (daily) and `anchor_receipts` batches | fractions of a milli-NEAR per tx |

Where each service fits:

- **LLM router → Phala Cloud** is a good fit (HTTPS ingress, little egress). The $20 free credit can be used for it.
- **VPN exit → a TDX VM with its own public IP** (Azure DCesv5/ECesv5, or GCP C3 Confidential VMs) running
  dstack self-hosted, or a replacement of the mock host on that VM. Reasons: Phala's Terms (§7.4) forbid VPN /
  proxy / tunneling software on free or promotional credit, so the $20 credit cannot pay for the exit; managed
  Phala CVMs have **no public IP** — ingress only via the dstack-gateway
  (`https://<app-id>-<port>.dstack-pha-<node>.phala.network`, TLS/SNI-routed, TCP only, no UDP, which also rules
  out a later WireGuard exit) and egress via a shared NAT; and VPN traffic is egress-heavy while Phala publishes
  no egress price. For two-hop, put the entry and the exit in different clouds / organizations.
- Whatever runs dstack: Phala's October 2026 post-mortem requires **dstack OS ≥ v0.6.1 / v0.5.12**; approve only
  OS measurements of such images on the registries.

For mainnet, raise `PLR_ANCHOR_INTERVAL_MS` to about 10 minutes (`600000`; local default 3 s for the exit):
one `anchor_receipts` transaction per interval covers every receipt since the last one, so a longer interval
cuts gas and storage proportionally at the price of a later anchoring proof. Swap the MOCK root for Intel exactly
as described in *Swapping in real TDX* (`set_root("INTEL", …)` on the VPN registry as well).

### Cheapest demo deployment: one VM

For a demo, run **both services in one confidential VM**: the `plr-combo` build ([`SPEC-COMBO.md`](SPEC-COMBO.md)).
The (mock or dstack) host measures one compose that pins the router bundle, the VPN exit bundle, the model and the
runtime, then starts three isolated processes in the one TD — the LLM, the router (:18100) and the VPN exit
(:18200). Each service generates its own keys, registers on its own registry (router → LLM registry, exit → VPN
registry, both operator-bound, rev 1.3) and anchors its own receipts. Clients are unchanged: `plr verify` /
`plr chat` against the router URL, `plr vpn` against the exit URL.

| item | cost |
|---|---|
| Azure `Standard_DC2es_v5` (2 vCPU / 8 GiB, Intel TDX), **East US 2**, incl. OS disk + public IP | ≈ $2.50/day while running |
| egress | first 100 GB/month free, then $0.087/GB |
| NEAR | testnet (free); the same contract and code as mainnet |

- **Region**: Azure's TDX sizes (DCesv5 / ECesv5) are not offered in East US; East US 2 is the closest
  US-East region that has them.
- **Switch it off when idle**: compute is billed per second, so a stopped (deallocated) VM costs only its disk and
  IP (a few cents a day). A 2-hour demo is cents of compute; leaving it on all month ≈ $75.
- **Qwen 0.5B fits** on 2 vCPU / 8 GiB next to the router and the exit; a bigger model needs a bigger size.
- Local rehearsal of exactly that layout: `PLR_COMBO=1 scripts/dev-up.sh` (one production `combo` TD,
  `PLR_COMBO=combo-test` for the loopback-allowing test build), or the combo steps of `scripts/demo.sh`.

Trade-offs (SPEC-COMBO §3), why this is a demo layout and not the recommended production one:

- **Approval is per registry.** The owner approves the combo compose hash (and the OS measurement) on the LLM
  registry for the router role and on the VPN registry for the exit role; approving one does not approve the other,
  and revoking one stops only that role (the demo shows both directions).
- **One measurement covers both programs**: any change to either the router or the exit changes the combo compose
  hash, so both roles need re-approval together.
- **Isolation is process-level, not TD-level.** The three processes share the TD's memory-encryption domain, so a
  defect in one service is not cryptographically contained from the other. Network isolation still holds: the
  production exit cannot reach the router or the LLM (`allow_loopback: false`, private ranges denied — the demo
  shows `127.0.0.1` / `::1` / `localhost` on the router's port refused), and the LLM requires a per-boot API key
  that only the router process receives. For production, run separate TDs (and, for two-hop, separate
  organizations).

### Next step: WireGuard with the attested key

Proxy mode protects what you point at the SOCKS proxy. A full-tunnel VPN can reuse everything here: WireGuard's
static keys are Curve25519, so the exit's **attested X25519 key** (already bound into `report_data` and
registered on-chain) can be the WireGuard server's static public key. The client verifies the attestation and
the registry exactly as today, then configures that key as the peer; WireGuard's Noise IK handshake proves the
peer holds the matching private key, which only the measured code has. Inside the TD a userspace WireGuard
(`wireguard-go` / `boringtun`) terminates the tunnel and applies the same egress policy to IP packets (UDP
included); a new compose (`plr-vpn-wg`) is approved like any other build. The remaining work is packet-level
egress filtering, DNS inside the tunnel and per-peer receipts.

---

## Every quote states its purpose (SPEC rev 1.3)

A TDX quote signs 64 bytes of `report_data` chosen by the code inside the TD. Until rev 1.2 the router put
`key_hash ‖ nonce` there for *every* purpose: the client's random nonce for a session quote, and
`SHA256("PLR-v1/register" ‖ contract)` for the registration quote. The two were the same shape, so anyone could ask a
router's public `/v1/attestation` for a "session" quote **using the registration nonce as the client nonce** and
submit the result to `register_instance` first. Because the first registration decides the on-chain `operator` (and
so, for VPN exits, the organization used by two-hop), that hijacked the instance's attribution. The interim fix
(refusing that nonce value on `/v1/attestation`, plus the exit reading its operator back) closed the known path but
not the shape of the problem.

Rev 1.3 domain-separates the purposes so that no quote can serve another one:

```
session:       report_data = key_hash ‖ SHA256("PLR-v1/session-nonce" ‖ client_nonce)
registration:  report_data = key_hash ‖ SHA256("PLR-v1/register/2" ‖ u8(len c) ‖ c ‖ u8(len o) ‖ o)
               c = registry contract account, o = operator account (the instance's PLR_OPERATOR_ID)
```

- A session quote never contains the raw client nonce, so turning it into a registration quote would require a
  SHA-256 preimage — whatever nonce the client picks. The `/v1/attestation` special case is gone.
- The registration quote names the operator, and the contract recomputes the nonce from `current_account_id` and
  `predecessor_account_id`: only the account the enclave chose can submit it. A replay can only re-register the
  same keys under the same operator. The length prefixes keep `(contract, operator)` unambiguous.
- Clients check `report_data[32:64] == SHA256("PLR-v1/session-nonce" ‖ nonce)` (`E_NONCE`). The VPN exit still reads
  its on-chain operator back after registering (defense in depth; fail closed on a mismatch).
- **Upgrading an existing registry: every old compose hash must go.** A pre-rev-1.3 router or exit still answers
  `/v1/attestation?nonce=<registration_nonce(registry, attacker)>` with a quote the rev 1.3 contract accepts from the
  attacker, and the contract cannot tell build versions apart. So the rev 1.3 contract does not load a rev 1.2 state
  at all (every call fails) until the contract account runs `migrate()` (deploy + `migrate` in one batch), which
  **empties the compose allowlist**; the owner then approves only rev 1.3 builds. See
  [contracts/near/README.md](contracts/near/README.md). Never re-approve a pre-rev-1.3 compose hash.

---

## Runtime measurement (spec revision to SPEC §4)

SPEC §4 has the host hash the router bundle and the model, but the programs that see plaintext — `node`
(router, mock LLM) and `llama-server` — were only a free-form `llm.runtime` label, so an operator could swap
in a prompt-logging llama-server (or node) under the approved compose hash. The compose now pins them:

```json
{ "llm":    { "kind": "...", "model_sha256": "...", "runtime": "...", "runtime_sha256": "<64 hex>" },
  "router": { "bundle_sha256": "...", "entry": "router.bundle.mjs", "node_sha256": "<64 hex>" }, ... }
```

- A runtime digest covers the executable **and its closure**: on macOS both executables are small stubs whose
  code lives in dylibs (`libnode.*.dylib`, `libllama-server-impl.dylib`, ggml, openssl, …), and ggml `dlopen`s
  its backends from `<keg>/libexec`. The host follows `LC_LOAD_DYLIB`/`LC_RPATH` transitively (dyld rules,
  system images under `/usr/lib` and `/System` excluded as OS), adds the libexec plugins, and hashes the
  sorted manifest `"<sha256> <exe|lib> <leaf name>"` (`enclave/src/mock-tdx/runtime.ts`).
- `llm.runtime_sha256` is llama-server's digest for `llama.cpp` composes and equals `router.node_sha256` for
  `mock` composes (the mock LLM is a node script).
- At launch the host clones every closure file into its private 0700 directory, re-hashes the **copies**,
  refuses on any mismatch (`E_MEASUREMENT_MISMATCH`, or `E_RUNTIME_FORMAT` for a non-Mach-O such as a wrapper
  script), and runs the copies (`DYLD_LIBRARY_PATH` points dyld at them). The GGUF model gets the same treatment
  (0400 clone, re-hashed against `llm.model_sha256`, and llama-server is only given the copy), so swapping the
  operator-writable original after the host measured it changes nothing. `--llama-server` / `PLR_LLAMA_SERVER`
  is accepted only if it reproduces the pinned digest.
- `enclave/build.mjs` pins the node that runs the build and `PLR_LLAMA_SERVER` (default
  `/opt/homebrew/bin/llama-server`); `approveBuild` and `plr-tdx-host measure` measure exactly like the host.
  Upgrading node or llama.cpp changes the compose hashes, so the owner must approve the new build — by design.
- Real-TDX mapping: dstack's compose pins container image digests, which play this role.

LLM isolation between users: llama-server runs with prompt caching off (`--no-cache-prompt`,
`--cache-reuse 0`, `-cram 0`, `--no-cache-idle-slots`, one slot), and the router sends `cache_prompt: false`,
so one user's prompt prefix can't be probed through `timings.cache_n` or prompt-processing time (verified
live: a request sharing the previous prompt's prefix gets `cache_n = 0`). `--no-cache-prompt` is only a
per-request default, so the LLM is also locked to the router: the host generates a per-boot API key
(`LLAMA_API_KEY` / `PLR_LLM_API_KEY`, via env, never argv) and any other local process gets `401`. Residual
(MOCK limitation): a process of the operator's own uid can read that key from the process environment.
Requests are still served one at a time, so residual queueing latency is in the out-of-scope timing metadata.

Anchor storage: `anchor_receipts` is payable. The storage it adds is paid by the attached deposit (the router
attaches `PLR_ANCHOR_DEPOSIT`, default 0.01 NEAR, and the excess is refunded) or else by the instance's prepaid
anchor credit, which `register_instance` keeps from its deposit (up to 0.05 NEAR, view `get_anchor_credit`).
The contract's own balance never pays, so a registered instance cannot drain it.

---

## Swapping in real TDX (Phala dstack)

The mock is built to the real formats, so the swap is two components, not a redesign:

- **Attester (router side).** The router only talks to `Attester.getQuote(report_data)`; locally that is the
  mock host's `POST /GetQuote` on a Unix socket, which mirrors dstack's guest-agent `GetQuote` (raw 64-byte
  `report_data`, no hashing). In a dstack CVM, `DstackAttester` (`@plr/shared`, stub today) calls the dstack
  SDK; dstack already extends RTMR3 with the same boot events (`system-preparing`, `app-id`, `compose-hash`,
  `instance-id`, `boot-mr-done`) and the same digest rule, so the event-log verification is unchanged. The
  `app-compose.json` becomes the dstack app compose of the CVM.
- **Verifier (client side).** `DcapQvlVerifier` (stub today) verifies real v4 quotes with Intel DCAP
  (`@phala/dcap-qvl`: PCK chain to the pinned Intel root, TCB status `UpToDate`), and returns the same
  `ParsedQuote`. Everything after step 3 of the checks is identical.
- **Registry.** `set_root("INTEL", <Intel root>)`; the OS measurement is then the real MRTD/RTMR0–2 of the
  dstack OS image (`SHA256(mr_td ‖ rtmr0 ‖ rtmr1 ‖ rtmr2)`, SPEC §2.5). On-chain verification of a full Intel
  quote (PCK chain + QE report) is out of scope for milestone 1: with an INTEL root `register_instance` fails
  closed (`E_QUOTE_SIG`); production would verify via a DCAP-verifier contract or an attested relayer.

## Multi-chain registries (SPEC-CHAINS)

The client depends only on the chain-agnostic `RegistryReader` interface (`getRoot`, `isComposeAllowed`,
`isOsAllowed`, `getInstance`, `getAnchor`, SPEC §10), so the registry (SPEC §7) can live on any chain. Chains
differ in **what they can check on-chain**, which `SPEC-CHAINS.md` §1 sorts into tiers:

| tier | chains | the chain enforces | the client additionally verifies |
|---|---|---|---|
| A | NEAR | full registration-quote verification (SPEC §7), owner policy, operator orgs, Ed25519-checked anchors | — |
| B | EVM / Monad, Stellar, Solana | owner policy, operator orgs, registration only by owner-approved operators (`operator` = tx signer), the registration quote stored on-chain, contiguous anchors by the instance's operator | the stored registration quote + each anchor's Ed25519 signature |
| C | **Zcash** (no contracts) | only ordering + authenticity of signed `OP_RETURN` records | everything of tier B, from records it parses itself; the quote is SHA-256-committed on-chain and served by the instance |

**The rev 1.4 client rule (registration evidence, SPEC §9 step 9b).** Every reader says `verifiesOnChain` (true
only on tier A). When it is false, after step 9 the client fetches the registration quote
(`getRegistrationQuote(key_hash, bundle.registration_quote)` — tier C returns the instance-served quote only if
its SHA-256 equals the on-chain commitment), verifies it against the same pinned root (DEBUG clear), checks
`report_data == registrationReportData(x25519, ed25519, contractId, record.operator)` and that MRTD and RTMR0–3
equal the session quote's (same TD boot, so the already-verified event log, compose hash and OS measurement
apply). Anything missing or different ⇒ `E_REGISTRATION_EVIDENCE`. Anchors on tier B/C must also carry a valid
Ed25519 signature by the attested key over `anchorMessage` (`E_ANCHOR_SIG`). Safety therefore never depends on
the tier: a lower tier only moves checks from the chain to the client. Instance records count only from
operators the owner approved on that registry (`approve_operator`, live), so strangers cannot front-run or spam
registrations.

**Zcash record log (SPEC-CHAINS §5).** The registry `zcash:<network>:<owner t-address>` is the sequence of
confirmed transparent transactions whose inputs are all P2PKH-signed by one key and that carry exactly one
`OP_RETURN` with `"PLR1" ‖ type ‖ body` (≤ 80 bytes): owner records (`allow_compose` / `revoke_compose` /
`allow_os` / `revoke_os` / `set_root` / `approve_operator` / `revoke_operator` / `transfer_owner`) and operator
records (`reg_keys`, `reg_measure`, `reg_os`, `reg_quote`, `anchor`, `anchor_sig`), ordered by (height, tx
index). Readers (`client/src/zcash-registry.ts`, `ZcashLog` in `@plr/shared`) fold blocks from a Zebra node
(`getblockcount`, `getblockhash`, raw `getblock <hash> 0` — bounded by the 2 MB consensus block size — and
`getrawtransaction <txid> 0` for the coins record transactions spend) deterministically and never throw on chain
data; routers and exits (`PLR_CHAIN=zcash`, `enclave/src/zcash.ts`) build and sign v5 transparent transactions
themselves (ZIP-244 sighash, ZIP-317 fee, branch id from `getblockchaininfo`) and submit them with `sendrawtransaction`.

Strict mode (SPEC-CHAINS §7 `strict`, used by every production reader and writer; found in review):
- **Authorship needs the author's own coin.** Consensus runs the spent coin's script, so a `<sig> <pubkey>`
  scriptSig alone proves nothing (a coin locked by `OP_2DROP OP_1` accepts any). A record counts only if every
  input spends `P2PKH(hash160(pubkey))` with a SIGHASH_ALL signature; the reader fetches the prevouts and fails
  the query (never skips) if it cannot.
- **Anchor signatures are checked at fold time** (Ed25519 by the key's registered `ed25519` over `anchorMessage`)
  and matched against every pending anchor of that operator and key, so a retried or reordered anchor can never
  carry another batch's signature; the writer also never posts a new anchor while an earlier one of that key can
  still be mined, and caps `anchor_sig` expiry at anchor height + 10.
- **Registration selection is §5's** (earliest completed, operator currently approved). Approved operators are
  owner-trusted: one that copies another's public registration records first becomes the recorded operator, and
  clients then refuse the instance (`E_REGISTRATION_EVIDENCE`, the quote binds the real operator) — a denial of
  service the owner ends by revoking it, never a hijack.
- **Spam cannot block registrations.** Slots of authors that are not approved when their record lands share a
  separate store capped at 10 000 (oldest evicted); approved operators are never limited by it.
- **Catch-up is bounded in time** (`syncTimeoutMs`, CLI `PLR_ZCASH_SYNC_TIMEOUT_MS`, progress kept), not a fixed
  block budget.

**Run it on Zcash** (needs `zebrad` — `~/.cargo/bin/zebrad`, on `PATH`, or `ZEBRAD_BIN`; tested with 7.0.0):

```sh
PLR_CHAIN=zcash PLR_LLM=mock scripts/dev-up.sh     # zebrad regtest + both registries (two owner t-addresses)
set -a; . .run/stack.env; set +a                    # PLR_CHAIN=zcash, PLR_ZCASH_RPC, PLR_ZCASH_NETWORK, PLR_REGISTRY=zcash:regtest:tm…
node client/dist/cli.js verify                      # "tier: C — … this client checks the registration evidence"
node e2e/dist/stack-cli.js owner revoke_compose '{"hash":"'$PLR_COMPOSE_HASH'"}'   # an owner OP_RETURN record
scripts/dev-down.sh
cd e2e && PLR_E2E_CHAINS=near,zcash npx vitest run test/chains.test.ts             # same conformance tests on both chains
```

The harness (`startStack({ chain: "zcash" })`, `e2e/src/chains/zcash.ts`) runs one ephemeral zebrad regtest node
per stack with its state under `.run/<id>/zcash/`, mines 110 blocks to a fresh faucet key, gives owner, VPN owner,
operator (twice), operator2 and stranger 40 coins each, keeps mining one block per second, and posts `set_root`
for both registries. Owner actions go through `S.admin` / `S.vpnAdmin` (`ChainAdmin`) on every chain; the
`demo.sh` Zcash section (only when zebrad is installed) shows verify, chat and revocation via records.

**Limits.** The Zebra node is trusted like the NEAR RPC (no SPV / light-client proofs; https or loopback only).
Records need a confirmation (≈ 1 s on the regtest stack, ~75 s on a public network): a revocation takes effect
for clients once mined, and on public networks `minConfirmations` trades freshness for reorg safety. Every record
costs a ZIP-317 fee (20 000 zats) and anchors take two transactions (`anchor`, then `anchor_sig`). Expiry runs on
chain time (regtest blocks carry 2011 timestamps; readers rebase to the local clock). Only transparent
(t-address) records are used — nothing here is shielded, and the log is public by design.

### Tier B: EVM / Monad, Stellar, Solana (SPEC-CHAINS §9-§11)

Three contract registries with the same semantics: owner policy, operator organizations, registration only by an
owner-approved operator (`operator` = the transaction signer; the contract recomputes `key_hash` and checks the quote
format and that its `report_data` binds this registry's `contractId` and the signer), the **828-byte registration
quote stored on-chain**, and anchors `(key_hash, root, first_seq, count, sig)` that must be contiguous and posted by
the instance's operator while its compose and OS are still allowed. The quote signature and the anchor signature
are *not* checked on-chain; the client checks both (the rev 1.4 rule above), so a tier-B registry is as safe for
clients as NEAR. Errors are named after the PLR codes on every chain (Solidity custom errors, Soroban
`#[contracterror]` 1-9, Solana `ProgramError::Custom(1-9)`).

| chain | contract | `contractId` (§3) | instance env (`PLR_CHAIN=…`) | client (`plr`) env |
|---|---|---|---|---|
| EVM / Monad | `contracts/evm` (Foundry, `PlrRegistry.sol`, solc 0.8.30, `evm_version` cancun) | `evm:<chainId>:<0x address>` | `PLR_EVM_RPC`, `PLR_EVM_REGISTRY` (exit: `PLR_EVM_VPN_REGISTRY`), `PLR_EVM_KEY` (operator secp256k1 hex); optional `PLR_EVM_CHAIN_ID` (else asked from the node) | `PLR_EVM_RPC`, `PLR_REGISTRY` / `PLR_VPN_REGISTRY` = `evm:…` |
| Stellar | `contracts/stellar` (Soroban, soroban-sdk 29.0.1) | `stellar:C…` | `PLR_STELLAR_RPC`, `PLR_STELLAR_PASSPHRASE`, `PLR_STELLAR_REGISTRY` (exit: `PLR_STELLAR_VPN_REGISTRY`), `PLR_STELLAR_KEY` (S…) | `PLR_STELLAR_RPC`, `PLR_STELLAR_PASSPHRASE`, `PLR_REGISTRY` / `PLR_VPN_REGISTRY` = `stellar:C…` |
| Solana | `contracts/solana` (native solana-program 5.1.0; one program, one state account per registry, PDAs per item) | `solana:<state account>` | `PLR_SOLANA_RPC`, `PLR_SOLANA_PROGRAM`, `PLR_SOLANA_REGISTRY` (exit: `PLR_SOLANA_VPN_REGISTRY`), `PLR_SOLANA_KEY` (64-byte hex) | `PLR_SOLANA_RPC`, `PLR_SOLANA_PROGRAM`, `PLR_REGISTRY` / `PLR_VPN_REGISTRY` = `solana:…` |

The mock TDX host forwards exactly these variables (and in a combo TD the exit never receives the LLM registry
variable, only `PLR_<CHAIN>_VPN_REGISTRY`). The `plr` CLI also accepts the chain-specific registry variables instead
of the `contractId` (`PLR_EVM_REGISTRY` + `PLR_EVM_CHAIN_ID`, `PLR_STELLAR_REGISTRY`, `PLR_SOLANA_REGISTRY`, and the
`_VPN_` forms); when both are given they must agree. `plr verify` prints `tier: B`. Readers: `EvmRegistry` (viem),
`StellarRegistry` (`simulateTransaction`, no signing), `SolanaRegistry` (`getAccountInfo` / `getMultipleAccountsInfo`),
all exported from `@plr/client`; each RPC must be https, or http to a loopback host.

**Run them locally** (all offline; the e2e harness starts one node per stack and stops it in `stop()`):

```sh
# build the contract of the chain you want (scripts/build.sh does it for PLR_CHAIN / PLR_BUILD_CHAINS=evm,stellar,solana)
(cd contracts/evm && forge build)                     # → out/PlrRegistry.sol/PlrRegistry.json   (anvil: ANVIL_BIN, ~/.foundry/bin or PATH)
(cd contracts/stellar && stellar contract build)      # → target/wasm32v1-none/release/plr_stellar_registry.wasm (needs Docker)
export PATH=$HOME/.local/share/solana/install/active_release/bin:$PATH
(cd contracts/solana && cargo-build-sbf)              # → target/deploy/plr_registry_solana.so

PLR_CHAIN=evm PLR_LLM=mock scripts/dev-up.sh          # or stellar / solana: anvil :8545, quickstart :8000, test-validator :8899
set -a; . .run/stack.env; set +a; node client/dist/cli.js verify          # "tier: B — … this client checks the registration evidence"
node e2e/dist/stack-cli.js owner revoke_compose '{"hash":"'$PLR_COMPOSE_HASH'"}'   # an owner transaction on that chain
scripts/dev-down.sh
cd e2e && PLR_E2E_CHAINS=near,zcash,evm,stellar,solana npx vitest run test/chains.test.ts   # one conformance suite, every chain
```

Per chain: **EVM** — one `anvil` per stack (automine), two `PlrRegistry` deployments, accounts funded with
`anvil_setBalance`. **Stellar** — one `stellar/quickstart` container per stack (`--protocol-version 29 --limits
unlimited`: protocol 28 cannot run SDK-29 wasm), friendbot-funded accounts, the wasm uploaded once and deployed
twice (`__constructor`); startup takes ~1 minute (health + friendbot warm-up). **Solana** — one
`solana-test-validator` per stack with the program preloaded, two state accounts created by `Init`; a
registration's transaction uses an address lookup table so the 828-byte quote fits. On every tier-B chain one
operator account signs for all of its TDs (router, exit, both halves of a combo): the writers serialize their own
sends and retry sequence/nonce clashes a bounded number of times.

**Monad testnet.** Monad is bytecode-compatible with Ethereum, so the same `PlrRegistry` bytecode deploys
unchanged (Monad's contract size limit is 128 KB; `PlrRegistry` is ~9.5 KB). Testnet chain id **10143**, so the
registry id is `evm:10143:<address>`:

```sh
cd contracts/evm
PLR_EVM_OWNER=0x… PLR_ROOT_KIND=2 PLR_ROOT_P256=0x<64-byte Intel/MOCK root> PLR_INSTANCE_TTL_MS=86400000 \
  forge script script/Deploy.s.sol --rpc-url https://testnet-rpc.monad.xyz --private-key $DEPLOYER_KEY --broadcast
# instance: PLR_CHAIN=evm PLR_EVM_RPC=https://testnet-rpc.monad.xyz PLR_EVM_REGISTRY=0x… PLR_EVM_KEY=<operator key>
# client:   PLR_CHAIN=evm PLR_EVM_RPC=https://testnet-rpc.monad.xyz PLR_REGISTRY=evm:10143:0x…
```

(See `contracts/evm/README.md` for the exact `Deploy.s.sol` variables.) The writer checks once that the node reports
the configured chain id and that the contract's own `contractId()` equals its own, before it writes anything. Not
tested against a live Monad node here (no internet in the build environment): only anvil.

**Limits (tier B).** The RPC node is trusted like the NEAR RPC (no light-client proofs; https or loopback only).
A revocation takes effect for clients once the owner's transaction is included (immediately on anvil, after one ledger or slot on the
Stellar and Solana nodes). Revoking an operator (`revokeOperator`) also hides its instances from tier-B readers at once
(SPEC-CHAINS §1: records only from operators the owner currently approves). Expiry runs on chain time (block timestamp, ledger time,
Clock sysvar).

**Key squatting (tier B).** A key hash is public before its instance registers, and tier-B contracts cannot check
the quote signature. So any *approved* operator can register someone else's key hash first, with an unsigned quote
bound to itself. Clients never accept that record (the quote fails the evidence check), but the honest
registration is refused with `E_UNAUTHORIZED`. The first registrant keeps the key only while the owner approves it:
after `revokeOperator(squatter)`, another approved operator can take the key over as a fresh record (`next_seq` 0).
The honest instance's registration retries do this without help. Expiry alone never frees a key. On Solana the
writer passes the current holder's operator PDA as an optional sixth account so the program can check the
revocation. **Archived state (Stellar):** if a write's simulation needs archived entries restored (for example, an
allowlisted compose hash untouched for longer than its TTL), the writer first submits a `RestoreFootprint`
transaction (at most 2 per write).

---

## Local layout and ports

| what | where |
|---|---|
| llama-server / mock LLM | `127.0.0.1:18080` / `:18081` by SPEC; the mock host picks a free port by default |
| router | `127.0.0.1:18100` (dev-up), ephemeral in tests and the demo |
| VPN exit | `127.0.0.1:18200` (dev-up), ephemeral in tests and the demo |
| combo TD (router + exit) | `PLR_COMBO=1` dev-up: 18100 + 18200; ephemeral in tests and the demo (`PLR_COMBO_TEST_*` / `PLR_COMBO_*` in the demo env) |
| client proxy | `127.0.0.1:18787` |
| VPN exit #2 / two-hop entry | ephemeral (URLs in `.run/stack.env`: `PLR_VPN2_URL`, `PLR_VPN_ENTRY_URL`) |
| DoH resolver of the test builds | `127.0.0.1:18253` (`POST /dns-query`; measured in the test compose, so fixed; one stack per machine) |
| client SOCKS5 (`plr vpn`) | `127.0.0.1:18180` (the demo also uses 18181–18183: production exit, two-hop, two-hop to production) |
| near-sandbox RPC | `127.0.0.1:3030` (dev-up), ephemeral in tests and the demo; LLM registry `registry.<root>`, VPN registry `vpnregistry.<root>` |
| zebrad regtest RPC (`PLR_CHAIN=zcash`) | `127.0.0.1:18232` (dev-up, `PLR_RPC_PORT` overrides), ephemeral in tests and the demo; registries `zcash:regtest:<owner>` / `zcash:regtest:<vpn owner>` |
| anvil / Stellar quickstart / solana-test-validator RPC (`PLR_CHAIN=evm` / `stellar` / `solana`) | dev-up: `127.0.0.1:8545` / `localhost:8000/rpc` / `127.0.0.1:8899` (`PLR_RPC_PORT` overrides), ephemeral in tests; one node (Stellar: one Docker container `stellar-<name>`) per stack, two registries on it |
| run state | `.run/<id>/` (chain home under `near/` or `zcash/`), host sockets in `.run/<id>-host/` (or a short `plr-<hash>` dir in `.run`, or under the OS temp dir, when that path would exceed the 104-byte socket limit); removed on stop (`PLR_KEEP_RUN=1` keeps them). `.run` is `PLR_RUN_ROOT` if set, else `<repo>/.run`, else `<repo>/e2e/.run` when the repo root is not writable (e.g. a sandbox confined to the `e2e/` cwd) |

The harness and the dev stack run every long-lived process under a "lifeline" that leads its own process
group: stop = SIGTERM to the group, SIGKILL after 10 s; and if the controlling process dies in any way, the
lifeline's stdin pipe closes and the subtree is torn down. Nothing is left running.
