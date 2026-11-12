# Limits

What ProvenExit does not prove, what it trusts, and what has only been shown in part. Each section says what the
limit is, why it exists, and what you can do about it. Closed limits are listed at the end with what closed them.

## Testnet only

The registry is on NEAR **testnet** (`vpnreg.pe-owner-erhan.testnet`); nothing runs on mainnet. There is one live
exit, a `tdx.small` CVM on Phala Cloud running the production OS `dstack-0.6.1` (not the SSH-enabled dev OS). It is
paid by the hour: it runs through judging and may be stopped afterwards. When it is down, `npx provenexit verify`
refuses (the exit is unreachable), and the offline replay of [`fixtures/live-exit`](../fixtures/live-exit) still
works (see [The fixture replay proves the past](#the-fixture-replay-proves-the-past)).

## The exit sees your destinations

Any VPN exit must know the host and port it connects to and relays the bytes. ProvenExit proves the approved code
does not *keep* them (no destination, DNS name, IP, port or payload in logs, receipts or on-chain data), not that it
never sees them.

## "No logs" covers the attested code, not the operator's network

DNS is not exposed: the exit resolves names over DNS-over-HTTPS only, so the exit's host and ISP see only TLS to the
resolver's IP, and the resolver sees the names the exit asks for, never your IP (only the exit's).

The exit still dials destinations over a network card the host controls. So the operator, not only the exit's ISP,
can watch the upstream leg without touching the measured code: destination IP and port, timing, the TLS SNI, and
every byte of plain-HTTP traffic. ProvenExit proves the approved exit code retains nothing; it does not stop the
operator's host from watching the exit's own traffic to destinations. Use HTTPS (ideally with ECH) for anything
sensitive, and two hops (see [HOW-IT-WORKS.md](HOW-IT-WORKS.md#two-hop)) so that operator does not also know who
you are.

## TLS is still needed for content

For `https://` the exit relays TLS ciphertext. For plain `http://` the exit code processes the plaintext (it never
stores it). The destination sees the exit's IP.

## Metadata: timing and sizes

Timing and sizes of tunnelled traffic are visible to the operator and the network. Tunnel data is not padded and
there is no cover traffic; only the CONNECT / CONNECT_ERR payloads have fixed sizes. With one hop, your own IP is
visible to the exit operator's network.

## Proxy mode only

Only what you send through the local SOCKS5 proxy is protected: TCP CONNECT only, no UDP (so no QUIC, no WebRTC
media), no system-wide tunnel. Use `socks5h://` (or "proxy DNS" in a browser) so names are not resolved locally.

The same holds for AI agents using the MCP server: only what goes through `fetch_via_exit` uses the exit. The agent's
other traffic (its model API calls, its other tools, any command it runs) does not.

## Direct connection only

The client opens its own TLS connections to the exit and does not use `HTTP_PROXY` /
`HTTPS_PROXY`. On a network that only lets traffic out through an HTTP(S) proxy, `vpn verify` and
`scripts/try-live.sh` stop at the first exit check with `E_BAD_RESPONSE` (exit unreachable) although the exit is up.
The offline replay (`vpn verify --fixture fixtures/live-exit`) needs no network.

## The local demo stack uses a MOCK root

The full local demo (`scripts/demo.sh`, with revocation, two hops and attacker exits) runs on a **MOCK root, not
Intel**. Its quote is signed by a locally generated test root through a per-boot attestation key, and the "TD" is a
Node process supervised by a mock TDX host. The byte layouts, hashes, event log and verification logic are the real
TDX/dstack ones, but a MOCK root attests nothing about hardware: whoever holds the mock root secret can forge quotes.
The CLI says so on every verify (`MOCK ROOT (local test root, NOT Intel)`).

Mock-host limits, which real TDX removes: the quote socket is a 0600 Unix socket of the operator's uid (any same-uid
process can obtain a genuine quote for any `report_data`), the root secret is a 0600 file of the same uid, and the TD
is a set of same-uid processes.

## What has been shown about revocation

A client refusing the next connection right after an owner revocation is shown on the local demo stack (MOCK root):
`E_COMPOSE_NOT_ALLOWED`, then restored by re-approval. On testnet, owner revoke and re-allow transactions ran on the
first, now retired, registry against a test compose. On the live registry the owner revoked the previous exit
compose `9411d0f7…` after the redeploy (tx `9HhvupZA…`); no exit ran that compose any more, so no client refusal
was observed for it. [`scripts/demo-live.sh`](../scripts/demo-live.sh) drives verify → browse → owner revoke →
refusal → re-allow against the live exit; the two owner transactions are signed by the owner, not by the script.

## Collateral freshness

The client fetches Intel's collateral (PCK CRL, TCB info, QE identity) itself, by default from Intel's PCS
(`https://api.trustedservices.intel.com`; `PLR_PCCS_URL` names another PCCS), and refuses the exit with
`E_COLLATERAL_FETCH` when it cannot. It never falls back to the exit's copy. The window that remains is the CRL's own
update interval: a TCB or key revocation by Intel reaches the client only when Intel publishes it.

Two modes skip the fresh fetch, and both say so in `vpn verify`: `PLR_PCCS_URL=exit` (opt out: use the collateral the
exit serves, which can be stale yet unexpired) and the offline fixture replay (uses the recorded collateral, shown as
the one `·` line).

## The OS measurement was observed, not reproduced

The allowlisted OS measurement `821d442f07d638c696f4c5e1e4962bf4e28515ba5d790f5cf502b1c0d4dd323d` is
`SHA256(mr_td ‖ rtmr0 ‖ rtmr1 ‖ rtmr2)` of the dstack OS image that booted, read from the quote. It has not been
re-derived from Phala's `dstack-0.6.1` release with `dstack-mr`. The owner approved the value they saw, not one
computed from source.

## What a matching image digest proves

`scripts/verify-exit-image.sh` rebuilds the exit image from the checkout and compares it with the digest
`deploy/phala/docker-compose.yml` pins, which is the image dstack pulls and whose compose hash the registry allows.
`MATCH` says the image is byte for byte what this source builds. It does not say the source is honest: that question
moves from "what is in that image" to "what does this source do", and the source still has to be read. It also says
nothing about the base image beyond its digest, or about the npm packages beyond the lockfile's integrity hashes.

Not pinned: the Docker client and buildx version, the host CPU (on an arm64 host the `linux/amd64` steps run under
emulation), and the npm registry has to keep serving the tarballs the lockfile names.

The image the exit ran before 2026-11-12 20:05 UTC (`sha256:7e53f383…`) was built on the host before the build was
made reproducible; it cannot be rebuilt bit for bit. Details: [`deploy/phala/README.md`](../deploy/phala/README.md#reproduce-the-exit-image).

## One owner key decides the allowlist

`pe-owner-erhan.testnet` is one NEAR account: whoever holds its key can allow or revoke builds, OS measurements and
operators. The client pins the Intel root, the registry contract id and its code hash, not the owner. A multisig or a
DAO as owner is future work (the contract has `propose_owner` / `accept_owner`).

## The registry RPC endpoint is trusted

NEAR view results carry no state proofs, so whoever answers the client's `get_root` / `is_*_allowed` /
`get_instance` calls, and the `view_account` call behind the code-hash pin, decides those checks. The client
therefore talks to the registry only over `https:`, or plain `http:` to a loopback address; a remote
`PLR_NEAR_RPC=http://…` is refused. Pick an RPC provider you trust (the defaults use
`https://rpc.testnet.fastnear.com`). A quorum of independent RPCs or light-client proofs is future work.

## Phala's gateway terminates TLS

In a cloud deployment, HTTPS to the exit ends at Phala's dstack-gateway
(`https://<app-id>-18200.<gateway-domain>`), which then speaks to the container. The tunnel inside is end-to-end
encrypted to the attested key, so the gateway sees only ciphertext, cannot impersonate the exit (its key is inside
the signed quote) and cannot read or forge tunnel content. It can still observe connection timing and volume, and it
is a liveness dependency: it can always refuse to serve. The live exit runs behind it.

## The fixture replay proves the past

`vpn verify --fixture fixtures/live-exit` runs the DCAP check at the capture time (2026-11-12 20:13 UTC) on the
recorded collateral and reads a recorded registry snapshot. It proves the recorded exit was genuine and registered at
capture time, not that it is now; for that, run `npx provenexit verify` against the live exit.

## TEE vendor trust and side channels

Intel, the TDX module and the dstack OS image are trusted roots. Micro-architectural side channels are not defended.

## Closed limits

- **Registry code could be swapped.** Closed: the registry `vpnreg.pe-owner-erhan.testnet` has no access keys, so
  nobody can deploy different code under its name, and its code is a reproducible build of this repo (code hash
  `C1hvenbrzHKN1n1f2z63Duburr8YXLAKBescrEvarCGM`). The client pins that code hash: before it uses any registry answer
  it reads `view_account.code_hash`, compares it with the pin (`PLR_VPN_REGISTRY_CODE_HASH`, shipped for the live
  registry) and refuses with `E_REGISTRY_CODE_HASH` on a difference; this is the first of the 20 checks. A passed
  check is reused for 30 seconds. Any other registry needs its own pin with the Intel root; only the local MOCK demo
  runs without one (it prints a warning). The hash comes from the same RPC as the views, so the RPC stays trusted
  (above). The first registry, `pe-vpnreg-erhan.testnet`, still has a full-access key and a non-reproducible build;
  it is retired and the client does not use it.
- **The exit's copy of Intel collateral was trusted.** Closed: the client fetches fresh collateral itself by default
  (see [Collateral freshness](#collateral-freshness) for what remains).
- **The image rebuild was shown on one machine only.** Closed: besides two fresh clones on the owner's machine, the
  "verify exit image" GitHub Actions workflow rebuilds the image on a GitHub-hosted `ubuntu` `linux/amd64` runner on
  every push to `main` and prints `MATCH` (for example run
  [43319605400](https://github.com/erhantrk/provenexit/actions/runs/43319605400) on commit `47d9794`, 2026-11-12:
  built `sha256:74c6d1c5…2785` with BuildKit v0.34.2).
- **A test compose was allowlisted.** Closed: the 2026-11-09 spike compose `b9823a79…d05f` (a quote dump, never an
  exit; the client refuses it with `E_COMPOSE_POLICY`) was allowed on the first registry only to show the on-chain
  checks 1–12 on a real quote. It was revoked there on 2026-11-12
  ([tx `3DmY4Rqr…`](https://testnet.nearblocks.io/txns/3DmY4RqrDAVknLov5pDYMgAQvjmMpM354eeGZdWifh7n)) and was never
  allowed on the live registry, which allows only the live exit's compose.
