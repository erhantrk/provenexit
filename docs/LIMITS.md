# Limits

What ProvenExit does not do yet, and what it trusts. Closed limits are listed at the end with what closed them.

## Testnet only

The registry is on NEAR **testnet** (`vpnreg.pe-owner-erhan.testnet`); nothing runs on mainnet. There is one live
exit, a `tdx.small` CVM on Phala Cloud running the production OS `dstack-0.6.1` (not the SSH-enabled dev OS). It is
paid by the hour and may be stopped outside judging. When it is down, `npx provenexit verify` refuses (the exit is
unreachable); the offline replay of [`fixtures/live-exit`](../fixtures/live-exit) still works.

## Proxy mode only

Only what you send through the local SOCKS5 proxy goes through the exit: TCP only, no UDP (so no QUIC, no WebRTC
media), no system-wide tunnel. Use `socks5h://` (or "proxy DNS" in a browser) so names are not resolved locally. For
AI agents on the MCP server, only `fetch_via_exit` uses the exit. The client connects to the exit directly and does
not use `HTTP_PROXY` / `HTTPS_PROXY`.

## Usual VPN and TEE caveats

These hold for any VPN exit, or any app on Intel TDX, and ProvenExit does not change them.

- The exit sees the hosts and ports you connect to. ProvenExit proves the approved code does not keep them.
- The network around the exit (Phala's host and its gateway) sees destination IPs, timing and sizes, the TLS server
  name and plain HTTP. Use HTTPS; [two hops](HOW-IT-WORKS.md#two-hop) keep your IP from the exit's operator.
- Phala's gateway terminates the outer TLS. The tunnel inside is encrypted end to end to the attested key, so the
  gateway sees only ciphertext; it can refuse to serve.
- Intel, the TDX module and Phala's dstack OS image are trusted roots. The allowlisted OS measurement `821d442f…323d`
  is the one Phala's `dstack-0.6.1` image produced, read from the exit's quote. Side channels are not defended. The
  client fetches Intel's revocation data itself, so an Intel revocation reaches it when Intel publishes it.
- A matching image digest shows the image is exactly what this source builds; whether the source does what it says
  is for the reader to check.

## Closed limits

- **One owner key decided the allowlist.** Closed on 2026-11-13: the single owner `pe-owner-erhan.testnet` named the
  council DAO as owner ([`BLaRVAn1…`](https://testnet.nearblocks.io/txns/BLaRVAn19UAjboeJEJQ9Xqc5nN7f2Yn1N9AeqYV1ao3K)), and the DAO accepted after two approvals ([`HzsVd6XC…`](https://testnet.nearblocks.io/txns/HzsVd6XCWaB3JCxKfhktTAvP7htxKtNESsqczxHfPgsq)). The old key is no
  longer the owner. Details and every transaction: [deploy/testnet/MULTISIG-OWNER.md](../deploy/testnet/MULTISIG-OWNER.md).
- **Revocation was not shown on the live exit.** Closed on 2026-11-13: with [`scripts/demo-live.sh`](../scripts/demo-live.sh)
  against the live exit, the owner revoked the running compose `2f4100e6…dabf` ([`2JJdbyoG…`](https://testnet.nearblocks.io/txns/2JJdbyoGGr5GewNMDd9aeGrDSDjQ33xDoAWWovR8s1u2)); the very next
  connection through the open proxy was refused and `vpn verify` refused with `E_COMPOSE_NOT_ALLOWED`. The owner
  re-allowed it ([`tdQDjQkF…`](https://testnet.nearblocks.io/txns/tdQDjQkF6ZBVcsxuebHwuvykLEDJ9CvuuVSkicY57LW)) and the next connection went through again. See [VERIFY.md](VERIFY.md#the-on-chain-record).
- **Registry code could be swapped.** Closed: the registry `vpnreg.pe-owner-erhan.testnet` has no access keys, so
  nobody can deploy different code under its name, and its code is a reproducible build of this repo (code hash
  `C1hvenbrzHKN1n1f2z63Duburr8YXLAKBescrEvarCGM`). The client pins that code hash: before it uses any registry answer
  it reads `view_account.code_hash`, compares it with the pin (`PLR_VPN_REGISTRY_CODE_HASH`, shipped for the live
  registry) and refuses with `E_REGISTRY_CODE_HASH` on a difference; this is the first of the 20 checks. A passed
  check is reused for 30 seconds. Any other registry needs its own pin with the Intel root; only the local MOCK demo
  runs without one (it prints a warning). The hash comes from the same RPC providers as the views, cross-checked the same way
  (above). The first registry, `pe-vpnreg-erhan.testnet`, still has a full-access key and a non-reproducible build;
  it is retired and the client does not use it.
- **The exit's copy of Intel collateral was trusted.** Closed: the client fetches fresh collateral itself by default
  (an Intel revocation still reaches it only when Intel publishes it).
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
