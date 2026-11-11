# deploy/phala

## `docker-compose.yml` — the measured exit config (INTERFACES §5.2)

The dstack app-compose measured into RTMR3 when the VPN exit runs in INTEL/dstack mode. Fill-ins are the real
public testnet values from `deploy/testnet/env.live`:

- `PLR_VPN_REGISTRY: pe-vpnreg-erhan.testnet` (T16 deploy, tx `FyRSR12vo3KXEwmH8DN7DJQ78SFFHcXoYKeRREUCUWj`)
- `PLR_OPERATOR_ID: pe-op-erhan.testnet`
- `PLR_OPERATOR_KEY: ${PLR_OPERATOR_KEY}` stays a reference: it is the only secret and is supplied sealed at deploy
  time (`phala deploy -e PLR_OPERATOR_KEY=…`), never written to a file in this repo.

**Under S1-F2 (maintainer decision 2026-11-11) the VPN exit is never deployed to Phala Cloud.** The demo exit runs on
the mock root on the local machine; real TDX is shown by the spike fixture (`fixtures/phala-spike/`). This file is
kept as the exact measured configuration that a paid deploy would use, and so that the compose policy check runs
against a real file.

**The image digest is a documented placeholder.** There is no `Dockerfile` here either: building and pushing the
exit image is T13, which S1-F2 skips, so no image was built or published and there is nothing real to pin.
The digest in the `image:` line is the SHA-256 of this exact text:

```
provenexit-exit: S1-F2 placeholder image digest; T13 (docker build/push) was skipped, so this digest references no published image (see deploy/phala/README.md)
```

Recompute it with:

```sh
printf '%s' 'provenexit-exit: S1-F2 placeholder image digest; T13 (docker build/push) was skipped, so this digest references no published image (see deploy/phala/README.md)' | shasum -a 256
# 5e8c74ff72b68b80fef52e219fb94c56d4e02a65d5a00c12cd302674d7167ce3
```

`docker pull ghcr.io/erhantrk/provenexit-exit@sha256:5e8c74ff…` therefore fails. Before any real deploy: build
and push the image (T13), put the returned digest here, and re-approve the compose hash on chain
(`scripts/owner.sh allow_compose`) — any edit to this file is a different measured compose.

Policy check (INTERFACES §1.4: every image pinned by digest and not built, no `privileged`, service `exit` with
`logging.driver: none`):

```sh
node --input-type=module -e "import fs from 'node:fs'; const {checkDstackComposePolicy}=await import('./packages/shared/dist/index.js'); console.log(checkDstackComposePolicy(JSON.stringify({runner:'docker-compose',docker_compose_file:fs.readFileSync('deploy/phala/docker-compose.yml','utf8')})))"
# { images: [ 'ghcr.io/erhantrk/provenexit-exit@sha256:5e8c74ff…' ] }
```

(`node -e` without `--input-type=module` hits Node 22's `ERR_AMBIGUOUS_MODULE_SYNTAX` because the one-liner mixes
`require` with top-level `await`; the plan's fallback uses `--input-type=module`, which requires `import fs` instead
of `require("fs")`.)

## `spike/docker-compose.yml` — test-only quote dump, never a VPN exit

A byte-identical copy of the Day-0 spike compose (1 443 bytes, SHA-256
`809fdc24371eb06d06bd6b3d8015b158db6558123eaa2c628d41f1d9b3108c46`; also at `spike/docker-compose.s1.yml` and in
the plan). It runs `node:22-bookworm-slim` with a few lines of inline JS that answer `GET /dump` with the TDX quote,
the IMR3 event log and the CVM info read from `/var/run/dstack.sock`.

It is **not** a proxy, not a VPN and not the exit: it copies no traffic and opens no tunnel. It exists only because
the 2026-11-09 spike CVM produced the real-TDX evidence in `fixtures/phala-spike/phala-dump.json`, which backs the
demo's "same attestation code path, real Intel quote" claim (S1-F2). Its image is deliberately unpinned and it has
no `exit` service, so `checkDstackComposePolicy` rejects it — correctly, it must never be approved as an exit
compose on chain.

**Known exception (disclosed):** that compose hash (`b9823a79…d05f`) *is* allowlisted on the INTEL testnet registry,
only so checks 1–12 could be shown on the real quote (README "NEAR's role"). The client still refuses it with
`E_COMPOSE_POLICY`, but the registry would accept a registration under it. Revoke it
(`scripts/owner.sh revoke_compose '{"hash":"b9823a79…d05f"}'`, full hash from `fixtures/phala-spike`) after the demo
video is recorded; this has not been done.

## `scripts/owner.sh`

Owner calls against the registry, signed by `OWNER_ID` from `deploy/testnet/env.live`:

```sh
scripts/owner.sh approve_operator '{"account_id":"pe-op-erhan.testnet","org_id":"erhan-demo"}'
scripts/owner.sh allow_compose    '{"hash":"<compose hash from plr vpn inspect>"}'
scripts/owner.sh allow_os         '{"hash":"<OS measurement from plr vpn inspect>"}'
scripts/owner.sh revoke_compose   '{"hash":"<compose hash>"}'
```
