# deploy/phala

## `docker-compose.yml` — the measured exit config (INTERFACES §5.2)

The dstack app-compose measured into RTMR3 when the VPN exit runs in INTEL/dstack mode. Fill-ins are the real
public testnet values from `deploy/testnet/env.live`:

- `PLR_VPN_REGISTRY: pe-vpnreg-erhan.testnet` (T16 deploy, tx `FyRSR12vo3KXEwmH8DN7DJQ78SFFHcXoYKeRREUCUWj`)
- `PLR_OPERATOR_ID: pe-op-erhan.testnet`
- `PLR_OPERATOR_KEY: ${PLR_OPERATOR_KEY}` stays a reference: it is the only secret and is supplied sealed at deploy
  time (`phala deploy -e PLR_OPERATOR_KEY=…`), never written to a file in this repo.

- `PLR_VPN_ALLOWED_PORTS: "80,443"` and `PLR_VPN_MAX_TUNNELS: "32"`: the exit dials only web ports and serves at most 32
  tunnels at once. They are measured with the rest of the compose.

**Live since 2026-11-12.** This exact file runs on Phala Cloud (`tdx.small`, production OS `dstack-0.6.1`):

- exit URL: `https://d2c65be0bde4f9b7628ef399310823e9e6339251-18200.dstack-pha1-prod9.phala.network` (also in
  `deploy/testnet/env.live`)
- dstack compose hash `6b56436b06a60c2739c0718f198812b5727f98b72467c0335f72b5e01277e2c0`, allowed by the owner in tx
  `8fU3ScGVptLev9qdGbBsW72kJDcye9CzKTLpQzaKh8dm`; OS measurement `821d442f…d323d` (already allowed)
- registration (all 13 on-chain checks): tx `HSQqnRMupfLQeSi47h4dHv2K47WmDMBkT4CpuZuDpZR8`

## The image (T13)

`ghcr.io/erhantrk/provenexit-exit@sha256:7e53f383a6ea8ea8e537ad35c1d11665ca07540f537fe3d0c656879a92e61ad5` (public,
`linux/amd64`). [`Dockerfile`](Dockerfile): `node:22-bookworm-slim` pinned by digest, plus the `vpn-honest` bundle and
its SPEC-VPN §2 policy. Build and push with `scripts/build-exit-image.sh` (`IMAGE=…` to change the registry). Any
change to the image gives a new digest, so a new compose hash that the owner must approve again (`allow_compose`).
The build is not reproducible yet: no build provenance is published.

## Deploy

```sh
# the operator key is the only secret: an env file, encrypted by phala to the CVM, never committed
phala deploy -n provenexit-exit -c deploy/phala/docker-compose.yml -t tdx.small --image dstack-0.6.1 --no-dev-os \
  -e <env file with PLR_OPERATOR_KEY=ed25519:…> --no-public-logs
node client/dist/cli.js vpn inspect   # with PLR_VPN_URL etc. from deploy/testnet/env.live: compose hash + OS measurement
scripts/owner.sh allow_compose '{"hash":"<compose hash>"}'   # the exit retries registration with backoff (≤ 5 min)
```

Use a production OS image (`phala os-images`, DEV `no`): the dev images allow SSH into the CVM.

Policy check (INTERFACES §1.4: every image pinned by digest and not built, no `privileged`, service `exit` with
`logging.driver: none`):

```sh
node --input-type=module -e "import fs from 'node:fs'; const {checkDstackComposePolicy}=await import('./packages/shared/dist/index.js'); console.log(checkDstackComposePolicy(JSON.stringify({runner:'docker-compose',docker_compose_file:fs.readFileSync('deploy/phala/docker-compose.yml','utf8')})))"
# { images: [ 'ghcr.io/erhantrk/provenexit-exit@sha256:7e53f383…' ] }
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
