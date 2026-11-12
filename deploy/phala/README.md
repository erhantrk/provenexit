# deploy/phala

## `docker-compose.yml` — the measured exit config (SPEC-TDX §5.2)

The dstack app-compose measured into RTMR3 when the VPN exit runs in INTEL/dstack mode. Fill-ins are the real
public testnet values from `deploy/testnet/env.live`:

- `PLR_VPN_REGISTRY: vpnreg.pe-owner-erhan.testnet` (the keyless, reproducibly built registry; deploy tx `HLKDypfvxYKi55j5RnS7pxfwVbTrNNtRWgmTVhvZBg5L`)
- `PLR_OPERATOR_ID: pe-op-erhan.testnet`
- `PLR_OPERATOR_KEY: ${PLR_OPERATOR_KEY}` stays a reference: it is the only secret and is supplied sealed at deploy
  time (`phala deploy -e PLR_OPERATOR_KEY=…`), never written to a file in this repo.

- `PLR_VPN_ALLOWED_PORTS: "80,443"` and `PLR_VPN_MAX_TUNNELS: "32"`: the exit dials only web ports and serves at most 32
  tunnels at once. They are measured with the rest of the compose.

**Live since 2026-11-12.** This exact file runs on Phala Cloud (`tdx.small`, production OS `dstack-0.6.1`):

- exit URL: `https://d2c65be0bde4f9b7628ef399310823e9e6339251-18200.dstack-pha1-prod9.phala.network` (also in
  `deploy/testnet/env.live`)
- dstack compose hash `9411d0f7125c31e0d392a96d956bcc29c04ee801f0494a12be75ac68f081c85c`, allowed by the owner in tx
  `HeP6W5LMo9bnGAi9mTF4aoeEQSJrxJvdmcybE6cBRdFx`; OS measurement `821d442f…d323d` allowed in tx `61pQhJr3dbHZTmk9NVquB5yKu6xz18mLWRTD5iRYf722`
- registration (all 13 on-chain checks, 186.34 Tgas): tx `EZDveHx5571sdsm72MrbC7xayf4rhhpp8BTa6MFcUruN`
- (the same exit first registered on the retired registry `pe-vpnreg-erhan.testnet`, compose `6b56436b…`, tx `HSQqnRMu…`)

## The image (T13)

`ghcr.io/erhantrk/provenexit-exit@sha256:7e53f383a6ea8ea8e537ad35c1d11665ca07540f537fe3d0c656879a92e61ad5` (public,
`linux/amd64`). [`Dockerfile`](Dockerfile): `node:22-bookworm-slim` pinned by digest, plus the `vpn-honest` bundle and
its SPEC-VPN §2 policy. Any change to the image gives a new digest, so a new compose hash that the owner must approve
again (`allow_compose`).

That live image was built from an older tree, on the host, before the build was made reproducible. It cannot be
rebuilt bit for bit, so `scripts/verify-exit-image.sh` prints `MISMATCH` against it. This holds until the exit is
redeployed from an image built as described below.

## Reproduce the exit image

```sh
git clone <this repo> && cd provenexit        # a full clone, not --depth 1
scripts/verify-exit-image.sh                  # rebuilds, compares with the digest in docker-compose.yml: MATCH / MISMATCH
scripts/verify-exit-image.sh --print-digest   # rebuilds, prints only sha256:<64 hex>
scripts/build-exit-image.sh                   # the same build; pushes only with PUSH=1, and never from a dirty tree
```

Needs git and Docker with buildx, nothing else: no node or npm on the host. The builder must be able to write an OCI
archive (Docker Desktop, the containerd image store, or a `docker-container` builder passed as `BUILDER=<name>`).
Nothing is pushed or loaded. Exit codes of `verify-exit-image.sh`: 0 `MATCH`, 1 `MISMATCH`, 2 could not build.

What is pinned (all of it in [`Dockerfile`](Dockerfile), [`Dockerfile.dockerignore`](Dockerfile.dockerignore) and
`scripts/exit-image-common.sh`):

- **Base and build tools.** Both stages start from `node:22-bookworm-slim@sha256:e9f565d3…`. The bundle and the policy
  are built inside it: `npm ci --ignore-scripts` from `package-lock.json`, `tsc`, then `enclave/build.mjs
  --node-exe-only`. The final image is the base plus `/app/vpn.bundle.mjs`, `/app/vpn-policy.json` and the `CMD`.
- **Inputs.** The build context is the repo root filtered by `Dockerfile.dockerignore`: the root `package.json`,
  `package-lock.json`, `tsconfig.base.json`, `packages/shared`, `enclave` (both without their tests) and the
  `package.json` of the other workspaces (`npm ci` needs them). Nothing else in the repo can change the image.
- **Timestamps.** `SOURCE_DATE_EPOCH` with `rewrite-timestamp=true`. The epoch is the commit time of the last commit
  that changed one of the inputs above (or the Dockerfile). At that commit it is the commit time of `HEAD`; later
  commits that only touch docs or pin the new digest in `docker-compose.yml` keep it, so the pinned digest can be
  checked from the commit that pins it. This needs the git history, hence the full clone.
- **Manifest.** `linux/amd64` only, `--provenance=false --sbom=false`, OCI media types and gzip layers for both the
  local build and the push. `PUSH=1 scripts/build-exit-image.sh` builds locally first, pushes, and fails if the
  registry digest differs from the local one.

Not pinned: the BuildKit version of the builder, and the npm registry has to serve the tarballs the lockfile names
(their integrity hashes are checked). In the policy file, `vpn.node_sha256` is the manifest digest of the node
executable alone (`--node-exe-only`): the closure walk of the mock host reads Mach-O and does not run on Linux. Nothing
checks that field in dstack mode; node is pinned by the base image digest.

What a `MATCH` proves: the image the compose pins, which is the image dstack pulls by digest and whose compose hash
the registry allows, is byte for byte what this checkout builds. What it does not prove: that the source is honest.
It moves the question from "what is in that image" to "what does this source do", and the source still has to be
read. It also says nothing about the base image beyond its digest, or about the npm packages beyond the lockfile.

Status of this section (2026-11-12): measured before this Dockerfile existed, with the older single-stage one: two
`--no-cache` builds with `SOURCE_DATE_EPOCH` and `rewrite-timestamp=true` gave the same digest, and without them
different ones. Run for the current tree, outside Docker: the build-stage commands in two fresh clones gave the same
bundle (`c472440f…`) and policy bytes, and the scripts' logic is tested against a fake `docker`
(`enclave/test/exit-image-scripts.test.ts`). **Not run yet:** the multi-stage build itself, the two-clone digest
comparison through Docker, and a push (local digest = registry digest is checked by the script at push time).

## Deploy

```sh
# the operator key is the only secret: an env file, encrypted by phala to the CVM, never committed
phala deploy -n provenexit-exit -c deploy/phala/docker-compose.yml -t tdx.small --image dstack-0.6.1 --no-dev-os \
  -e <env file with PLR_OPERATOR_KEY=ed25519:…> --no-public-logs
node client/dist/cli.js vpn inspect   # with PLR_VPN_URL etc. from deploy/testnet/env.live: compose hash + OS measurement
scripts/owner.sh allow_compose '{"hash":"<compose hash>"}'   # the exit retries registration with backoff (≤ 5 min)
```

Use a production OS image (`phala os-images`, DEV `no`): the dev images allow SSH into the CVM.

Policy check (SPEC-TDX §1.4: every image pinned by digest and not built, no `privileged`, service `exit` with
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
