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

**Live since 2026-11-12; this exact file since 2026-11-12 20:05 UTC.** It runs on Phala Cloud (`tdx.small`,
production OS `dstack-0.6.1`), CVM `d2c65be0bde4f9b7628ef399310823e9e6339251`:

- exit URL: `https://d2c65be0bde4f9b7628ef399310823e9e6339251-18200.dstack-pha1-prod9.phala.network` (also in
  `deploy/testnet/env.live`)
- dstack compose hash `2f4100e62c7794139867276f8bc9fa525bc85808380501e3975bfac3fd08dabf`, allowed by the owner in tx
  `GdY61VR2ZBFR9SpgwVCmb7e6AN7Mx5PRt59XmKio9HhD` (20:05:57 UTC); OS measurement `821d442f…d323d`, unchanged, allowed
  earlier in tx `61pQhJr3dbHZTmk9NVquB5yKu6xz18mLWRTD5iRYf722`
- registration (all 13 on-chain checks, 186.76 Tgas): tx `6yBT47ijg4AgqpYGUk6dUw9tdD3kRFw4iScL7aaSBCp` (20:06:19 UTC),
  key hash `9f7434d4a895d3256efb6cd15216f04e2e2c7fcdfee9fa4b28e38d85b15bba8f`, TCB `UpToDate`

Earlier, on the same CVM (same app id and URL):

- 2026-11-12 until 20:05 UTC: image `sha256:7e53f383…1ad5` (not reproducible), compose hash
  `9411d0f7125c31e0d392a96d956bcc29c04ee801f0494a12be75ac68f081c85c`, allowed in tx
  `HeP6W5LMo9bnGAi9mTF4aoeEQSJrxJvdmcybE6cBRdFx`, registration (13 checks, 186.34 Tgas) tx
  `EZDveHx5571sdsm72MrbC7xayf4rhhpp8BTa6MFcUruN`. The owner revoked that compose after the redeploy: tx
  `9HhvupZAQWnrdFtXDMUuA4w6sVYfzHPF8Mtk4VXuhNVx` (20:06:50 UTC).
- before that, the same image first registered on the retired registry `pe-vpnreg-erhan.testnet`, compose
  `6b56436b…`, tx `HSQqnRMu…`.

## The image (T13)

`ghcr.io/erhantrk/provenexit-exit@sha256:74c6d1c52e2ce72698fb238e52e27d03eefe1770af00a1dae3405d3474f22785` (public,
`linux/amd64`, an OCI image manifest). [`Dockerfile`](Dockerfile): `node:22-bookworm-slim` pinned by digest, plus the
`vpn-honest` bundle and its SPEC-VPN §2 policy. Any change to the image gives a new digest, so a new compose hash that
the owner must approve again (`allow_compose`).

It was built from commit `6740b3f` as described below and pushed with `PUSH=1 scripts/build-exit-image.sh`. The
digest above is the **manifest** digest: it is what the compose pins, what dstack pulls and what
`verify-exit-image.sh` compares. The tag `ghcr.io/erhantrk/provenexit-exit:6740b3f` does not resolve to that digest
directly: `docker buildx imagetools create` stored it as an OCI image index,
`sha256:05a7b52ebaa33e194442555a57816810da497457fd46e7101a5fcc46eedc6518`, whose only entry is that manifest
(`linux/amd64`). Pulling by the tag gives the same image; the digest to compare is the manifest's. At the time of
that push the script's last line said "tag = manifest digest", which was inaccurate; it now reads the tag back raw
and prints both digests.

The image before it, `sha256:7e53f383a6ea8ea8e537ad35c1d11665ca07540f537fe3d0c656879a92e61ad5` (live until
2026-11-12 20:05 UTC), was built from an older tree, on the host, before the build was made reproducible. It cannot
be rebuilt bit for bit.

## Reproduce the exit image

```sh
git clone <this repo> && cd provenexit        # --depth 1 is enough
scripts/verify-exit-image.sh                  # rebuilds, compares with the digest in docker-compose.yml: MATCH / MISMATCH
scripts/verify-exit-image.sh --print-digest   # rebuilds, prints only sha256:<64 hex>
scripts/build-exit-image.sh                   # the same build; pushes only with PUSH=1, and never from a dirty tree
```

Needs git and Docker with buildx, nothing else: no node or npm on the host. On the first run the scripts create a
buildx builder (`docker-container` driver) that runs the pinned BuildKit image, which Docker pulls from Docker Hub;
your current builder is not changed. Nothing is pushed or loaded. Exit codes of `verify-exit-image.sh`: 0 `MATCH`,
1 `MISMATCH`, 2 could not build. The scripts print the builder and the BuildKit version it reports next to the digest.

What is pinned (all of it in [`Dockerfile`](Dockerfile), [`Dockerfile.dockerignore`](Dockerfile.dockerignore) and
`scripts/exit-image-common.sh`):

- **Base and build tools.** Both stages start from `node:22-bookworm-slim@sha256:e9f565d3…`. The bundle and the policy
  are built inside it: `npm ci --ignore-scripts` from `package-lock.json`, `tsc`, then `enclave/build.mjs
  --node-exe-only`. The final image is the base plus `/app/vpn.bundle.mjs`, `/app/vpn-policy.json` and the `CMD`.
- **Inputs.** The build context is the repo root filtered by `Dockerfile.dockerignore`: the root `package.json`,
  `package-lock.json`, `tsconfig.base.json`, `packages/shared`, `enclave` (both without their tests) and the
  `package.json` of the other workspaces (`npm ci` needs them). No other file of the repo enters the build context.
  The image also depends on the build options and the builder, which `scripts/exit-image-common.sh` fixes (next
  three points): a change there can change the digest too.
- **Timestamps.** `SOURCE_DATE_EPOCH=1767225600` (2026-01-01T00:00:00Z, a constant in `exit-image-common.sh`) with
  `rewrite-timestamp=true`. The epoch does not come from the clock or from git, so the digest depends on the content
  of the checkout only: a rebase, a squash-merge, or a commit that touches only docs or pins the new digest in
  `docker-compose.yml` keeps it, and a shallow clone can verify.
- **Builder.** BuildKit writes the layers and the manifest, so its release is part of the result. The scripts build
  with their own builder `provenexit-exit-buildkit-v0.34.2-c5f8862f5249`, which runs
  `moby/buildkit:v0.34.2@sha256:c5f8862f52499773af85bc07695b2379ef08e8002352b0df2c4864c91d78dabe` (the multi-arch
  index digest on Docker Hub), and refuse to build if that builder reports another BuildKit version.
  `BUILDER=<name>` uses a builder of your choice instead; the scripts then warn that the digest can differ for that
  reason alone. No `# syntax=` line: the Dockerfile frontend is the one built into that BuildKit.
- **Manifest.** `linux/amd64` only, `--provenance=false --sbom=false`, OCI media types and gzip layers for both the
  local build and the push. `PUSH=1 scripts/build-exit-image.sh` builds locally first, then runs the same build with
  a registry output that uploads by digest without a tag (`push-by-digest=true`). Only if the registry digest equals
  the local one does it add the tag (`docker buildx imagetools create`) and read it back. On a difference it fails
  and no tag exists; the untagged manifest stays in the registry. The tag may be stored as an image index that wraps
  the manifest (it was, for the live image): the script accepts the manifest itself or an index that lists only it,
  prints the tag's digest and the manifest digest, and refuses anything else.

Not pinned: the Docker client and buildx version (they pass the options to the pinned BuildKit), the host CPU (on an
arm64 host the `linux/amd64` build steps run under emulation), and the npm registry has to serve the tarballs the
lockfile names (their integrity hashes are checked). In the policy file, `vpn.node_sha256` is the manifest digest of
the node executable alone (`--node-exe-only`): the closure walk of the mock host reads Mach-O and does not run on
Linux. Nothing checks that field in dstack mode; node is pinned by the base image digest.

What a `MATCH` proves: the image the compose pins, which is the image dstack pulls by digest and whose compose hash
the registry allows, is byte for byte what this checkout builds. What it does not prove: that the source is honest.
It moves the question from "what is in that image" to "what does this source do", and the source still has to be
read. It also says nothing about the base image beyond its digest, or about the npm packages beyond the lockfile.

Status of this section (2026-11-12, after the redeploy). Run with the scripts as they are at `6740b3f` (constant
epoch, pinned BuildKit v0.34.2 builder), all on one machine:

- the image was built by hand in two fresh clones: the same digest both times, `sha256:74c6d1c5…2785`;
- `PUSH=1 scripts/build-exit-image.sh` pushed it (by-digest upload, tag, read-back). The registry serves exactly that
  manifest (OCI, `linux/amd64`) and an anonymous pull works. The tag is an index that wraps it (see "The image");
- `scripts/verify-exit-image.sh` printed `MATCH` against a compose that pins this digest;
- the Phala CVM was updated to this compose (`phala deploy --cvm-id … --no-public-logs`), the owner allowed the new
  compose hash, the exit registered (13 checks) and `vpn verify` against it printed `VERIFIED`, before and after the
  old compose was revoked.

The scripts' logic is tested against a fake `docker` (`enclave/test/exit-image-scripts.test.ts`). **Not run:** a
build on a second machine, and the changed tag read-back of `build-exit-image.sh` (index digest and manifest digest)
against a real registry: it is covered by the fake-`docker` test and was checked by hand against the raw index the
registry serves for the `6740b3f` tag, but no push was made with it.

Earlier measurements, kept for the record: with the older single-stage Dockerfile, two `--no-cache` builds with
`SOURCE_DATE_EPOCH` and `rewrite-timestamp=true` gave the same digest, and without them different ones. With the
multi-stage Dockerfile, Docker Desktop's built-in builder and the commit-time epoch the scripts used before,
`verify-exit-image.sh --print-digest` in two fresh clones printed the same digest (`sha256:db6bc56d…`).

## Deploy

```sh
# the operator key is the only secret: an env file, encrypted by phala to the CVM, never committed
phala deploy -n provenexit-exit -c deploy/phala/docker-compose.yml -t tdx.small --image dstack-0.6.1 --no-dev-os \
  -e <env file with PLR_OPERATOR_KEY=ed25519:…> --no-public-logs
node client/dist/cli.js vpn inspect   # with PLR_VPN_URL etc. from deploy/testnet/env.live: compose hash + OS measurement
scripts/owner.sh allow_compose '{"hash":"<compose hash>"}'   # the exit retries registration with backoff (≤ 5 min)
```

To move the running CVM to a new compose (same app id and URL, as done on 2026-11-12): `phala deploy --cvm-id <id>
-c deploy/phala/docker-compose.yml --no-public-logs`, then `vpn inspect`, `allow_compose` for the new hash, and
`revoke_compose` for the old one once the exit has registered again. The exit gets new keys with a new compose.

Use a production OS image (`phala os-images`, DEV `no`): the dev images allow SSH into the CVM.

Policy check (SPEC-TDX §1.4: every image pinned by digest and not built, no `privileged`, service `exit` with
`logging.driver: none`):

```sh
node --input-type=module -e "import fs from 'node:fs'; const {checkDstackComposePolicy}=await import('./packages/shared/dist/index.js'); console.log(checkDstackComposePolicy(JSON.stringify({runner:'docker-compose',docker_compose_file:fs.readFileSync('deploy/phala/docker-compose.yml','utf8')})))"
# { images: [ 'ghcr.io/erhantrk/provenexit-exit@sha256:74c6d1c5…' ] }
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
