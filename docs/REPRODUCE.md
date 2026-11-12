# Reproduce the exit image and the registry contract

Both artifacts the client trusts by hash can be rebuilt from this repository: the exit image (pinned by digest in
the measured compose, whose hash the registry allows) and the registry contract (whose code hash the client pins).

## The exit image

The live exit runs `ghcr.io/erhantrk/provenexit-exit@sha256:74c6d1c52e2ce72698fb238e52e27d03eefe1770af00a1dae3405d3474f22785`
(public, `linux/amd64`, an OCI image manifest), pinned in [`deploy/phala/docker-compose.yml`](../deploy/phala/docker-compose.yml).
It was built from commit `6740b3f`.

```sh
git clone https://github.com/erhantrk/provenexit && cd provenexit   # --depth 1 is enough
scripts/verify-exit-image.sh                  # rebuilds, compares with the digest in docker-compose.yml: MATCH / MISMATCH
scripts/verify-exit-image.sh --print-digest   # rebuilds, prints only sha256:<64 hex>
```

Needs git and Docker with buildx; no Node or npm on the host. On the first run the script creates its own buildx
builder (`docker-container` driver) running the pinned BuildKit image, which Docker pulls from Docker Hub; your
current builder is not changed. Nothing is pushed or loaded. Exit codes: 0 `MATCH`, 1 `MISMATCH`, 2 could not build.
The end of the output looks like this (from the CI run on commit `47d9794`):

```
source  47d979418ac50a81c6113185284005dbb14abdd9
builder provenexit-exit-buildkit-v0.34.2-c5f8862f5249 (BuildKit v0.34.2)
built   sha256:74c6d1c52e2ce72698fb238e52e27d03eefe1770af00a1dae3405d3474f22785
pinned  sha256:74c6d1c52e2ce72698fb238e52e27d03eefe1770af00a1dae3405d3474f22785  (deploy/phala/docker-compose.yml)
MATCH
```

Where it has been run:

- two fresh clones on the owner's machine, before the image was pushed: the same digest both times;
- the [verify exit image](https://github.com/erhantrk/provenexit/actions/workflows/verify-exit-image.yml) workflow, a
  GitHub-hosted ubuntu `linux/amd64` runner (no emulation), on every push to `main` or `provenexit` and on manual
  dispatch; it prints `MATCH` (for example run
  [43319605400](https://github.com/erhantrk/provenexit/actions/runs/43319605400)).

What is pinned: the base image `node:22-bookworm-slim` by digest, the npm packages by `package-lock.json`, the build
context (the root `package.json`, `package-lock.json`, `tsconfig.base.json`, `packages/shared`, `enclave` without
tests, and the other workspaces' `package.json`, filtered by `deploy/phala/Dockerfile.dockerignore`), the timestamps
(`SOURCE_DATE_EPOCH=1767225600` with `rewrite-timestamp=true`, a constant, so a docs-only commit keeps the digest),
the builder (BuildKit v0.34.2 by digest) and the manifest options (`linux/amd64` only, no provenance or SBOM, OCI
media types, gzip layers). The full list, what is not pinned, how the image was pushed and why the tag resolves to an
image index that wraps this manifest: [`deploy/phala/README.md`](../deploy/phala/README.md#reproduce-the-exit-image).

What a `MATCH` proves and does not prove: [LIMITS.md](LIMITS.md#what-a-matching-image-digest-proves).

## The registry contract

`vpnreg.pe-owner-erhan.testnet` runs a reproducible build of commit `dcd37e6`, recorded in the contract's own
metadata (which NEAR source verifiers read):

```sh
git checkout dcd37e6 && cd contracts/near && cargo near build reproducible-wasm   # needs Docker and cargo-near
```

It builds in the image `sourcescan/cargo-near:0.23.0-rust-1.99.1`, pinned by digest in
[`contracts/near/Cargo.toml`](../contracts/near/Cargo.toml), and gives a wasm of 617 739 bytes with SHA-256
`a39ed48c2c7cdad5d5b732031db1f115cb6569400bcb7521c81061368d8a0d9e`. NEAR's code hash is the base58 form of that
SHA-256: `C1hvenbrzHKN1n1f2z63Duburr8YXLAKBescrEvarCGM`, the value `view_account` returns for the registry (see
[VERIFY.md](VERIFY.md#the-claims) for the RPC call) and the value the client pins. A build of a later commit differs
only because the commit is part of the metadata. Details: [`contracts/near/README.md`](../contracts/near/README.md#rebuild-the-deployed-registry).

The account has no access keys (deleted in tx
[`58sZ72Aa…`](https://testnet.nearblocks.io/txns/58sZ72Aa7aAtCFjYQnKxxkcZ2PbGoS6D1yhBam343kiz)), so this code can
never be replaced.

Contract tests: `cd contracts/near && cargo test --release` (60 tests); `--features tdx-test-clock` adds a run of
dcap-qvl's sample quote through the real DCAP pipeline under a fixed clock.

## Deploying your own exit

The deploy steps (Phala CLI, the owner's `allow_compose` / `allow_os` / `revoke_compose` with
[`scripts/owner.sh`](../scripts/owner.sh), moving a running CVM to a new compose) are in
[`deploy/phala/README.md`](../deploy/phala/README.md#deploy). Use a production OS image: the dev images allow SSH
into the CVM.
