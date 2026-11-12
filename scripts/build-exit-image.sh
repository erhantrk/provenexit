#!/usr/bin/env bash
# Builds and pushes the ProvenExit exit image (linux/amd64) and prints its digest for deploy/phala/docker-compose.yml.
set -euo pipefail
cd "$(dirname "$0")/.."
IMAGE="${IMAGE:-ghcr.io/erhantrk/provenexit-exit}"
TAG="${TAG:-$(git rev-parse --short HEAD)}"
npm run build -w @plr/enclave >/dev/null
CTX=deploy/phala/image
rm -rf "$CTX" && mkdir -p "$CTX"
cp enclave/dist/vpn-exit/vpn-honest/vpn.bundle.mjs "$CTX/"
cp enclave/dist/vpn-exit/vpn-honest/app-compose.json "$CTX/vpn-policy.json"
docker buildx build --platform linux/amd64 --provenance=false --sbom=false -f deploy/phala/Dockerfile -t "$IMAGE:$TAG" --push "$CTX"
docker buildx imagetools inspect "$IMAGE:$TAG" --format '{{json .Manifest.Digest}}'
