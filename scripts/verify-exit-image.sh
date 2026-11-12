#!/usr/bin/env bash
# Rebuilds the ProvenExit exit image from this checkout and compares its digest with the one the exit is pinned to.
# Needs only git and Docker with buildx (a builder that can write an OCI archive: Docker Desktop, the containerd
# image store, or a docker-container builder via BUILDER=<name>). No node, no npm on the host: the bundle is built
# inside the pinned base image. Nothing is pushed or loaded into Docker.
#
#   scripts/verify-exit-image.sh                  rebuild, compare with deploy/phala/docker-compose.yml:
#                                                 prints MATCH (exit 0) or MISMATCH (exit 1); exit 2 = could not build
#   scripts/verify-exit-image.sh --print-digest   rebuild, print only the digest (sha256:<64 hex>) on stdout
#
# The build ignores the cache (NO_CACHE=0 allows it). A MATCH proves the pinned image is what this source builds;
# it says nothing about what the source does: read it. See deploy/phala/README.md.
set -euo pipefail
cd "$(dirname "$0")/.."
. scripts/exit-image-common.sh

MODE=compare
case "${1:-}" in
  "") ;;
  --print-digest) MODE=print ;;
  *) echo "usage: scripts/verify-exit-image.sh [--print-digest]" >&2; exit 2 ;;
esac
[ "$#" -le 1 ] || { echo "usage: scripts/verify-exit-image.sh [--print-digest]" >&2; exit 2; }

if [ -n "$(exit_image_dirty_inputs)" ]; then
  echo "verify-exit-image: WARNING: uncommitted changes in the image inputs; this is not the digest of a commit" >&2
fi

BUILT="$(exit_image_build_local)"
if [ "$MODE" = print ]; then
  echo "$BUILT"
  exit 0
fi

PINNED="$(exit_image_pinned_digest)"
echo "source  $(git rev-parse HEAD)"
echo "built   $BUILT"
echo "pinned  $PINNED  ($EXIT_IMAGE_COMPOSE)"
if [ "$BUILT" = "$PINNED" ]; then
  echo "MATCH"
else
  echo "MISMATCH"
  exit 1
fi
