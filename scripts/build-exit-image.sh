#!/usr/bin/env bash
# Builds the ProvenExit exit image (linux/amd64) reproducibly and prints its digest.
#
#   scripts/build-exit-image.sh            build locally, print the digest, push nothing
#   PUSH=1 scripts/build-exit-image.sh     the same, then push $IMAGE:$TAG and check the registry digest is the same
#
# IMAGE (default ghcr.io/erhantrk/provenexit-exit), TAG (default: short HEAD), NO_CACHE=0 (allow the build cache),
# BUILDER (a buildx builder name). A push is refused from a dirty tree: a pushed image must be a commit.
# The build inputs and options live in scripts/exit-image-common.sh; anyone can check the result with
# scripts/verify-exit-image.sh. After a push, pin the digest in deploy/phala/docker-compose.yml.
set -euo pipefail
cd "$(dirname "$0")/.."
. scripts/exit-image-common.sh
IMAGE="${IMAGE:-ghcr.io/erhantrk/provenexit-exit}"
TAG="${TAG:-$(git rev-parse --short HEAD)}"

if [ "${PUSH:-0}" = "1" ] && [ -n "$(git status --porcelain)" ]; then
  echo "build-exit-image: refusing to push from a dirty tree (commit or stash first):" >&2
  git status --porcelain >&2
  exit 1
fi
if [ -n "$(exit_image_dirty_inputs)" ]; then
  echo "build-exit-image: WARNING: uncommitted changes in the image inputs; this digest is not the digest of a commit" >&2
fi

LOCAL="$(exit_image_build_local)"
echo "built $LOCAL (source $(git rev-parse HEAD), SOURCE_DATE_EPOCH $(exit_image_epoch))" >&2
if [ "${PUSH:-0}" != "1" ]; then
  echo "not pushed (set PUSH=1 to push $IMAGE:$TAG)" >&2
  echo "$LOCAL"
  exit 0
fi

# Same build, registry output. The cache from the build above is reused: the point is to upload those layers.
PUSHED="$(NO_CACHE=0 exit_image_build "type=image,name=$IMAGE:$TAG,push=true")"
if [ "$PUSHED" != "$LOCAL" ]; then
  echo "build-exit-image: the registry digest $PUSHED differs from the local digest $LOCAL." >&2
  echo "The image was pushed, but verifiers would not reproduce it: do not deploy it." >&2
  exit 1
fi
echo "pushed $IMAGE:$TAG" >&2
echo "$PUSHED"
