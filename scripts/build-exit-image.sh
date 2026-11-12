#!/usr/bin/env bash
# Builds the ProvenExit exit image (linux/amd64) reproducibly and prints its digest.
#
#   scripts/build-exit-image.sh            build locally, print the digest, push nothing
#   PUSH=1 scripts/build-exit-image.sh     the same, then upload to $IMAGE without a tag, and tag it $IMAGE:$TAG only
#                                          if the registry digest equals the local one. The tag may be stored as an
#                                          image index wrapping the manifest: the script reports both digests; the
#                                          one printed on stdout (and to pin) is always the manifest digest
#
# IMAGE (default ghcr.io/erhantrk/provenexit-exit), TAG (default: short HEAD), NO_CACHE=0 (allow the build cache),
# BUILDER (a buildx builder to use instead of the pinned one; the digest can then differ). A push is refused from a
# dirty tree: a pushed image must be a commit.
# The build inputs, options and the pinned builder live in scripts/exit-image-common.sh; anyone can check the result
# with scripts/verify-exit-image.sh. After a push, pin the digest in deploy/phala/docker-compose.yml.
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

exit_image_prepare_builder
LOCAL="$(exit_image_build_local)"
echo "built $LOCAL (source $(git rev-parse HEAD), SOURCE_DATE_EPOCH $EXIT_IMAGE_EPOCH, builder $(exit_image_builder_line))" >&2
if [ "${PUSH:-0}" != "1" ]; then
  echo "not pushed (set PUSH=1 to push $IMAGE:$TAG)" >&2
  echo "$LOCAL"
  exit 0
fi

# Same build, registry output, by digest only: no tag exists until the registry digest is known to be the local one.
# The cache from the build above is reused: the point is to upload those layers.
PUSHED="$(NO_CACHE=0 exit_image_build "type=image,name=$IMAGE,push-by-digest=true,push=true")"
if [ "$PUSHED" != "$LOCAL" ]; then
  echo "build-exit-image: the registry digest $PUSHED differs from the local digest $LOCAL." >&2
  echo "An untagged manifest was uploaded to $IMAGE; no tag points at it. Verifiers would not reproduce it: do not deploy it." >&2
  exit 1
fi
docker buildx imagetools create --builder "$EXIT_IMAGE_USE_BUILDER" -t "$IMAGE:$TAG" "$IMAGE@$LOCAL" >&2 \
  || { echo "build-exit-image: $IMAGE@$LOCAL is uploaded, but tagging it $IMAGE:$TAG failed" >&2; exit 1; }
# Read the tag back as the registry serves it (raw bytes; their sha256 is the digest the tag resolves to).
# `imagetools create` may store the tag as an image index that wraps the manifest, so the tag's digest is then the
# index digest, not the manifest digest. Accepted: the tag is the manifest itself, or an index listing only it.
RAW="$(mktemp "${TMPDIR:-/tmp}/exit-image-tag.XXXXXX")"
docker buildx imagetools inspect --builder "$EXIT_IMAGE_USE_BUILDER" --raw "$IMAGE:$TAG" >"$RAW" || : >"$RAW"
TAG_DIGEST=""
[ -s "$RAW" ] && TAG_DIGEST="sha256:$(exit_image_sha256 <"$RAW")"
TAG_KIND="$(exit_image_tag_kind "$LOCAL" "$TAG_DIGEST" <"$RAW")"
rm -f "$RAW"
case "$TAG_KIND" in
  manifest) TAG_LINE="tag $IMAGE:$TAG -> $TAG_DIGEST (that manifest)" ;;
  index) TAG_LINE="tag $IMAGE:$TAG -> image index $TAG_DIGEST, which lists only that manifest" ;;
  *)
    echo "build-exit-image: $IMAGE:$TAG resolves to '${TAG_DIGEST:-nothing}', which is neither the local manifest $LOCAL nor an index listing only it: do not deploy by tag." >&2
    exit 1 ;;
esac
echo "pushed $IMAGE@$LOCAL (image manifest, $EXIT_IMAGE_PLATFORM)" >&2
echo "$TAG_LINE" >&2
echo "pin and verify the manifest digest (printed below), not the tag" >&2
echo "$LOCAL"
