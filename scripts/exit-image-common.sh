# Shared by scripts/build-exit-image.sh and scripts/verify-exit-image.sh (sourced, not run).
# Everything the exit image digest depends on is fixed here, so "build" and "verify" cannot drift apart.
#
# What makes the digest reproducible:
#   - base image pinned by digest, bundle + policy built inside it from the lockfile (deploy/phala/Dockerfile)
#   - one platform (linux/amd64), no provenance / SBOM attestations (they carry build-time data)
#   - SOURCE_DATE_EPOCH + rewrite-timestamp: every timestamp in the image config and the layers is that epoch
#   - OCI media types for both the local build and the registry push (oci-mediatypes=true), gzip layers, so the
#     manifest a verifier computes locally has the same bytes, and the same digest, as the one a push uploads
#
# SOURCE_DATE_EPOCH is the commit time of the last commit that changed an image input (EXIT_IMAGE_INPUTS). At the
# commit that changes an input this is the commit time of HEAD. Later commits that touch nothing the image is built
# from (docs, or the commit that pins the new digest in deploy/phala/docker-compose.yml) keep the digest.

EXIT_IMAGE_PLATFORM=linux/amd64
EXIT_IMAGE_DOCKERFILE=deploy/phala/Dockerfile
EXIT_IMAGE_COMPOSE=deploy/phala/docker-compose.yml
# The build inputs (git pathspecs): the Dockerfile, its ignore file, and what the ignore file lets into the build
# context. Tests are not inputs.
EXIT_IMAGE_INPUTS=(
  deploy/phala/Dockerfile
  deploy/phala/Dockerfile.dockerignore
  package.json
  package-lock.json
  tsconfig.base.json
  packages/shared
  enclave
  client/package.json
  mcp/package.json
  e2e/package.json
  ':(exclude)enclave/test'
  ':(exclude)packages/shared/test'
)

exit_image_die() { echo "exit image: $*" >&2; exit 2; }

# Prints SOURCE_DATE_EPOCH for the current checkout (see above). Needs full history: a shallow clone cannot tell
# which commit last changed an input.
exit_image_epoch() {
  [ "$(git rev-parse --is-shallow-repository)" = "false" ] || exit_image_die "shallow clone: run 'git fetch --unshallow' first"
  local t
  t="$(git log -1 --format=%ct -- "${EXIT_IMAGE_INPUTS[@]}")"
  [[ "$t" =~ ^[0-9]+$ ]] || exit_image_die "no commit found for the image inputs"
  echo "$t"
}

# Prints the uncommitted changes (tracked or untracked, not ignored) under the image inputs; empty if none.
exit_image_dirty_inputs() { git status --porcelain -- "${EXIT_IMAGE_INPUTS[@]}"; }

# exit_image_build <extra buildx output options, e.g. "type=oci,dest=/tmp/x.tar"> [more buildx args...]
# Runs the one build both scripts share and prints the manifest digest (sha256:<64 hex>) on stdout; build output goes
# to stderr. NO_CACHE=0 allows the build cache (default: --no-cache, so nothing but this checkout decides the result).
exit_image_build() {
  local output="$1"; shift
  local epoch meta digest
  epoch="$(exit_image_epoch)" || exit 2
  meta="$(mktemp "${TMPDIR:-/tmp}/exit-image-meta.XXXXXX")"
  local args=(buildx build
    --platform "$EXIT_IMAGE_PLATFORM"
    --provenance=false --sbom=false
    --build-arg "SOURCE_DATE_EPOCH=$epoch"
    --output "$output,oci-mediatypes=true,compression=gzip,rewrite-timestamp=true"
    --metadata-file "$meta"
    -f "$EXIT_IMAGE_DOCKERFILE")
  [ "${NO_CACHE:-1}" = "0" ] || args+=(--no-cache)
  [ -z "${BUILDER:-}" ] || args+=(--builder "$BUILDER")
  SOURCE_DATE_EPOCH="$epoch" docker "${args[@]}" "$@" . >&2 || { rm -f "$meta"; exit_image_die "docker buildx build failed"; }
  digest="$(tr -d '\n' <"$meta" | sed -n 's/.*"containerimage\.digest"[[:space:]]*:[[:space:]]*"\(sha256:[0-9a-f]\{64\}\)".*/\1/p')"
  rm -f "$meta"
  [ -n "$digest" ] || exit_image_die "the build did not report a digest"
  echo "$digest"
}

# Builds without pushing (an OCI archive in a temp dir, deleted afterwards) and prints the digest.
exit_image_build_local() {
  local dir digest
  dir="$(mktemp -d "${TMPDIR:-/tmp}/exit-image.XXXXXX")"
  digest="$(exit_image_build "type=oci,dest=$dir/image.tar")" || { rm -rf "$dir"; exit 2; }
  rm -rf "$dir"
  echo "$digest"
}

# Prints the sha256:<hex> digest the exit service is pinned to in deploy/phala/docker-compose.yml.
exit_image_pinned_digest() {
  local d
  d="$(sed -n 's/^[[:space:]]*image:[[:space:]]*[^[:space:]]*@\(sha256:[0-9a-f]\{64\}\)[[:space:]]*$/\1/p' "$EXIT_IMAGE_COMPOSE")"
  [ "$(printf '%s\n' "$d" | grep -c .)" = "1" ] || exit_image_die "expected exactly one digest-pinned image in $EXIT_IMAGE_COMPOSE"
  echo "$d"
}
