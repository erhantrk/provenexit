# Shared by scripts/build-exit-image.sh and scripts/verify-exit-image.sh (sourced, not run).
# Everything the exit image digest depends on is fixed here, so "build" and "verify" cannot drift apart.
#
# What makes the digest reproducible:
#   - base image pinned by digest, bundle + policy built inside it from the lockfile (deploy/phala/Dockerfile)
#   - one platform (linux/amd64), no provenance / SBOM attestations (they carry build-time data)
#   - SOURCE_DATE_EPOCH + rewrite-timestamp with a constant epoch (EXIT_IMAGE_EPOCH): the timestamps in the image
#     config and in the layers the build adds do not depend on the clock or on git history, only the content does
#   - OCI media types for both the local build and the registry push (oci-mediatypes=true), gzip layers, so the
#     manifest a verifier computes locally has the same bytes, and the same digest, as the one a push uploads
#   - the builder: BuildKit writes the layers (tar, gzip) and the manifest, so its release decides their bytes. The
#     scripts create and use a docker-container builder that runs the BuildKit image pinned below by digest.

EXIT_IMAGE_PLATFORM=linux/amd64
EXIT_IMAGE_DOCKERFILE=deploy/phala/Dockerfile
EXIT_IMAGE_COMPOSE=deploy/phala/docker-compose.yml
# A constant, not a commit time: a rebase, a squash-merge or a docs commit must not change the digest of the same
# content, and a shallow clone must be able to verify. 1767225600 = 2026-01-01T00:00:00Z; the value has no meaning.
EXIT_IMAGE_EPOCH=1767225600
# The pinned builder (multi-arch index digest of the moby/buildkit release on Docker Hub). To change it, change the
# three lines together; the builder name carries the pin, so a new pin gets a new builder.
EXIT_IMAGE_BUILDKIT_VERSION=v0.34.2
EXIT_IMAGE_BUILDKIT_IMAGE=moby/buildkit:v0.34.2@sha256:c5f8862f52499773af85bc07695b2379ef08e8002352b0df2c4864c91d78dabe
EXIT_IMAGE_BUILDER=provenexit-exit-buildkit-v0.34.2-c5f8862f5249
# The build inputs (git pathspecs): the Dockerfile, its ignore file, and what the ignore file lets into the build
# context. Tests are not inputs. Used to warn about uncommitted changes in them.
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

# Prints the uncommitted changes (tracked or untracked, not ignored) under the image inputs; empty if none.
exit_image_dirty_inputs() { git status --porcelain -- "${EXIT_IMAGE_INPUTS[@]}"; }

# Picks and starts the builder. Call it once, at the top level of a script (not inside $(...)): it sets
#   EXIT_IMAGE_USE_BUILDER       the buildx builder every build of this run uses
#   EXIT_IMAGE_BUILDKIT_RUNNING  the BuildKit version that builder reports ("unknown" if it reports none)
# Default: the pinned docker-container builder, created on first use. BUILDER=<name> uses another builder; its
# BuildKit is then not the pinned one and the digest can differ (a warning says so).
exit_image_prepare_builder() {
  local info
  if [ -n "${BUILDER:-}" ]; then
    EXIT_IMAGE_USE_BUILDER="$BUILDER"
  else
    EXIT_IMAGE_USE_BUILDER="$EXIT_IMAGE_BUILDER"
    if ! docker buildx inspect "$EXIT_IMAGE_USE_BUILDER" >/dev/null 2>&1; then
      # A parallel run may create it first: only fail if it still does not exist.
      docker buildx create --name "$EXIT_IMAGE_USE_BUILDER" --driver docker-container \
        --driver-opt "image=$EXIT_IMAGE_BUILDKIT_IMAGE" >&2 \
        || docker buildx inspect "$EXIT_IMAGE_USE_BUILDER" >/dev/null 2>&1 \
        || exit_image_die "could not create the pinned builder $EXIT_IMAGE_USE_BUILDER ($EXIT_IMAGE_BUILDKIT_IMAGE)"
    fi
  fi
  info="$(docker buildx inspect --bootstrap "$EXIT_IMAGE_USE_BUILDER" 2>&1)" \
    || { echo "$info" >&2; exit_image_die "could not start the builder $EXIT_IMAGE_USE_BUILDER"; }
  EXIT_IMAGE_BUILDKIT_RUNNING="$(printf '%s\n' "$info" | sed -n 's/^[Bb]uild[Kk]it\( version\)\{0,1\}:[[:space:]]*\(v[^[:space:]]*\).*/\2/p' | head -n 1)"
  [ -n "$EXIT_IMAGE_BUILDKIT_RUNNING" ] || EXIT_IMAGE_BUILDKIT_RUNNING=unknown
  if [ -n "${BUILDER:-}" ]; then
    echo "exit image: WARNING: BUILDER=$BUILDER (BuildKit $EXIT_IMAGE_BUILDKIT_RUNNING) is not the pinned builder ($EXIT_IMAGE_BUILDKIT_IMAGE); the digest can differ for that reason alone" >&2
  elif [ "$EXIT_IMAGE_BUILDKIT_RUNNING" != unknown ] && [ "$EXIT_IMAGE_BUILDKIT_RUNNING" != "$EXIT_IMAGE_BUILDKIT_VERSION" ]; then
    exit_image_die "the builder $EXIT_IMAGE_USE_BUILDER runs BuildKit $EXIT_IMAGE_BUILDKIT_RUNNING, not the pinned $EXIT_IMAGE_BUILDKIT_VERSION: remove it ('docker buildx rm $EXIT_IMAGE_USE_BUILDER') and run again"
  fi
  echo "exit image: builder $EXIT_IMAGE_USE_BUILDER, BuildKit $EXIT_IMAGE_BUILDKIT_RUNNING" >&2
}

# One line for the reports: which builder made the digest.
exit_image_builder_line() { echo "$EXIT_IMAGE_USE_BUILDER (BuildKit $EXIT_IMAGE_BUILDKIT_RUNNING)"; }

# exit_image_build <extra buildx output options, e.g. "type=oci,dest=/tmp/x.tar"> [more buildx args...]
# Runs the one build both scripts share and prints the manifest digest (sha256:<64 hex>) on stdout; build output goes
# to stderr. NO_CACHE=0 allows the build cache (default: --no-cache, so nothing but this checkout decides the result).
exit_image_build() {
  local output="$1"; shift
  local meta digest
  [ -n "${EXIT_IMAGE_USE_BUILDER:-}" ] || exit_image_die "exit_image_prepare_builder was not called"
  meta="$(mktemp "${TMPDIR:-/tmp}/exit-image-meta.XXXXXX")"
  local args=(buildx build
    --builder "$EXIT_IMAGE_USE_BUILDER"
    --platform "$EXIT_IMAGE_PLATFORM"
    --provenance=false --sbom=false
    --build-arg "SOURCE_DATE_EPOCH=$EXIT_IMAGE_EPOCH"
    --output "$output,oci-mediatypes=true,compression=gzip,rewrite-timestamp=true"
    --metadata-file "$meta"
    -f "$EXIT_IMAGE_DOCKERFILE")
  [ "${NO_CACHE:-1}" = "0" ] || args+=(--no-cache)
  SOURCE_DATE_EPOCH="$EXIT_IMAGE_EPOCH" docker "${args[@]}" "$@" . >&2 || { rm -f "$meta"; exit_image_die "docker buildx build failed"; }
  digest="$(exit_image_digest_in <"$meta")"
  rm -f "$meta"
  [ -n "$digest" ] || exit_image_die "the build did not report a digest"
  echo "$digest"
}

# stdin: JSON with a "containerimage.digest" or "digest" field; prints the first sha256:<64 hex> found there.
exit_image_digest_in() {
  tr -d '\n' | sed -n 's/.*"\(containerimage\.\)\{0,1\}digest"[[:space:]]*:[[:space:]]*"\(sha256:[0-9a-f]\{64\}\)".*/\2/p'
}

# stdin: bytes; prints their sha256 as 64 hex.
exit_image_sha256() {
  if command -v sha256sum >/dev/null 2>&1; then sha256sum | cut -d' ' -f1; else shasum -a 256 | cut -d' ' -f1; fi
}

# exit_image_tag_kind <manifest digest> <digest of the raw document a tag resolves to>; stdin: that raw document.
# Prints "manifest" if the tag is the manifest itself, "index" if it is an image index (OCI index or Docker manifest
# list) in which the only digest is that manifest's, and nothing otherwise (another manifest, an index that lists
# anything else, an empty or unreadable document).
exit_image_tag_kind() {
  local manifest="$1" tag="$2" raw listed
  raw="$(cat)"
  [ -n "$tag" ] && [ -n "$raw" ] || return 0
  if [ "$tag" = "$manifest" ]; then echo manifest; return 0; fi
  printf '%s' "$raw" | tr -d '\n' | grep -q '"mediaType"[[:space:]]*:[[:space:]]*"application/vnd\.\(oci\.image\.index\.v1\|docker\.distribution\.manifest\.list\.v2\)+json"' || return 0
  listed="$(printf '%s' "$raw" | grep -o 'sha256:[0-9a-f]\{64\}' | sort -u)"
  [ "$listed" = "$manifest" ] && echo index
  return 0
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
