# ProvenExit VPN exit image (T13). Reproducible: build it with scripts/build-exit-image.sh, check it with
# scripts/verify-exit-image.sh (both set the platform, SOURCE_DATE_EPOCH and the output options the digest depends on).
# Build context: the repo root, filtered by Dockerfile.dockerignore (the list of inputs).
# The image digest is what dstack measures (via the compose); the bundle and policy inside are the vpn-honest build.
#
# No `# syntax=` line on purpose: it would pull an unpinned Dockerfile frontend.

# --- build stage: the bundle and its policy, built inside the same pinned node the exit runs on ---
FROM node:22-bookworm-slim@sha256:e9f565d32859f0cbfb52125eafe8be39390f24dac302dc3cdf566e8ba3ab21ee AS build
WORKDIR /src
COPY package.json package-lock.json tsconfig.base.json ./
COPY packages/shared/package.json packages/shared/
COPY enclave/package.json enclave/
COPY client/package.json client/
COPY mcp/package.json mcp/
COPY e2e/package.json e2e/
# Exactly the lockfile (every tarball is checked against its integrity hash); no install scripts run.
RUN npm ci --ignore-scripts --no-audit --no-fund
COPY packages/shared packages/shared
COPY enclave enclave
RUN npx tsc -b enclave && node enclave/build.mjs --node-exe-only --out /out

# --- the image that runs: base + the two files + CMD ---
FROM node:22-bookworm-slim@sha256:e9f565d32859f0cbfb52125eafe8be39390f24dac302dc3cdf566e8ba3ab21ee
WORKDIR /app
COPY --from=build --chmod=644 /out/vpn-exit/vpn-honest/vpn.bundle.mjs /app/vpn.bundle.mjs
COPY --from=build --chmod=644 /out/vpn-exit/vpn-honest/app-compose.json /app/vpn-policy.json
ENV NODE_ENV=production
EXPOSE 18200
CMD ["node", "/app/vpn.bundle.mjs"]
