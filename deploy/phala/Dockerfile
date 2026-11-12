# ProvenExit VPN exit image (T13). Build context: deploy/phala/image/ (filled by scripts/build-exit-image.sh).
# The image digest is what dstack measures (via the compose); the bundle and policy inside are the vpn-honest build.
FROM node:22-bookworm-slim@sha256:e9f565d32859f0cbfb52125eafe8be39390f24dac302dc3cdf566e8ba3ab21ee
WORKDIR /app
COPY vpn.bundle.mjs vpn-policy.json /app/
ENV NODE_ENV=production
EXPOSE 18200
CMD ["node", "/app/vpn.bundle.mjs"]
