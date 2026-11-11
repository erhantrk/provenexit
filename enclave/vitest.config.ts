import { defineConfig } from "vitest/config";

// "@phala/dstack-sdk" 0.5.8 declares @noble/hashes ^1.6.1 / @noble/curves ^1.8.1 as peers but imports the v1 deep
// paths; this repo pins the v2 packages, whose symbols live at "<name>.js". `enclave/build.mjs` applies these same
// aliases to the esbuild bundle; the tests run the TypeScript sources directly, so they need them too.
export default defineConfig({
  resolve: {
    alias: [
      { find: /^@noble\/hashes\/sha256$/, replacement: "@noble/hashes/sha2.js" },
      { find: /^@noble\/hashes\/sha512$/, replacement: "@noble/hashes/sha2.js" },
      { find: /^@noble\/hashes\/sha3$/, replacement: "@noble/hashes/sha3.js" },
      { find: /^@noble\/hashes\/utils$/, replacement: "@noble/hashes/utils.js" },
      { find: /^@noble\/curves\/secp256k1$/, replacement: "@noble/curves/secp256k1.js" },
    ],
  },
  test: {
    include: ["test/**/*.test.ts"],
    testTimeout: 120_000,
    hookTimeout: 300_000,
    fileParallelism: false,
    // Processed by Vite (not loaded by Node's resolver), so the aliases above apply to its deep imports.
    server: { deps: { inline: ["@phala/dstack-sdk"] } },
  },
});
