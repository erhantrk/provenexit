// Entry of the `provenexit` npm package (bundled by scripts/build-npm.mjs into npm/dist/provenexit.mjs).
// Fills in the public settings of the live testnet deployment (from deploy/testnet/env.live at build time) for any
// that are not already set, accepts `verify` / `inspect` / `connect` as short forms of `vpn verify` / `vpn inspect` /
// `vpn`, then runs the CLI.
const defaults = __NPM_DEFAULTS__;
for (const [k, v] of Object.entries(defaults)) {
  if (process.env[k] === undefined || process.env[k] === "") process.env[k] = v;
}
const first = process.argv[2];
if (first === "verify" || first === "inspect") process.argv.splice(2, 0, "vpn"); // provenexit vpn verify|inspect
else if (first === "connect") process.argv[2] = "vpn"; // provenexit vpn = verify, then run the local SOCKS5 proxy
// The CLI runs itself when it is the main module, which it is inside this single-file bundle.
await import("../client/src/cli.ts");
