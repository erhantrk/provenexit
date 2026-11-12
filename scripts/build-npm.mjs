// Builds the `provenexit` npm package in npm/: npm/dist/provenexit.mjs (the CLI, one self-contained ESM file) and
// npm/dist/provenexit-mcp.mjs (a copy of the MCP server bundle). Run `npx tsc -b` and `npm run build:mcp` first.
// Defaults are the public settings of the live testnet deployment in deploy/testnet/env.live (no secrets there).
import { copyFileSync, readFileSync, mkdirSync, chmodSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { bundleSelfContained, parseEnvFile } from "./esbuild-common.mjs";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const env = parseEnvFile(readFileSync(join(ROOT, "deploy/testnet/env.live"), "utf8"));
const keys = ["PLR_VPN_URL", "PLR_VPN_REGISTRY", "PLR_NEAR_RPC", "PLR_TRUSTED_ROOT"];
const defaults = Object.fromEntries(keys.map((k) => {
  if (!env[k]) throw new Error(`deploy/testnet/env.live: ${k} missing`);
  return [k, env[k]];
}));
const out = join(ROOT, "npm/dist");
mkdirSync(out, { recursive: true });
await bundleSelfContained({
  entry: join(ROOT, "npm/launcher.mjs"),
  outfile: join(out, "provenexit.mjs"),
  shebang: "#!/usr/bin/env node",
  define: { __NPM_DEFAULTS__: defaults },
});
copyFileSync(join(ROOT, "mcp/dist/provenexit-mcp.mjs"), join(out, "provenexit-mcp.mjs"));
copyFileSync(join(ROOT, "LICENSE"), join(ROOT, "npm/LICENSE"));
for (const f of ["provenexit.mjs", "provenexit-mcp.mjs"]) chmodSync(join(out, f), 0o755);
console.log("wrote npm/dist/provenexit.mjs and npm/dist/provenexit-mcp.mjs");
