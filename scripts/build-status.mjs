// Builds status/provenexit-status.mjs: the status bundle as ONE self-contained ESM file (Node >= 22, no
// node_modules). Defaults (exit URL, registry, Intel root, RPC) come from deploy/testnet/env.live at build time; the
// offline replay fixture (fixtures/live-exit) is embedded. Run `npx tsc -b` first.
//   node scripts/build-status.mjs
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { bundleSelfContained, parseEnvFile } from "./esbuild-common.mjs";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const env = parseEnvFile(readFileSync(join(ROOT, "deploy/testnet/env.live"), "utf8"));
const need = (k) => env[k] || (() => { throw new Error(`deploy/testnet/env.live: ${k} missing`); })();
const defaults = {
  exitUrl: need("PLR_VPN_URL"),
  registry: need("PLR_VPN_REGISTRY"),
  registryCodeHash: need("PLR_VPN_REGISTRY_CODE_HASH"),
  trustedRoot: need("PLR_TRUSTED_ROOT"),
  rpcUrl: need("PLR_NEAR_RPC"),
  operator: env.OPERATOR_ID,
  ...(env.PLATFORM ? { platform: env.PLATFORM } : {}),
  ...(env.REPRODUCIBLE_BUILD === "true" || env.REPRODUCIBLE_BUILD === "false" ? { reproducibleBuild: env.REPRODUCIBLE_BUILD === "true" } : {}),
};
const fx = join(ROOT, "fixtures/live-exit");
const replay = {
  meta: JSON.parse(readFileSync(join(fx, "meta.json"), "utf8")),
  nonce_hex: readFileSync(join(fx, "nonce.hex"), "utf8").trim(),
  bundle: JSON.parse(readFileSync(join(fx, "bundle.json"), "utf8")),
  registry: JSON.parse(readFileSync(join(fx, "registry.json"), "utf8")),
};
mkdirSync(join(ROOT, "status"), { recursive: true });
await bundleSelfContained({
  entry: join(ROOT, "client/src/status-main.ts"),
  outfile: join(ROOT, "status/provenexit-status.mjs"),
  shebang: "#!/usr/bin/env node",
  define: { __STATUS_DEFAULTS__: defaults, __STATUS_REPLAY__: replay },
});
console.log("wrote status/provenexit-status.mjs");
