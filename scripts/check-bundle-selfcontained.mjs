#!/usr/bin/env node
// Build check: the VPN exit bundle must start without `node_modules`.
//
// The exit image (T12/T13) copies `vpn.bundle.mjs` alone, so every module the bundle imports at start-up must be
// inlined by esbuild. `@phala/dcap-qvl` is loaded lazily by `packages/shared/src/attest/intel.ts` (a bare `require`
// that esbuild cannot inline), so this check bundles `enclave/src/vpn/entry.ts` exactly like `enclave/build.mjs`,
// runs it from an empty directory and fails if node reports a missing module.
//
//   npx tsc -b packages/shared enclave     # dist/ must be current, like `npm run build -w @plr/enclave`
//   node scripts/check-bundle-selfcontained.mjs [--out <dir>]
//
// Exit 0: the bundle booted (config may legitimately fail; that is not this check). Exit 1: a module was missing.
import { spawnSync } from "node:child_process";
import { mkdirSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { parseArgs } from "node:util";
import * as esbuild from "esbuild";

const HERE = dirname(fileURLToPath(import.meta.url));
const REPO = resolve(HERE, "..");
const { values } = parseArgs({ options: { out: { type: "string" } }, strict: true });
const created = values.out === undefined;
const out = values.out === undefined ? mkdtempSync(join(tmpdir(), "plr-bundle-check-")) : resolve(values.out);
mkdirSync(out, { recursive: true });

const bundle = join(out, "vpn.bundle.mjs");
await esbuild.build({
  absWorkingDir: join(REPO, "enclave"),
  entryPoints: [join(REPO, "enclave", "src", "vpn", "entry.ts")],
  outfile: bundle,
  bundle: true,
  write: true,
  platform: "node",
  format: "esm",
  target: "node22",
  sourcemap: false,
  legalComments: "none",
  minify: false,
  treeShaking: true,
  charset: "utf8",
  metafile: false,
  logLevel: "warning",
  // Same banner as enclave/build.mjs: CommonJS dependencies inside an ESM bundle need a real `require`.
  banner: { js: 'import { createRequire as __plrCreateRequire } from "node:module";\nconst require = __plrCreateRequire(import.meta.url);' },
});

// Empty cwd + a temp dir outside the repo: `require("…")` cannot resolve any workspace package.
const run = spawnSync(process.execPath, [bundle], { cwd: out, encoding: "utf8", timeout: 20_000 });
const output = `${run.stdout ?? ""}${run.stderr ?? ""}`;
const missing = /Cannot find module|ERR_MODULE_NOT_FOUND|MODULE_NOT_FOUND/.test(output);
if (created) rmSync(out, { recursive: true, force: true });
if (missing) {
  process.stderr.write(`FAIL: ${bundle} needs a runtime module:\n${output.split("\n").slice(0, 12).join("\n")}\n`);
  process.exit(1);
}
process.stdout.write(`ok: ${bundle} starts without node_modules (exit ${run.status ?? run.signal})\n`);
