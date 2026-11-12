// Reproducible VPN exit build (SPEC §4, SPEC-VPN §2).
//
//   node build.mjs [--out <dir>]        (default: dist; run after `tsc -b`, which provides dist/compose.js)
//
// Produces, deterministically (same sources + lockfile ⇒ same bytes):
//   vpn-exit/<variant>/vpn.bundle.mjs              VPN exit builds (esbuild, platform node, esm, no sourcemap, no legal
//   vpn-exit/<variant>/app-compose.json            comments, paths relative to this package), one directory per variant
//                                                  because the compose entry is always "vpn.bundle.mjs":
//                                               vpn-honest       production policy (allow_loopback false, DoH via
//                                                                https://1.1.1.1 then https://9.9.9.9)
//                                               vpn-honest-test  same bundle, allow_loopback true, DoH via the local
//                                                                test resolver http://127.0.0.1:18253/dns-query (local
//                                                                tests only; different compose hash, never production)
//                                               vpn-evil-logger  ⚠️ honest source + evil/logging-dialer.ts, test policy
//   build-info.json                           every hash above, for harnesses and the demo (VPN under the "vpn" key:
//                                             { <variant>: { dir, bundle, bundle_sha256, allow_loopback, doh,
//                                                            compose: { file, compose_hash } } }; paths relative to OUT)
//
// Runtime pin: `vpn.node_sha256` = runtime closure digest of the node running this build (the mock TDX host runs the
// exit with the same node). See src/mock-tdx/runtime.ts. A different node install ⇒ different compose hashes (by design).
import { createHash } from "node:crypto";
import { mkdirSync, writeFileSync, existsSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { parseArgs } from "node:util";
import * as esbuild from "esbuild";

const HERE = dirname(fileURLToPath(import.meta.url));

const { values } = parseArgs({ options: { out: { type: "string", default: "dist" } }, strict: true });
const OUT = resolve(HERE, values.out);

const composeModule = join(HERE, "dist", "compose.js");
if (!existsSync(composeModule)) {
  process.stderr.write("build.mjs: dist/compose.js missing — run `tsc -b` first (npm run build does)\n");
  process.exit(1);
}
const { makeVpnCompose, composeBytes, VPN_DOH_PRODUCTION, VPN_DOH_TEST } = await import(pathToFileURL(composeModule).href);
const { measureRuntime } = await import(pathToFileURL(join(HERE, "dist", "mock-tdx", "runtime.js")).href);
let nodeRuntime;
try {
  nodeRuntime = await measureRuntime(process.execPath);
} catch (e) {
  process.stderr.write(`build.mjs: cannot measure the node runtime (${e?.code ?? "error"})\n`);
  process.exit(1);
}

const sha256 = (b) => createHash("sha256").update(b).digest("hex");

/** One deterministic esbuild bundle → bytes (nothing is written by esbuild itself). */
async function bundle(entry, outName) {
  const r = await esbuild.build({
    absWorkingDir: HERE,
    entryPoints: [entry],
    outfile: join(OUT, outName),
    bundle: true,
    write: false,
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
    // "@phala/dstack-sdk" 0.5.8 (dstack mode) declares @noble/hashes ^1.6.1 / @noble/curves ^1.8.1 as peers but
    // imports the v1 deep paths. This repo pins the v2 packages, where the same symbols live at "<name>.js":
    // sha256/sha384 in sha2.js, keccak_256 in sha3.js, bytesToHex in utils.js, secp256k1 in secp256k1.js.
    alias: {
      "@noble/hashes/sha256": "@noble/hashes/sha2.js",
      "@noble/hashes/sha512": "@noble/hashes/sha2.js",
      "@noble/hashes/sha3": "@noble/hashes/sha3.js",
      "@noble/hashes/utils": "@noble/hashes/utils.js",
      "@noble/curves/secp256k1": "@noble/curves/secp256k1.js",
    },
    // CommonJS dependencies inside an ESM bundle need a real `require` for node builtins.
    banner: { js: 'import { createRequire as __plrCreateRequire } from "node:module";\nconst require = __plrCreateRequire(import.meta.url);' },
  });
  if (r.errors.length || r.outputFiles.length !== 1) throw new Error(`esbuild failed for ${entry}`);
  return r.outputFiles[0].contents;
}

function writeOut(name, bytes) {
  mkdirSync(dirname(join(OUT, name)), { recursive: true });
  writeFileSync(join(OUT, name), bytes);
  return sha256(bytes);
}

mkdirSync(OUT, { recursive: true });
const info = { runtime: { node_sha256: nodeRuntime.digest } };

// VPN exit (SPEC-VPN §2). Bundled once per source; the honest bytes serve both honest variants.
const vpnBundles = {
  honest: await bundle("src/vpn/entry.ts", "vpn-exit/vpn.bundle.mjs"),
  evil: await bundle("evil/vpn-entry.ts", "vpn-exit/vpn.bundle.mjs"),
};
// SPEC-VPN §2: test-policy builds resolve through the local test resolver; production through 1.1.1.1 + 9.9.9.9.
const vpnVariants = [
  { name: "vpn-honest", source: "honest", allowLoopback: false, doh: VPN_DOH_PRODUCTION },
  { name: "vpn-honest-test", source: "honest", allowLoopback: true, doh: VPN_DOH_TEST },
  { name: "vpn-evil-logger", source: "evil", allowLoopback: true, doh: VPN_DOH_TEST },
];
info.vpn = {};
for (const v of vpnVariants) {
  const dir = `vpn-exit/${v.name}`;
  const bundleSha = writeOut(`${dir}/vpn.bundle.mjs`, vpnBundles[v.source]);
  const cb = composeBytes(makeVpnCompose({ bundleSha256: bundleSha, nodeSha256: nodeRuntime.digest, allowLoopback: v.allowLoopback, doh: v.doh }));
  const composeHash = writeOut(`${dir}/app-compose.json`, cb);
  info.vpn[v.name] = {
    dir,
    bundle: `${dir}/vpn.bundle.mjs`,
    bundle_sha256: bundleSha,
    allow_loopback: v.allowLoopback,
    doh: [...v.doh],
    compose: { file: `${dir}/app-compose.json`, compose_hash: composeHash },
  };
}

writeFileSync(join(OUT, "build-info.json"), JSON.stringify(info, null, 2) + "\n");
process.stdout.write(
  `built ${OUT}\n` +
    Object.entries(info.vpn)
      .map(([n, v]) => `  ${n.padEnd(16)} bundle ${v.bundle_sha256}  compose ${v.compose.compose_hash}\n`)
      .join(""),
);
