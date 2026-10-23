// Reproducible router build (SPEC §4).
//
//   node build.mjs [--out <dir>]        (default: dist; run after `tsc -b`, which provides dist/compose.js)
//
// Produces, deterministically (same sources + lockfile ⇒ same bytes):
//   router.bundle.mjs                         honest router (esbuild, platform node, esm, no sourcemap,
//                                             no legal comments, paths relative to this package)
//   app-compose.mock.json / .llama.json       canonical compose for each llm kind (keys sorted, 2-space, "\n")
//   app-compose.json                          = app-compose.mock.json (default local stack)
//   evil-logger.bundle.mjs                    ⚠️ EVIL demo build: honest source + evil/stealing-llm.ts
//   app-compose.evil-logger.{mock,llama}.json its compose files (different bundle_sha256 ⇒ different hash)
//   vpn-exit/<variant>/vpn.bundle.mjs              VPN exit builds (SPEC-VPN §2), one directory per variant because the
//   vpn-exit/<variant>/app-compose.json            compose entry is always "vpn.bundle.mjs":
//                                               vpn-honest       production policy (allow_loopback false, DoH via
//                                                                https://1.1.1.1 then https://9.9.9.9)
//                                               vpn-honest-test  same bundle, allow_loopback true, DoH via the local
//                                                                test resolver http://127.0.0.1:18253/dns-query (local
//                                                                tests only; different compose hash, never production)
//                                               vpn-evil-logger  ⚠️ honest source + evil/logging-dialer.ts, test policy
//   build-info.json                           every hash above, for harnesses and the demo (VPN under the "vpn" key:
//                                             { <variant>: { dir, bundle, bundle_sha256, allow_loopback, doh,
//                                                            compose: { file, compose_hash } } }, paths relative to OUT)
//
// Runtime pins: `router.node_sha256` = runtime closure digest of the node running this build (the host runs the
// router and the mock LLM with the same node), `llm.runtime_sha256` = closure digest of llama-server
// (PLR_LLAMA_SERVER, default /opt/homebrew/bin/llama-server) for llama.cpp composes, of node for mock ones.
// See src/mock-tdx/runtime.ts. A different node / llama.cpp install ⇒ different compose hashes (by design).
import { createHash } from "node:crypto";
import { mkdirSync, readFileSync, writeFileSync, existsSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { parseArgs } from "node:util";
import * as esbuild from "esbuild";

const HERE = dirname(fileURLToPath(import.meta.url));
/** SPEC §11: sha256 of ~/models/qwen2.5-0.5b-instruct-q4_k_m.gguf (the measured model is fixed by spec). */
export const QWEN_MODEL_SHA256 = "74a4da8c9fdbcd15bd1f6d01d621410d31c6fc00986f5eb687824e7b93d7a9db";
const MOCK_LLM = join(HERE, "mock-llm", "server.mjs");
const RUNTIME = { mock: "node-mock-llm", "llama.cpp": "llama.cpp/llama-server" };

const { values } = parseArgs({ options: { out: { type: "string", default: "dist" } }, strict: true });
const OUT = resolve(HERE, values.out);

const composeModule = join(HERE, "dist", "compose.js");
if (!existsSync(composeModule)) {
  process.stderr.write("build.mjs: dist/compose.js missing — run `tsc -b` first (npm run build does)\n");
  process.exit(1);
}
const { makeCompose, makeVpnCompose, composeBytes, VPN_DOH_PRODUCTION, VPN_DOH_TEST } = await import(pathToFileURL(composeModule).href);
const { measureRuntime } = await import(pathToFileURL(join(HERE, "dist", "mock-tdx", "runtime.js")).href);
const LLAMA_SERVER = process.env.PLR_LLAMA_SERVER || "/opt/homebrew/bin/llama-server";
let nodeRuntime, llamaRuntime;
try {
  nodeRuntime = await measureRuntime(process.execPath);
} catch (e) {
  process.stderr.write(`build.mjs: cannot measure the node runtime (${e?.code ?? "error"})\n`);
  process.exit(1);
}
try {
  llamaRuntime = await measureRuntime(LLAMA_SERVER);
} catch (e) {
  process.stderr.write(`build.mjs: cannot measure llama-server at ${LLAMA_SERVER} (${e?.code ?? "error"}); set PLR_LLAMA_SERVER\n`);
  process.exit(1);
}
const RUNTIME_SHA = { mock: nodeRuntime.digest, "llama.cpp": llamaRuntime.digest };

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
const mockLlmSha = sha256(readFileSync(MOCK_LLM));
const info = {
  llm: { "llama.cpp": QWEN_MODEL_SHA256, mock: mockLlmSha },
  runtime: { node_sha256: nodeRuntime.digest, llama_server_sha256: llamaRuntime.digest },
  variants: {},
};

const variants = [
  { name: "honest", entry: "src/entry.ts", bundle: "router.bundle.mjs", prefix: "app-compose" },
  { name: "evil-logger", entry: "evil/entry.ts", bundle: "evil-logger.bundle.mjs", prefix: "app-compose.evil-logger" },
];
for (const v of variants) {
  const bytes = await bundle(v.entry, v.bundle);
  const bundleSha = writeOut(v.bundle, bytes);
  const entry = { bundle: v.bundle, bundle_sha256: bundleSha, compose: {} };
  for (const [kindName, kind] of [["mock", "mock"], ["llama", "llama.cpp"]]) {
    const c = makeCompose({
      kind,
      modelSha256: info.llm[kind],
      runtime: RUNTIME[kind],
      runtimeSha256: RUNTIME_SHA[kind],
      bundleSha256: bundleSha,
      entry: v.bundle,
      nodeSha256: nodeRuntime.digest,
    });
    const file = `${v.prefix}.${kindName}.json`;
    const cb = composeBytes(c);
    writeOut(file, cb);
    entry.compose[kindName] = { file, compose_hash: sha256(cb) };
    if (v.name === "honest" && kindName === "mock") writeOut("app-compose.json", cb);
  }
  info.variants[v.name] = entry;
}

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
    Object.entries(info.variants)
      .map(([n, v]) => `  ${n.padEnd(12)} bundle ${v.bundle_sha256}  compose(mock) ${v.compose.mock.compose_hash}  compose(llama) ${v.compose.llama.compose_hash}\n`)
      .join("") +
    Object.entries(info.vpn)
      .map(([n, v]) => `  ${n.padEnd(16)} bundle ${v.bundle_sha256}  compose ${v.compose.compose_hash}\n`)
      .join(""),
);
