// Shared by scripts/build-status.mjs and mcp/build.mjs: one self-contained ESM file for Node >= 22 (no node_modules).
import { readFileSync } from "node:fs";
import * as esbuild from "esbuild";

/**
 * @plr/shared loads `@phala/dcap-qvl` (pure JS) through `createRequire(...)("@phala/dcap-qvl")`, which a bundler
 * cannot follow. This plugin rewrites exactly that call to a static import of the package, so it is inlined.
 */
const dcapPlugin = {
  name: "inline-dcap-qvl",
  setup(build) {
    build.onLoad({ filter: /[\\/]attest[\\/]intel\.js$/ }, (args) => {
      const src = readFileSync(args.path, "utf8");
      const call = 'require("@phala/dcap-qvl")';
      if (!src.includes(call)) throw new Error("inline-dcap-qvl: expected call not found in " + args.path);
      return { contents: 'import * as __dcapQvl from "@phala/dcap-qvl";\n' + src.replace(call, "__dcapQvl"), loader: "js" };
    });
  },
};

/** Bundles `entry` to `outfile`. `define` maps identifiers to JSON-serialisable values. `shebang` keeps a #! line first. */
export async function bundleSelfContained({ entry, outfile, define = {}, shebang }) {
  const result = await esbuild.build({
    entryPoints: [entry],
    outfile,
    bundle: true,
    platform: "node",
    format: "esm",
    target: "node22",
    sourcemap: false,
    legalComments: "none",
    minify: false,
    charset: "utf8",
    logLevel: "warning",
    plugins: [dcapPlugin],
    // CommonJS code inside the bundle (near-api-js dependencies, dcap-qvl) may call require() for node builtins.
    banner: { js: `${shebang ? shebang + "\n" : ""}import { createRequire as __plrCreateRequire } from "node:module";\nconst require = __plrCreateRequire(import.meta.url);` },
    define: Object.fromEntries(Object.entries(define).map(([k, v]) => [k, JSON.stringify(v)])),
  });
  return result;
}

/** Values of `export KEY=value` lines of an env file (no shell expansion except the `$NAME` of an earlier key). */
export function parseEnvFile(text) {
  const out = {};
  for (const line of text.split("\n")) {
    const m = /^export\s+([A-Z0-9_]+)=(.*)$/.exec(line.trim());
    if (!m) continue;
    let v = m[2].trim().replace(/^"(.*)"$/, "$1").replace(/^'(.*)'$/, "$1");
    v = v.replace(/\$\{?([A-Z0-9_]+)\}?/g, (_, k) => out[k] ?? "");
    out[m[1]] = v;
  }
  return out;
}
