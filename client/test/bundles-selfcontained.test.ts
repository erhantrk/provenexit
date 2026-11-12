// The committed status bundle and MCP bundle run without node_modules (Vercel, `npx`), so no npm package may be
// loaded at run time through createRequire/require: esbuild must have inlined it (scripts/esbuild-common.mjs).
import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";

const ROOT = new URL("../../", import.meta.url);
const BUNDLES = ["status/provenexit-status.mjs", "mcp/dist/provenexit-mcp.mjs"];
// A runtime require of a bare package name (not a node: builtin), e.g. createRequire(import.meta.url)("@phala/dcap-qvl").
const RUNTIME_PACKAGE = /(?:Require\d*\(import\.meta\.url\)|\brequire)\(\s*"(?!node:)(@[a-z0-9-]+\/[a-z0-9.-]+|dcap|near-api-js)[^"]*"\s*\)/;

describe("self-contained bundles", () => {
  for (const f of BUNDLES) {
    it(`${f} loads no npm package at run time`, () => {
      const src = readFileSync(new URL(f, ROOT), "utf8");
      expect(src.match(RUNTIME_PACKAGE)?.[0] ?? null).toBeNull();
    });
  }
});
