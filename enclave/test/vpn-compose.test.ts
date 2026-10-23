import { describe, expect, it } from "vitest";
import { canonicalJson, composeBytes, composeService, makeCompose, makeVpnCompose, parseCompose, parseVpnCompose, VPN_ENTRY } from "../src/compose.js";
import { loadExitConfig } from "../src/vpn/config.js";

const enc = (s: string) => new TextEncoder().encode(s);
const base = () => makeVpnCompose({ bundleSha256: "aa".repeat(32), nodeSha256: "bb".repeat(32), allowLoopback: false });
const bytesOf = (o: unknown) => enc(canonicalJson(o as never));
const code = (f: () => unknown) => { try { f(); } catch (e) { return (e as { code?: string }).code; } return "NO_THROW"; };

describe("VPN compose (SPEC-VPN §2)", () => {
  it("canonical form, exact schema, round-trips", () => {
    const b = composeBytes(base());
    expect(new TextDecoder().decode(b)).toBe(
      '{\n  "manifest_version": 1,\n  "name": "plr-vpn",\n  "policy": {\n    "disk": "none",\n    "egress": {\n      "allow_loopback": false,\n      "deny_private": true\n    },\n    "logs": "none"\n  },\n' +
        `  "vpn": {\n    "bundle_sha256": "${"aa".repeat(32)}",\n    "entry": "vpn.bundle.mjs",\n    "node_sha256": "${"bb".repeat(32)}"\n  }\n}\n`,
    );
    expect(parseVpnCompose(b)).toEqual(base());
    expect(composeService(b)).toBe("vpn");
    expect(VPN_ENTRY).toBe("vpn.bundle.mjs");
  });

  it("allow_loopback changes the bytes (a test build never passes as production)", () => {
    const t = composeBytes(makeVpnCompose({ bundleSha256: "aa".repeat(32), nodeSha256: "bb".repeat(32), allowLoopback: true }));
    expect(Buffer.from(t).equals(Buffer.from(composeBytes(base())))).toBe(false);
    expect(parseVpnCompose(t).policy.egress.allow_loopback).toBe(true);
  });

  it("rejects extras, missing keys, wrong values, non-canonical bytes", () => {
    const mut = (f: (o: any) => void) => { const o = JSON.parse(JSON.stringify(base())); f(o); return bytesOf(o); };
    const bad = [
      mut((o) => { o.extra = 1; }),
      mut((o) => { o.vpn.extra = 1; }),
      mut((o) => { o.policy.egress.extra = true; }),
      mut((o) => { delete o.policy.egress.allow_loopback; }),
      mut((o) => { o.policy.egress.deny_private = false; }),
      mut((o) => { o.policy.egress.allow_loopback = "true"; }),
      mut((o) => { o.policy.egress = []; }),
      mut((o) => { o.policy.disk = "rw"; }),
      mut((o) => { o.policy.logs = "stdout"; }),
      mut((o) => { o.name = "plr-router"; }),
      mut((o) => { o.manifest_version = 2; }),
      mut((o) => { o.vpn.entry = "evil.bundle.mjs"; }),
      mut((o) => { o.vpn.entry = "../vpn.bundle.mjs"; }),
      mut((o) => { o.vpn.bundle_sha256 = "AA".repeat(32); }),
      mut((o) => { o.vpn.node_sha256 = "bb"; }),
      enc(JSON.stringify(base())),                                   // not canonical (no indentation)
      enc(canonicalJson(base() as never).trimEnd()),                 // no trailing newline
      new Uint8Array(0),
      new Uint8Array(9000).fill(0x20),
      new Uint8Array([0xff, 0xfe]),
    ];
    for (const b of bad) expect(code(() => parseVpnCompose(b))).toBe("E_BAD_INPUT");
    expect(() => makeVpnCompose({ bundleSha256: "zz", nodeSha256: "bb".repeat(32), allowLoopback: false })).toThrow();
  });

  it("the services are disjoint: each parser refuses the other's compose; the router compose is unchanged", () => {
    const router = composeBytes(makeCompose({ kind: "mock", modelSha256: "11".repeat(32), runtime: "node", runtimeSha256: "33".repeat(32), bundleSha256: "22".repeat(32), entry: "router.bundle.mjs", nodeSha256: "33".repeat(32) }));
    const vpn = composeBytes(base());
    expect(composeService(router)).toBe("router");
    expect(code(() => parseCompose(vpn))).toBe("E_BAD_INPUT");
    expect(code(() => parseVpnCompose(router))).toBe("E_BAD_INPUT");
    expect(parseCompose(router).name).toBe("plr-router");
    expect(code(() => composeService(enc('{"name":"other"}')))).toBe("E_BAD_INPUT");
    expect(code(() => composeService(enc("[]")))).toBe("E_BAD_INPUT");
  });
});

describe("exit config (env from the host)", () => {
  const env = { PLR_TDX_SOCKET: "/tmp/q.sock", PLR_APP_COMPOSE_PATH: "/tmp/c.json" };
  it("defaults to 127.0.0.1:18200, unregistered", () => {
    const c = loadExitConfig(env);
    expect([c.host, c.port, c.near, c.nearConfigError]).toEqual(["127.0.0.1", 18200, null, false]);
  });
  it("PLR_VPN_PORT / PLR_VPN_HOST are validated", () => {
    expect(loadExitConfig({ ...env, PLR_VPN_PORT: "0", PLR_VPN_HOST: "0.0.0.0" }).port).toBe(0);
    for (const bad of [{ PLR_VPN_PORT: "70000" }, { PLR_VPN_PORT: "-1" }, { PLR_VPN_HOST: "example.com" }, { PLR_TDX_SOCKET: "" }]) {
      expect(code(() => loadExitConfig({ ...env, ...bad }))).toBe("E_BAD_INPUT");
    }
  });
  it("registers on PLR_VPN_REGISTRY (else PLR_REGISTRY); partial NEAR config disables registration", () => {
    const near = { PLR_NEAR_RPC: "http://127.0.0.1:3030", PLR_OPERATOR_ID: "op.test.near", PLR_OPERATOR_KEY: "ed25519:" + "1".repeat(64) };
    expect(loadExitConfig({ ...env, ...near, PLR_REGISTRY: "registry.test.near" }).near?.contractId).toBe("registry.test.near");
    expect(loadExitConfig({ ...env, ...near, PLR_REGISTRY: "registry.test.near", PLR_VPN_REGISTRY: "vpnregistry.test.near" }).near?.contractId).toBe("vpnregistry.test.near");
    const partial = loadExitConfig({ ...env, PLR_NEAR_RPC: "http://127.0.0.1:3030", PLR_VPN_REGISTRY: "vpnregistry.test.near" });
    expect([partial.near, partial.nearConfigError]).toEqual([null, true]);
  });
});
