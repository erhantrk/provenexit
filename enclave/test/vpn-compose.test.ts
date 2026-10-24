import { describe, expect, it } from "vitest";
import {
  MAX_DOH_RESOLVERS, VPN_DOH_PRODUCTION, VPN_DOH_TEST, VPN_ENTRY, canonicalJson, composeBytes, composeService, dohUrlProblem, makeCompose,
  makeVpnCompose, parseCompose, parseVpnCompose,
} from "../src/compose.js";
import { loadExitConfig } from "../src/vpn/config.js";

const enc = (s: string) => new TextEncoder().encode(s);
const base = () => makeVpnCompose({ bundleSha256: "aa".repeat(32), nodeSha256: "bb".repeat(32), allowLoopback: false });
const bytesOf = (o: unknown) => enc(canonicalJson(o as never));
const code = (f: () => unknown) => { try { f(); } catch (e) { return (e as { code?: string }).code; } return "NO_THROW"; };

describe("VPN compose (SPEC-VPN §2)", () => {
  it("canonical form, exact schema, round-trips", () => {
    const b = composeBytes(base());
    expect(new TextDecoder().decode(b)).toBe(
      '{\n  "manifest_version": 1,\n  "name": "plr-vpn",\n  "policy": {\n    "disk": "none",\n' +
        '    "dns": {\n      "doh": [\n        "https://1.1.1.1/dns-query",\n        "https://9.9.9.9/dns-query"\n      ]\n    },\n' +
        '    "egress": {\n      "allow_loopback": false,\n      "deny_private": true\n    },\n    "logs": "none"\n  },\n' +
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

  it("policy.dns.doh: production list on production builds, the local test resolver on loopback builds (SPEC-VPN §2)", () => {
    expect([...VPN_DOH_PRODUCTION]).toEqual(["https://1.1.1.1/dns-query", "https://9.9.9.9/dns-query"]);
    expect([...VPN_DOH_TEST]).toEqual(["http://127.0.0.1:18253/dns-query"]);
    expect(base().policy.dns.doh).toEqual([...VPN_DOH_PRODUCTION]);
    const t = makeVpnCompose({ bundleSha256: "aa".repeat(32), nodeSha256: "bb".repeat(32), allowLoopback: true });
    expect(t.policy.dns.doh).toEqual([...VPN_DOH_TEST]);
    expect(parseVpnCompose(composeBytes(t))).toEqual(t);
    // Resolver order is measured (arrays are not sorted by the canonical form).
    const swapped = makeVpnCompose({ bundleSha256: "aa".repeat(32), nodeSha256: "bb".repeat(32), allowLoopback: false, doh: [...VPN_DOH_PRODUCTION].reverse() });
    expect(Buffer.from(composeBytes(swapped)).equals(Buffer.from(composeBytes(base())))).toBe(false);
    expect(parseVpnCompose(composeBytes(swapped)).policy.dns.doh).toEqual([...VPN_DOH_PRODUCTION].reverse());
  });

  it("policy.dns.doh validation: IP-literal hosts, https only (loopback http only on allow_loopback builds), 1..4 unique", () => {
    const ok = (u: string, lb: boolean) => expect(dohUrlProblem(u, lb), `${u} lb=${lb}`).toBeNull();
    const no = (u: unknown, lb: boolean) => expect(dohUrlProblem(u, lb), `${String(u)} lb=${lb}`).not.toBeNull();
    for (const lb of [false, true]) {
      ok("https://1.1.1.1/dns-query", lb);
      ok("https://9.9.9.9:5053/dns-query", lb);
      ok("https://[2606:4700:4700::1111]/dns-query", lb);
      no("https://cloudflare-dns.com/dns-query", lb);          // a name would need bootstrap DNS
      no("https://dns.google./dns-query", lb);
      no("https://1.1.1.1/dns-query?dns=x", lb);                // query
      no("https://1.1.1.1/dns-query#f", lb);                    // fragment
      no("https://user:pw@1.1.1.1/dns-query", lb);              // credentials
      no("https://1.1.1.1:443/dns-query", lb);                  // not in normalised form
      no("HTTPS://1.1.1.1/dns-query", lb);
      no("https://01.1.1.1/dns-query", lb);                     // octal-ish IPv4 spelling
      no("https://16843009/dns-query", lb);                     // integer IPv4 spelling
      no("https://[::ffff:1.1.1.1]/dns-query", lb);
      no("https://10.0.0.53/dns-query", lb);                    // private resolver: egress policy applies
      no("https://169.254.169.254/dns-query", lb);
      no("https://[fe80::1]/dns-query", lb);
      no("ftp://1.1.1.1/dns-query", lb);
      no("http://1.1.1.1/dns-query", lb);                       // plain http to the internet: never
      no("http://127.0.0.2:18253/dns-query", lb);
      no("http://[::1]:18253/dns-query", lb);
      no("http://127.0.0.1/dns-query", lb);                     // explicit port required
      no("dns-query", lb);
      no("", lb);
      no(42, lb);
      no("https://1.1.1.1/" + "a".repeat(300), lb);
    }
    ok("http://127.0.0.1:18253/dns-query", true);
    no("http://127.0.0.1:18253/dns-query", false);              // loopback http is a test-build-only allowance
    ok("https://127.0.0.1:8443/dns-query", true);
    no("https://127.0.0.1:8443/dns-query", false);

    const mk = (allowLoopback: boolean, doh: string[]) => () => makeVpnCompose({ bundleSha256: "aa".repeat(32), nodeSha256: "bb".repeat(32), allowLoopback, doh });
    expect(code(mk(false, []))).toBe("E_BAD_INPUT");
    expect(code(mk(false, Array.from({ length: MAX_DOH_RESOLVERS + 1 }, (_, i) => `https://1.1.1.${i + 1}/dns-query`)))).toBe("E_BAD_INPUT");
    expect(code(mk(false, Array.from({ length: MAX_DOH_RESOLVERS }, (_, i) => `https://1.1.1.${i + 1}/dns-query`)))).toBe("NO_THROW");
    expect(code(mk(false, ["https://1.1.1.1/dns-query", "https://1.1.1.1/dns-query"]))).toBe("E_BAD_INPUT");
    expect(code(mk(false, [...VPN_DOH_TEST]))).toBe("E_BAD_INPUT");
    expect(code(mk(true, [...VPN_DOH_TEST, ...VPN_DOH_PRODUCTION]))).toBe("NO_THROW");
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
      mut((o) => { delete o.policy.dns; }),
      mut((o) => { o.policy.dns = { doh: [] }; }),
      mut((o) => { o.policy.dns = { doh: "https://1.1.1.1/dns-query" }; }),
      mut((o) => { o.policy.dns.extra = 1; }),
      mut((o) => { o.policy.dns.doh.push("https://dns.example/dns-query"); }),
      mut((o) => { o.policy.dns.doh = ["http://127.0.0.1:18253/dns-query"]; }),     // loopback http on a production build
      mut((o) => { o.policy.dns.doh = ["https://1.1.1.1/dns-query", null]; }),
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
  it("rev 1.3: no reserved-nonce configuration is left (session quotes are domain-separated instead)", () => {
    const c = loadExitConfig({ ...env, PLR_REGISTRY: "registry.test.near", PLR_VPN_REGISTRY: "vpnregistry.test.near" });
    expect(Object.keys(c).sort()).toEqual(["anchorIntervalMs", "composePath", "host", "near", "nearConfigError", "port", "registry", "tdxSocket"]);
  });
});
