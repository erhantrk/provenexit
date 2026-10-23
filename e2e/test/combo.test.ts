// LOCKED — SPEC-COMBO: LLM router + VPN exit in one TEE (one measurement, two services, two registries).
import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { readFileSync, readdirSync, statSync } from "node:fs";
import { join } from "node:path";
import { PlrError, toHex, verifyReceipt } from "@plr/shared";
import { PrivateClient, VpnClient, type VpnStream } from "@plr/client";
import { startStack, type Stack, type ComboHandle, type Destination } from "../src/harness.js";

const SECRET = "combo-secret-" + Math.random().toString(36).slice(2);
let S: Stack;
let combo: ComboHandle;
let dest: Destination;

beforeAll(async () => {
  S = await startStack({ llm: "mock" });
  await S.approveComboBuild("combo-test");
  combo = await S.startCombo("combo-test");
  dest = await S.startDestination();
  S.dns.set("dest.plr.test", ["127.0.0.1"]);
}, 300_000);
afterAll(async () => { await S?.stop(); });

const llm = (url: string) => new PrivateClient({ routerUrl: url, registry: S.registry, trustedRoot: S.trustedRoot });
const vpn = (url: string) => new VpnClient({ exitUrl: url, registry: S.vpnRegistry, trustedRoot: S.trustedRoot });
async function codeOf(p: Promise<unknown>) {
  try { await p; } catch (e) { expect(e).toBeInstanceOf(PlrError); return (e as PlrError).code; }
  return "NO_THROW";
}
function httpOver(s: VpnStream, path: string): Promise<string> {
  return new Promise((ok) => {
    const chunks: Buffer[] = [];
    let done = false;
    const fin = () => { if (!done) { done = true; ok(Buffer.concat(chunks).toString("latin1")); } };
    s.on("data", (c: Buffer) => chunks.push(Buffer.from(c)));
    s.on("end", () => { s.end(); fin(); });
    s.on("error", fin);
    s.on("close", fin);
    s.write(`GET ${path} HTTP/1.1\r\nHost: dest\r\nConnection: close\r\n\r\n`);
  });
}

describe("1. both services from one measurement", () => {
  it("router and exit attest the same combo compose with different keys", async () => {
    const r = await llm(combo.routerUrl).attest();
    const v = await vpn(combo.vpnUrl).attest();
    expect(toHex(r.composeHash)).toBe(combo.composeHash);
    expect(toHex(v.composeHash)).toBe(combo.composeHash);
    expect(toHex(r.keyHash)).toBe(combo.routerKeyHash);
    expect(toHex(v.keyHash)).toBe(combo.vpnKeyHash);
    expect(combo.routerKeyHash).not.toBe(combo.vpnKeyHash);
    expect(r.osMeasurement).toEqual(v.osMeasurement);
  });

  it("private chat works through the combo router", async () => {
    const r = await llm(combo.routerUrl).chat({ messages: [{ role: "user", content: `${SECRET} hi` }], max_tokens: 8 });
    expect(r.content.length).toBeGreaterThan(0);
    expect(verifyReceipt(r.receipt, r.sig, r.verified.ed25519)).toBe(true);
    expect(r.receipt.compose_hash).toBe(combo.composeHash);
  });

  it("the VPN tunnel works through the combo exit (DoH name)", async () => {
    const s = await vpn(combo.vpnUrl).connect("dest.plr.test", dest.port);
    expect(await httpOver(s, `/${SECRET}/combo`)).toContain(`dest-ok:/${SECRET}/combo`);
    const { receipt } = await s.receipt();
    expect(receipt.compose_hash).toBe(combo.composeHash);
    expect(receipt.key_hash).toBe(combo.vpnKeyHash);
  });

  it("each role is registered on its own registry", async () => {
    expect(await S.registry.getInstance(combo.routerKeyHash)).not.toBeNull();
    expect(await S.vpnRegistry.getInstance(combo.vpnKeyHash)).not.toBeNull();
    expect(await S.registry.getInstance(combo.vpnKeyHash)).toBeNull();
    expect(await S.vpnRegistry.getInstance(combo.routerKeyHash)).toBeNull();
  });
});

describe("2. approval is per registry", () => {
  it("revoking the combo on the VPN registry stops the exit role only", async () => {
    await S.callVpn("owner", "revoke_compose", { hash: combo.composeHash });
    try {
      expect(await codeOf(vpn(combo.vpnUrl).connect("dest.plr.test", dest.port))).toBe("E_COMPOSE_NOT_ALLOWED");
      const r = await llm(combo.routerUrl).chat({ messages: [{ role: "user", content: "still up?" }], max_tokens: 4 });
      expect(r.content.length).toBeGreaterThan(0);
    } finally { await S.callVpn("owner", "allow_compose", { hash: combo.composeHash }); }
  });
  it("revoking it on the LLM registry stops the router role only", async () => {
    await S.call("owner", "revoke_compose", { hash: combo.composeHash });
    try {
      expect(await codeOf(llm(combo.routerUrl).attest())).toBe("E_COMPOSE_NOT_ALLOWED");
      const s = await vpn(combo.vpnUrl).connect("dest.plr.test", dest.port);
      expect(await httpOver(s, "/vpn-still-up")).toContain("dest-ok:/vpn-still-up");
    } finally { await S.call("owner", "allow_compose", { hash: combo.composeHash }); }
  });
});

describe("3. the exit cannot reach the router or the LLM (production combo)", () => {
  it("refuses loopback targets, including the router's own port", async () => {
    await S.approveComboBuild("combo");
    const prod = await S.startCombo("combo");
    expect(prod.composeHash).not.toBe(combo.composeHash);
    const c = vpn(prod.vpnUrl);
    for (const host of ["127.0.0.1", "::1", "localhost"])
      expect(await codeOf(c.connect(host, prod.routerPort)), host).toBe("E_EGRESS_DENIED");
    await prod.stop();
  });
});

describe("4. no retention across either service", () => {
  it("neither the prompt nor the VPN payload appears in combo output or the run directory", async () => {
    await llm(combo.routerUrl).chat({ messages: [{ role: "user", content: `${SECRET} again` }], max_tokens: 4 });
    await httpOver(await vpn(combo.vpnUrl).connect("dest.plr.test", dest.port), `/${SECRET}/again`);
    expect(combo.output()).not.toContain(SECRET);
    const walk = (d: string): string[] => readdirSync(d).flatMap((f) => { const p = join(d, f); return statSync(p).isDirectory() ? walk(p) : [p]; });
    for (const f of walk(S.runDir)) {
      if (statSync(f).size > 5_000_000) continue;
      expect(readFileSync(f).includes(Buffer.from(SECRET)), `secret found in ${f}`).toBe(false);
    }
  });
});
