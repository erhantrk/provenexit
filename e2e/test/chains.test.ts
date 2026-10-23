// LOCKED — SPEC-CHAINS: the same conformance scenarios on every registry chain.
// Chains under test: PLR_E2E_CHAINS (comma list, default "near"), e.g. PLR_E2E_CHAINS=near,zcash
import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { PlrError, parseQuote, registrationReportData, fromHex, toHex } from "@plr/shared";
import { randomBytes } from "@noble/hashes/utils.js";
import { PrivateClient, VpnClient, type VpnStream } from "@plr/client";
import { startStack, type Stack, type RouterHandle, type Chain } from "../src/harness.js";

const CHAINS = (process.env.PLR_E2E_CHAINS ?? "near").split(",").map((s) => s.trim()).filter(Boolean) as Chain[];

async function codeOf(p: Promise<unknown>) {
  try { await p; } catch (e) { expect(e).toBeInstanceOf(PlrError); return (e as PlrError).code; }
  return "NO_THROW";
}
/** Polls until `fn` returns true (chains confirm writes in blocks). */
async function eventually(fn: () => Promise<boolean>, ms = 45_000, what = "condition") {
  const t0 = Date.now();
  for (;;) {
    if (await fn().catch(() => false)) return;
    if (Date.now() - t0 > ms) throw new Error(`timed out waiting for ${what}`);
    await new Promise((r) => setTimeout(r, 500));
  }
}
const h32 = () => toHex(randomBytes(32));
const msg = (s: string) => ({ messages: [{ role: "user", content: s }], max_tokens: 8 });

for (const chain of CHAINS) {
  describe(`chain: ${chain}`, () => {
    let S: Stack;
    let router: RouterHandle;
    const llm = (url: string) => new PrivateClient({ routerUrl: url, registry: S.registry, trustedRoot: S.trustedRoot });

    beforeAll(async () => {
      S = await startStack({ llm: "mock", chain });
      await S.admin.approveOperator("operator", "org-a");
      await S.approveBuild("honest");
      router = await S.startRouter("honest");
    }, 600_000);
    afterAll(async () => { await S?.stop(); });

    it("identifies its tier", () => {
      expect(S.chain).toBe(chain);
      expect(S.registry.verifiesOnChain).toBe(chain === "near");
    });

    it("reader reflects owner policy; a stranger cannot change it", async () => {
      const h = h32();
      await S.admin.allowCompose(h);
      await eventually(() => S.registry.isComposeAllowed(h), 45_000, "allowCompose");
      await S.admin.revokeCompose(h);
      await eventually(async () => !(await S.registry.isComposeAllowed(h)), 45_000, "revokeCompose");
      await S.admin.allowOs(h);
      await eventually(() => S.registry.isOsAllowed(h), 45_000, "allowOs");
      await S.admin.revokeOs(h);
      await eventually(async () => !(await S.registry.isOsAllowed(h)), 45_000, "revokeOs");
      const h2 = h32();
      await S.asStranger(S.admin).allowCompose(h2).catch(() => undefined);
      await S.admin.allowOs(h32()); // a later owner write: once visible, the stranger's earlier write had its chance too
      await new Promise((r) => setTimeout(r, 5_000));
      expect(await S.registry.isComposeAllowed(h2)).toBe(false);
    }, 240_000);

    it("private chat works through a router registered on this chain", async () => {
      const r = await llm(router.url).chat(msg("hello"));
      expect(r.content.length).toBeGreaterThan(0);
      expect(r.receipt.compose_hash).toBe(router.composeHash);
      expect(toHex(r.verified.keyHash)).toBe(router.keyHash);
    });

    it("registration evidence binds the on-chain operator (tier B/C)", async () => {
      const rec = (await S.registry.getInstance(router.keyHash))!;
      expect(rec).not.toBeNull();
      expect(rec.operator).toBe(S.accounts.operator);
      if (S.registry.verifiesOnChain) return;
      const b = await (await fetch(`${router.url}/v1/attestation?nonce=${toHex(randomBytes(32))}`)).json() as Record<string, string>;
      const offered = typeof b.registration_quote === "string" ? fromHex(b.registration_quote) : undefined;
      const rq = await S.registry.getRegistrationQuote(router.keyHash, offered);
      expect(rq).not.toBeNull();
      expect(parseQuote(rq!).report.reportData).toEqual(
        registrationReportData(fromHex(b.x25519!, 32), fromHex(b.ed25519!, 32), S.registry.contractId, rec.operator));
    });

    it("receipts are anchored and verify (incl. the anchor signature)", async () => {
      const c = llm(router.url);
      const r = await c.chat(msg("anchor me"));
      await eventually(async () => {
        try { return await c.verifyAnchored(r.receipt); }
        catch (e) { if ((e as PlrError).code === "E_NOT_ANCHORED") return false; throw e; }
      }, 120_000, "anchor");
    }, 180_000);

    it("revocation on this chain refuses the next session; re-approval restores it", async () => {
      await S.admin.revokeCompose(router.composeHash);
      await eventually(async () => (await codeOf(llm(router.url).attest())) === "E_COMPOSE_NOT_ALLOWED", 60_000, "revocation");
      await S.admin.allowCompose(router.composeHash);
      await eventually(async () => (await codeOf(llm(router.url).attest())) === "NO_THROW", 60_000, "re-approval");
    }, 180_000);

    it("an unapproved build is refused", async () => {
      const evil = await S.startRouter("evil-logger");
      expect(await codeOf(llm(evil.url).chat(msg("secret")))).toBe("E_COMPOSE_NOT_ALLOWED");
      await evil.stop();
    }, 180_000);

    it("an unregistered instance of an approved build is refused", async () => {
      const u = await S.startRouter("honest", { register: false });
      expect(await codeOf(llm(u.url).attest())).toBe("E_INSTANCE_NOT_REGISTERED");
      await u.stop();
    }, 180_000);

    it("the operator's organization is live", async () => {
      expect((await S.registry.getInstance(router.keyHash))!.org_id).toBe("org-a");
      await S.admin.approveOperator("operator", "org-b");
      await eventually(async () => (await S.registry.getInstance(router.keyHash))?.org_id === "org-b", 60_000, "org change");
    }, 120_000);

    it("a VPN exit registered on this chain tunnels end-to-end", async () => {
      await S.vpnAdmin.approveOperator("operator", "org-a");
      await S.approveVpnBuild("vpn-honest-test");
      const exit = await S.startExit("vpn-honest-test");
      const dest = await S.startDestination();
      S.dns.set("dest.plr.test", ["127.0.0.1"]);
      const s: VpnStream = await new VpnClient({ exitUrl: exit.url, registry: S.vpnRegistry, trustedRoot: S.trustedRoot }).connect("dest.plr.test", dest.port);
      const data = await new Promise<string>((ok) => {
        const chunks: Buffer[] = [];
        s.on("data", (c: Buffer) => chunks.push(Buffer.from(c)));
        s.on("end", () => { s.end(); ok(Buffer.concat(chunks).toString("latin1")); });
        s.on("error", () => ok(Buffer.concat(chunks).toString("latin1")));
        s.write("GET /chain-vpn HTTP/1.1\r\nHost: dest\r\nConnection: close\r\n\r\n");
      });
      expect(data).toContain("dest-ok:/chain-vpn");
    }, 300_000);
  });
}
