// LOCKED — SPEC-CHAINS §2 (rev 1.4 client rule for registries that do not verify quotes on-chain)
import { describe, it, expect } from "vitest";
import {
  verifyAttestation, MockVerifier, MockTdxAttester, MemoryRegistry, PlrError, registrationReportData, reportData, toHex,
} from "../src/index.js";
import { fixture, hex, randomBytes } from "./helpers.js";

const CONTRACT = "evm:31337:0x00000000000000000000000000000000000000aa";
const OPERATOR = "0x1111111111111111111111111111111111111111";

async function codeOf(p: Promise<unknown>) {
  try { await p; } catch (e) { expect(e).toBeInstanceOf(PlrError); return (e as PlrError).code; }
  return "NO_THROW";
}

function setup(o: { quote?: (f: ReturnType<typeof fixture>) => Promise<Uint8Array | null>; verifiesOnChain?: boolean } = {}) {
  const f = fixture();
  const build = async () => {
    const rq = o.quote ? await o.quote(f) : (await f.attester.getQuote(registrationReportData(f.xp, f.ep, CONTRACT, OPERATOR))).quote;
    const reg = new MemoryRegistry({
      root: { kind: "MOCK", p256: toHex(f.root.publicKey) }, compose: [hex(f.composeHash)], os: [hex(f.osHash)],
      instances: { [hex(f.keyHash)]: { ...f.record, operator: OPERATOR } },
      contractId: CONTRACT, chain: "evm",
      verifiesOnChain: o.verifiesOnChain ?? false,
      registrationQuotes: rq ? { [hex(f.keyHash)]: hex(rq) } : {},
    });
    return reg;
  };
  return { f, build };
}

const run = async (f: ReturnType<typeof fixture>, registry: MemoryRegistry) => {
  const n = randomBytes(32);
  return verifyAttestation({ bundle: await f.bundle(n), nonce: n, verifier: new MockVerifier(f.root.publicKey), registry, trustedRoot: f.root.publicKey });
};

describe("registration evidence (verifiesOnChain = false)", () => {
  it("accepts a registration quote from the same boot bound to (contract, operator)", async () => {
    const { f, build } = setup();
    const v = await run(f, await build());
    expect(v.keyHash).toEqual(f.keyHash);
  });

  it("missing registration quote ⇒ E_REGISTRATION_EVIDENCE", async () => {
    const { f, build } = setup({ quote: async () => null });
    expect(await codeOf(run(f, await build()))).toBe("E_REGISTRATION_EVIDENCE");
  });

  it("quote bound to a different operator (front-running hijack) ⇒ E_REGISTRATION_EVIDENCE", async () => {
    const { f, build } = setup({ quote: async (f) => (await f.attester.getQuote(registrationReportData(f.xp, f.ep, CONTRACT, "0x2222222222222222222222222222222222222222"))).quote });
    expect(await codeOf(run(f, await build()))).toBe("E_REGISTRATION_EVIDENCE");
  });

  it("quote bound to a different registry ⇒ E_REGISTRATION_EVIDENCE", async () => {
    const { f, build } = setup({ quote: async (f) => (await f.attester.getQuote(registrationReportData(f.xp, f.ep, "evm:1:0x00000000000000000000000000000000000000bb", OPERATOR))).quote });
    expect(await codeOf(run(f, await build()))).toBe("E_REGISTRATION_EVIDENCE");
  });

  it("a SESSION quote offered as registration evidence ⇒ E_REGISTRATION_EVIDENCE", async () => {
    const { f, build } = setup({ quote: async (f) => (await f.attester.getQuote(reportData(f.xp, f.ep, randomBytes(32)))).quote });
    expect(await codeOf(run(f, await build()))).toBe("E_REGISTRATION_EVIDENCE");
  });

  it("quote from a different boot (other instance-id ⇒ other RTMR3) ⇒ E_REGISTRATION_EVIDENCE", async () => {
    const { f, build } = setup({
      quote: async (f) => {
        const other = new MockTdxAttester({ root: f.root, composeBytes: f.composeBytes }); // same root + compose, fresh boot
        return (await other.getQuote(registrationReportData(f.xp, f.ep, CONTRACT, OPERATOR))).quote;
      },
    });
    expect(await codeOf(run(f, await build()))).toBe("E_REGISTRATION_EVIDENCE");
  });

  it("garbage / truncated quote ⇒ E_REGISTRATION_EVIDENCE", async () => {
    const { f, build } = setup({ quote: async () => randomBytes(828) });
    expect(await codeOf(run(f, await build()))).toBe("E_REGISTRATION_EVIDENCE");
    const { f: f2, build: b2 } = setup({ quote: async () => randomBytes(10) });
    expect(await codeOf(run(f2, await b2()))).toBe("E_REGISTRATION_EVIDENCE");
  });

  it("verifiesOnChain = true (tier A) skips the step entirely", async () => {
    const { f, build } = setup({ quote: async () => null, verifiesOnChain: true });
    expect((await run(f, await build())).keyHash).toEqual(f.keyHash);
  });

  it("MemoryRegistry defaults to verifiesOnChain = true and returns configured quotes", async () => {
    const f = fixture();
    expect(f.registry.verifiesOnChain).toBe(true);
    const { build } = setup();
    const reg = await build();
    expect(reg.verifiesOnChain).toBe(false);
    expect(await reg.getRegistrationQuote(hex(f.keyHash))).toBeNull();
  });
});
