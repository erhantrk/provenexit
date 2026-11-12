// T15 / SPEC-TDX §3.2: "Pinning the Intel SGX Root CA is what selects INTEL mode. There is no new env var."
// A wrong default is silent — an INTEL bundle verified with the MOCK verifier (or the reverse) — so both
// constructors are pinned here: the verifier class selected, its rootKind, and the behaviour that follows from it
// (the constructor is given no `verifier`, exactly like the CLI).
import { readFileSync } from "node:fs";
import { afterEach, describe, expect, it } from "vitest";
import { DcapQvlVerifier, INTEL_ROOT_P256, MockVerifier, PlrError } from "@plr/shared";
import { PrivateClient } from "../src/index.js";
import { ExitHop, resolveTimeouts } from "../src/vpn/hop.js";
import { makeFakeRouter } from "./fake-router.js";

const closers: (() => Promise<void>)[] = [];
afterEach(async () => {
  while (closers.length) await closers.pop()!();
});

const codeOf = async (p: Promise<unknown>): Promise<string> => {
  try {
    await p;
  } catch (e) {
    return e instanceof PlrError ? e.code : `non-PlrError: ${String(e)}`;
  }
  return "NO_THROW";
};

/** A real Intel-signed quote (TV-Q1): only a DcapQvlVerifier can even look at it. */
const TVQ1 = new Uint8Array(readFileSync(new URL("../../packages/shared/test/vectors/dcap/tdx_quote.bin", import.meta.url)));

describe("PrivateClient picks the verifier from the pinned root", () => {
  it("the Intel root selects DcapQvlVerifier: a MOCK bundle is then refused (root_kind)", async () => {
    const r = makeFakeRouter(); // serves a MOCK bundle and a MOCK registry
    const c = new PrivateClient({ routerUrl: "http://router.test", registry: r.registry, trustedRoot: INTEL_ROOT_P256, fetch: r.fetch });
    expect(c.rootKind).toBe("INTEL");
    // A MockVerifier would have accepted this bundle (the MOCK-root client below does); the INTEL default does not.
    expect(await codeOf(c.attest())).toBe("E_BAD_RESPONSE");
  });

  it("any other root still selects MockVerifier", async () => {
    const r = makeFakeRouter();
    const c = new PrivateClient({ routerUrl: "http://router.test", registry: r.registry, trustedRoot: r.root.publicKey, fetch: r.fetch });
    expect(c.rootKind).toBe("MOCK");
    await expect(c.attest()).resolves.toMatchObject({ rootKind: "MOCK" });
  });
});

describe("ExitHop picks the verifier from the pinned root", () => {
  async function hop(rootOf: (r: ReturnType<typeof makeFakeRouter>) => Uint8Array) {
    const r = makeFakeRouter();
    const srv = await r.listen();
    closers.push(srv.close);
    const h = new ExitHop({
      base: new URL(srv.url),
      registry: r.registry,
      trustedRoot: rootOf(r),
      verifier: undefined,
      attestTtlMs: 60_000,
      lookup: undefined,
      timeouts: resolveTimeouts({}),
      clock: () => 0,
    });
    return { r, h };
  }

  it("the Intel root selects DcapQvlVerifier, which demands Intel collateral", async () => {
    const { h } = await hop(() => INTEL_ROOT_P256);
    expect(h.verifier).toBeInstanceOf(DcapQvlVerifier);
    expect(h.verifier.rootKind).toBe("INTEL");
    expect(() => h.verifier.verify(TVQ1, {})).toThrow(/E_COLLATERAL/);
    // Same behaviour end to end: the hop refuses the MOCK bundle the fake exit serves.
    expect(await codeOf(h.attest())).toBe("E_BAD_RESPONSE");
  });

  it("any other root still selects MockVerifier", async () => {
    const { h } = await hop((r) => r.root.publicKey);
    expect(h.verifier).toBeInstanceOf(MockVerifier);
    expect(h.verifier.rootKind).toBe("MOCK");
    await expect(h.attest()).resolves.toMatchObject({ verified: expect.objectContaining({ rootKind: "MOCK" }) });
  });

  it("an explicit verifier is never overridden by the root", async () => {
    const r = makeFakeRouter();
    const mock = new MockVerifier(r.root.publicKey);
    const h = new ExitHop({
      base: new URL("http://127.0.0.1:18200"),
      registry: r.registry,
      trustedRoot: INTEL_ROOT_P256,
      verifier: mock,
      attestTtlMs: 60_000,
      lookup: undefined,
      timeouts: resolveTimeouts({}),
      clock: () => 0,
    });
    expect(h.verifier).toBe(mock);
  });
});
