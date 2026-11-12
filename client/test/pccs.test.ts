// T24 (TASKS) + R7: in INTEL mode the client fetches fresh Intel collateral from a PCCS itself BY DEFAULT
// (`getCollateral(url, quote)`, Intel's PCS unless `PLR_PCCS_URL` names another), right before the DCAP check, and
// refuses the exit when it cannot (E_COLLATERAL_FETCH). `PLR_PCCS_URL=exit` opts out. The fake PCCS serves the recorded dcap-qvl sample
// collateral, so the real `@phala/dcap-qvl` `getCollateral` runs (quote PCK chain → CRL / TCB / QE identity / root
// CA CRL endpoints) and its output is a genuine Intel-signed collateral set for TV-Q1.
import { readFileSync } from "node:fs";
import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { ed25519 } from "@noble/curves/ed25519.js";
import { afterEach, describe, expect, it } from "vitest";
import {
  DcapQvlVerifier,
  INTEL_ROOT_P256,
  PlrError,
  toHex,
  type AttestationBundle,
  type CollateralJson,
  type ParsedQuote,
  type QuoteVerifier,
  type RegistryReader,
  type VerifyContext,
} from "@plr/shared";
import {
  AttestationCache, COLLATERAL_FROM_EXIT, COLLATERAL_LINE, CollateralFetchError, DEFAULT_PCCS_URL, VpnClient, collateralSource, fetchPccsCollateral, isPccsUrl, loadVpnConfig,
} from "../src/index.js";
import { checkLines, formatCheckLine } from "../src/verify-report.js";

const VECTORS = new URL("../../packages/shared/test/vectors/dcap/", import.meta.url);
const QUOTE = new Uint8Array(readFileSync(new URL("tdx_quote.bin", VECTORS)));
/** dcap-qvl's sample collateral (SPEC-TDX TV-Q1), valid 2025-06-19..2025-07-19: verify at 2025-06-20T00:00:00Z. */
const SAMPLE = JSON.parse(readFileSync(new URL("tdx_quote_collateral.json", VECTORS), "utf8")) as CollateralJson;
const TV_Q1_NOW_MS = 1_750_377_600_000;

/** A syntactically valid collateral object the exit might serve; never the one the PCCS returns. */
const STALE: CollateralJson = {
  pck_crl_issuer_chain: "stale-pck-crl-chain",
  tcb_info_issuer_chain: "stale-tcb-chain",
  tcb_info: '{"id":"TDX","fmspc":"000000000000"}',
  qe_identity_issuer_chain: "stale-qe-chain",
  qe_identity: '{"id":"TD_QE"}',
  root_ca_crl: "00",
  pck_crl: "00",
  tcb_info_signature: "00",
  qe_identity_signature: "00",
};

/** A local PCCS speaking the dcap-qvl endpoints, answering with the recorded sample collateral. */
class FakePccs {
  readonly paths: string[] = [];
  #server: Server | undefined;
  #url = "";

  get url(): string {
    return this.#url;
  }

  async start(): Promise<this> {
    this.#server = createServer((req, res) => {
      const u = new URL(req.url ?? "/", "http://pccs.test");
      this.paths.push(u.pathname);
      // `getCollateral` reads the issuer chains from headers and decodes them with decodeURIComponent.
      const header = (name: string, value: string): void => res.setHeader(name, encodeURIComponent(value));
      if (u.pathname === "/sgx/certification/v4/pckcrl") {
        header("SGX-PCK-CRL-Issuer-Chain", SAMPLE.pck_crl_issuer_chain!);
        res.end(Buffer.from(SAMPLE.pck_crl!, "hex"));
      } else if (u.pathname === "/tdx/certification/v4/tcb") {
        header("SGX-TCB-Info-Issuer-Chain", SAMPLE.tcb_info_issuer_chain!);
        res.end(`{"tcbInfo":${SAMPLE.tcb_info},"signature":"${SAMPLE.tcb_info_signature}"}`);
      } else if (u.pathname === "/tdx/certification/v4/qe/identity") {
        header("SGX-Enclave-Identity-Issuer-Chain", SAMPLE.qe_identity_issuer_chain!);
        res.end(`{"enclaveIdentity":${SAMPLE.qe_identity},"signature":"${SAMPLE.qe_identity_signature}"}`);
      } else if (u.pathname === "/sgx/certification/v4/rootcacrl") {
        res.end(SAMPLE.root_ca_crl);
      } else {
        res.statusCode = 404;
        res.end();
      }
    });
    await new Promise<void>((resolve) => this.#server!.listen(0, "127.0.0.1", resolve));
    this.#url = `http://127.0.0.1:${(this.#server!.address() as AddressInfo).port}`;
    return this;
  }

  async stop(): Promise<void> {
    const s = this.#server;
    this.#server = undefined;
    if (s !== undefined) await new Promise<void>((resolve) => s.close(() => resolve()));
  }
}

/** Records the verification context, then fails: what matters here is what the verifier was handed. */
class RecordingVerifier implements QuoteVerifier {
  readonly rootKind = "INTEL" as const;
  readonly calls: (VerifyContext | undefined)[] = [];
  constructor(readonly rootPublicKey: Uint8Array = INTEL_ROOT_P256) {}
  verify(_quote: Uint8Array, ctx?: VerifyContext): ParsedQuote {
    this.calls.push(ctx);
    throw new PlrError("E_QUOTE_SIG", "recorded");
  }
}

const registry: RegistryReader = {
  chain: "near",
  contractId: "pe-vpnreg-erhan.testnet",
  getRoot: async () => ({ kind: "INTEL", p256: toHex(INTEL_ROOT_P256) }),
  isComposeAllowed: async () => true,
  isOsAllowed: async () => true,
  getInstance: async () => null,
  getAnchor: async () => null,
};

/** Passes `verifyAttestation`'s shape and root checks so the verifier is reached; the quote is the real TV-Q1. */
function bundleWith(collateral: CollateralJson): AttestationBundle {
  return {
    v: "PLR-v1",
    root_kind: "INTEL",
    quote: toHex(QUOTE),
    event_log: [],
    app_compose: "{}",
    x25519: "11".repeat(32),
    ed25519: toHex(ed25519.getPublicKey(ed25519.utils.randomSecretKey())),
    collateral,
  };
}

type FetchCollateral = (pccsUrl: string, quote: Uint8Array) => Promise<Record<string, unknown>>;

function cache(o: { bundle: AttestationBundle; verifier: QuoteVerifier; pccsUrl?: string; fetchCollateral?: FetchCollateral }): AttestationCache {
  return new AttestationCache({
    fetchBundle: async () => o.bundle,
    verifier: o.verifier,
    registry,
    trustedRoot: INTEL_ROOT_P256,
    ttlMs: 0,
    clock: () => 0,
    ...(o.pccsUrl !== undefined ? { pccsUrl: o.pccsUrl } : {}),
    ...(o.fetchCollateral !== undefined ? { fetchCollateral: o.fetchCollateral } : {}),
  });
}

const codeOf = async (p: Promise<unknown>): Promise<string> => {
  try {
    await p;
  } catch (e) {
    return e instanceof PlrError ? e.code : `not-a-PlrError: ${String(e)}`;
  }
  return "no error";
};

let pccs: FakePccs | undefined;
afterEach(async () => {
  await pccs?.stop();
  pccs = undefined;
});

describe("fetchPccsCollateral", () => {
  it("fetches the quote's collateral from the PCCS and it verifies (TV-Q1 with the real Intel signature)", async () => {
    pccs = await new FakePccs().start();
    const collateral = await fetchPccsCollateral(pccs.url, QUOTE);
    // Canonical wire form (§1.2): binary fields lowercase hex, issuer chains as PEM, pck_certificate_chain kept.
    expect(collateral.root_ca_crl).toBe(SAMPLE.root_ca_crl);
    expect(collateral.pck_crl).toBe(SAMPLE.pck_crl);
    expect(collateral.pck_certificate_chain).toMatch(/^-----BEGIN CERTIFICATE-----/);
    const verifier = new DcapQvlVerifier(INTEL_ROOT_P256, { clock: () => TV_Q1_NOW_MS });
    verifier.verify(QUOTE, { collateral });
    expect(verifier.lastStatus).toBe("UpToDate");
    expect(pccs.paths).toEqual(
      expect.arrayContaining([
        "/sgx/certification/v4/pckcrl",
        "/tdx/certification/v4/tcb",
        "/tdx/certification/v4/qe/identity",
      ]),
    );
  });
});

describe("AttestationCache.attest: fresh collateral (T24, R7)", () => {
  it("default-on: with no PLR_PCCS_URL the client fetches from the default PCCS and the verifier gets that copy", async () => {
    const verifier = new RecordingVerifier();
    const asked: string[] = [];
    const c = cache({
      bundle: bundleWith(STALE),
      verifier,
      fetchCollateral: async (url, quote) => {
        asked.push(url);
        expect(toHex(quote)).toBe(toHex(QUOTE));
        return SAMPLE;
      },
    });
    expect(c.collateral).toEqual({ source: "pccs", url: DEFAULT_PCCS_URL });
    expect(DEFAULT_PCCS_URL).toBe("https://api.trustedservices.intel.com");
    expect(await codeOf(c.attest())).toBe("E_QUOTE_SIG");
    expect(asked).toEqual([DEFAULT_PCCS_URL]);
    expect(verifier.calls).toHaveLength(1);
    expect(verifier.calls[0]?.collateral).toEqual(SAMPLE);
  });

  it("default-on fails closed: a PCCS failure refuses with E_COLLATERAL_FETCH and never falls back to the exit's copy", async () => {
    const verifier = new RecordingVerifier();
    const c = cache({ bundle: bundleWith(STALE), verifier, fetchCollateral: async () => Promise.reject(new Error("pccs down")) });
    expect(await codeOf(c.attest())).toBe("E_COLLATERAL_FETCH");
    expect(verifier.calls).toHaveLength(0);
  });

  // Moved here from packages/shared (the check lives in the client: the shared package is in the measured exit image).
  it("a PCCS answer that is not collateral is E_COLLATERAL_FETCH: the exit's copy is never a fallback", async () => {
    const verifier = new RecordingVerifier();
    const c = cache({ bundle: bundleWith(STALE), verifier, fetchCollateral: async () => ({ not: "collateral" }) });
    const e = await c.attest().catch((x: unknown) => x);
    expect(e).toBeInstanceOf(CollateralFetchError);
    expect((e as PlrError).code).toBe("E_COLLATERAL_FETCH");
    expect(verifier.calls).toHaveLength(0);
  });

  it("the fetch runs right before the DCAP check: an earlier failing check keeps its own code and no PCCS is asked", async () => {
    let fetched = 0;
    const fetchCollateral: FetchCollateral = async () => {
      fetched++;
      return SAMPLE;
    };
    // response shape (check 1)
    const noKeys = { ...bundleWith(STALE), x25519: "00".repeat(32) };
    const v1 = new RecordingVerifier();
    expect(await codeOf(cache({ bundle: noKeys, verifier: v1, fetchCollateral }).attest())).toBe("E_BAD_RESPONSE");
    // pinned root (the check right before the collateral one)
    const otherRoot = INTEL_ROOT_P256.slice();
    otherRoot[0] = otherRoot[0]! ^ 1;
    const v2 = new RecordingVerifier(otherRoot);
    expect(await codeOf(cache({ bundle: bundleWith(STALE), verifier: v2, fetchCollateral }).attest())).toBe("E_ROOT_UNTRUSTED");
    expect(fetched).toBe(0);
    expect(v1.calls).toHaveLength(0);
    expect(v2.calls).toHaveLength(0);
  });

  it("reads the registry root once per attestation and runs the real verifier once, on the fresh copy", async () => {
    const verifier = new RecordingVerifier();
    let roots = 0;
    const counting: RegistryReader = {
      ...registry,
      getRoot: async () => {
        roots++;
        return registry.getRoot();
      },
    };
    const c = new AttestationCache({
      fetchBundle: async () => bundleWith(STALE),
      verifier,
      registry: counting,
      trustedRoot: INTEL_ROOT_P256,
      ttlMs: 0,
      clock: () => 0,
      fetchCollateral: async () => SAMPLE,
    });
    expect(await codeOf(c.attest())).toBe("E_QUOTE_SIG");
    expect(roots).toBe(1);
    expect(verifier.calls).toHaveLength(1);
    expect(verifier.calls[0]?.collateral).toEqual(SAMPLE);
  });

  it("opt-out: PLR_PCCS_URL=exit uses the exit's collateral and contacts no PCCS", async () => {
    const verifier = new RecordingVerifier();
    let fetched = 0;
    const c = cache({
      bundle: bundleWith(STALE),
      verifier,
      pccsUrl: COLLATERAL_FROM_EXIT,
      fetchCollateral: async () => {
        fetched++;
        return SAMPLE;
      },
    });
    expect(c.collateral).toEqual({ source: "exit" });
    expect(await codeOf(c.attest())).toBe("E_QUOTE_SIG");
    expect(fetched).toBe(0);
    expect(verifier.calls[0]?.collateral).toEqual(STALE);
  });

  it("an explicit PLR_PCCS_URL: fetches fresh collateral from that PCCS right before the DCAP check", async () => {
    pccs = await new FakePccs().start();
    const verifier = new RecordingVerifier();
    expect(await codeOf(cache({ bundle: bundleWith(STALE), verifier, pccsUrl: pccs.url }).attest())).toBe("E_QUOTE_SIG");
    expect(verifier.calls).toHaveLength(1);
    const got = verifier.calls[0]?.collateral as CollateralJson;
    expect(got.pck_crl).toBe(SAMPLE.pck_crl);
    expect(got.root_ca_crl).toBe(SAMPLE.root_ca_crl);
    expect(got.tcb_info_issuer_chain).toBe(SAMPLE.tcb_info_issuer_chain);
    expect(got).not.toEqual(STALE);
    expect(pccs.paths.length).toBeGreaterThan(0);
  });

  it("fails closed with E_COLLATERAL_FETCH when the PCCS is unreachable, before the verifier runs", async () => {
    const verifier = new RecordingVerifier();
    const c = cache({ bundle: bundleWith(STALE), verifier, pccsUrl: "http://127.0.0.1:1" });
    expect(await codeOf(c.attest())).toBe("E_COLLATERAL_FETCH");
    expect(verifier.calls).toHaveLength(0);
  });

  it("fails closed when the PCCS answers but not in time (the fetch is bounded)", async () => {
    const stalled = createServer(() => undefined);
    await new Promise<void>((resolve) => stalled.listen(0, "127.0.0.1", resolve));
    try {
      const url = `http://127.0.0.1:${(stalled.address() as AddressInfo).port}`;
      const t = Date.now();
      expect(await codeOf(fetchPccsCollateral(url, QUOTE, 200))).toBe("E_COLLATERAL_FETCH");
      expect(Date.now() - t).toBeLessThan(5_000);
    } finally {
      stalled.closeAllConnections();
      await new Promise<void>((resolve) => stalled.close(() => resolve()));
    }
  });

  it("never contacts the PCCS for a MOCK verifier (collateral is an INTEL-mode input)", async () => {
    pccs = await new FakePccs().start();
    const mock: QuoteVerifier = {
      rootKind: "MOCK",
      rootPublicKey: new Uint8Array(64),
      verify: () => {
        throw new PlrError("E_QUOTE_SIG", "mock");
      },
    };
    // The bundle is INTEL-shaped, so verification fails at the root_kind shape check; no PCCS request may happen.
    expect(await codeOf(cache({ bundle: bundleWith(STALE), verifier: mock, pccsUrl: pccs.url }).attest())).toBe("E_BAD_RESPONSE");
    expect(pccs.paths).toEqual([]);
  });
});

describe("PLR_PCCS_URL config", () => {
  const base = {
    PLR_NEAR_RPC: "https://rpc.testnet.fastnear.com",
    PLR_TRUSTED_ROOT: toHex(INTEL_ROOT_P256),
    PLR_VPN_REGISTRY: "vpnreg.pe-owner-erhan.testnet",
  };

  it("accepts an https PCCS, the `exit` opt-out, and leaves it undefined (= the default PCCS) when unset", () => {
    expect(loadVpnConfig({ ...base, PLR_PCCS_URL: "https://pccs.phala.network" }).pccsUrl).toBe("https://pccs.phala.network");
    expect(loadVpnConfig({ ...base, PLR_PCCS_URL: "exit" }).pccsUrl).toBe(COLLATERAL_FROM_EXIT);
    expect(loadVpnConfig(base).pccsUrl).toBeUndefined();
    expect(loadVpnConfig({ ...base, PLR_PCCS_URL: "" }).pccsUrl).toBeUndefined();
    expect(collateralSource(undefined)).toEqual({ source: "pccs", url: DEFAULT_PCCS_URL });
    expect(collateralSource("https://pccs.phala.network")).toEqual({ source: "pccs", url: "https://pccs.phala.network" });
    expect(collateralSource("exit")).toEqual({ source: "exit" });
  });

  it("a client pinned to the Intel root fetches from the default PCCS; a MOCK-root client has no collateral source", () => {
    const o = { exitUrl: "https://exit.example", registry };
    expect(new VpnClient({ ...o, trustedRoot: INTEL_ROOT_P256 }).collateral).toEqual({ source: "pccs", url: DEFAULT_PCCS_URL });
    expect(new VpnClient({ ...o, trustedRoot: INTEL_ROOT_P256, pccsUrl: "exit" }).collateral).toEqual({ source: "exit" });
    const mockRoot = new Uint8Array(64);
    mockRoot.set(INTEL_ROOT_P256);
    const mock: QuoteVerifier = { rootKind: "MOCK", rootPublicKey: mockRoot, verify: () => { throw new PlrError("E_QUOTE_SIG"); } };
    expect(new VpnClient({ ...o, trustedRoot: INTEL_ROOT_P256, verifier: mock }).collateral).toBeUndefined();
  });

  it("rejects a non-https or oversized PCCS URL", () => {
    expect(isPccsUrl("https://pccs.phala.network")).toBe(true);
    expect(isPccsUrl("http://pccs.phala.network")).toBe(false);
    expect(isPccsUrl("file:///etc/passwd")).toBe(false);
    expect(isPccsUrl(`https://pccs.example/${"a".repeat(2048)}`)).toBe(false);
    for (const u of ["http://pccs.example", "pccs.example", "ftp://pccs.example"]) {
      expect(() => loadVpnConfig({ ...base, PLR_PCCS_URL: u }), u).toThrow(/PLR_PCCS_URL/);
    }
  });
});

describe("vpn verify lines for the collateral check", () => {
  const NAME = "fresh Intel collateral fetched by the client from the PCCS (not the exit's copy)";

  it("the check name is the client's own line", () => {
    expect(COLLATERAL_LINE).toBe(NAME);
  });
  const text = (e: unknown, collateral?: "pccs" | "exit" | "recorded"): string[] =>
    checkLines(e, undefined, { intel: true, ...(collateral !== undefined ? { collateral } : {}) }).map(formatCheckLine);

  it("INTEL: 17 lines, the collateral check right before the signature check; MOCK: unchanged 14", () => {
    const lines = text(undefined);
    expect(lines).toHaveLength(17);
    expect(lines[4]).toBe(`  ✔ ${NAME}`);
    expect(lines[3]).toBe("  ✔ pinned root == registry root == verifier root");
    expect(lines[5]).toBe("  ✔ quote signature chain to root");
    const mock = checkLines(undefined, undefined, {});
    expect(mock).toHaveLength(14);
    expect(mock.some((l) => l.name === NAME)).toBe(false);
  });

  it("a PCCS failure fails exactly that line; earlier lines passed, later ones did not run", () => {
    const lines = text(new CollateralFetchError());
    expect(lines[3]).toMatch(/^  ✔ /);
    expect(lines[4]).toBe(`  ✘ ${NAME}  [E_COLLATERAL_FETCH]`);
    expect(lines[5]).toBe("  · quote signature chain to root  (not checked)");
  });

  it("opt-out and fixture replay say the collateral was not fetched, and why", () => {
    expect(text(undefined, "exit")[4]).toBe(`  · ${NAME}  (not checked: PLR_PCCS_URL=exit, the exit's own copy is used)`);
    expect(text(undefined, "recorded")[4]).toBe(`  · ${NAME}  (not checked: offline replay uses the recorded collateral)`);
    expect(text(undefined, "recorded").filter((l) => l.startsWith("  ✔ "))).toHaveLength(16);
    // A later failure keeps the note on the collateral line.
    expect(text(new PlrError("E_TCB_STATUS"), "exit")[4]).toContain("PLR_PCCS_URL=exit");
  });
});
