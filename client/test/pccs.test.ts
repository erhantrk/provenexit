// T24 (TASKS): with `PLR_PCCS_URL` set, the client fetches fresh Intel collateral from the PCCS
// (`getCollateral(url, quote)`) inside `AttestationCache.attest()`, before `verifyAttestation`, and the verifier
// receives it through the bundle's `collateral` field. The fake PCCS serves the recorded dcap-qvl sample
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
import { AttestationCache, fetchPccsCollateral, isPccsUrl, loadVpnConfig } from "../src/index.js";

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

function cache(o: { bundle: AttestationBundle; verifier: QuoteVerifier; pccsUrl?: string }): AttestationCache {
  return new AttestationCache({
    fetchBundle: async () => o.bundle,
    verifier: o.verifier,
    registry,
    trustedRoot: INTEL_ROOT_P256,
    ttlMs: 0,
    clock: () => 0,
    ...(o.pccsUrl !== undefined ? { pccsUrl: o.pccsUrl } : {}),
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

describe("AttestationCache.attest with PLR_PCCS_URL (T24)", () => {
  it("fetches fresh collateral before verifyAttestation and passes it via the bundle field", async () => {
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

  it("uses the exit's collateral when PLR_PCCS_URL is not set (unchanged behaviour)", async () => {
    const verifier = new RecordingVerifier();
    expect(await codeOf(cache({ bundle: bundleWith(STALE), verifier }).attest())).toBe("E_QUOTE_SIG");
    expect(verifier.calls[0]?.collateral).toEqual(STALE);
  });

  it("fails closed with E_COLLATERAL when the PCCS is unreachable, before the verifier runs", async () => {
    const verifier = new RecordingVerifier();
    const c = cache({ bundle: bundleWith(STALE), verifier, pccsUrl: "http://127.0.0.1:1" });
    expect(await codeOf(c.attest())).toBe("E_COLLATERAL");
    expect(verifier.calls).toHaveLength(0);
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
    PLR_VPN_REGISTRY: "pe-vpnreg-erhan.testnet",
  };

  it("accepts an https PCCS and leaves it undefined when unset", () => {
    expect(loadVpnConfig({ ...base, PLR_PCCS_URL: "https://pccs.phala.network" }).pccsUrl).toBe("https://pccs.phala.network");
    expect(loadVpnConfig(base).pccsUrl).toBeUndefined();
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
