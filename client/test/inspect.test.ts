// T15 — `plr vpn inspect` (TASKS T15 step 4). The owner uses these values to approve compose / OS on chain, so
// every security-relevant check it reports is exercised here: a synthetic INTEL bundle served over a local HTTP
// server and driven through `runCli(["vpn", "inspect"])`. The one thing a synthetic quote cannot provide is the
// Intel signature, so the verifier is injected exactly as `verifyFixture(dir, verifier)` does.
import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { ed25519, x25519 } from "@noble/curves/ed25519.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { randomBytes } from "@noble/hashes/utils.js";
import { afterEach, describe, expect, it } from "vitest";
import {
  INTEL_QE_VENDOR_ID, INTEL_ROOT_P256, PlrError, encodeQuote, fromHex, keyHash, makeEvent, mockOsReport,
  osMeasurement, parseQuote, replayRtmr3, reportData, toHex,
  type AttestationBundle, type PlrErrorCode, type QuoteVerifier, type TdReport, type TdxEvent,
} from "@plr/shared";
import { inspectIntelBundle, runCli } from "../src/index.js";

const enc = (s: string): Uint8Array => new TextEncoder().encode(s);
const EMPTY = new Uint8Array(0);

const IMAGE = `ghcr.io/erhantrk/provenexit-exit@sha256:${"ab".repeat(32)}`;
/** Same image, unpinned: checkDstackComposePolicy must refuse it (E_COMPOSE_POLICY). */
const UNPINNED = "ghcr.io/erhantrk/provenexit-exit:latest";

/** SPEC-TDX §1.4 app-compose with one digest-pinned exit image and logging disabled. */
function appCompose(image = IMAGE): string {
  const dockerComposeFile = `services:
  exit:
    image: ${image}
    restart: always
    read_only: true
    cap_drop: [ALL]
    security_opt: ["no-new-privileges:true"]
    logging:
      driver: none
    ports:
      - "18200:18200"
    volumes:
      - /var/run/dstack.sock:/var/run/dstack.sock
`;
  return JSON.stringify({
    manifest_version: 2,
    name: "provenexit-exit",
    runner: "docker-compose",
    docker_compose_file: dockerComposeFile,
    kms_enabled: true,
    gateway_enabled: true,
    public_logs: false,
    public_sysinfo: false,
    allowed_envs: ["PLR_OPERATOR_KEY"],
    no_instance_id: false,
    secure_time: false,
  });
}

/** The exit's per-boot keys (one set per test file: the quote and the bundle must agree). */
const xs = x25519.utils.randomSecretKey();
const xp = x25519.getPublicKey(xs);
const es = ed25519.utils.randomSecretKey();
const ep = ed25519.getPublicKey(es);
const KH = keyHash(xp, ep);

/** Canonical collateral shape (§1.2); the stub only checks that collateral is present. */
const COLLATERAL = {
  pck_crl_issuer_chain: "-----BEGIN CERTIFICATE-----\nstub\n-----END CERTIFICATE-----\n",
  tcb_info_issuer_chain: "-----BEGIN CERTIFICATE-----\nstub\n-----END CERTIFICATE-----\n",
  tcb_info: "{}",
  qe_identity_issuer_chain: "-----BEGIN CERTIFICATE-----\nstub\n-----END CERTIFICATE-----\n",
  qe_identity: "{}",
  root_ca_crl: "00",
  pck_crl: "00",
  tcb_info_signature: "00",
  qe_identity_signature: "00",
};

/** What the untrusted exit serves. One defect per case; "none" is an honest INTEL bundle. */
type Defect = "none" | "nonce" | "keys" | "compose" | "image" | "collateral" | "mock-root";

function buildBundle(nonce: Uint8Array, defect: Defect): AttestationBundle {
  const published = appCompose(defect === "image" ? UNPINNED : IMAGE);
  // "compose": the log measures a different app-compose than the one published.
  const measured = defect === "compose" ? `${published} ` : published;
  const composeHash = new Uint8Array(sha256(enc(measured)));
  const log: TdxEvent[] = [
    makeEvent("key-provider", enc("{}")),
    makeEvent("system-preparing", EMPTY),
    makeEvent("app-id", new Uint8Array(20).fill(0x11)),
    makeEvent("compose-hash", composeHash),
    makeEvent("instance-id", new Uint8Array(20).fill(0x22)),
    makeEvent("boot-mr-done", EMPTY),
    makeEvent("system-ready", EMPTY),
  ];
  // "nonce": the quote binds a different client nonce (the CLI mints a fresh random one per run).
  const rd = defect === "nonce" ? reportData(xp, ep, new Uint8Array(randomBytes(32))) : reportData(xp, ep, nonce);
  const base = mockOsReport();
  const report: TdReport = { ...base, reportData: rd, rtmr: [base.rtmr[0], base.rtmr[1], base.rtmr[2], replayRtmr3(log)] };
  const quote = encodeQuote({ qeVendorId: INTEL_QE_VENDOR_ID }, report, new Uint8Array(randomBytes(64)));
  return {
    v: "PLR-v1",
    root_kind: defect === "mock-root" ? "MOCK" : "INTEL",
    quote: toHex(quote),
    event_log: log,
    app_compose: published,
    // "keys": the bundle advertises the two keys swapped, so report_data no longer binds key_hash.
    x25519: toHex(defect === "keys" ? ep : xp),
    ed25519: toHex(defect === "keys" ? xp : ep),
    ...(defect === "collateral" ? {} : { collateral: COLLATERAL }),
  };
}

type StubVerifier = QuoteVerifier & { lastStatus?: string };

/** T09 stub verifier: only the Intel signature/TCB part is stubbed; parseQuote and every other check are real. */
function stubVerifier(fail?: PlrErrorCode): StubVerifier {
  return {
    rootKind: "INTEL",
    rootPublicKey: INTEL_ROOT_P256,
    verify(q, ctx) {
      if (fail !== undefined) throw new PlrError(fail);
      if (!ctx?.collateral) throw new PlrError("E_COLLATERAL");
      this.lastStatus = "UpToDate";
      return parseQuote(q, "INTEL");
    },
  };
}

const closers: (() => Promise<void>)[] = [];
afterEach(async () => {
  while (closers.length) await closers.pop()!();
});

async function serveBundle(make: (nonce: Uint8Array) => AttestationBundle): Promise<{ url: string; requests: string[]; close: () => Promise<void> }> {
  const requests: string[] = [];
  const server: Server = createServer((req, res) => {
    const url = new URL(req.url ?? "/", "http://127.0.0.1");
    if (req.method !== "GET" || url.pathname !== "/v1/attestation") {
      res.writeHead(404, { "content-type": "application/json" });
      res.end("{}");
      return;
    }
    const nonceHex = url.searchParams.get("nonce") ?? "";
    requests.push(nonceHex);
    const text = JSON.stringify(make(fromHex(nonceHex, 32)));
    res.writeHead(200, { "content-type": "application/json", "content-length": Buffer.byteLength(text) });
    res.end(text);
  });
  await new Promise<void>((ok) => server.listen(0, "127.0.0.1", ok));
  const { port } = server.address() as AddressInfo;
  return {
    url: `http://127.0.0.1:${port}`,
    requests,
    close: () => new Promise<void>((ok) => { server.closeAllConnections(); server.close(() => ok()); }),
  };
}

/** Runs `plr vpn inspect` against a server for `defect`, with the stub DCAP verifier. */
async function inspect(o: { defect?: Defect; verifier?: StubVerifier; fail?: PlrErrorCode } = {}) {
  const srv = await serveBundle((nonce) => buildBundle(nonce, o.defect ?? "none"));
  closers.push(srv.close);
  const out: string[] = [];
  const err: string[] = [];
  const code = await runCli(
    ["vpn", "inspect"],
    { PLR_VPN_URL: srv.url },
    { out: (s) => out.push(s), err: (s) => err.push(s) },
    undefined,
    o.verifier ?? stubVerifier(o.fail),
  );
  return { code, out, err, text: out.join("\n"), srv };
}

describe("plr vpn inspect: a good INTEL bundle", () => {
  it("prints exactly the five values the owner approves, and exits 0", async () => {
    const r = await inspect();
    expect(r.code).toBe(0);
    expect(r.text).not.toContain("✘");
    expect(r.text).toContain("PLR VPN inspect");
    expect(r.text).toContain("root:     INTEL ROOT (Intel SGX Root CA)");

    const lines = r.out.filter((l) => /^(compose hash|OS measurement|key hash|tcb|image):/.test(l));
    expect(lines).toEqual([
      `compose hash:    ${toHex(new Uint8Array(sha256(enc(appCompose()))))}`,
      `OS measurement:  ${toHex(osMeasurement(mockOsReport()))}`,
      `key hash:        ${toHex(KH)}`,
      `tcb:             UpToDate`,
      `image:           ${IMAGE}`,
    ]);
    // The CLI minted one fresh 32-byte nonce for the request.
    expect(r.srv.requests).toHaveLength(1);
    expect(r.srv.requests[0]).toMatch(/^[0-9a-f]{64}$/);
  });

  it("inspectIntelBundle is exported and applies the same rules without the CLI", () => {
    const nonce = new Uint8Array(randomBytes(32));
    const got = inspectIntelBundle(buildBundle(nonce, "none"), nonce, stubVerifier());
    expect(toHex(got.composeHash)).toBe(toHex(new Uint8Array(sha256(enc(appCompose())))));
    expect(toHex(got.keyHash)).toBe(toHex(KH));
    expect(got.tcbStatus).toBe("UpToDate");
    expect(got.images).toEqual([IMAGE]);
    expect(() => inspectIntelBundle(buildBundle(nonce, "none"), new Uint8Array(randomBytes(32)), stubVerifier())).toThrow(/E_NONCE/);
  });
});

describe("plr vpn inspect: every failing check exits 1 with ✘ <code>", () => {
  const cases: [string, { defect?: Defect; fail?: PlrErrorCode }][] = [
    ["a quote that binds another nonce", { defect: "nonce" }],
    ["swapped x25519 / ed25519 keys", { defect: "keys" }],
    ["a compose hash that does not match the app-compose", { defect: "compose" }],
    ["an unpinned image", { defect: "image" }],
    ["missing collateral", { defect: "collateral" }],
    ["a non-INTEL (MOCK) exit", { defect: "mock-root" }],
    ["a DCAP signature failure", { fail: "E_QUOTE_SIG" }],
  ];
  const expected: Record<string, PlrErrorCode> = {
    nonce: "E_NONCE",
    keys: "E_REPORT_DATA_KEYS",
    compose: "E_COMPOSE_MISMATCH",
    image: "E_COMPOSE_POLICY",
    collateral: "E_BAD_RESPONSE",
    "mock-root": "E_ROOT_UNTRUSTED",
  };

  for (const [name, o] of cases) {
    const code = o.fail ?? expected[o.defect ?? "none"]!;
    it(`${name} ⇒ ${code}`, async () => {
      const r = await inspect(o);
      expect(r.code).toBe(1);
      expect(r.text).toContain(`✘ ${code}`);
      // Fail closed: no value line is printed for a bundle that did not pass.
      expect(r.text).not.toMatch(/^(compose hash|OS measurement|key hash|tcb|image):/m);
    });
  }
});

describe("plr vpn inspect: usage", () => {
  it("refuses extra arguments and a non-http PLR_VPN_URL", async () => {
    const out: string[] = [];
    const err: string[] = [];
    const io = { out: (s: string) => out.push(s), err: (s: string) => err.push(s) };
    expect(await runCli(["vpn", "inspect", "extra"], {}, io)).toBe(2);
    expect(await runCli(["vpn", "inspect"], { PLR_VPN_URL: "file:///etc/passwd" }, io)).toBe(2);
    expect(err.join("\n")).toContain("PLR_VPN_URL");
  });
});
