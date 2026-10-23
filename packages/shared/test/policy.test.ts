// LOCKED — SPEC §9
import { describe, it, expect } from "vitest";
import { x25519 } from "@noble/curves/ed25519.js";
import {
  verifyAttestation, MockVerifier, MockRoot, MockTdxAttester, MemoryRegistry, PlrError, makeEvent,
  type RegistryReader, type AttestationBundle,
} from "../src/index.js";
import { fixture, enc, hex, randomBytes, COMPOSE_OBJ } from "./helpers.js";

async function codeOf(p: Promise<unknown>) {
  try { await p; } catch (e) { expect(e).toBeInstanceOf(PlrError); return (e as PlrError).code; }
  return "NO_THROW";
}

function run(f: ReturnType<typeof fixture>, bundle: AttestationBundle, nonce: Uint8Array, o: { registry?: RegistryReader; trustedRoot?: Uint8Array; verifierRoot?: Uint8Array } = {}) {
  return verifyAttestation({
    bundle, nonce,
    verifier: new MockVerifier(o.verifierRoot ?? o.trustedRoot ?? f.root.publicKey),
    registry: o.registry ?? f.registry,
    trustedRoot: o.trustedRoot ?? f.root.publicKey,
  });
}

describe("verifyAttestation — happy path", () => {
  it("accepts an honest router and reports every check", async () => {
    const f = fixture();
    const n = randomBytes(32);
    const v = await run(f, await f.bundle(n), n);
    expect(v.x25519).toEqual(f.xp);
    expect(v.ed25519).toEqual(f.ep);
    expect(v.keyHash).toEqual(f.keyHash);
    expect(v.composeHash).toEqual(f.composeHash);
    expect(v.osMeasurement).toEqual(f.osHash);
    expect(v.rootKind).toBe("MOCK");
    expect(v.checks.length).toBeGreaterThanOrEqual(8);
  });
});

describe("verifyAttestation — each failure maps to exactly one code", () => {
  it("E_NONCE: replayed quote from an older session", async () => {
    const f = fixture();
    const old = randomBytes(32);
    const b = await f.bundle(old);
    expect(await codeOf(run(f, b, randomBytes(32)))).toBe("E_NONCE");
  });

  it("E_REPORT_DATA_KEYS: genuine quote re-advertised with an attacker key (MITM)", async () => {
    const f = fixture();
    const n = randomBytes(32);
    const attackerXp = x25519.getPublicKey(x25519.utils.randomSecretKey());
    expect(await codeOf(run(f, await f.bundle(n, { xp: attackerXp }), n))).toBe("E_REPORT_DATA_KEYS");
  });

  it("E_COMPOSE_MISMATCH: published compose differs from the measured one", async () => {
    const f = fixture();
    const n = randomBytes(32);
    const lie = JSON.stringify({ ...COMPOSE_OBJ, name: "honest-router" }, null, 2) + "\n";
    expect(await codeOf(run(f, await f.bundle(n, { compose: lie }), n))).toBe("E_COMPOSE_MISMATCH");
  });

  it("E_COMPOSE_NOT_ALLOWED: evil build (different compose) not on-chain", async () => {
    const evilCompose = JSON.stringify({ ...COMPOSE_OBJ, router: { ...COMPOSE_OBJ.router, bundle_sha256: "66".repeat(32) } }, null, 2) + "\n";
    const f = fixture({ composeStr: evilCompose });
    const good = fixture();
    const reg = new MemoryRegistry({
      root: { kind: "MOCK", p256: hex(f.root.publicKey) },
      compose: [hex(good.composeHash)], os: [hex(f.osHash)], instances: { [hex(f.keyHash)]: f.record },
    });
    const n = randomBytes(32);
    expect(await codeOf(run(f, await f.bundle(n), n, { registry: reg }))).toBe("E_COMPOSE_NOT_ALLOWED");
  });

  it("E_OS_NOT_ALLOWED", async () => {
    const f = fixture();
    const reg = new MemoryRegistry({
      root: { kind: "MOCK", p256: hex(f.root.publicKey) },
      compose: [hex(f.composeHash)], os: ["77".repeat(32)], instances: { [hex(f.keyHash)]: f.record },
    });
    const n = randomBytes(32);
    expect(await codeOf(run(f, await f.bundle(n), n, { registry: reg }))).toBe("E_OS_NOT_ALLOWED");
  });

  it("E_INSTANCE_NOT_REGISTERED: keys never published on-chain", async () => {
    const f = fixture();
    const reg = new MemoryRegistry({
      root: { kind: "MOCK", p256: hex(f.root.publicKey) }, compose: [hex(f.composeHash)], os: [hex(f.osHash)], instances: {},
    });
    const n = randomBytes(32);
    expect(await codeOf(run(f, await f.bundle(n), n, { registry: reg }))).toBe("E_INSTANCE_NOT_REGISTERED");
  });

  it("E_INSTANCE_NOT_REGISTERED: on-chain record disagrees with the attestation", async () => {
    const f = fixture();
    const reg = new MemoryRegistry({
      root: { kind: "MOCK", p256: hex(f.root.publicKey) }, compose: [hex(f.composeHash), "88".repeat(32)], os: [hex(f.osHash)],
      instances: { [hex(f.keyHash)]: { ...f.record, compose_hash: "88".repeat(32) } },
    });
    const n = randomBytes(32);
    expect(await codeOf(run(f, await f.bundle(n), n, { registry: reg }))).toBe("E_INSTANCE_NOT_REGISTERED");
  });

  it("E_DEBUG_TD", async () => {
    const f = fixture({ debug: true });
    const n = randomBytes(32);
    expect(await codeOf(run(f, await f.bundle(n), n))).toBe("E_DEBUG_TD");
  });

  it("E_QUOTE_SIG: quote from a different (fake) root", async () => {
    const f = fixture();
    const fake = new MockTdxAttester({ root: MockRoot.generate(), composeBytes: f.composeBytes });
    const n = randomBytes(32);
    expect(await codeOf(run(f, await f.bundle(n, { attester: fake }), n))).toBe("E_QUOTE_SIG");
  });

  it("E_ROOT_UNTRUSTED: client's pinned root differs from the registry's root", async () => {
    const f = fixture();
    const other = MockRoot.generate();
    const n = randomBytes(32);
    expect(await codeOf(run(f, await f.bundle(n), n, { trustedRoot: other.publicKey, verifierRoot: other.publicKey }))).toBe("E_ROOT_UNTRUSTED");
  });

  it("E_ROOT_UNTRUSTED: verifier root differs from the pinned root", async () => {
    const f = fixture();
    const n = randomBytes(32);
    expect(await codeOf(run(f, await f.bundle(n), n, { verifierRoot: MockRoot.generate().publicKey }))).toBe("E_ROOT_UNTRUSTED");
  });

  it("E_EVENT_LOG: tampered event log", async () => {
    const f = fixture();
    const n = randomBytes(32);
    const b = await f.bundle(n);
    b.event_log = [...b.event_log.slice(0, 2), makeEvent("compose-hash", new Uint8Array(32).fill(1)), ...b.event_log.slice(3)];
    expect(await codeOf(run(f, b, n))).toMatch(/^E_(EVENT_LOG|RTMR3)$/);
  });

  it("E_RTMR3: valid-looking log that does not replay to the quoted RTMR3", async () => {
    const f = fixture();
    const n = randomBytes(32);
    const b = await f.bundle(n);
    b.event_log = [...b.event_log, makeEvent("extra", enc("x"))];
    expect(await codeOf(run(f, b, n))).toBe("E_RTMR3");
  });

  it("E_BAD_RESPONSE: malformed bundle fields / root_kind mismatch", async () => {
    const f = fixture();
    const n = randomBytes(32);
    const b = await f.bundle(n);
    expect(await codeOf(run(f, { ...b, x25519: "XYZ" }, n))).toBe("E_BAD_RESPONSE");
    expect(await codeOf(run(f, { ...b, v: "PLR-v0" as "PLR-v1" }, n))).toBe("E_BAD_RESPONSE");
    expect(await codeOf(run(f, { ...b, root_kind: "INTEL" }, n))).toBe("E_BAD_RESPONSE");
    expect(await codeOf(run(f, { ...b, event_log: "nope" as never }, n))).toBe("E_BAD_RESPONSE");
    expect(await codeOf(run(f, b, randomBytes(31)))).toBe("E_BAD_RESPONSE");
  });

  it("E_QUOTE_FORMAT: truncated quote", async () => {
    const f = fixture();
    const n = randomBytes(32);
    const b = await f.bundle(n);
    expect(await codeOf(run(f, { ...b, quote: b.quote.slice(0, 1000) }, n))).toBe("E_QUOTE_FORMAT");
  });

  it("E_REGISTRY_UNAVAILABLE: fails closed when the chain can't be read", async () => {
    const f = fixture();
    const n = randomBytes(32);
    const down: RegistryReader = {
      chain: "near", contractId: "registry.test.near",
      getRoot: () => Promise.reject(new Error("ECONNREFUSED")),
      isComposeAllowed: () => Promise.reject(new Error("ECONNREFUSED")),
      isOsAllowed: () => Promise.reject(new Error("ECONNREFUSED")),
      getInstance: () => Promise.reject(new Error("ECONNREFUSED")),
      getAnchor: () => Promise.reject(new Error("ECONNREFUSED")),
    };
    expect(await codeOf(run(f, await f.bundle(n), n, { registry: down }))).toBe("E_REGISTRY_UNAVAILABLE");
  });
});
