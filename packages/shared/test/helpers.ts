// LOCKED test helpers — independent reference computations (do not import implementation internals).
import { sha256, sha384 } from "@noble/hashes/sha2.js";
import { x25519, ed25519 } from "@noble/curves/ed25519.js";
import { randomBytes } from "@noble/hashes/utils.js";
import {
  MockRoot,
  MockTdxAttester,
  MemoryRegistry,
  keyHash,
  toHex,
  osMeasurement,
  mockOsReport,
  type AttestationBundle,
  type InstanceRecord,
} from "../src/index.js";

export const enc = (s: string) => new TextEncoder().encode(s);
export const cat = (...a: Uint8Array[]) => {
  const out = new Uint8Array(a.reduce((n, x) => n + x.length, 0));
  let o = 0;
  for (const x of a) { out.set(x, o); o += x.length; }
  return out;
};
export const u32le = (n: number) => { const b = new Uint8Array(4); new DataView(b.buffer).setUint32(0, n, true); return b; };
export const u64be = (n: bigint | number) => { const b = new Uint8Array(8); new DataView(b.buffer).setBigUint64(0, BigInt(n), false); return b; };
export const hex = (b: Uint8Array) => Buffer.from(b).toString("hex");
export const unhex = (h: string) => new Uint8Array(Buffer.from(h, "hex"));
export { sha256, sha384, randomBytes };

export function refEventDigest(name: string, payload: Uint8Array): Uint8Array {
  return sha384(cat(u32le(0x08000001), enc(":"), enc(name), enc(":"), payload));
}
export function refReplay(digests: Uint8Array[]): Uint8Array {
  let rt = new Uint8Array(48);
  for (const d of digests) rt = sha384(cat(rt, d));
  return rt;
}

export const COMPOSE_OBJ = {
  llm: { kind: "mock", model_sha256: "11".repeat(32), runtime: "mock-llm 1" },
  manifest_version: 1,
  name: "plr-router",
  policy: { disk: "none", egress: [], logs: "none" },
  router: { bundle_sha256: "22".repeat(32), entry: "router.bundle.mjs" },
};
export const COMPOSE_STR = JSON.stringify(COMPOSE_OBJ, null, 2) + "\n";

export interface Fixture {
  root: MockRoot;
  composeBytes: Uint8Array;
  composeHash: Uint8Array;
  xs: Uint8Array; xp: Uint8Array; es: Uint8Array; ep: Uint8Array;
  attester: MockTdxAttester;
  keyHash: Uint8Array;
  osHash: Uint8Array;
  record: InstanceRecord;
  registry: MemoryRegistry;
  bundle(nonce: Uint8Array, over?: { xp?: Uint8Array; ep?: Uint8Array; compose?: string; attester?: MockTdxAttester }): Promise<AttestationBundle>;
}

export function fixture(opts: { debug?: boolean; composeStr?: string } = {}): Fixture {
  const root = MockRoot.generate();
  const composeStr = opts.composeStr ?? COMPOSE_STR;
  const composeBytes = enc(composeStr);
  const composeHash = sha256(composeBytes);
  const xs = x25519.utils.randomSecretKey();
  const xp = x25519.getPublicKey(xs);
  const es = ed25519.utils.randomSecretKey();
  const ep = ed25519.getPublicKey(es);
  const attester = new MockTdxAttester({ root, composeBytes, debug: opts.debug ?? false });
  const kh = keyHash(xp, ep);
  const osHash = osMeasurement(mockOsReport());
  const record: InstanceRecord = {
    compose_hash: hex(composeHash), os_measurement: hex(osHash), x25519: hex(xp), ed25519: hex(ep),
    operator: "op.test.near", org_id: null, registered_at_ms: 1, expires_at_ms: Date.now() + 3_600_000, next_seq: 0,
  };
  const registry = new MemoryRegistry({
    root: { kind: "MOCK", p256: toHex(root.publicKey) },
    compose: [hex(composeHash)],
    os: [hex(osHash)],
    instances: { [hex(kh)]: record },
  });
  return {
    root, composeBytes, composeHash, xs, xp, es, ep, attester, keyHash: kh, osHash, record, registry,
    async bundle(nonce, over = {}) {
      const bxp = over.xp ?? xp, bep = over.ep ?? ep;
      // Quote always binds the REAL keys; `over.xp/ep` only changes what the bundle advertises.
      const rd = cat(keyHash(xp, ep), nonce);
      const { quote, eventLog } = await (over.attester ?? attester).getQuote(rd);
      return {
        v: "PLR-v1", root_kind: "MOCK", quote: hex(quote), event_log: eventLog,
        app_compose: over.compose ?? composeStr, x25519: hex(bxp), ed25519: hex(bep),
      };
    },
  };
}
