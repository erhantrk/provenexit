// In-process fake PLR router built only from @plr/shared primitives + MemoryRegistry (SPEC §6.2, §6.3, §8).
// Usable as an injected `fetch` or behind a real node:http server. Misbehaviours are switchable per test.
import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { sha256 } from "@noble/hashes/sha2.js";
import { x25519, ed25519 } from "@noble/curves/ed25519.js";
import {
  MockRoot,
  MockTdxAttester,
  MemoryRegistry,
  keyHash,
  reportData,
  registrationReportData,
  osMeasurement,
  mockOsReport,
  serverOpen,
  sealFrame,
  signReceipt,
  toHex,
  fromHex,
  type AttestationBundle,
  type Receipt,
  type InstanceRecord,
} from "@plr/shared";

export const COMPOSE = JSON.stringify(
  {
    llm: { kind: "mock", model_sha256: "11".repeat(32), runtime: "mock-llm 1" },
    manifest_version: 1,
    name: "plr-router",
    policy: { disk: "none", egress: [], logs: "none" },
    router: { bundle_sha256: "22".repeat(32), entry: "router.bundle.mjs" },
  },
  null,
  2,
) + "\n";

export interface Behaviour {
  deltas: string[];
  /** Mutate the receipt before signing (re-signed with the real key ⇒ E_RECEIPT_MISMATCH). */
  mutateReceipt?: (r: Receipt) => Receipt;
  /** Replace the signature hex. */
  sig?: (sig: string) => string;
  /** Sign the receipt with a different Ed25519 key. */
  wrongSigner?: boolean;
  /** Raw final receipt-frame payload override. */
  finalPayload?: (r: Receipt, sig: string) => unknown;
  finalError?: boolean;
  dropFinal?: boolean;
  /** Flip one byte of the decoded ciphertext of frame n. */
  flipFrame?: number;
  /** Swap frames 0 and 1. */
  swapFrames?: boolean;
  duplicateFrame?: number;
  /** Seal non-final frame n with fin=1 (and keep going). */
  finOnFrame?: number;
  /** Replace the ct text of frame n with this string. */
  rawCt?: { frame: number; ct: string };
  /** Pre-decrypt HTTP error for chat. */
  httpError?: { status: number; body: string };
  /** Content type of the chat reply. */
  contentType?: string;
  /** Splits the SSE byte stream into chunks (default: one chunk per event). */
  chunker?: (b: Uint8Array) => Uint8Array[];
  /** Replay the first attestation bundle for every nonce. */
  replayAttestation?: boolean;
  /** Advertise a different x25519 key than the one the quote binds. */
  mitmKey?: boolean;
  /**
   * Quote a report_data of another purpose than §5 rev 1.3 session: `raw-nonce` = pre-1.3 `key_hash ‖ client nonce`,
   * `registration` = the operator-bound registration report_data (the router's own keys, a real quote either way).
   */
  quotePurpose?: "raw-nonce" | "registration";
  /** Never finish the stream after the deltas (hang). */
  hangAfterDeltas?: boolean;
}

export interface FakeRouter {
  root: MockRoot;
  registry: MemoryRegistry;
  composeHash: string;
  keyHash: string;
  osHash: string;
  record: InstanceRecord;
  behaviour: Behaviour;
  stats: { attestations: number; chats: number; nonces: string[]; plaintexts: string[] };
  fetch: typeof fetch;
  handle(req: Request): Promise<Response>;
  /** Serves the router over real HTTP; returns its base URL. */
  listen(): Promise<{ url: string; close(): Promise<void> }>;
}

const enc = new TextEncoder();
/** report_data a fake quotes for `nonce`: the §5 rev 1.3 session value unless a misbehaviour picks another purpose. */
export function quoteReportData(
  purpose: "raw-nonce" | "registration" | undefined,
  xp: Uint8Array,
  ep: Uint8Array,
  nonce: Uint8Array,
  reg: { contractId: string; operator: string },
): Uint8Array {
  if (purpose === "raw-nonce") {
    const rd = new Uint8Array(64);
    rd.set(keyHash(xp, ep), 0);
    rd.set(nonce, 32);
    return rd;
  }
  if (purpose === "registration") return registrationReportData(xp, ep, reg.contractId, reg.operator);
  return reportData(xp, ep, nonce);
}

const json = (status: number, body: unknown) =>
  new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });

export function makeFakeRouter(o: { debug?: boolean } = {}): FakeRouter {
  const root = MockRoot.generate();
  const composeBytes = enc.encode(COMPOSE);
  const attester = new MockTdxAttester({ root, composeBytes, debug: o.debug ?? false });
  const xs = x25519.utils.randomSecretKey();
  const xp = x25519.getPublicKey(xs);
  const es = ed25519.utils.randomSecretKey();
  const ep = ed25519.getPublicKey(es);
  const kh = toHex(keyHash(xp, ep));
  const composeHash = toHex(sha256(composeBytes));
  const osHash = toHex(osMeasurement(mockOsReport()));
  const record: InstanceRecord = {
    compose_hash: composeHash,
    os_measurement: osHash,
    x25519: toHex(xp),
    ed25519: toHex(ep),
    operator: "operator.test.near",
    org_id: null,
    registered_at_ms: 1,
    expires_at_ms: Date.now() + 3_600_000,
    next_seq: 0,
  };
  const registry = new MemoryRegistry({
    root: { kind: "MOCK", p256: toHex(root.publicKey) },
    compose: [composeHash],
    os: [osHash],
    instances: { [kh]: record },
  });
  const stats = { attestations: 0, chats: 0, nonces: [] as string[], plaintexts: [] as string[] };
  let seq = 0;
  let firstBundle: AttestationBundle | undefined;

  const r: FakeRouter = {
    root,
    registry,
    composeHash,
    keyHash: kh,
    osHash,
    record,
    behaviour: { deltas: ["Hel", "lo, ", "wörld 🌍", ""] },
    stats,
    fetch: (input, init) => r.handle(new Request(input, init)),
    async handle(req) {
      const url = new URL(req.url);
      if (req.method === "GET" && url.pathname === "/v1/attestation") {
        const nonceHex = url.searchParams.get("nonce") ?? "";
        if (!/^[0-9a-f]{64}$/.test(nonceHex)) return json(400, { error: "E_BAD_REQUEST" });
        stats.attestations++;
        stats.nonces.push(nonceHex);
        if (r.behaviour.replayAttestation && firstBundle) return json(200, firstBundle);
        const { quote, eventLog } = await attester.getQuote(quoteReportData(r.behaviour.quotePurpose, xp, ep, fromHex(nonceHex, 32), { contractId: "registry.test.near", operator: record.operator }));
        const bundle: AttestationBundle = {
          v: "PLR-v1",
          root_kind: "MOCK",
          quote: toHex(quote),
          event_log: eventLog,
          app_compose: COMPOSE,
          x25519: r.behaviour.mitmKey ? toHex(x25519.getPublicKey(x25519.utils.randomSecretKey())) : toHex(xp),
          ed25519: toHex(ep),
        };
        firstBundle ??= bundle;
        return json(200, bundle);
      }
      if (req.method === "POST" && url.pathname === "/v1/private/chat") {
        stats.chats++;
        const b = r.behaviour;
        if (b.httpError) return new Response(b.httpError.body, { status: b.httpError.status, headers: { "content-type": "application/json" } });
        const body = (await req.json()) as { v: number; att_nonce: string; epk: string; ct: string };
        const ct = new Uint8Array(Buffer.from(body.ct, "base64"));
        let opened;
        try {
          opened = serverOpen({ xs, xp, ep, attNonce: fromHex(body.att_nonce, 32), epk: fromHex(body.epk, 32), ct });
        } catch {
          return json(400, { error: "E_DECRYPT" });
        }
        stats.plaintexts.push(new TextDecoder().decode(opened.plaintext));
        const { th, kS2c } = opened;
        const events: { seq: number; ct: string }[] = [];
        const cts: Uint8Array[] = [];
        b.deltas.forEach((d, i) => {
          const c = sealFrame(kS2c, th, i, b.finOnFrame === i, enc.encode(JSON.stringify({ type: "delta", content: d })));
          cts.push(c);
          const sent = c.slice();
          if (b.flipFrame === i) sent[Math.floor(sent.length / 2)]! ^= 0x01;
          events.push({ seq: i, ct: Buffer.from(sent).toString("base64") });
        });
        const n = b.deltas.length;
        let receipt: Receipt = {
          v: 1,
          th: toHex(th),
          req_hash: toHex(sha256(ct)),
          resp_hash: toHex(sha256(Buffer.concat(cts))),
          compose_hash: composeHash,
          key_hash: kh,
          seq: seq++,
          ts_ms: Date.now(),
        };
        if (b.mutateReceipt) receipt = b.mutateReceipt(receipt);
        let sig = signReceipt(receipt, b.wrongSigner ? ed25519.utils.randomSecretKey() : es);
        if (b.sig) sig = b.sig(sig);
        const finalPt = b.finalError
          ? { type: "error", code: "E_UPSTREAM" }
          : b.finalPayload
            ? b.finalPayload(receipt, sig)
            : { type: "receipt", receipt, sig };
        const fin = sealFrame(kS2c, th, n, true, enc.encode(JSON.stringify(finalPt)));
        if (!b.dropFinal) events.push({ seq: n, ct: Buffer.from(fin).toString("base64") });
        if (b.swapFrames && events.length > 1) [events[0], events[1]] = [events[1]!, events[0]!];
        if (b.duplicateFrame !== undefined) events.splice(b.duplicateFrame + 1, 0, events[b.duplicateFrame]!);
        if (b.rawCt) events[b.rawCt.frame]!.ct = b.rawCt.ct;
        const text = events.map((e) => `data: ${JSON.stringify(e)}\n\n`).join("");
        const bytes = enc.encode(b.hangAfterDeltas ? text.split("\n\n").slice(0, n).join("\n\n") + "\n\n" : text);
        const chunks = b.chunker ? b.chunker(bytes) : [bytes];
        const hang = b.hangAfterDeltas === true;
        const stream = new ReadableStream<Uint8Array>({
          start(c) {
            for (const ch of chunks) c.enqueue(ch);
            if (!hang) c.close();
          },
        });
        return new Response(stream, { status: 200, headers: { "content-type": b.contentType ?? "text/event-stream" } });
      }
      return json(404, { error: "E_BAD_REQUEST" });
    },
    async listen() {
      const server: Server = createServer((req, res) => {
        void (async () => {
          const chunks: Buffer[] = [];
          for await (const c of req) chunks.push(c as Buffer);
          const init: RequestInit = { method: req.method ?? "GET", headers: req.headers as Record<string, string> };
          if (req.method === "POST") init.body = Buffer.concat(chunks);
          const resp = await r.handle(new Request(`http://${req.headers.host}${req.url}`, init));
          res.writeHead(resp.status, Object.fromEntries(resp.headers));
          if (resp.body) for await (const c of resp.body) res.write(c);
          res.end();
        })();
      });
      await new Promise<void>((ok) => server.listen(0, "127.0.0.1", ok));
      const port = (server.address() as AddressInfo).port;
      return {
        url: `http://127.0.0.1:${port}`,
        close: () => new Promise<void>((ok) => { server.closeAllConnections(); server.close(() => ok()); }),
      };
    },
  };
  return r;
}

/** Splits bytes at `k` random points. */
export function randomChunker(rand: () => number, maxPieces = 40): (b: Uint8Array) => Uint8Array[] {
  return (b) => {
    const k = Math.floor(rand() * maxPieces);
    const cuts = new Set<number>();
    for (let i = 0; i < k; i++) cuts.add(1 + Math.floor(rand() * Math.max(1, b.length - 1)));
    const sorted = [...cuts].filter((c) => c > 0 && c < b.length).sort((a, c) => a - c);
    const out: Uint8Array[] = [];
    let prev = 0;
    for (const c of sorted) { out.push(b.slice(prev, c)); prev = c; }
    out.push(b.slice(prev));
    return out;
  };
}

/** Deterministic PRNG (mulberry32). */
export function prng(seed: number): () => number {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}
