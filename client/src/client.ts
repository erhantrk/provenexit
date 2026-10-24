/**
 * PLR client SDK (SPEC §12): verifies the router's attestation against the pinned root and the on-chain
 * registry, then sends an end-to-end encrypted chat request and authenticates the streamed reply and its
 * signed receipt. Fails closed: any failure throws `PlrError(code)` and returns no partial answer.
 */
import { createHash } from "node:crypto";
import {
  FrameReader,
  MockVerifier,
  PlrError,
  clientSeal,
  equalBytes,
  isReceipt,
  isPlrError,
  isValidP256Pub,
  parseJsonIntegers,
  toHex,
  verifyReceipt,
  fromHex,
  type AttestationBundle,
  type PlrErrorCode,
  type QuoteVerifier,
  type Receipt,
  type RegistryReader,
  type VerifiedRouter,
} from "@plr/shared";
import { base64DecodeStrict, base64Encode } from "./base64.js";
import { encodeChatPlaintext, type ChatRequest } from "./chat-request.js";
import { BodyTooLargeError, Deadline, fail, parseJsonBytes, readBodyLimited, routerErrorCode } from "./http.js";
import { SseParser } from "./sse.js";
import { verifyReceiptAnchored, type AnchoredReceipt } from "./anchored.js";
import { isPlainObject, raceAbort } from "./util.js";
import { AttestationCache, type AttestationSession } from "./attestation.js";

export interface ChatResult {
  content: string;
  receipt: Receipt;
  sig: string;
  verified: VerifiedRouter;
}

export interface ChatOptions {
  /** Called with each delta, only after its frame authenticated and decrypted (strictly in order). */
  onDelta?: (s: string) => void;
  /** Aborts the request; a stream aborted before its final frame fails with E_TRUNCATED. */
  signal?: AbortSignal;
}

export interface PrivateClientTimeouts {
  /** Whole attestation fetch (default 15 s). */
  attestMs: number;
  /** Max silence while waiting for response headers or the next stream chunk (default 120 s). */
  idleMs: number;
  /** Whole chat request (default 10 min). */
  requestMs: number;
}

export interface PrivateClientOptions {
  routerUrl: string;
  registry: RegistryReader;
  /** Pinned attestation root, 64-byte P-256 `x‖y`. */
  trustedRoot: Uint8Array;
  /** Quote verifier (default: {@link MockVerifier} pinned to `trustedRoot`). */
  verifier?: QuoteVerifier;
  fetch?: typeof fetch;
  timeouts?: Partial<PrivateClientTimeouts>;
  /** Monotonic clock in ms, for the verification cache (default `performance.now`). Tests only. */
  clock?: () => number;
}

/** A verification is reused for at most this long (SPEC §12). */
export const VERIFIED_TTL_MS = 60_000;
/** Router request body limit (SPEC §6.3). */
export const MAX_REQUEST_BODY = 1024 * 1024;
const MAX_ATTESTATION_BODY = 256 * 1024;
const MAX_PROOF_BODY = 16 * 1024;
const MAX_FRAME_CT = 1024 * 1024;
const MAX_STREAM_BYTES = 64 * 1024 * 1024;
const MAX_FRAMES = 1_000_000;
const DEFAULT_TIMEOUTS: PrivateClientTimeouts = { attestMs: 15_000, idleMs: 120_000, requestMs: 600_000 };

/** Wraps an error thrown by the caller's `onDelta` so it is re-thrown unchanged. */
class CallbackError {
  constructor(readonly error: unknown) {}
}

type FinalFrame = { type: "receipt"; receipt: unknown; sig: unknown } | { type: "error" };

function normalizeRouterUrl(u: unknown): string {
  if (typeof u !== "string") return fail("E_BAD_INPUT", "routerUrl must be a string");
  let url: URL;
  try {
    url = new URL(u);
  } catch {
    return fail("E_BAD_INPUT", "routerUrl must be a URL");
  }
  if (url.protocol !== "http:" && url.protocol !== "https:") fail("E_BAD_INPUT", "routerUrl must be http(s)");
  if (url.username !== "" || url.password !== "" || url.search !== "" || url.hash !== "") {
    fail("E_BAD_INPUT", "routerUrl must not carry credentials, query or fragment");
  }
  return url.origin + url.pathname.replace(/\/+$/, "");
}

function timeoutValue(v: unknown, dflt: number): number {
  if (v === undefined) return dflt;
  if (typeof v !== "number" || !Number.isSafeInteger(v) || v < 1 || v > 3_600_000) return fail("E_BAD_INPUT", "bad timeout");
  return v;
}

export class PrivateClient {
  readonly routerUrl: string;
  readonly registry: RegistryReader;
  readonly #verifier: QuoteVerifier;
  readonly #fetch: typeof fetch;
  readonly #timeouts: PrivateClientTimeouts;
  readonly #attestation: AttestationCache;

  constructor(o: PrivateClientOptions) {
    if (!isPlainObject(o)) fail("E_BAD_INPUT", "options required");
    this.routerUrl = normalizeRouterUrl(o.routerUrl);
    const r: unknown = o.registry;
    if (typeof r !== "object" || r === null) fail("E_BAD_INPUT", "registry required");
    this.registry = o.registry;
    if (!isValidP256Pub(o.trustedRoot)) fail("E_ROOT_UNTRUSTED", "trustedRoot must be a valid 64-byte P-256 key");
    const trustedRoot = o.trustedRoot.slice();
    this.#verifier = o.verifier ?? new MockVerifier(trustedRoot);
    const f = o.fetch ?? globalThis.fetch;
    if (typeof f !== "function") fail("E_BAD_INPUT", "fetch unavailable");
    this.#fetch = f;
    const t = o.timeouts ?? {};
    this.#timeouts = {
      attestMs: timeoutValue(t.attestMs, DEFAULT_TIMEOUTS.attestMs),
      idleMs: timeoutValue(t.idleMs, DEFAULT_TIMEOUTS.idleMs),
      requestMs: timeoutValue(t.requestMs, DEFAULT_TIMEOUTS.requestMs),
    };
    this.#attestation = new AttestationCache({
      fetchBundle: (nonce) => this.#fetchAttestation(nonce),
      verifier: this.#verifier,
      registry: this.registry,
      trustedRoot,
      ttlMs: VERIFIED_TTL_MS,
      clock: o.clock ?? (() => performance.now()),
    });
  }

  /** Root kind of the configured verifier ("MOCK" | "INTEL"). */
  get rootKind(): QuoteVerifier["rootKind"] {
    return this.#verifier.rootKind;
  }

  /** Fetches and verifies a fresh attestation (new random nonce every call). @throws PlrError */
  async attest(): Promise<VerifiedRouter> {
    return (await this.#attestation.attest()).verified;
  }

  /** The current verification if it is younger than 60 s, else a fresh one. @throws PlrError */
  async ensureVerified(): Promise<VerifiedRouter> {
    return (await this.#attestation.current()).verified;
  }

  /**
   * Checks that `receipt` (from a verified {@link ChatResult}) is included in an on-chain anchor: fetches the
   * router's proof (§6.4), then verifies it against `get_anchor` using the CHAIN's `first_seq`/`count`/`root`
   * (index = seq − first_seq, size = count); router values that disagree are rejected.
   * @throws PlrError E_NOT_ANCHORED (not yet anchored — retry later), E_ANCHOR_MISMATCH, E_ANCHOR_SIG (tier B/C: bad or missing anchor signature, SPEC-CHAINS §2), E_BAD_RESPONSE,
   *         E_REGISTRY_UNAVAILABLE, E_BAD_INPUT
   */
  async verifyAnchored(receipt: Receipt): Promise<AnchoredReceipt> {
    if (!isReceipt(receipt)) fail("E_BAD_INPUT", "malformed receipt");
    const deadline = new Deadline(this.#timeouts.attestMs);
    let reply: unknown;
    try {
      let res: Response;
      try {
        res = await raceAbort(
          this.#fetch(`${this.routerUrl}/v1/receipts/proof?seq=${receipt.seq}`, {
            method: "GET",
            headers: { accept: "application/json" },
            redirect: "error",
            signal: deadline.signal,
          }),
          deadline.signal,
        );
      } catch {
        return fail("E_BAD_RESPONSE", "router unreachable");
      }
      if (res.status === 404) {
        await res.body?.cancel().catch(() => undefined);
        return fail("E_NOT_ANCHORED");
      }
      if (res.status !== 200) {
        await res.body?.cancel().catch(() => undefined);
        return fail("E_BAD_RESPONSE", `proof HTTP ${res.status}`);
      }
      try {
        reply = parseJsonBytes(await raceAbort(readBodyLimited(res, MAX_PROOF_BODY), deadline.signal));
      } catch {
        return fail("E_BAD_RESPONSE", "proof read failed");
      }
    } finally {
      deadline.clear();
    }
    return verifyReceiptAnchored({ receipt, reply, registry: this.registry, signer: this.#attestation.verifiedKeys });
  }

  /** Forgets the cached verification; the next chat re-attests. */
  invalidate(): void {
    this.#attestation.invalidate();
  }

  /** Encrypted chat (SPEC §6.3) with full stream and receipt verification. @throws PlrError */
  async chat(req: ChatRequest, o: ChatOptions = {}): Promise<ChatResult> {
    const plaintext = encodeChatPlaintext(req); // validate before any network traffic
    try {
      const session = await this.#attestation.current();
      return await this.#chatOnce(session, plaintext, o);
    } catch (e) {
      this.#attestation.invalidate(); // fail closed: never reuse a verification after a failed session
      if (e instanceof CallbackError) throw e.error;
      if (isPlrError(e)) throw e;
      throw new PlrError("E_BAD_RESPONSE");
    } finally {
      plaintext.fill(0);
    }
  }

  // ---------------------------------------------------------------- attestation

  async #fetchAttestation(nonce: Uint8Array): Promise<AttestationBundle> {
    const deadline = new Deadline(this.#timeouts.attestMs);
    try {
      let res: Response;
      try {
        res = await raceAbort(
          this.#fetch(`${this.routerUrl}/v1/attestation?nonce=${toHex(nonce)}`, {
            method: "GET",
            headers: { accept: "application/json" },
            redirect: "error",
            signal: deadline.signal,
          }),
          deadline.signal,
        );
      } catch {
        return fail("E_BAD_RESPONSE", "router unreachable");
      }
      if (res.status !== 200) {
        await res.body?.cancel().catch(() => undefined);
        return fail("E_BAD_RESPONSE", `attestation HTTP ${res.status}`);
      }
      let body: Uint8Array;
      try {
        body = await raceAbort(readBodyLimited(res, MAX_ATTESTATION_BODY), deadline.signal);
      } catch (e) {
        return fail("E_BAD_RESPONSE", e instanceof BodyTooLargeError ? "attestation too large" : "attestation read failed");
      }
      const j = parseJsonBytes(body);
      if (!isPlainObject(j)) return fail("E_BAD_RESPONSE", "attestation is not a JSON object");
      // Full shape validation happens in verifyAttestation (step 1, E_BAD_RESPONSE).
      return j as unknown as AttestationBundle;
    } finally {
      deadline.clear();
    }
  }

  // ---------------------------------------------------------------- chat

  async #chatOnce(session: AttestationSession, plaintext: Uint8Array, o: ChatOptions): Promise<ChatResult> {
    const v = session.verified;
    const { epk, ct, th, kS2c } = clientSeal({ xp: v.x25519, ep: v.ed25519, attNonce: session.attNonce, plaintext });
    const reqHash = createHash("sha256").update(ct).digest();
    const body = JSON.stringify({ v: 1, att_nonce: toHex(session.attNonce), epk: toHex(epk), ct: base64Encode(ct) });
    if (Buffer.byteLength(body, "utf8") > MAX_REQUEST_BODY) fail("E_TOO_LARGE", "request exceeds 1 MiB");

    const total = new Deadline(this.#timeouts.requestMs, o.signal);
    const idle = new Deadline(this.#timeouts.idleMs, total.signal);
    try {
      let res: Response;
      try {
        res = await raceAbort(
          this.#fetch(`${this.routerUrl}/v1/private/chat`, {
            method: "POST",
            headers: { "content-type": "application/json", accept: "text/event-stream" },
            body,
            redirect: "error",
            signal: idle.signal,
          }),
          idle.signal,
        );
      } catch {
        return fail("E_BAD_RESPONSE", "router unreachable");
      }
      if (res.status !== 200) {
        let code: PlrErrorCode;
        try {
          code = await raceAbort(routerErrorCode(res), idle.signal);
        } catch {
          code = "E_BAD_RESPONSE";
        }
        return fail(code);
      }
      const ctype = (res.headers.get("content-type") ?? "").toLowerCase();
      if (!ctype.startsWith("text/event-stream") || res.body === null) {
        await res.body?.cancel().catch(() => undefined);
        return fail("E_BAD_RESPONSE", "not an event stream");
      }
      return await this.#readStream(res.body, { v, th, kS2c, reqHash, idle, onDelta: o.onDelta });
    } finally {
      idle.clear();
      total.clear();
      kS2c.fill(0);
    }
  }

  async #readStream(
    stream: ReadableStream<Uint8Array>,
    p: {
      v: VerifiedRouter;
      th: Uint8Array;
      kS2c: Uint8Array;
      reqHash: Uint8Array;
      idle: Deadline;
      onDelta: ((s: string) => void) | undefined;
    },
  ): Promise<ChatResult> {
    const frames = new FrameReader(p.kS2c, p.th);
    const parser = new SseParser({ maxLineLength: 2 * MAX_FRAME_CT, maxEventLength: 2 * MAX_FRAME_CT });
    const respHash = createHash("sha256");
    const reader = stream.getReader();
    // Timeouts/aborts end the read loop even if the transport ignores the fetch signal.
    const onAbort = (): void => void reader.cancel().catch(() => undefined);
    p.idle.signal.addEventListener("abort", onAbort, { once: true });
    let content = "";
    let received = 0;
    let count = 0;
    let final: FinalFrame | undefined;
    try {
      outer: for (;;) {
        let chunk: Awaited<ReturnType<typeof reader.read>>;
        try {
          chunk = await reader.read();
        } catch {
          break; // transport error / timeout / abort: no valid fin frame ⇒ E_TRUNCATED below
        }
        if (chunk.done) break;
        p.idle.arm();
        received += chunk.value.byteLength;
        if (received > MAX_STREAM_BYTES) fail("E_BAD_RESPONSE", "response stream too large");
        let events: string[];
        try {
          events = parser.push(chunk.value);
        } catch {
          return fail("E_DECRYPT", "malformed event stream");
        }
        for (const data of events) {
          if (++count > MAX_FRAMES) fail("E_BAD_RESPONSE", "too many frames");
          const { seq, ct } = parseFrameEvent(data);
          const { fin, plaintext } = frames.push(seq, ct); // E_DECRYPT: wrong seq, bad tag, after fin
          const msg = parseFramePlaintext(plaintext, fin);
          if (msg.type === "delta") {
            respHash.update(ct);
            content += msg.content;
            if (p.onDelta !== undefined) {
              try {
                p.onDelta(msg.content);
              } catch (e) {
                throw new CallbackError(e);
              }
            }
          } else {
            final = msg;
            break outer; // anything after the final frame is ignored; the receipt covers every delta
          }
        }
      }
    } finally {
      p.idle.signal.removeEventListener("abort", onAbort);
      await reader.cancel().catch(() => undefined);
    }
    if (final === undefined) {
      frames.end(); // throws E_TRUNCATED
      return fail("E_TRUNCATED");
    }
    if (final.type === "error") return fail("E_UPSTREAM");
    const receipt = verifyFinalReceipt(final, p.v, {
      th: p.th,
      reqHash: p.reqHash,
      respHash: new Uint8Array(respHash.digest()),
    });
    return { content, receipt, sig: final.sig as string, verified: p.v };
  }
}

// ---------------------------------------------------------------- frame parsing

const FRAME_KEYS = new Set(["seq", "ct"]);

/** `data: {"seq":n,"ct":"<base64>"}` — anything malformed is a frame that cannot be authenticated. */
function parseFrameEvent(data: string): { seq: number; ct: Uint8Array } {
  let j: unknown;
  try {
    j = parseJsonIntegers(data);
  } catch {
    return fail("E_DECRYPT", "malformed frame");
  }
  if (!isPlainObject(j) || Object.keys(j).some((k) => !FRAME_KEYS.has(k))) return fail("E_DECRYPT", "malformed frame");
  const seq = j.seq;
  if (typeof seq !== "number" || !Number.isSafeInteger(seq) || seq < 0) return fail("E_DECRYPT", "malformed frame seq");
  const ct = base64DecodeStrict(j.ct, MAX_FRAME_CT);
  if (ct === null) return fail("E_DECRYPT", "malformed frame ciphertext");
  return { seq, ct };
}

/** Authenticated frame plaintext (SPEC §6.3). A malformed one is a protocol violation by the router. */
function parseFramePlaintext(pt: Uint8Array, fin: boolean): { type: "delta"; content: string } | FinalFrame {
  let j: unknown;
  try {
    j = parseJsonIntegers(new TextDecoder("utf-8", { fatal: true }).decode(pt));
  } catch {
    return fail("E_BAD_RESPONSE", "malformed frame plaintext");
  } finally {
    pt.fill(0);
  }
  if (!isPlainObject(j)) return fail("E_BAD_RESPONSE", "malformed frame plaintext");
  if (!fin) {
    if (j.type !== "delta" || typeof j.content !== "string") return fail("E_BAD_RESPONSE", "non-final frame is not a delta");
    return { type: "delta", content: j.content };
  }
  if (j.type === "error") return { type: "error" };
  if (j.type === "receipt") return { type: "receipt", receipt: j.receipt, sig: j.sig };
  return fail("E_BAD_RESPONSE", "final frame is neither receipt nor error");
}

/** Receipt checks of SPEC §8: signature under the attested key, then every hash recomputed locally. */
function verifyFinalReceipt(
  final: { receipt: unknown; sig: unknown },
  v: VerifiedRouter,
  own: { th: Uint8Array; reqHash: Uint8Array; respHash: Uint8Array },
): Receipt {
  const r = final.receipt;
  if (!isReceipt(r) || typeof final.sig !== "string" || !verifyReceipt(r, final.sig, v.ed25519)) {
    return fail("E_RECEIPT_SIG");
  }
  const same = (hex: string, b: Uint8Array): boolean => equalBytes(fromHex(hex, 32), b);
  const ok =
    same(r.th, own.th) &&
    same(r.req_hash, own.reqHash) &&
    same(r.resp_hash, own.respHash) &&
    same(r.compose_hash, v.composeHash) &&
    same(r.key_hash, v.keyHash);
  if (!ok) fail("E_RECEIPT_MISMATCH");
  return {
    v: 1,
    th: r.th,
    req_hash: r.req_hash,
    resp_hash: r.resp_hash,
    compose_hash: r.compose_hash,
    key_hash: r.key_hash,
    seq: r.seq,
    ts_ms: r.ts_ms,
  };
}

/** PlrError codes produced by attestation verification (SPEC §9 steps 1–10). */
export const VERIFICATION_CODES: ReadonlySet<PlrErrorCode> = new Set<PlrErrorCode>([
  "E_BAD_RESPONSE",
  "E_QUOTE_FORMAT",
  "E_TEE_TYPE",
  "E_ROOT_UNTRUSTED",
  "E_QUOTE_SIG",
  "E_DEBUG_TD",
  "E_REPORT_DATA_KEYS",
  "E_NONCE",
  "E_EVENT_LOG",
  "E_RTMR3",
  "E_COMPOSE_MISMATCH",
  "E_COMPOSE_NOT_ALLOWED",
  "E_OS_NOT_ALLOWED",
  "E_INSTANCE_NOT_REGISTERED",
  "E_REGISTRY_UNAVAILABLE",
]);
