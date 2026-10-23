/**
 * The router's Attester: calls the mock TDX host's quote endpoint (SPEC §6.1) over the Unix socket given in
 * `PLR_TDX_SOCKET`. Mirrors dstack's `GetQuote` (report_data is passed through, not hashed). The response
 * is size-bounded and shape-checked; anything unexpected is an error.
 */
import http from "node:http";
import { MAX_EVENTS, MAX_EVENT_PAYLOAD, PlrError, QUOTE, fromHex, isHex, parseJsonIntegers, toHex, type Attester, type TdxEvent } from "@plr/shared";

const MAX_RESPONSE = 256 * 1024;
const EVENT_KEYS = ["digest", "event", "event_payload", "event_type", "imr"];

function fail(): never {
  throw new PlrError("E_BAD_RESPONSE", "quote service");
}

function isEvent(e: unknown): e is TdxEvent {
  if (typeof e !== "object" || e === null || Array.isArray(e)) return false;
  const keys = Object.keys(e).sort();
  if (keys.length !== EVENT_KEYS.length || !keys.every((k, i) => k === EVENT_KEYS[i])) return false;
  const ev = e as Record<string, unknown>;
  return (
    Number.isSafeInteger(ev.imr) &&
    Number.isSafeInteger(ev.event_type) &&
    isHex(ev.digest, 48) &&
    typeof ev.event === "string" &&
    ev.event.length <= 128 &&
    isHex(ev.event_payload) &&
    ev.event_payload.length <= MAX_EVENT_PAYLOAD * 2
  );
}

/** Validates a `{quote, event_log}` JSON document from the quote service. */
export function parseQuoteResponse(text: string): { quote: Uint8Array; eventLog: TdxEvent[] } {
  let o: unknown;
  try {
    o = parseJsonIntegers(text);
  } catch {
    fail();
  }
  if (typeof o !== "object" || o === null || Array.isArray(o)) fail();
  const r = o as Record<string, unknown>;
  if (Object.keys(r).length !== 2 || !isHex(r.quote) || !Array.isArray(r.event_log)) fail();
  if (r.quote.length < QUOTE.SIGNED_LEN * 2 || r.quote.length > QUOTE.MAX_LEN * 2) fail();
  if (r.event_log.length > MAX_EVENTS || !r.event_log.every(isEvent)) fail();
  return {
    quote: fromHex(r.quote),
    eventLog: r.event_log.map((e: TdxEvent) => ({ imr: e.imr, event_type: e.event_type, digest: e.digest, event: e.event, event_payload: e.event_payload })),
  };
}

export class SocketAttester implements Attester {
  readonly #socketPath: string;
  readonly #timeoutMs: number;

  constructor(socketPath: string, opts: { timeoutMs?: number } = {}) {
    if (typeof socketPath !== "string" || socketPath.length === 0) throw new PlrError("E_BAD_INPUT", "socket path");
    this.#socketPath = socketPath;
    this.#timeoutMs = opts.timeoutMs ?? 10_000;
  }

  getQuote(reportData: Uint8Array): Promise<{ quote: Uint8Array; eventLog: TdxEvent[] }> {
    if (!(reportData instanceof Uint8Array) || reportData.length !== 64) {
      return Promise.reject(new PlrError("E_BAD_INPUT", "report_data must be 64 bytes"));
    }
    const body = Buffer.from(JSON.stringify({ report_data: toHex(reportData) }), "utf8");
    return new Promise((resolve, reject) => {
      const req = http.request(
        {
          socketPath: this.#socketPath,
          path: "/GetQuote",
          method: "POST",
          headers: { "content-type": "application/json", "content-length": body.length, host: "tdx" },
          signal: AbortSignal.timeout(this.#timeoutMs),
          agent: false,
        },
        (res) => {
          const chunks: Buffer[] = [];
          let n = 0;
          res.on("data", (c: Buffer) => {
            n += c.length;
            if (n > MAX_RESPONSE) {
              res.destroy();
              reject(new PlrError("E_BAD_RESPONSE", "quote service"));
              return;
            }
            chunks.push(c);
          });
          res.on("error", () => reject(new PlrError("E_BAD_RESPONSE", "quote service")));
          res.on("end", () => {
            if (res.statusCode !== 200) return reject(new PlrError("E_BAD_RESPONSE", "quote service"));
            try {
              resolve(parseQuoteResponse(Buffer.concat(chunks).toString("utf8")));
            } catch (e) {
              reject(e);
            }
          });
        },
      );
      req.on("error", () => reject(new PlrError("E_BAD_RESPONSE", "quote service")));
      req.end(body);
    });
  }
}
