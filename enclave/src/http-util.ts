/** Small node:http helpers: bounded body reading and content-free JSON responses. */
import type http from "node:http";

export class HttpError extends Error {
  constructor(
    readonly status: number,
    readonly code: string,
  ) {
    super(code);
    this.name = "HttpError";
  }
}

const BASE_HEADERS = {
  "cache-control": "no-store",
  "x-content-type-options": "nosniff",
  "referrer-policy": "no-referrer",
} as const;

export function securityHeaders(): Record<string, string> {
  return { ...BASE_HEADERS };
}

export function sendJson(res: http.ServerResponse, status: number, body: unknown, extra: Record<string, string> = {}): void {
  if (res.headersSent || res.destroyed) {
    res.destroy();
    return;
  }
  const buf = Buffer.from(JSON.stringify(body), "utf8");
  res.writeHead(status, { ...BASE_HEADERS, "content-type": "application/json", "content-length": String(buf.length), ...extra });
  res.end(buf);
}

export function sendError(res: http.ServerResponse, status: number, code: string): void {
  sendJson(res, status, { error: code }, status === 413 ? { connection: "close" } : {});
}

/** Bytes we are willing to read and discard from an oversized body before dropping the connection. */
const DISCARD_LIMIT = 16 * 1024 * 1024;

/**
 * Reads the request body, at most `limit` bytes. Oversized bodies → HttpError(413, E_TOO_LARGE); the
 * remainder is drained (bounded) so the client reliably receives the 413.
 */
export function readBody(req: http.IncomingMessage, limit: number): Promise<Uint8Array> {
  return new Promise((resolve, reject) => {
    const declared = req.headers["content-length"];
    if (declared !== undefined) {
      if (!/^[0-9]{1,16}$/.test(declared)) {
        reject(new HttpError(400, "E_BAD_REQUEST"));
        req.resume();
        return;
      }
      const n = Number(declared);
      if (n > DISCARD_LIMIT) {
        reject(new HttpError(413, "E_TOO_LARGE"));
        return;
      }
    }
    const chunks: Buffer[] = [];
    let size = 0;
    let tooLarge = false;
    let settled = false;
    const finish = (err: HttpError | null) => {
      if (settled) return;
      settled = true;
      if (err) {
        for (const c of chunks) c.fill(0);
        chunks.length = 0;
        reject(err);
      } else {
        const buf = Buffer.concat(chunks, size);
        for (const c of chunks) c.fill(0);
        resolve(new Uint8Array(buf.buffer, buf.byteOffset, buf.byteLength));
      }
    };
    req.on("data", (c: Buffer) => {
      size += c.length;
      if (tooLarge) {
        if (size > DISCARD_LIMIT) {
          req.destroy();
          finish(new HttpError(413, "E_TOO_LARGE"));
        }
        return;
      }
      if (size > limit) {
        tooLarge = true;
        for (const x of chunks) x.fill(0);
        chunks.length = 0;
        return;
      }
      chunks.push(c);
    });
    req.on("end", () => finish(tooLarge ? new HttpError(413, "E_TOO_LARGE") : null));
    req.on("error", () => finish(new HttpError(400, "E_BAD_REQUEST")));
    req.on("aborted", () => finish(new HttpError(400, "E_BAD_REQUEST")));
  });
}

/** Splits an origin-form request target (`/path?query`). Anything else (absolute-form, `//x`, `*`) → 400. */
export function parseUrl(rawUrl: string | undefined): { path: string; query: URLSearchParams } {
  if (typeof rawUrl !== "string" || !rawUrl.startsWith("/") || rawUrl.startsWith("//") || rawUrl.length > 4096) {
    throw new HttpError(400, "E_BAD_REQUEST");
  }
  let u: URL;
  try {
    u = new URL(rawUrl, "http://router.invalid");
  } catch {
    throw new HttpError(400, "E_BAD_REQUEST");
  }
  if (u.host !== "router.invalid") throw new HttpError(400, "E_BAD_REQUEST");
  return { path: u.pathname, query: u.searchParams };
}

/** Every parameter must be in `allowed` and appear at most once. */
export function onlyParams(query: URLSearchParams, allowed: readonly string[]): Map<string, string> {
  const params = new Map<string, string>();
  for (const [k, v] of query) {
    if (!allowed.includes(k) || params.has(k)) throw new HttpError(400, "E_BAD_REQUEST");
    params.set(k, v);
  }
  return params;
}
