/** Small node:http helpers: content-free JSON responses and strict request-target parsing. */
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

/** Splits an origin-form request target (`/path?query`). Anything else (absolute-form, `//x`, `*`) → 400. */
export function parseUrl(rawUrl: string | undefined): { path: string; query: URLSearchParams } {
  if (typeof rawUrl !== "string" || !rawUrl.startsWith("/") || rawUrl.startsWith("//") || rawUrl.length > 4096) {
    throw new HttpError(400, "E_BAD_REQUEST");
  }
  let u: URL;
  try {
    u = new URL(rawUrl, "http://exit.invalid");
  } catch {
    throw new HttpError(400, "E_BAD_REQUEST");
  }
  if (u.host !== "exit.invalid") throw new HttpError(400, "E_BAD_REQUEST");
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
