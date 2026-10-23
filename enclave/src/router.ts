/**
 * The PLR-v1 router HTTP API (SPEC §6.2–§6.5), node:http only.
 *
 * No-retention rules (SPEC §6): request/response plaintext and ciphertext are never logged, echoed in errors,
 * written to disk or put in the environment. Logs carry only route, status and duration. Receipts are kept
 * as leaf hashes only.
 */
import http from "node:http";
import { sha256 } from "@noble/hashes/sha2.js";
import { sealFrame, toHex, type Attester } from "@plr/shared";
import { HttpError, onlyParams, parseUrl, readBody, securityHeaders, sendError } from "./http-util.js";
import type { RouterKeys } from "./keys.js";
import type { LlmClient } from "./llm.js";
import { Logger, codeOf, route as routeField } from "./log.js";
import type { ReceiptLog } from "./receipts.js";
import { commonRoutes, type RouteHandler } from "./service-routes.js";
import { MAX_BODY_BYTES, parseChatEnvelope, parseChatPlaintext, toBase64, type ChatRequest } from "./validate.js";

export interface RouterOptions {
  attester: Attester;
  keys: RouterKeys;
  /** Exact bytes of the measured app-compose.json. */
  composeBytes: Uint8Array;
  llm: LlmClient;
  receipts: ReceiptLog;
  log?: Logger;
  /** Registration nonces of this instance's registries: refused on `/v1/attestation` (see `commonRoutes`). */
  reservedNonces?: readonly Uint8Array[];
  /** Concurrent /v1/private/chat requests (default 64). */
  maxInflight?: number;
  /**
   * Request ephemeral keys remembered to refuse replays (default 1,000,000). A replayed request would make
   * the router encrypt a *different* answer under the same single-use key and nonces; once the bound is
   * reached the router refuses new chats (fail closed) until restarted with fresh keys.
   */
  maxSeenEpks?: number;
  now?: () => number;
}

const TEXT = new TextEncoder();

function frameLine(seq: number, ct: Uint8Array): string {
  return `data: {"seq":${seq},"ct":"${toBase64(ct)}"}\n\n`;
}

/** Waits until `res` can take more data, or resolves false if the connection went away. */
function writeFrame(res: http.ServerResponse, line: string): Promise<boolean> {
  if (res.destroyed || res.writableEnded) return Promise.resolve(false);
  if (res.write(line)) return Promise.resolve(true);
  return new Promise((ok) => {
    const done = (v: boolean) => {
      res.off("drain", onDrain);
      res.off("close", onClose);
      ok(v);
    };
    const onDrain = () => done(true);
    const onClose = () => done(false);
    res.on("drain", onDrain);
    res.on("close", onClose);
  });
}

export function createRouter(o: RouterOptions): http.Server {
  const log = o.log ?? new Logger("plr-router");
  const now = o.now ?? Date.now;
  const maxInflight = o.maxInflight ?? 64;
  const maxSeen = o.maxSeenEpks ?? 1_000_000;
  const composeBytes = o.composeBytes.slice();
  const composeHash = sha256(composeBytes);
  const seenEpks = new Set<string>();
  let inflight = 0;

  async function chat(req: http.IncomingMessage, res: http.ServerResponse, query: URLSearchParams): Promise<void> {
    if (req.method !== "POST") throw new HttpError(405, "E_BAD_REQUEST");
    onlyParams(query, []);
    if (inflight >= maxInflight || seenEpks.size >= maxSeen) {
      req.resume();
      throw new HttpError(503, "E_UPSTREAM");
    }
    inflight++;
    try {
      await chatInner(req, res);
    } finally {
      inflight--;
    }
  }

  async function chatInner(req: http.IncomingMessage, res: http.ServerResponse): Promise<void> {
    const body = await readBody(req, MAX_BODY_BYTES);
    let env;
    try {
      env = parseChatEnvelope(body);
    } catch {
      throw new HttpError(400, "E_BAD_REQUEST");
    } finally {
      body.fill(0);
    }
    const epkHex = toHex(env.epk);
    if (seenEpks.has(epkHex)) throw new HttpError(400, "E_DECRYPT");
    let opened;
    try {
      opened = o.keys.open(env);
    } catch {
      throw new HttpError(400, "E_DECRYPT");
    }
    seenEpks.add(epkHex);
    const { th, kS2c } = opened;
    try {
      let chatReq: ChatRequest;
      try {
        chatReq = parseChatPlaintext(opened.plaintext);
      } catch {
        throw new HttpError(400, "E_BAD_REQUEST");
      } finally {
        opened.plaintext.fill(0);
      }
      const reqHash = sha256(env.ct);
      await respond(req, res, chatReq, th, kS2c, reqHash);
    } finally {
      kS2c.fill(0);
    }
  }

  async function respond(req: http.IncomingMessage, res: http.ServerResponse, chatReq: ChatRequest, th: Uint8Array, kS2c: Uint8Array, reqHash: Uint8Array): Promise<void> {
    const ac = new AbortController();
    const onClose = () => {
      if (!res.writableFinished) ac.abort();
    };
    res.on("close", onClose);
    req.on("close", () => {
      if (req.destroyed && !req.complete) ac.abort();
    });
    let upstream: AsyncIterable<string>;
    try {
      upstream = await o.llm.chat(chatReq, ac.signal);
    } catch {
      throw new HttpError(503, "E_UPSTREAM");
    }
    res.writeHead(200, { ...securityHeaders(), "content-type": "text/event-stream", "x-accel-buffering": "no" });
    res.flushHeaders();
    const respHasher = sha256.create();
    let seq = 0;
    let ok = false;
    try {
      for await (const delta of upstream) {
        const ct = sealFrame(kS2c, th, seq, false, TEXT.encode(JSON.stringify({ type: "delta", content: delta })));
        respHasher.update(ct);
        if (!(await writeFrame(res, frameLine(seq, ct)))) {
          ac.abort();
          return;
        }
        seq++;
      }
      ok = true;
    } catch {
      ok = false;
    }
    if (res.destroyed || ac.signal.aborted) return;
    let finalPt: Uint8Array;
    if (ok) {
      const { receipt, sig } = o.receipts.issue({
        th,
        reqHash,
        respHash: respHasher.digest(),
        composeHash,
        keyHash: o.keys.keyHash,
        sign: (r) => o.keys.signReceipt(r),
        nowMs: now(),
      });
      finalPt = TEXT.encode(JSON.stringify({ type: "receipt", receipt, sig }));
    } else {
      finalPt = TEXT.encode(JSON.stringify({ type: "error", code: "E_UPSTREAM" }));
    }
    const fin = sealFrame(kS2c, th, seq, true, finalPt);
    res.end(frameLine(seq, fin));
  }

  const common = commonRoutes({ attester: o.attester, keys: o.keys, composeBytes, receipts: o.receipts, reservedNonces: o.reservedNonces ?? [] });
  const routes: Record<string, RouteHandler> = {
    "/v1/attestation": common.attestation,
    "/v1/private/chat": chat,
    "/v1/receipts/proof": common.proof,
    "/healthz": common.healthz,
  };

  const server = http.createServer({ maxHeaderSize: 16 * 1024 }, (req, res) => {
    const t0 = performance.now();
    let routeName = "other";
    res.on("close", () => {
      log.info("request", { route: routeField(routeName), status: res.statusCode, ms: performance.now() - t0 });
    });
    void (async () => {
      try {
        const { path, query } = parseUrl(req.url);
        const handler = Object.hasOwn(routes, path) ? routes[path] : undefined;
        if (!handler) throw new HttpError(404, "E_NOT_FOUND");
        routeName = path;
        await handler(req, res, query);
      } catch (e) {
        if (e instanceof HttpError) {
          if (e.status !== 413) req.resume();
          sendError(res, e.status, e.code);
        } else {
          log.info("internal_error", { code: codeOf(e) });
          req.resume();
          sendError(res, 500, "E_INTERNAL");
        }
      }
    })();
  });
  server.headersTimeout = 10_000;
  server.requestTimeout = 60_000;
  server.keepAliveTimeout = 5_000;
  server.on("clientError", (_err, socket) => {
    if (socket.writable) socket.end("HTTP/1.1 400 Bad Request\r\nconnection: close\r\ncontent-length: 0\r\n\r\n");
    else socket.destroy();
  });
  return server;
}
