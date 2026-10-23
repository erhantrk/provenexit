/**
 * HTTP routes common to every enclave service (LLM router SPEC §6.2/§6.4/§6.5, VPN exit SPEC-VPN §3):
 * `GET /v1/attestation`, `GET /v1/receipts/proof`, `GET /healthz`. Content-free errors only.
 */
import type http from "node:http";
import { QUOTE, equalBytes, fromHex, isHex, toHex, type Attester, type TdxEvent } from "@plr/shared";
import { HttpError, onlyParams, sendJson } from "./http-util.js";
import type { EnclaveKeys } from "./keys.js";
import type { LeafLog } from "./receipts.js";
import { parseUintParam } from "./validate.js";

export type RouteHandler = (req: http.IncomingMessage, res: http.ServerResponse, q: URLSearchParams) => void | Promise<void>;

const MAX_QUOTE_BYTES = QUOTE.MAX_LEN;

export function commonRoutes(o: { attester: Attester; keys: EnclaveKeys; composeBytes: Uint8Array; receipts: LeafLog }): {
  attestation: RouteHandler;
  proof: RouteHandler;
  healthz: RouteHandler;
} {
  const composeText = new TextDecoder("utf-8", { fatal: true }).decode(o.composeBytes);
  const xpHex = toHex(o.keys.x25519);
  const epHex = toHex(o.keys.ed25519);

  async function attestation(req: http.IncomingMessage, res: http.ServerResponse, query: URLSearchParams): Promise<void> {
    if (req.method !== "GET") throw new HttpError(405, "E_BAD_REQUEST");
    const nonceHex = onlyParams(query, ["nonce"]).get("nonce");
    if (!isHex(nonceHex, 32)) throw new HttpError(400, "E_BAD_REQUEST");
    const rd = o.keys.reportData(fromHex(nonceHex, 32));
    let quote: Uint8Array;
    let eventLog: TdxEvent[];
    try {
      ({ quote, eventLog } = await o.attester.getQuote(rd));
    } catch {
      throw new HttpError(503, "E_UPSTREAM");
    }
    // Sanity check on what the quote service returned: it must quote exactly our report_data.
    if (!(quote instanceof Uint8Array) || quote.length < QUOTE.SIGNED_LEN || quote.length > MAX_QUOTE_BYTES) {
      throw new HttpError(503, "E_UPSTREAM");
    }
    if (!equalBytes(quote.subarray(QUOTE.OFF.REPORT_DATA, QUOTE.OFF.REPORT_DATA + 64), rd)) throw new HttpError(503, "E_UPSTREAM");
    sendJson(res, 200, {
      v: "PLR-v1",
      root_kind: "MOCK",
      quote: toHex(quote),
      event_log: eventLog,
      app_compose: composeText,
      x25519: xpHex,
      ed25519: epHex,
    });
  }

  function proof(req: http.IncomingMessage, res: http.ServerResponse, query: URLSearchParams): void {
    if (req.method !== "GET") throw new HttpError(405, "E_BAD_REQUEST");
    const seqStr = onlyParams(query, ["seq"]).get("seq") ?? null;
    let seq: number;
    try {
      seq = parseUintParam(seqStr);
    } catch {
      throw new HttpError(400, "E_BAD_REQUEST");
    }
    const p = o.receipts.proof(seq);
    if (!p) throw new HttpError(404, "E_NOT_ANCHORED");
    sendJson(res, 200, p);
  }

  function healthz(req: http.IncomingMessage, res: http.ServerResponse, query: URLSearchParams): void {
    if (req.method !== "GET" && req.method !== "HEAD") throw new HttpError(405, "E_BAD_REQUEST");
    onlyParams(query, []);
    sendJson(res, 200, { ok: true });
  }

  return { attestation, proof, healthz };
}
