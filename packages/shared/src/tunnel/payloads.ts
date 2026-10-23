/**
 * Strict codecs for the JSON payloads of CONNECT, CONNECT_ERR and RECEIPT frames (SPEC-VPN §4.2).
 * Errors are content-free (never echo the host/port or payload).
 */
import { PlrError, type PlrErrorCode } from "../errors.js";
import { isHex, isPlainObject, utf8 } from "../bytes.js";
import { parseJsonIntegers } from "../json.js";
import { validateDestination } from "../net/egress.js";
import { isVpnReceipt, type VpnReceipt } from "../receipts/vpn-receipt.js";
import { MAX_CONNECT_PAYLOAD, TUNNEL } from "./constants.js";

/** The only codes an exit may put in CONNECT_ERR (SPEC-VPN §4.3 step 2). */
export const CONNECT_ERR_CODES = ["E_BAD_INPUT", "E_DNS", "E_EGRESS_DENIED", "E_CONNECT_FAILED"] as const satisfies readonly PlrErrorCode[];
export type ConnectErrCode = (typeof CONNECT_ERR_CODES)[number];
const CONNECT_ERR_SET: ReadonlySet<string> = new Set(CONNECT_ERR_CODES);

export function isConnectErrCode(c: unknown): c is ConnectErrCode {
  return typeof c === "string" && CONNECT_ERR_SET.has(c);
}

/** Strict UTF-8 JSON object decode; any failure → `code`. */
function decodeObject(payload: Uint8Array, maxLen: number, code: PlrErrorCode): Record<string, unknown> {
  if (!(payload instanceof Uint8Array) || payload.length === 0 || payload.length > maxLen) throw new PlrError(code, "bad payload size");
  let v: unknown;
  try {
    v = parseJsonIntegers(new TextDecoder("utf-8", { fatal: true, ignoreBOM: false }).decode(payload));
  } catch {
    throw new PlrError(code, "payload is not valid JSON");
  }
  if (!isPlainObject(v)) throw new PlrError(code, "payload is not an object");
  return v;
}

function exactKeys(o: Record<string, unknown>, keys: readonly string[]): boolean {
  const k = Object.keys(o);
  return k.length === keys.length && keys.every((x) => Object.prototype.hasOwnProperty.call(o, x));
}

/** `{"host":…,"port":…}` (validated per SPEC-VPN §6, ≤ 512 bytes). @throws PlrError E_BAD_INPUT */
export function encodeConnect(host: string, port: number): Uint8Array {
  validateDestination(host, port);
  const b = utf8(JSON.stringify({ host, port }));
  if (b.length > MAX_CONNECT_PAYLOAD) throw new PlrError("E_BAD_INPUT", "connect payload too large");
  return b;
}

/** Parses and validates a CONNECT payload. @throws PlrError E_BAD_INPUT */
export function parseConnect(payload: Uint8Array): { host: string; port: number } {
  const o = decodeObject(payload, MAX_CONNECT_PAYLOAD, "E_BAD_INPUT");
  if (!exactKeys(o, ["host", "port"]) || typeof o.host !== "string" || typeof o.port !== "number") {
    throw new PlrError("E_BAD_INPUT", "bad connect payload");
  }
  validateDestination(o.host, o.port);
  return { host: o.host, port: o.port };
}

/** `{"code":"E_…"}` with one of {@link CONNECT_ERR_CODES} only. @throws PlrError E_BAD_INPUT */
export function encodeConnectErr(code: ConnectErrCode): Uint8Array {
  if (!isConnectErrCode(code)) throw new PlrError("E_BAD_INPUT", "not a CONNECT_ERR code");
  return utf8(JSON.stringify({ code }));
}

/** @returns the CONNECT_ERR code. @throws PlrError E_TUNNEL_PROTOCOL for a malformed payload or any other code */
export function parseConnectErr(payload: Uint8Array): ConnectErrCode {
  const o = decodeObject(payload, MAX_CONNECT_PAYLOAD, "E_TUNNEL_PROTOCOL");
  if (!exactKeys(o, ["code"]) || !isConnectErrCode(o.code)) throw new PlrError("E_TUNNEL_PROTOCOL", "bad connect error payload");
  return o.code;
}

/** `{"receipt":{…},"sig":"<128 hex>"}` @throws PlrError E_BAD_INPUT */
export function encodeReceiptPayload(p: { receipt: VpnReceipt; sig: string }): Uint8Array {
  if (!isPlainObject(p) || !isVpnReceipt(p.receipt) || !isHex(p.sig, 64)) throw new PlrError("E_BAD_INPUT", "malformed receipt payload");
  const r = p.receipt;
  const receipt: VpnReceipt = {
    v: r.v, th: r.th, compose_hash: r.compose_hash, key_hash: r.key_hash, seq: r.seq, ts_open_ms: r.ts_open_ms, ts_close_ms: r.ts_close_ms,
  };
  const b = utf8(JSON.stringify({ receipt, sig: p.sig }));
  if (b.length > TUNNEL.MAX_PAYLOAD) throw new PlrError("E_BAD_INPUT", "receipt payload too large");
  return b;
}

/**
 * Shape-checks a RECEIPT payload (signature NOT verified — use `verifyVpnReceipt` with the attested `ep` and
 * compare `th` / `compose_hash` / `key_hash`). @throws PlrError E_TUNNEL_PROTOCOL
 */
export function parseReceiptPayload(payload: Uint8Array): { receipt: VpnReceipt; sig: string } {
  const o = decodeObject(payload, TUNNEL.MAX_PAYLOAD, "E_TUNNEL_PROTOCOL");
  if (!exactKeys(o, ["receipt", "sig"]) || !isVpnReceipt(o.receipt) || !isHex(o.sig, 64)) {
    throw new PlrError("E_TUNNEL_PROTOCOL", "bad receipt payload");
  }
  return { receipt: o.receipt, sig: o.sig };
}
