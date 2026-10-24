/** PLR Zcash record payloads (SPEC-CHAINS §5): `"PLR1" ‖ u8(type) ‖ body`, ≤ 80 bytes, carried in one OP_RETURN. */
import { PlrError } from "../errors.js";
import { concatBytes, fromHex, isBytes, isHex, toHex, utf8 } from "../bytes.js";
import { isOrgId } from "../registry.js";
import { MAX_OP_RETURN_DATA } from "./script.js";

export const ZCASH_RECORD_MAGIC: Uint8Array = utf8("PLR1");
export const ZCASH_RECORD_TYPE = Object.freeze({
  allow_compose: 0x01,
  revoke_compose: 0x02,
  allow_os: 0x03,
  revoke_os: 0x04,
  set_root: 0x05,
  approve_operator: 0x06,
  revoke_operator: 0x07,
  transfer_owner: 0x08,
  reg_keys: 0x10,
  reg_measure: 0x11,
  reg_os: 0x12,
  reg_quote: 0x13,
  anchor: 0x20,
  anchor_sig: 0x21,
} as const);
/** Max org_id bytes in an approve_operator record (fits the 80-byte payload). */
export const ZCASH_MAX_ORG_ID = 48;
/** Anchor batch bounds (SPEC §7). */
export const ZCASH_MAX_ANCHOR_COUNT = 10_000;

export type ZcashRecord =
  | { type: "allow_compose" | "revoke_compose" | "allow_os" | "revoke_os"; hash: string }
  | { type: "set_root"; kind: "MOCK" | "INTEL"; p256: string }
  | { type: "approve_operator"; hash160: string; org_id: string }
  | { type: "revoke_operator" | "transfer_owner"; hash160: string }
  | { type: "reg_keys"; x25519: string; ed25519: string }
  | { type: "reg_measure"; key_hash: string; compose_hash: string }
  | { type: "reg_os"; key_hash: string; os_measurement: string }
  | { type: "reg_quote"; key_hash: string; quote_sha256: string }
  | { type: "anchor"; key_hash: string; root: string; first_seq: number; count: number }
  | { type: "anchor_sig"; key_prefix: string; sig: string };

export type ZcashRecordType = ZcashRecord["type"];

const bad = (d: string): never => {
  throw new PlrError("E_BAD_INPUT", `zcash record: ${d}`);
};
const h = (v: unknown, n: number, what: string): Uint8Array => (isHex(v, n) ? fromHex(v, n) : bad(what));
const isU32 = (n: unknown): n is number => typeof n === "number" && Number.isInteger(n) && n >= 0 && n <= 0xffffffff;
const isCount = (n: unknown): n is number => typeof n === "number" && Number.isInteger(n) && n >= 1 && n <= ZCASH_MAX_ANCHOR_COUNT;

function be(n: number, len: 2 | 4): Uint8Array {
  const b = new Uint8Array(len);
  const dv = new DataView(b.buffer);
  if (len === 4) dv.setUint32(0, n, false);
  else dv.setUint16(0, n, false);
  return b;
}

/** Encodes a record as its OP_RETURN payload. @throws PlrError E_BAD_INPUT on any invalid field */
export function encodeZcashRecord(r: ZcashRecord): Uint8Array {
  if (typeof r !== "object" || r === null) return bad("record required");
  let body: Uint8Array;
  switch (r.type) {
    case "allow_compose":
    case "revoke_compose":
    case "allow_os":
    case "revoke_os":
      body = h(r.hash, 32, "hash");
      break;
    case "set_root":
      if (r.kind !== "MOCK" && r.kind !== "INTEL") bad("root kind");
      body = concatBytes(Uint8Array.of(r.kind === "MOCK" ? 1 : 2), h(r.p256, 64, "p256"));
      break;
    case "approve_operator": {
      if (!isOrgId(r.org_id)) bad("org_id");
      const org = utf8(r.org_id);
      if (org.length > ZCASH_MAX_ORG_ID) bad("org_id too long");
      body = concatBytes(h(r.hash160, 20, "hash160"), Uint8Array.of(org.length), org);
      break;
    }
    case "revoke_operator":
    case "transfer_owner":
      body = h(r.hash160, 20, "hash160");
      break;
    case "reg_keys":
      body = concatBytes(h(r.x25519, 32, "x25519"), h(r.ed25519, 32, "ed25519"));
      break;
    case "reg_measure":
      body = concatBytes(h(r.key_hash, 32, "key_hash"), h(r.compose_hash, 32, "compose_hash"));
      break;
    case "reg_os":
      body = concatBytes(h(r.key_hash, 32, "key_hash"), h(r.os_measurement, 32, "os_measurement"));
      break;
    case "reg_quote":
      body = concatBytes(h(r.key_hash, 32, "key_hash"), h(r.quote_sha256, 32, "quote_sha256"));
      break;
    case "anchor":
      if (!isU32(r.first_seq)) bad("first_seq");
      if (!isCount(r.count)) bad("count");
      body = concatBytes(h(r.key_hash, 32, "key_hash"), h(r.root, 32, "root"), be(r.first_seq, 4), be(r.count, 2));
      break;
    case "anchor_sig":
      body = concatBytes(h(r.key_prefix, 8, "key_prefix"), h(r.sig, 64, "sig"));
      break;
    default:
      return bad("unknown type");
  }
  const out = concatBytes(ZCASH_RECORD_MAGIC, Uint8Array.of(ZCASH_RECORD_TYPE[r.type]), body);
  if (out.length > MAX_OP_RETURN_DATA) bad("too long");
  return out;
}

/** Decodes an OP_RETURN payload; null for anything that is not exactly a well-formed record. Never throws. */
export function decodeZcashRecord(payload: Uint8Array): ZcashRecord | null {
  if (!isBytes(payload) || payload.length < 5 || payload.length > MAX_OP_RETURN_DATA) return null;
  for (let i = 0; i < 4; i++) if (payload[i] !== ZCASH_RECORD_MAGIC[i]) return null;
  const t = payload[4]!;
  const b = payload.subarray(5);
  const x = (from: number, to: number) => toHex(b.subarray(from, to));
  const dv = new DataView(b.buffer, b.byteOffset, b.byteLength);
  switch (t) {
    case 0x01:
    case 0x02:
    case 0x03:
    case 0x04: {
      if (b.length !== 32) return null;
      const type = t === 0x01 ? "allow_compose" : t === 0x02 ? "revoke_compose" : t === 0x03 ? "allow_os" : "revoke_os";
      return { type, hash: x(0, 32) };
    }
    case 0x05:
      if (b.length !== 65 || (b[0] !== 1 && b[0] !== 2)) return null;
      return { type: "set_root", kind: b[0] === 1 ? "MOCK" : "INTEL", p256: x(1, 65) };
    case 0x06: {
      if (b.length < 22) return null;
      const len = b[20]!;
      if (len < 1 || len > ZCASH_MAX_ORG_ID || b.length !== 21 + len) return null;
      let org: string;
      try {
        org = new TextDecoder("utf-8", { fatal: true }).decode(b.subarray(21));
      } catch {
        return null;
      }
      if (!isOrgId(org)) return null;
      return { type: "approve_operator", hash160: x(0, 20), org_id: org };
    }
    case 0x07:
    case 0x08:
      if (b.length !== 20) return null;
      return { type: t === 0x07 ? "revoke_operator" : "transfer_owner", hash160: x(0, 20) };
    case 0x10:
      if (b.length !== 64) return null;
      return { type: "reg_keys", x25519: x(0, 32), ed25519: x(32, 64) };
    case 0x11:
      if (b.length !== 64) return null;
      return { type: "reg_measure", key_hash: x(0, 32), compose_hash: x(32, 64) };
    case 0x12:
      if (b.length !== 64) return null;
      return { type: "reg_os", key_hash: x(0, 32), os_measurement: x(32, 64) };
    case 0x13:
      if (b.length !== 64) return null;
      return { type: "reg_quote", key_hash: x(0, 32), quote_sha256: x(32, 64) };
    case 0x20: {
      if (b.length !== 70) return null;
      const count = dv.getUint16(68, false);
      if (!isCount(count)) return null;
      return { type: "anchor", key_hash: x(0, 32), root: x(32, 64), first_seq: dv.getUint32(64, false), count };
    }
    case 0x21:
      if (b.length !== 72) return null;
      return { type: "anchor_sig", key_prefix: x(0, 8), sig: x(8, 72) };
    default:
      return null;
  }
}
