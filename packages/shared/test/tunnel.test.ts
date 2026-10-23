// LOCKED — SPEC-VPN §4, §5
import { describe, it, expect } from "vitest";
import { x25519, ed25519 } from "@noble/curves/ed25519.js";
import { hkdf } from "@noble/hashes/hkdf.js";
import { chacha20poly1305 } from "@noble/ciphers/chacha.js";
import {
  TUNNEL, FRAME, deriveTunnel, encodeHello, parseHello, encodeServerHello, parseServerHello, tunnelClientStart, tunnelServerAccept,
  TunnelWriter, TunnelReader,
  vpnReceiptMessage, signVpnReceipt, verifyVpnReceipt, vpnReceiptLeaf, PlrError, type VpnReceipt,
} from "../src/index.js";
import { sha256, enc, cat, u64be, hex, unhex, randomBytes } from "./helpers.js";

const code = (fn: () => unknown) => { try { fn(); } catch (e) { expect(e).toBeInstanceOf(PlrError); return (e as PlrError).code; } return "NO_THROW"; };
const u32be = (n: number) => { const b = new Uint8Array(4); new DataView(b.buffer).setUint32(0, n, false); return b; };
const keys = () => {
  const xs = x25519.utils.randomSecretKey(), es = ed25519.utils.randomSecretKey();
  return { xs, xp: x25519.getPublicKey(xs), es, ep: ed25519.getPublicKey(es) };
};
const nonceFor = (dir: number, seq: number) => cat(u32be(dir), u64be(seq));

describe("constants", () => {
  it("match SPEC-VPN §4 (rev 2)", () => {
    expect(TUNNEL).toMatchObject({ VERSION: 2, HELLO_LEN: 65, SERVER_HELLO_LEN: 33, MAX_PAYLOAD: 16384, MIN_FRAME_LEN: 17, MAX_FRAME_LEN: 16401, DIR_C2S: 1, DIR_S2C: 2 });
    expect(FRAME).toEqual({ CONNECT: 1, CONNECT_OK: 2, CONNECT_ERR: 3, DATA: 4, FIN: 5, RECEIPT: 6 });
  });
});

describe("handshake v2 key schedule (§4.1)", () => {
  it("deriveTunnel matches §4.1 and is domain-separated from v1 and PLR-v1", () => {
    const { xp, ep } = keys();
    const dh1 = randomBytes(32), dh2 = randomBytes(32), attNonce = randomBytes(32), epkC = randomBytes(32), epkS = randomBytes(32);
    const t = deriveTunnel({ dh1, dh2, attNonce, epkC, epkS, xp, ep });
    const th = sha256(cat(enc("PLR-VPN-v2/tunnel"), attNonce, epkC, epkS, xp, ep));
    const okm = hkdf(sha256, cat(dh1, dh2), th, enc("PLR-VPN-v2/keys"), 64);
    expect(t.th).toEqual(th);
    expect(t.kC2s).toEqual(okm.slice(0, 32));
    expect(t.kS2c).toEqual(okm.slice(32, 64));
    expect(t.th).not.toEqual(sha256(cat(enc("PLR-VPN-v1/tunnel"), attNonce, epkC, xp, ep)));
    expect(code(() => deriveTunnel({ dh1: new Uint8Array(32), dh2, attNonce, epkC, epkS, xp, ep }))).toBe("E_DECRYPT");
    expect(code(() => deriveTunnel({ dh1, dh2: new Uint8Array(32), attNonce, epkC, epkS, xp, ep }))).toBe("E_DECRYPT");
  });

  it("hello / server_hello codecs", () => {
    const n = randomBytes(32), e = randomBytes(32), s2 = randomBytes(32);
    const h = encodeHello(n, e);
    expect(h).toEqual(cat(new Uint8Array([2]), n, e));
    expect(parseHello(h)).toEqual({ attNonce: n, epkC: e });
    expect(code(() => parseHello(h.slice(0, 64)))).toBe("E_TUNNEL_PROTOCOL");
    expect(code(() => parseHello(cat(new Uint8Array([1]), n, e)))).toBe("E_TUNNEL_PROTOCOL"); // v1 is gone
    expect(code(() => parseHello(cat(h, new Uint8Array(1))))).toBe("E_TUNNEL_PROTOCOL");
    const sh = encodeServerHello(s2);
    expect(sh).toEqual(cat(new Uint8Array([2]), s2));
    expect(parseServerHello(sh)).toEqual({ epkS: s2 });
    expect(code(() => parseServerHello(sh.slice(0, 32)))).toBe("E_TUNNEL_PROTOCOL");
    expect(code(() => parseServerHello(cat(new Uint8Array([1]), s2)))).toBe("E_TUNNEL_PROTOCOL");
  });

  it("client and server agree; keys match an independent derivation from both DH outputs", () => {
    const k = keys();
    const attNonce = randomBytes(32);
    const c = tunnelClientStart({ xp: k.xp, ep: k.ep, attNonce });
    const s = tunnelServerAccept({ ...k, hello: c.hello });
    expect(s.serverHello.length).toBe(33);
    const ck = c.finish(s.serverHello);
    expect(s.attNonce).toEqual(attNonce);
    expect(ck.th).toEqual(s.th);
    expect(ck.kC2s).toEqual(s.kC2s);
    expect(ck.kS2c).toEqual(s.kS2c);
    const epkC = c.hello.slice(33), epkS = s.serverHello.slice(1);
    const th = sha256(cat(enc("PLR-VPN-v2/tunnel"), attNonce, epkC, epkS, k.xp, k.ep));
    expect(s.th).toEqual(th);
    // dh1 = X25519(xs, epk_c) is reproducible from the exit's static key; dh2 is not (ephemeral) — so a key
    // derived WITHOUT the right dh2 must differ: compromise of xs alone does not give the tunnel keys.
    const dh1 = x25519.getSharedSecret(k.xs, epkC);
    const guess = hkdf(sha256, cat(dh1, new Uint8Array(32).fill(1)), th, enc("PLR-VPN-v2/keys"), 64);
    expect(guess.slice(0, 32)).not.toEqual(s.kC2s);
    expect(code(() => c.finish(s.serverHello))).toBe("E_TUNNEL_PROTOCOL"); // finish at most once
  });

  it("replaying the same client hello yields fresh keys (replay ⇒ auth failure)", () => {
    const k = keys();
    const c = tunnelClientStart({ xp: k.xp, ep: k.ep, attNonce: randomBytes(32) });
    const s1 = tunnelServerAccept({ ...k, hello: c.hello });
    const s2 = tunnelServerAccept({ ...k, hello: c.hello });
    expect(s2.serverHello).not.toEqual(s1.serverHello);
    expect(s2.kC2s).not.toEqual(s1.kC2s);
    const ck = c.finish(s1.serverHello);
    const frame = new TunnelWriter(ck.kC2s, ck.th, 1).seal(FRAME.CONNECT, enc('{"host":"example.com","port":443}'));
    expect(new TunnelReader(s1.kC2s, s1.th, 1).push(frame).length).toBe(1);
    expect(code(() => new TunnelReader(s2.kC2s, s2.th, 1).push(frame))).toBe("E_DECRYPT");
  });

  it("fresh client ephemeral per tunnel; bad inputs rejected", () => {
    const k = keys();
    const attNonce = randomBytes(32);
    const a = tunnelClientStart({ xp: k.xp, ep: k.ep, attNonce }), b = tunnelClientStart({ xp: k.xp, ep: k.ep, attNonce });
    expect(a.hello.slice(33)).not.toEqual(b.hello.slice(33));
    expect(code(() => tunnelServerAccept({ ...k, hello: encodeHello(randomBytes(32), new Uint8Array(32)) }))).toBe("E_DECRYPT");
    expect(code(() => tunnelServerAccept({ ...k, hello: randomBytes(10) }))).toBe("E_TUNNEL_PROTOCOL");
    expect(code(() => a.finish(encodeServerHello(new Uint8Array(32))))).toBe("E_DECRYPT");   // low-order server ephemeral
    expect(code(() => b.finish(randomBytes(5)))).toBe("E_TUNNEL_PROTOCOL");
  });
});

describe("frames", () => {
  const key = randomBytes(32), th = randomBytes(32);

  it("wire format: u32be(len)‖ChaCha20-Poly1305(nonce=u32be(dir)‖u64be(seq), aad=th‖dir, type‖payload)", () => {
    const w = new TunnelWriter(key, th, 1);
    const f0 = w.seal(FRAME.CONNECT, enc('{"host":"example.com","port":443}'));
    const f1 = w.seal(FRAME.DATA, enc("hello"));
    for (const [i, f, type, body] of [[0, f0, 1, '{"host":"example.com","port":443}'], [1, f1, 4, "hello"]] as const) {
      const len = new DataView(f.buffer, f.byteOffset).getUint32(0, false);
      expect(len).toBe(f.length - 4);
      const pt = chacha20poly1305(key, nonceFor(1, i), cat(th, new Uint8Array([1]))).decrypt(f.slice(4));
      expect(pt).toEqual(cat(new Uint8Array([type]), enc(body)));
    }
    const s = new TunnelWriter(key, th, 2).seal(FRAME.FIN, new Uint8Array());
    expect(chacha20poly1305(key, nonceFor(2, 0), cat(th, new Uint8Array([2]))).decrypt(s.slice(4))).toEqual(new Uint8Array([5]));
    expect(s.length).toBe(4 + 17);
  });

  it("reader handles arbitrary chunking, in order", () => {
    const w = new TunnelWriter(key, th, 2);
    const wire = cat(w.seal(FRAME.CONNECT_OK, new Uint8Array()), w.seal(FRAME.DATA, enc("abc")), w.seal(FRAME.DATA, randomBytes(16384)), w.seal(FRAME.FIN, new Uint8Array()));
    for (const step of [1, 3, 7, 4096, wire.length]) {
      const r = new TunnelReader(key, th, 2);
      const out: Array<{ type: number; payload: Uint8Array }> = [];
      for (let i = 0; i < wire.length; i += step) out.push(...r.push(wire.slice(i, i + step)));
      expect(out.map((f) => f.type)).toEqual([2, 4, 4, 5]);
      expect(new TextDecoder().decode(out[1]!.payload)).toBe("abc");
      expect(out[2]!.payload.length).toBe(16384);
      expect(() => r.end()).not.toThrow();
    }
  });

  it("rejects payloads above MAX_PAYLOAD at the writer", () => {
    expect(() => new TunnelWriter(key, th, 1).seal(FRAME.DATA, new Uint8Array(16385))).toThrow(PlrError);
  });

  it("rejects bad lengths, tampering, reorder, replay, wrong direction, wrong key/th, unknown types", () => {
    const w = new TunnelWriter(key, th, 2);
    const a = w.seal(FRAME.DATA, enc("a")), b = w.seal(FRAME.DATA, enc("b"));
    const fresh = () => new TunnelReader(key, th, 2);

    expect(code(() => fresh().push(cat(u32be(16), new Uint8Array(16))))).toBe("E_TUNNEL_PROTOCOL");
    expect(code(() => fresh().push(cat(u32be(16402), new Uint8Array(8))))).toBe("E_TUNNEL_PROTOCOL"); // rejected from the header alone
    const t = a.slice(); t[10]! ^= 1;
    expect(code(() => fresh().push(t))).toBe("E_DECRYPT");
    expect(code(() => fresh().push(b))).toBe("E_DECRYPT");                // skip / reorder
    let r = fresh(); r.push(a);
    expect(code(() => r.push(a))).toBe("E_DECRYPT");                      // replay
    expect(code(() => new TunnelReader(key, th, 1).push(a))).toBe("E_DECRYPT"); // reflected into the other direction
    expect(code(() => new TunnelReader(randomBytes(32), th, 2).push(a))).toBe("E_DECRYPT");
    expect(code(() => new TunnelReader(key, randomBytes(32), 2).push(a))).toBe("E_DECRYPT");
    const badCt = chacha20poly1305(key, nonceFor(2, 0), cat(th, new Uint8Array([2]))).encrypt(new Uint8Array([99]));
    const bad = cat(u32be(badCt.length), badCt);
    expect(code(() => fresh().push(bad))).toBe("E_TUNNEL_PROTOCOL");
    // poisoned after an error
    r = fresh();
    expect(code(() => r.push(t))).toBe("E_DECRYPT");
    expect(() => r.push(a)).toThrow(PlrError);
  });

  it("end() with a partial frame buffered ⇒ E_TRUNCATED", () => {
    const a = new TunnelWriter(key, th, 2).seal(FRAME.DATA, enc("abcdef"));
    const r = new TunnelReader(key, th, 2);
    expect(r.push(a.slice(0, a.length - 3))).toEqual([]);
    expect(code(() => r.end())).toBe("E_TRUNCATED");
    const r2 = new TunnelReader(key, th, 2);
    r2.push(a.slice(0, 2));
    expect(code(() => r2.end())).toBe("E_TRUNCATED");
  });
});

describe("VPN session receipts (§5)", () => {
  const R = (): VpnReceipt => ({ v: 1, th: "a1".repeat(32), compose_hash: "b2".repeat(32), key_hash: "c3".repeat(32), seq: 7, ts_open_ms: 1_700_000_000_000, ts_close_ms: 1_700_000_000_999 });
  it("message layout, leaf, signature", () => {
    const r = R();
    const msg = cat(enc("PLR-VPN-v1/receipt"), unhex(r.th), unhex(r.compose_hash), unhex(r.key_hash), u64be(7), u64be(r.ts_open_ms), u64be(r.ts_close_ms));
    expect(vpnReceiptMessage(r)).toEqual(msg);
    expect(vpnReceiptLeaf(r)).toEqual(sha256(cat(new Uint8Array([0]), msg)));
    const sk = ed25519.utils.randomSecretKey(), pk = ed25519.getPublicKey(sk);
    const sig = signVpnReceipt(r, sk);
    expect(sig).toMatch(/^[0-9a-f]{128}$/);
    expect(ed25519.verify(unhex(sig), msg, pk)).toBe(true);
    expect(verifyVpnReceipt(r, sig, pk)).toBe(true);
    for (const k of ["th", "compose_hash", "key_hash"] as const) expect(verifyVpnReceipt({ ...r, [k]: "00".repeat(32) }, sig, pk)).toBe(false);
    expect(verifyVpnReceipt({ ...r, seq: 8 }, sig, pk)).toBe(false);
    expect(verifyVpnReceipt({ ...r, ts_close_ms: r.ts_close_ms + 1 }, sig, pk)).toBe(false);
    expect(verifyVpnReceipt(r, sig, ed25519.getPublicKey(ed25519.utils.randomSecretKey()))).toBe(false);
  });
  it("is distinct from an LLM receipt (domain separation)", () => {
    expect(hex(vpnReceiptMessage(R()).slice(0, 18))).toBe(hex(enc("PLR-VPN-v1/receipt")));
  });
  it("contains no metadata fields", () => {
    expect(Object.keys(R()).sort()).toEqual(["compose_hash", "key_hash", "seq", "th", "ts_close_ms", "ts_open_ms", "v"]);
  });
});
