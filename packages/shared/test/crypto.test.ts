// LOCKED — SPEC §6.3
import { describe, it, expect } from "vitest";
import { x25519, ed25519 } from "@noble/curves/ed25519.js";
import { hkdf } from "@noble/hashes/hkdf.js";
import { chacha20poly1305 } from "@noble/ciphers/chacha.js";
import { deriveSession, clientSeal, serverOpen, sealFrame, openFrame, FrameReader, PlrError } from "../src/index.js";
import { sha256, enc, cat, u64be, randomBytes } from "./helpers.js";

const code = (fn: () => unknown) => { try { fn(); } catch (e) { expect(e).toBeInstanceOf(PlrError); return (e as PlrError).code; } return "NO_THROW"; };
const keys = () => {
  const xs = x25519.utils.randomSecretKey(), es = ed25519.utils.randomSecretKey();
  return { xs, xp: x25519.getPublicKey(xs), es, ep: ed25519.getPublicKey(es) };
};
const frameNonce = (seq: number) => cat(new Uint8Array(4), u64be(seq));

describe("session key schedule", () => {
  it("deriveSession matches §6.3 exactly", () => {
    const { xp, ep } = keys();
    const shared = randomBytes(32), attNonce = randomBytes(32), epk = randomBytes(32);
    const s = deriveSession({ shared, attNonce, epk, xp, ep });
    const th = sha256(cat(enc("PLR-v1/session"), attNonce, epk, xp, ep));
    const okm = hkdf(sha256, shared, th, enc("PLR-v1/keys"), 64);
    expect(s.th).toEqual(th);
    expect(s.kC2s).toEqual(okm.slice(0, 32));
    expect(s.kS2c).toEqual(okm.slice(32, 64));
  });

  it("clientSeal → serverOpen round-trips; ciphertext is independently decryptable", () => {
    const { xs, xp, ep } = keys();
    const attNonce = randomBytes(32);
    const pt = enc(JSON.stringify({ model: "x", messages: [{ role: "user", content: "secret prompt" }] }));
    const c = clientSeal({ xp, ep, attNonce, plaintext: pt });
    expect(c.epk.length).toBe(32);
    expect(Buffer.from(c.ct).includes(Buffer.from("secret prompt"))).toBe(false);
    const s = serverOpen({ xs, xp, ep, attNonce, epk: c.epk, ct: c.ct });
    expect(s.plaintext).toEqual(pt);
    expect(s.th).toEqual(c.th);
    expect(s.kS2c).toEqual(c.kS2c);
    const shared = x25519.getSharedSecret(xs, c.epk);
    const d = deriveSession({ shared, attNonce, epk: c.epk, xp, ep });
    expect(chacha20poly1305(d.kC2s, new Uint8Array(12), d.th).decrypt(c.ct)).toEqual(pt);
  });

  it("uses a fresh ephemeral key per request", () => {
    const { xp, ep } = keys();
    const a = clientSeal({ xp, ep, attNonce: randomBytes(32), plaintext: enc("a") });
    const b = clientSeal({ xp, ep, attNonce: randomBytes(32), plaintext: enc("a") });
    expect(a.epk).not.toEqual(b.epk);
  });

  it("serverOpen fails closed", () => {
    const k = keys(), other = keys();
    const attNonce = randomBytes(32);
    const c = clientSeal({ xp: k.xp, ep: k.ep, attNonce, plaintext: enc("hello") });
    expect(code(() => serverOpen({ ...other, attNonce, epk: c.epk, ct: c.ct }))).toBe("E_DECRYPT");
    expect(code(() => serverOpen({ ...k, attNonce: randomBytes(32), epk: c.epk, ct: c.ct }))).toBe("E_DECRYPT");
    const t = c.ct.slice(); t[0]! ^= 1;
    expect(code(() => serverOpen({ ...k, attNonce, epk: c.epk, ct: t }))).toBe("E_DECRYPT");
    expect(code(() => serverOpen({ ...k, attNonce, epk: new Uint8Array(32), ct: c.ct }))).toBe("E_DECRYPT"); // low-order point
    expect(code(() => serverOpen({ ...k, attNonce, epk: c.epk, ct: new Uint8Array(3) }))).toBe("E_DECRYPT");
  });
});

describe("response frames", () => {
  const k = randomBytes(32), th = randomBytes(32);

  it("sealFrame uses nonce u32be(0)‖u64be(seq) and aad th‖fin", () => {
    const pt = enc("delta");
    const ct = sealFrame(k, th, 7, false, pt);
    expect(chacha20poly1305(k, frameNonce(7), cat(th, new Uint8Array([0]))).decrypt(ct)).toEqual(pt);
    const ctf = sealFrame(k, th, 8, true, pt);
    expect(chacha20poly1305(k, frameNonce(8), cat(th, new Uint8Array([1]))).decrypt(ctf)).toEqual(pt);
    expect(openFrame(k, th, 8, true, ctf)).toEqual(pt);
    expect(code(() => openFrame(k, th, 8, false, ctf))).toBe("E_DECRYPT");
    expect(code(() => openFrame(k, th, 9, true, ctf))).toBe("E_DECRYPT");
  });

  it("FrameReader accepts an in-order stream ending with fin", () => {
    const r = new FrameReader(k, th);
    const outs = [0, 1, 2].map((i) => r.push(i, sealFrame(k, th, i, i === 2, enc(`f${i}`))));
    expect(outs.map((o) => o.fin)).toEqual([false, false, true]);
    expect(outs.map((o) => new TextDecoder().decode(o.plaintext))).toEqual(["f0", "f1", "f2"]);
    expect(() => r.end()).not.toThrow();
  });

  it("FrameReader rejects reorder, skip, replay, truncation, data after fin", () => {
    const f = (i: number, fin = false) => sealFrame(k, th, i, fin, enc(`f${i}`));
    let r = new FrameReader(k, th);
    expect(code(() => r.push(1, f(1)))).toBe("E_DECRYPT"); // skip 0

    r = new FrameReader(k, th);
    r.push(0, f(0));
    expect(code(() => r.push(0, f(0)))).toBe("E_DECRYPT"); // replay

    r = new FrameReader(k, th);
    expect(code(() => r.push(0, f(1)))).toBe("E_DECRYPT"); // ct for seq 1 presented as seq 0

    r = new FrameReader(k, th);
    r.push(0, f(0)); r.push(1, f(1));
    expect(code(() => r.end())).toBe("E_TRUNCATED");

    r = new FrameReader(k, th);
    r.push(0, f(0, true));
    expect(() => r.push(1, f(1))).toThrow(PlrError);

    r = new FrameReader(k, th);
    expect(code(() => r.push(0, sealFrame(randomBytes(32), th, 0, true, enc("x"))))).toBe("E_DECRYPT");
  });
});
