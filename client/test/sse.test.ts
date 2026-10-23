import { describe, it, expect } from "vitest";
import { SseParser, SseError } from "../src/sse.js";
import { prng, randomChunker } from "./fake-router.js";

const enc = new TextEncoder();

function parseAll(chunks: Uint8Array[]): string[] {
  const p = new SseParser();
  const out: string[] = [];
  for (const c of chunks) out.push(...p.push(c));
  p.end();
  return out;
}

const ALPHABET = ["a", "Z", "0", " ", ":", "{", "\"", "é", "€", "🌍", "日", "=", "+", "/"];

/** Generates a random SSE stream and the data payloads a conforming parser must yield. */
function genStream(rand: () => number): { text: string; expected: string[] } {
  const pick = <T>(a: T[]): T => a[Math.floor(rand() * a.length)]!;
  const word = () => Array.from({ length: Math.floor(rand() * 12) }, () => pick(ALPHABET)).join("");
  const lines: string[] = [];
  const expected: string[] = [];
  const nEvents = 1 + Math.floor(rand() * 8);
  for (let e = 0; e < nEvents; e++) {
    const data: string[] = [];
    const nLines = 1 + Math.floor(rand() * 5);
    for (let l = 0; l < nLines; l++) {
      const r = rand();
      if (r < 0.15) lines.push(`: comment ${word()}`);
      else if (r < 0.25) lines.push(`event: ${word()}`);
      else if (r < 0.3) lines.push(`id: 7`);
      else if (r < 0.35) lines.push(`retry: 1000`);
      else {
        const v = word();
        const form = rand();
        if (form < 0.6) lines.push(`data: ${v}`);
        else if (form < 0.9) lines.push(`data:${v.startsWith(" ") ? " " + v : v}`);
        else { lines.push("data"); data.push(""); continue; }
        data.push(v);
      }
    }
    if (data.length > 0) expected.push(data.join("\n"));
    lines.push(""); // dispatch
  }
  // Random line endings, avoiding "\r" followed by a "\n" ending (which would merge into one CRLF).
  let text = "";
  let prev = "";
  for (const line of lines) {
    let eol = pick(["\n", "\r\n", "\r"]);
    if (prev === "\r" && line === "" && eol !== "\r") eol = "\r";
    text += line + eol;
    prev = eol;
  }
  if (rand() < 0.3) text += "data: incomplete-event-is-discarded";
  return { text, expected };
}

describe("SseParser", () => {
  it("parses basic events, comments and multi-line data", () => {
    const s = 'data: {"seq":0}\n\n: keepalive\n\ndata: a\ndata: b\n\nevent: x\ndata:c\r\n\r\n';
    expect(parseAll([enc.encode(s)])).toEqual(['{"seq":0}', "a\nb", "c"]);
  });

  it("handles CR at a chunk end followed by LF in the next chunk as one line break", () => {
    expect(parseAll([enc.encode("data: x\r"), enc.encode("\n\r"), enc.encode("\n")])).toEqual(["x"]);
    expect(parseAll([enc.encode("data: x\r"), enc.encode(""), enc.encode("\ndata: y\r\r")])).toEqual(["x\ny"]);
  });

  it("discards an event not terminated by a blank line", () => {
    expect(parseAll([enc.encode("data: a\n\ndata: b\n")])).toEqual(["a"]);
  });

  it("fuzz: identical output for any chunking (random split points, incl. inside UTF-8 sequences)", () => {
    for (let seed = 1; seed <= 400; seed++) {
      const rand = prng(seed);
      const { text, expected } = genStream(rand);
      const bytes = enc.encode(text);
      expect(parseAll([bytes]), `seed ${seed} whole`).toEqual(expected);
      for (let k = 0; k < 5; k++) {
        expect(parseAll(randomChunker(rand, 60)(bytes)), `seed ${seed} split ${k}`).toEqual(expected);
      }
      // byte-at-a-time
      expect(parseAll(Array.from(bytes, (b) => Uint8Array.of(b))), `seed ${seed} bytewise`).toEqual(expected);
    }
  });

  it("rejects invalid UTF-8, even when split", () => {
    const p = new SseParser();
    expect(() => p.push(Uint8Array.of(0x64, 0x61, 0xff))).toThrow(SseError);
    expect(() => p.push(enc.encode("data: x\n\n"))).toThrow(SseError); // sticky failure
    const q = new SseParser();
    q.push(enc.encode("data: ").subarray(0, 6));
    q.push(Uint8Array.of(0xf0, 0x9f)); // truncated 4-byte sequence
    expect(() => q.end()).toThrow(SseError);
  });

  it("enforces line and event size limits", () => {
    const p = new SseParser({ maxLineLength: 16 });
    expect(() => p.push(enc.encode("data: " + "x".repeat(20)))).toThrow(SseError);
    const q = new SseParser({ maxLineLength: 100, maxEventLength: 10 });
    expect(() => q.push(enc.encode("data: 123456\ndata: 123456\n"))).toThrow(SseError);
  });
});
