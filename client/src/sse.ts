/**
 * Incremental Server-Sent Events parser (WHATWG HTML §9.2 "event stream interpretation"), restricted to what
 * PLR needs: it yields the `data` payload of each dispatched event and ignores comments and other fields.
 *
 * Robust to arbitrary chunk boundaries: inside multi-byte UTF-8 sequences, between `\r` and `\n`, inside a
 * field name, etc. Invalid UTF-8 and oversized lines/events throw {@link SseError} (fail closed).
 */

export class SseError extends Error {
  constructor(detail: string) {
    super(`SSE: ${detail}`);
    this.name = "SseError";
  }
}

export interface SseLimits {
  /** Max length (UTF-16 code units) of a single line. Default 2 MiB. */
  maxLineLength?: number;
  /** Max total length of one event's data (UTF-16 code units). Default 2 MiB. */
  maxEventLength?: number;
}

const DEFAULT_MAX = 2 * 1024 * 1024;
const LINE_BREAK = /[\r\n]/g;

export class SseParser {
  readonly #decoder = new TextDecoder("utf-8", { fatal: true });
  readonly #maxLine: number;
  readonly #maxEvent: number;
  #partial = "";
  #skipLf = false;
  #data: string[] = [];
  #dataLen = 0;
  #hasData = false;
  #failed = false;

  constructor(limits: SseLimits = {}) {
    this.#maxLine = limits.maxLineLength ?? DEFAULT_MAX;
    this.#maxEvent = limits.maxEventLength ?? DEFAULT_MAX;
  }

  /** Feeds raw bytes; returns the data payloads of events completed by this chunk, in order. */
  push(chunk: Uint8Array): string[] {
    this.#assertUsable();
    let text: string;
    try {
      text = this.#decoder.decode(chunk, { stream: true });
    } catch {
      return this.#fail("invalid UTF-8");
    }
    return this.#feed(text);
  }

  /**
   * Signals end of stream. Per the SSE spec an event not terminated by a blank line is discarded, so this
   * never yields events; it only verifies that no truncated UTF-8 sequence is pending.
   */
  end(): void {
    this.#assertUsable();
    try {
      this.#decoder.decode();
    } catch {
      this.#fail("truncated UTF-8");
    }
    this.#partial = "";
    this.#data = [];
    this.#dataLen = 0;
    this.#hasData = false;
    this.#failed = true; // no further input accepted
  }

  #assertUsable(): void {
    if (this.#failed) throw new SseError("parser closed");
  }

  #fail(detail: string): never {
    this.#failed = true;
    throw new SseError(detail);
  }

  #feed(text: string): string[] {
    const out: string[] = [];
    let i = 0;
    if (this.#skipLf && text.length > 0) {
      if (text.charCodeAt(0) === 0x0a) i = 1;
      this.#skipLf = false;
    }
    while (i < text.length) {
      LINE_BREAK.lastIndex = i;
      const m = LINE_BREAK.exec(text);
      if (m === null) {
        if (this.#partial.length + (text.length - i) > this.#maxLine) this.#fail("line too long");
        this.#partial += text.slice(i);
        break;
      }
      let j = m.index;
      if (this.#partial.length + (j - i) > this.#maxLine) this.#fail("line too long");
      const line = this.#partial + text.slice(i, j);
      this.#partial = "";
      if (text.charCodeAt(j) === 0x0d) {
        if (j + 1 < text.length) {
          if (text.charCodeAt(j + 1) === 0x0a) j++;
        } else {
          this.#skipLf = true; // a `\n` at the start of the next chunk belongs to this line break
        }
      }
      this.#line(line, out);
      i = j + 1;
    }
    return out;
  }

  #line(line: string, out: string[]): void {
    if (line.length === 0) {
      if (this.#hasData) out.push(this.#data.join("\n"));
      this.#data = [];
      this.#dataLen = 0;
      this.#hasData = false;
      return;
    }
    if (line.charCodeAt(0) === 0x3a) return; // ":" comment
    const colon = line.indexOf(":");
    const field = colon < 0 ? line : line.slice(0, colon);
    if (field !== "data") return; // event / id / retry / unknown fields are irrelevant to PLR
    let value = colon < 0 ? "" : line.slice(colon + 1);
    if (value.charCodeAt(0) === 0x20) value = value.slice(1);
    this.#dataLen += value.length + 1;
    if (this.#dataLen > this.#maxEvent) this.#fail("event too large");
    this.#data.push(value);
    this.#hasData = true;
  }
}
