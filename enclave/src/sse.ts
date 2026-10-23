/**
 * Minimal, bounded Server-Sent-Events line parser for the upstream LLM stream. Yields the value of every
 * `data:` field; other fields and comments are ignored. Lines longer than `maxLine` are an error.
 */
export class SseParser {
  readonly #maxLine: number;
  #buf: Buffer = Buffer.alloc(0);
  #data: string[] = [];

  constructor(maxLine = 1024 * 1024) {
    this.#maxLine = maxLine;
  }

  /** Feeds a chunk; returns the completed events' data payloads. @throws Error("E_UPSTREAM") on oversize lines. */
  push(chunk: Uint8Array): string[] {
    this.#buf = this.#buf.length === 0 ? Buffer.from(chunk) : Buffer.concat([this.#buf, chunk]);
    const out: string[] = [];
    for (;;) {
      const nl = this.#buf.indexOf(0x0a);
      if (nl < 0) break;
      let line = this.#buf.subarray(0, nl);
      this.#buf = this.#buf.subarray(nl + 1);
      if (line.length > 0 && line[line.length - 1] === 0x0d) line = line.subarray(0, line.length - 1);
      if (line.length > this.#maxLine) throw new Error("E_UPSTREAM");
      this.#line(line.toString("utf8"), out);
    }
    if (this.#buf.length > this.#maxLine) throw new Error("E_UPSTREAM");
    return out;
  }

  /** Flushes a trailing event that was not terminated by a blank line. */
  end(): string[] {
    const out: string[] = [];
    if (this.#buf.length > 0) {
      this.#line(this.#buf.toString("utf8"), out);
      this.#buf = Buffer.alloc(0);
    }
    this.#line("", out);
    return out;
  }

  #line(line: string, out: string[]): void {
    if (line === "") {
      if (this.#data.length > 0) out.push(this.#data.join("\n"));
      this.#data = [];
      return;
    }
    if (line.startsWith(":")) return;
    const i = line.indexOf(":");
    const field = i < 0 ? line : line.slice(0, i);
    let value = i < 0 ? "" : line.slice(i + 1);
    if (value.startsWith(" ")) value = value.slice(1);
    if (field === "data") this.#data.push(value);
    // `error:` lines (llama-server) and others carry no data for us; an error surfaces as a missing finish.
  }
}
