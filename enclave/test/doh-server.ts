/**
 * A local RFC 8484 resolver for unit tests (POST /dns-query, application/dns-message), answering from `set()`
 * records: A for IPv4, AAAA for IPv6 entries, unknown names ⇒ NXDOMAIN. Failure modes are switchable so the exit's
 * no-fallback behaviour can be tested deterministically: "down" (HTTP 503), "hang" (never answers), "wrong-type"
 * (text/plain), "huge" (body above 64 KiB), "garbage" (unparseable 200), "servfail" (RCODE 2).
 */
import http from "node:http";
import type net from "node:net";
import { parseIpv4, parseIpv6 } from "@plr/shared";

export type DohMode = "ok" | "down" | "hang" | "wrong-type" | "huge" | "garbage" | "servfail";

export interface DohRequestRecord {
  method: string;
  path: string;
  contentType: string | undefined;
  accept: string | undefined;
  qname: string;
  qtype: number;
  length: number;
}

export interface FakeDoh {
  url: string;
  port: number;
  set(name: string, addrs: string[]): void;
  mode: DohMode;
  hits(): number;
  requests: DohRequestRecord[];
  /** Resolves when `n` requests have arrived (event-driven). */
  waitHits(n: number): Promise<void>;
  close(): Promise<void>;
}

const u16 = (n: number) => [(n >> 8) & 0xff, n & 0xff];

/** Reads the (uncompressed) question of a query: name (lowercase, dotted) and qtype, and where it ends. */
function readQuestion(q: Uint8Array): { qname: string; qtype: number; end: number } | null {
  if (q.length < 12) return null;
  const labels: string[] = [];
  let i = 12;
  while (i < q.length && q[i]! !== 0) {
    const len = q[i]!;
    if (len > 63 || i + 1 + len > q.length) return null;
    labels.push(Buffer.from(q.subarray(i + 1, i + 1 + len)).toString("latin1").toLowerCase());
    i += 1 + len;
  }
  if (i + 5 > q.length) return null;
  return { qname: labels.join("."), qtype: (q[i + 1]! << 8) | q[i + 2]!, end: i + 5 };
}

function answer(q: Uint8Array, rcode: number, rdatas: Uint8Array[], qtype: number, questionEnd: number): Uint8Array {
  const header = [0, 0, 0x81, 0x80 | rcode, ...u16(1), ...u16(rdatas.length), ...u16(0), ...u16(0)];
  const out: number[] = [...header, ...q.subarray(12, questionEnd)];
  for (const rd of rdatas) out.push(0xc0, 0x0c, ...u16(qtype), ...u16(1), 0, 0, 0, 60, ...u16(rd.length), ...rd);
  return Uint8Array.from(out);
}

export async function startFakeDoh(): Promise<FakeDoh> {
  const records = new Map<string, string[]>();
  const requests: DohRequestRecord[] = [];
  const waiters: Array<{ n: number; ok: () => void }> = [];
  const socks = new Set<net.Socket>();
  const state = { mode: "ok" as DohMode };
  const server = http.createServer((req, res) => {
    const chunks: Buffer[] = [];
    req.on("data", (c: Buffer) => chunks.push(c));
    req.on("end", () => {
      const q = new Uint8Array(Buffer.concat(chunks));
      const question = readQuestion(q);
      requests.push({
        method: req.method ?? "", path: req.url ?? "", contentType: req.headers["content-type"], accept: req.headers.accept,
        qname: question?.qname ?? "", qtype: question?.qtype ?? 0, length: q.length,
      });
      for (const w of waiters.splice(0)) if (requests.length >= w.n) w.ok(); else waiters.push(w);
      const reply = (status: number, type: string, body: Uint8Array | string) => {
        res.writeHead(status, { "content-type": type });
        res.end(body);
      };
      switch (state.mode) {
        case "hang": return; // never answers
        case "down": return reply(503, "text/plain", "down");
        case "wrong-type": return reply(200, "text/plain", "x");
        case "huge": return reply(200, "application/dns-message", new Uint8Array(70_000));
        case "garbage": return reply(200, "application/dns-message", new Uint8Array([1, 2, 3]));
        default: break;
      }
      if (req.method !== "POST" || req.url !== "/dns-query" || !question) return reply(400, "text/plain", "bad");
      if (state.mode === "servfail") return reply(200, "application/dns-message", answer(q, 2, [], question.qtype, question.end));
      const addrs = records.get(question.qname);
      if (!addrs) return reply(200, "application/dns-message", answer(q, 3, [], question.qtype, question.end));
      const rdatas: Uint8Array[] = [];
      for (const a of addrs) {
        const v4 = parseIpv4(a);
        if (v4 && question.qtype === 1) rdatas.push(v4);
        const v6 = v4 ? null : parseIpv6(a);
        if (v6 && question.qtype === 28) rdatas.push(v6);
      }
      reply(200, "application/dns-message", answer(q, 0, rdatas, question.qtype, question.end));
    });
  });
  server.on("connection", (s: net.Socket) => { socks.add(s); s.on("close", () => socks.delete(s)); });
  await new Promise<void>((ok) => server.listen(0, "127.0.0.1", ok));
  const port = (server.address() as net.AddressInfo).port;
  return {
    url: `http://127.0.0.1:${port}/dns-query`,
    port,
    set: (name, addrs) => void records.set(name.toLowerCase(), addrs),
    get mode() { return state.mode; },
    set mode(m: DohMode) { state.mode = m; },
    hits: () => requests.length,
    requests,
    waitHits: (n) => new Promise<void>((ok) => { if (requests.length >= n) ok(); else waiters.push({ n, ok }); }),
    close: () => new Promise<void>((ok) => { for (const s of socks) s.destroy(); server.close(() => ok()); }),
  };
}
