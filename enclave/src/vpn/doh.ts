/**
 * Exit-side name resolution: DNS-over-HTTPS only (SPEC-VPN §6.1, RFC 8484), no plaintext fallback.
 *
 *   for each resolver of the measured `policy.dns.doh`, in order:
 *     POST <url>  content-type/accept: application/dns-message, A and AAAA in parallel, 5 s deadline per resolver
 *     → answers (any family)            ⇒ done
 *     → NXDOMAIN / no data for both     ⇒ E_DNS (an answer, not a failure: the next resolver is not asked)
 *     → transport / HTTP / parse error  ⇒ next resolver
 *   all resolvers failed ⇒ E_DNS
 *
 * The host's resolver is never used: resolver URLs are IP literals (fetch performs no lookup for them), and this
 * module is the only resolver the exit has (egress.ts has no system-resolver fallback). Every error is the
 * content-free `PlrError("E_DNS")`: no name, address, resolver or response byte appears in an error or a log.
 * Query and response buffers (which contain the name) are zeroed after use.
 *
 * Bounded: ≤ 4 resolvers, 2 requests each, responses ≤ 65 535 bytes (read incrementally, aborted beyond), every
 * request under the per-resolver deadline and the caller's signal (the tunnel's dial deadline).
 */
import { DNS, PlrError, encodeDnsQuery, isIpLiteral, parseDnsResponse, parseIpv4, type DnsType } from "@plr/shared";
import { MAX_DOH_RESOLVERS, MAX_DOH_URL_LEN, urlHostIp } from "../compose.js";
import type { LookupAll } from "./egress.js";

export interface DohOptions {
  /** Deadline per resolver, both queries (SPEC-VPN §6.1: 5 s). */
  timeoutMs?: number;
  /** Creates the per-resolver deadline signal (default `AbortSignal.timeout`; tests trigger it by hand). */
  deadline?: (ms: number) => AbortSignal;
}

const dnsError = () => new PlrError("E_DNS", "resolution failed");

/** Resolver URLs must be http(s) with an IP-literal host (the compose validates the full rule set). */
function checkResolvers(resolvers: unknown): string[] {
  if (!Array.isArray(resolvers) || resolvers.length < 1 || resolvers.length > MAX_DOH_RESOLVERS) {
    throw new PlrError("E_BAD_INPUT", "doh: resolver list");
  }
  return resolvers.map((r: unknown) => {
    if (typeof r !== "string" || r.length > MAX_DOH_URL_LEN) throw new PlrError("E_BAD_INPUT", "doh: resolver");
    let u: URL;
    try {
      u = new URL(r);
    } catch {
      throw new PlrError("E_BAD_INPUT", "doh: resolver");
    }
    if ((u.protocol !== "https:" && u.protocol !== "http:") || urlHostIp(u.hostname) === null) throw new PlrError("E_BAD_INPUT", "doh: resolver");
    return u.href;
  });
}

function isDnsMessage(contentType: string | null): boolean {
  return typeof contentType === "string" && contentType.split(";")[0]!.trim().toLowerCase() === DNS.CONTENT_TYPE;
}

/** Reads a response body up to `max` bytes (else aborts it). */
async function readBounded(res: Response, max: number): Promise<Uint8Array> {
  const declared = res.headers.get("content-length");
  if (declared !== null && !(/^\d{1,6}$/.test(declared) && Number(declared) <= max)) throw dnsError();
  if (!res.body) return new Uint8Array(0);
  const reader = res.body.getReader();
  const chunks: Uint8Array[] = [];
  let n = 0;
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      n += value.length;
      chunks.push(value);
      if (n > max) throw dnsError();
    }
    const out = new Uint8Array(n);
    let off = 0;
    for (const c of chunks) {
      out.set(c, off);
      off += c.length;
    }
    return out;
  } catch {
    await reader.cancel().catch(() => undefined);
    throw dnsError();
  } finally {
    for (const c of chunks) c.fill(0);
  }
}

/** One RFC 8484 POST query. @throws PlrError E_DNS (any failure) */
async function query(url: string, name: string, type: DnsType, signal: AbortSignal): Promise<string[]> {
  const q = encodeDnsQuery(name, type);
  const wire = new Uint8Array(q); // (an ArrayBuffer-backed copy: what fetch's BodyInit accepts)
  q.fill(0);
  let body: Uint8Array | null = null;
  try {
    const res = await fetch(url, {
      method: "POST",
      headers: { "content-type": DNS.CONTENT_TYPE, accept: DNS.CONTENT_TYPE },
      body: wire,
      redirect: "error",
      signal,
    });
    if (res.status !== 200 || !isDnsMessage(res.headers.get("content-type"))) {
      await res.body?.cancel().catch(() => undefined);
      throw dnsError();
    }
    body = await readBounded(res, DNS.MAX_MESSAGE_LEN);
    return parseDnsResponse(body, name, type);
  } catch {
    throw dnsError();
  } finally {
    wire.fill(0);
    body?.fill(0);
  }
}

type ResolverOutcome = { kind: "answer"; addresses: string[] } | { kind: "failed" };

async function askResolver(url: string, name: string, deadline: AbortSignal, outer: AbortSignal | undefined): Promise<ResolverOutcome> {
  const signal = outer ? AbortSignal.any([deadline, outer]) : deadline;
  const [a, aaaa] = await Promise.allSettled([query(url, name, "A", signal), query(url, name, "AAAA", signal)]);
  const addresses: string[] = [];
  for (const r of [a, aaaa]) if (r.status === "fulfilled") for (const ip of r.value) if (!addresses.includes(ip)) addresses.push(ip);
  if (addresses.length > 0) return { kind: "answer", addresses };
  // Both answered and neither has an address (NXDOMAIN / NODATA): that is the resolver's answer.
  if (a.status === "fulfilled" && aaaa.status === "fulfilled") return { kind: "answer", addresses: [] };
  return { kind: "failed" };
}

/**
 * A {@link LookupAll} that resolves only through the given RFC 8484 resolvers (SPEC-VPN §6.1).
 * @throws PlrError E_BAD_INPUT at construction for a malformed resolver list
 */
export function createDohLookup(resolvers: readonly string[], o: DohOptions = {}): LookupAll {
  const urls = checkResolvers(resolvers);
  const timeoutMs = o.timeoutMs ?? DNS.RESOLVER_TIMEOUT_MS;
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 1) throw new PlrError("E_BAD_INPUT", "doh: timeout");
  const deadline = o.deadline ?? ((ms: number) => AbortSignal.timeout(ms));
  return async (hostname, signal) => {
    // Names only (IP literals are never resolved); encodeDnsQuery re-validates the §6 name rules.
    if (typeof hostname !== "string" || isIpLiteral(hostname)) throw dnsError();
    for (const url of urls) {
      if (signal?.aborted) throw dnsError();
      const r = await askResolver(url, hostname, deadline(timeoutMs), signal);
      if (r.kind === "failed") continue;
      if (r.addresses.length === 0) throw dnsError();
      return r.addresses.map((address) => ({ address, family: parseIpv4(address) !== null ? 4 : 6 }));
    }
    throw dnsError();
  };
}
