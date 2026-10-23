/**
 * Exit-side destination handling (SPEC-VPN §4.3 step 2, §6):
 *
 *   validateDestination → resolve (exit-side DNS, all addresses) → egressAllowed on EVERY address →
 *   dial the first address **by IP literal** (no second resolution, the hostname never reaches net.connect).
 *
 * Fail closed: if any resolved address is denied, the whole destination is denied (a name that also resolves to
 * loopback/private space is refused, whatever else it resolves to). IPv4 addresses are preferred (stable order).
 *
 * On top of the SPEC-VPN §6 classes, addresses that are "public" by the table but reach the exit's own host are
 * denied too ({@link hostOnlyDenied}): cloud host-agent endpoints that live in public space (Azure WireServer
 * 168.63.129.16, reachable only from inside the VM) and every address of the exit's own network interfaces (any
 * service the TD binds on 0.0.0.0 / ::, including the exit API itself). Compared by {@link egressIdentity}, so
 * IPv4-mapped / NAT64 / 6to4 spellings of those addresses are caught as well.
 * Errors are `PlrError`s with a CONNECT_ERR code and a static message: never the host, an address or the port.
 */
import dns from "node:dns";
import net from "node:net";
import os from "node:os";
import {
  PlrError, classifyIp, egressAllowed, egressIdentity, isIpLiteral, isPlrError, parseIpv4, validateDestination, type EgressPolicy,
} from "@plr/shared";

export interface Destination {
  host: string;
  port: number;
}

export interface ResolvedAddress {
  address: string;
  family: 4 | 6;
}

/** All addresses of `hostname` (no particular order). Must not be called for IP literals. */
export type LookupAll = (hostname: string) => Promise<ReadonlyArray<{ address: string; family: number }>>;

/** The system resolver (getaddrinfo via `dns.lookup`), all addresses. */
export const systemLookup: LookupAll = (hostname) => dns.promises.lookup(hostname, { all: true, verbatim: true });

/**
 * Host-only services that sit in "public" address space (SPEC-VPN §1.5 "metadata", not covered by the §6 table):
 * 168.63.129.16 = Azure WireServer / host agent (goal state, extension config, certificates), the mainstream
 * Intel TDX cloud. Link-local metadata (169.254.169.254), fd00:ec2::254 and 100.100.100.200 are already denied by class.
 */
export const HOST_ONLY_PUBLIC_ADDRESSES: readonly string[] = Object.freeze(["168.63.129.16"]);

/** The exit's own interface addresses (any spelling; non-literals are ignored). @throws if they cannot be listed */
export type LocalAddresses = () => Iterable<string>;

/** `os.networkInterfaces()`, read per dial (interfaces may change at runtime). */
export const systemLocalAddresses: LocalAddresses = () => {
  const out: string[] = [];
  for (const list of Object.values(os.networkInterfaces())) for (const i of list ?? []) out.push(i.address);
  return out;
};

/**
 * True if `address` (an allowed, "public" IP literal) reaches a host-only service or the exit's own host.
 * Only "public" interface addresses matter: every other class is decided by {@link egressAllowed} (so a test
 * build with `allow_loopback` still reaches 127.0.0.1). Fail closed: if the interfaces cannot be listed, or
 * `address` has no canonical form, it is denied.
 */
export function hostOnlyDenied(address: string, localAddresses: LocalAddresses): boolean {
  const id = egressIdentity(address);
  if (id === null) return true;
  if (classifyIp(address) !== "public") return false;
  if (HOST_ONLY_PUBLIC_ADDRESSES.includes(id)) return true;
  let local: Iterable<string>;
  try {
    local = localAddresses();
  } catch {
    return true;
  }
  for (const l of local) if (typeof l === "string" && egressIdentity(l) === id) return true;
  return false;
}

export interface DialOptions {
  policy: EgressPolicy;
  /** Resolver (default {@link systemLookup}). */
  lookup?: LookupAll;
  /** The exit's own addresses (default {@link systemLocalAddresses}); tests inject fixed lists. */
  localAddresses?: LocalAddresses;
  /** Deadline for resolve + connect (SPEC-VPN §4.3: 10 s). */
  timeoutMs: number;
  /** Aborts resolve/connect (e.g. the tunnel closed). */
  signal?: AbortSignal;
}

/** Opens the upstream TCP connection for a CONNECT. Rejects with PlrError E_BAD_INPUT | E_DNS | E_EGRESS_DENIED | E_CONNECT_FAILED. */
export type Dialer = (dest: Destination, o: DialOptions) => Promise<net.Socket>;

/** Upper bound on resolver answers we are willing to check. */
export const MAX_RESOLVED_ADDRESSES = 64;

function aborted(signal: AbortSignal, code: "E_DNS" | "E_CONNECT_FAILED"): Promise<never> {
  return new Promise((_, reject) => {
    const fail = () => reject(new PlrError(code, "timeout"));
    if (signal.aborted) fail();
    else signal.addEventListener("abort", fail, { once: true });
  });
}

/**
 * Validates, resolves and egress-checks a destination. IP literals are not resolved.
 * @throws PlrError E_BAD_INPUT | E_DNS | E_EGRESS_DENIED
 */
export async function resolveEgress(
  dest: Destination,
  policy: EgressPolicy,
  lookup: LookupAll,
  signal: AbortSignal,
  localAddresses: LocalAddresses = systemLocalAddresses,
): Promise<ResolvedAddress> {
  validateDestination(dest.host, dest.port); // E_BAD_INPUT
  let answers: ReadonlyArray<{ address: string; family: number }>;
  if (isIpLiteral(dest.host)) {
    answers = [{ address: dest.host, family: parseIpv4(dest.host) !== null ? 4 : 6 }];
  } else {
    try {
      answers = await Promise.race([lookup(dest.host), aborted(signal, "E_DNS")]);
    } catch {
      throw new PlrError("E_DNS", "resolution failed");
    }
  }
  if (!Array.isArray(answers) || answers.length === 0 || answers.length > MAX_RESOLVED_ADDRESSES) throw new PlrError("E_DNS", "no usable answer");
  const resolved: ResolvedAddress[] = [];
  for (const a of answers) {
    const address: unknown = (a as { address?: unknown } | null)?.address;
    if (typeof address !== "string" || !isIpLiteral(address)) throw new PlrError("E_DNS", "malformed answer");
    resolved.push({ address, family: parseIpv4(address) !== null ? 4 : 6 });
  }
  // EVERY address must be allowed (DNS answers may mix public and internal addresses).
  for (const r of resolved) if (!egressAllowed(r.address, policy)) throw new PlrError("E_EGRESS_DENIED", "destination not allowed");
  for (const r of resolved) if (hostOnlyDenied(r.address, localAddresses)) throw new PlrError("E_EGRESS_DENIED", "destination not allowed");
  const v4 = resolved.filter((r) => r.family === 4);
  return (v4[0] ?? resolved[0])!;
}

/** net.connect never resolves anything for us: it only ever gets IP literals, and this refuses any lookup. */
const refuseLookup: net.LookupFunction = (_hostname, _options, callback) => {
  callback(Object.assign(new Error("E_DNS"), { code: "E_DNS" }), "", 0);
};

/** Connects to an already egress-checked IP literal. @throws PlrError E_CONNECT_FAILED */
export function connectIp(addr: ResolvedAddress, port: number, signal: AbortSignal): Promise<net.Socket> {
  return new Promise((resolve, reject) => {
    if (!isIpLiteral(addr.address)) return reject(new PlrError("E_CONNECT_FAILED", "not an IP literal"));
    if (signal.aborted) return reject(new PlrError("E_CONNECT_FAILED", "timeout"));
    const sock = net.connect({ host: addr.address, port, family: addr.family, allowHalfOpen: true, noDelay: true, lookup: refuseLookup });
    const done = (err: PlrError | null) => {
      signal.removeEventListener("abort", onAbort);
      sock.off("connect", onConnect);
      sock.off("error", onError);
      if (err) {
        sock.destroy();
        reject(err);
      } else resolve(sock);
    };
    const onConnect = () => done(null);
    const onError = () => done(new PlrError("E_CONNECT_FAILED", "connect failed"));
    const onAbort = () => done(new PlrError("E_CONNECT_FAILED", "timeout"));
    sock.once("connect", onConnect);
    sock.once("error", onError);
    signal.addEventListener("abort", onAbort, { once: true });
  });
}

/** The honest dialer: {@link resolveEgress} then {@link connectIp}, under one deadline. */
export const dialEgress: Dialer = async (dest, o) => {
  const deadline = AbortSignal.timeout(o.timeoutMs);
  const signal = o.signal ? AbortSignal.any([deadline, o.signal]) : deadline;
  try {
    const addr = await resolveEgress(dest, o.policy, o.lookup ?? systemLookup, signal, o.localAddresses ?? systemLocalAddresses);
    return await connectIp(addr, dest.port, signal);
  } catch (e) {
    if (isPlrError(e)) throw e;
    throw new PlrError("E_CONNECT_FAILED", "connect failed");
  }
};
