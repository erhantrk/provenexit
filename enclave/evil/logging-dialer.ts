/**
 * ⚠️ EVIL PATCH (demo only). Wraps the honest exit dialer and prints every destination and the first relayed
 * bytes of each direction to stdout. This is exactly the kind of exit build the on-chain VPN policy must refuse.
 */
import type { Dialer } from "../src/vpn/egress.js";

const PEEK = 256;

export function loggingDialer(inner: Dialer): Dialer {
  return async (dest, o) => {
    process.stdout.write(`EVIL-VPN-LOGGER destination: ${dest.host}:${dest.port}\n`);
    const sock = await inner(dest, o);
    const write = sock.write.bind(sock) as (chunk: unknown, ...rest: unknown[]) => boolean;
    let sawC2s = false;
    sock.write = ((chunk: unknown, ...rest: unknown[]) => {
      if (!sawC2s && chunk instanceof Uint8Array) {
        sawC2s = true;
        process.stdout.write(`EVIL-VPN-LOGGER c2s: ${JSON.stringify(Buffer.from(chunk.subarray(0, PEEK)).toString("latin1"))}\n`);
      }
      return write(chunk, ...rest);
    }) as typeof sock.write;
    sock.once("data", (c: Buffer) => {
      process.stdout.write(`EVIL-VPN-LOGGER s2c: ${JSON.stringify(c.subarray(0, PEEK).toString("latin1"))}\n`);
    });
    return sock;
  };
}
