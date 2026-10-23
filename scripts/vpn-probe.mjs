#!/usr/bin/env node
/**
 * One verified VPN connection, for scripts/demo.sh: shows the exact PLR error code of a refusal, which a SOCKS5
 * client only sees as a reply byte (SPEC-VPN §8).
 *
 *   node scripts/vpn-probe.mjs <host> <port> [<path>]
 *
 * Same env as `plr vpn` (PLR_VPN_URL, PLR_VPN_ENTRY_URL ⇒ two-hop, PLR_VPN_REGISTRY, PLR_NEAR_RPC,
 * PLR_TRUSTED_ROOT, PLR_VPN_ATTEST_TTL_MS). Runs the full client procedure (attestation, registry re-check, and in
 * two-hop mode the operator-organization rules), sends `GET <path>` (default `/`) over the tunnel, prints the
 * response (≤ 4 KiB) and the verified receipt(s): `✔ …` and exit 0, or `✘ <E_CODE>` and exit 1.
 * The client never resolves <host>: the exit does (DoH).
 */
import { dirname, join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const client = await import(pathToFileURL(join(dirname(fileURLToPath(import.meta.url)), "..", "client", "dist", "index.js")).href);
const { loadVpnConfig, NearRegistry, VpnClient, TwoHopClient } = client;

const MAX_SHOWN = 4096;
const DEADLINE_MS = 60_000;

const [host, portStr, path = "/"] = process.argv.slice(2);
if (!host || host.length > 253 || !/^[0-9]{1,5}$/.test(portStr ?? "") || Number(portStr) < 1 || Number(portStr) > 65535 || !/^\/[\x21-\x7e]{0,1024}$/.test(path)) {
  process.stderr.write("usage: vpn-probe.mjs <host> <port 1..65535> [</path>]\n");
  process.exit(2);
}
const code = (e) => (e && typeof e === "object" && typeof e.code === "string" && /^E_[A-Z0-9_]+$/.test(e.code) ? e.code : "E_INTERNAL");

setTimeout(() => {
  console.log("✘ E_TIMEOUT (probe deadline)");
  process.exit(1);
}, DEADLINE_MS).unref();

let cfg;
try {
  cfg = loadVpnConfig(process.env);
} catch (e) {
  process.stderr.write(`config error: ${e instanceof Error ? e.message : String(e)}\n`);
  process.exit(2);
}
const common = { registry: new NearRegistry({ rpcUrl: cfg.rpcUrl, contractId: cfg.contractId }), trustedRoot: cfg.trustedRoot, attestTtlMs: cfg.attestTtlMs };
const twoHop = cfg.entryUrl !== undefined;
const c = twoHop ? new TwoHopClient({ entryUrl: cfg.entryUrl, exitUrl: cfg.exitUrl, ...common }) : new VpnClient({ exitUrl: cfg.exitUrl, ...common });

try {
  const s = await c.connect(host, Number(portStr));
  const body = await new Promise((ok, fail) => {
    const chunks = [];
    let n = 0;
    s.on("data", (b) => {
      if (n < MAX_SHOWN) chunks.push(b.subarray(0, MAX_SHOWN - n));
      n += b.length;
    });
    s.once("end", () => {
      s.end(); // half-close our side only after the response (then both FINs ⇒ receipts)
      ok(Buffer.concat(chunks).toString("latin1"));
    });
    s.once("error", fail);
    s.write(`GET ${path} HTTP/1.1\r\nHost: ${host}\r\nConnection: close\r\nUser-Agent: plr-vpn-probe\r\n\r\n`);
  });
  const status = body.split("\r\n", 1)[0];
  const text = body.slice(body.indexOf("\r\n\r\n") + 4);
  console.log(`✔ connected ${twoHop ? "via entry → exit" : "via the exit"}: ${status}`);
  console.log(`  body: ${JSON.stringify(text.slice(0, 200))}`);
  const r = await s.receipt();
  console.log(`✔ ${twoHop ? "exit " : ""}receipt seq=${r.receipt.seq} key_hash=${r.receipt.key_hash.slice(0, 16)}… signature verified`);
  if (twoHop) {
    const e = await s.entryReceipt();
    console.log(`✔ entry receipt seq=${e.receipt.seq} key_hash=${e.receipt.key_hash.slice(0, 16)}… signature verified`);
  }
  process.exit(0);
} catch (e) {
  console.log(`✘ ${code(e)}`);
  process.exit(1);
}
