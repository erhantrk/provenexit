// usage: node spike/s1-analyze.mjs https://<app-id>-18300.<gateway-domain>
//        node spike/s1-analyze.mjs docs/plan/spike-2026-11-09/fixtures/phala-dump.json   (offline, S1-F2)
import { createHash } from "node:crypto"; import { mkdirSync, readFileSync, writeFileSync } from "node:fs"; import tls from "node:tls";
import { createRequire } from "node:module"; const require = createRequire(import.meta.url);
const dcap = require("./node_modules/@phala/dcap-qvl");
const arg = process.argv[2];
if (!arg) { console.error("usage: node spike/s1-analyze.mjs <url|dump.json>"); process.exit(2); }
const url = /^https?:\/\//.test(arg) ? arg.replace(/\/$/, "") : null;
const out = "fixtures/phala-spike"; mkdirSync(out, { recursive: true });
const d = url ? await (await fetch(url + "/dump")).json() : JSON.parse(readFileSync(arg, "utf8"));
const qhex = String(d.quote).replace(/^0x/, ""); const q = Buffer.from(qhex, "hex");
writeFileSync(`${out}/quote.hex`, qhex); writeFileSync(`${out}/event_log_raw.json`, d.event_log); writeFileSync(`${out}/info.json`, JSON.stringify(d.info, null, 2));
console.log("quote prefix 0x?", String(d.quote).startsWith("0x"), "len", q.length, "header", q.subarray(0, 28).toString("hex"));
const sl = q.readUInt32LE(632); const tail = q.subarray(636 + sl); console.log("sig_data_len", sl, "trailing", tail.length, "all zero", tail.every((b) => b === 0));
console.log("mr_signer_seam zero", q.subarray(112, 160).every((b) => b === 0), "debug", (q[168] & 1) === 1);
const r = await dcap.getCollateralAndVerify(q); console.log("TCB status", r.status, "advisories", r.advisory_ids);
const all = JSON.parse(d.event_log); const ev = all.filter((e) => e.imr === 3);
writeFileSync(`${out}/event_log.json`, JSON.stringify(ev, null, 2));
console.log("imr3 events in order:", ev.map((e) => e.event).join(", "));
const et = Buffer.alloc(4); et.writeUInt32LE(0x08000001);
let rt = Buffer.alloc(48), allOk = true;
for (const e of ev) {
  const dig = createHash("sha384").update(Buffer.concat([et, Buffer.from(":"), Buffer.from(e.event), Buffer.from(":"), Buffer.from(e.event_payload, "hex")])).digest();
  if (dig.toString("hex") !== String(e.digest).toLowerCase()) { allOk = false; console.log("V1 digest MISMATCH for", e.event); }
  rt = createHash("sha384").update(Buffer.concat([rt, Buffer.from(e.digest, "hex")])).digest();
}
console.log("V1 digests ok", allOk, "replay == rtmr3", rt.equals(q.subarray(520, 568)));
const tcb = typeof d.info.tcb_info === "string" ? JSON.parse(d.info.tcb_info) : d.info.tcb_info;
const appCompose = tcb.app_compose; writeFileSync(`${out}/app_compose.json`, appCompose);
const ch = createHash("sha256").update(appCompose, "utf8").digest("hex");
const evCh = ev.find((e) => e.event === "compose-hash")?.event_payload; console.log("compose hash", ch, "matches event", ch === evCh, "bytes", Buffer.byteLength(appCompose));
console.log("app-id event", ev.find((e) => e.event === "app-id")?.event_payload, "info.app_id", d.info.app_id);
const os = createHash("sha256").update(Buffer.concat([q.subarray(184, 232), q.subarray(376, 424), q.subarray(424, 472), q.subarray(472, 520)])).digest("hex");
console.log("os_measurement", os, "os_image_hash", d.info.os_image_hash ?? tcb.os_image_hash);
if (!url) { console.log("S1-c gateway upgrade: not tested (offline dump; S1-F2: exit is not behind dstack-gateway)"); process.exit(0); }
// gateway upgrade test
const host = new URL(url).hostname;
const s = tls.connect(443, host, { servername: host, ALPNProtocols: ["http/1.1"] }, () =>
  s.write(`GET /up HTTP/1.1\r\nHost: ${host}\r\nConnection: Upgrade\r\nUpgrade: plr-vpn/1\r\n\r\n`));
let buf = ""; s.on("data", (c) => { buf += c.toString("latin1");
  if (buf.includes("\r\n\r\n") && !buf.includes("ping-123")) { console.log("upgrade status:", buf.split("\r\n")[0]); s.write("ping-123"); }
  if (buf.includes("ping-123")) { console.log("ECHO OK"); s.end(); } });
setTimeout(() => { console.log("upgrade test timeout; got:", JSON.stringify(buf.slice(0, 200))); process.exit(0); }, 10000);
