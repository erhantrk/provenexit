// operator one-off: build register_instance_tdx args from the 2026-11-09 Phala spike dump (S1-F2)
import { readFileSync, writeFileSync } from "node:fs";
import { randomBytes } from "node:crypto";
const R = new URL("../..", import.meta.url).pathname.replace(/\/$/, "");
const dcap = await import(R + "/node_modules/@phala/dcap-qvl/dist/index.js").catch(() => import(R + "/node_modules/@phala/dcap-qvl/index.js")).catch(async () => (await import("module")).createRequire(R + "/package.json")("@phala/dcap-qvl"));
const shared = await import(R + "/packages/shared/dist/index.js");
const d = JSON.parse(readFileSync(R + "/fixtures/phala-spike/phala-dump.json", "utf8"));
const quoteHex = d.quote.replace(/^0x/, "");
const raw = await dcap.getCollateral("https://pccs.phala.network", Buffer.from(quoteHex, "hex"));
const collateral = JSON.stringify(shared.canonicalCollateral(raw));
const event_log = JSON.parse(d.event_log).filter((e) => e.imr === 3).map((e) => ({ imr: 3, event_type: e.event_type, digest: String(e.digest), event: String(e.event), event_payload: String(e.event_payload) }));
const tcb = typeof d.info.tcb_info === "string" ? JSON.parse(d.info.tcb_info) : d.info.tcb_info; const app_compose = tcb.app_compose;
const args = { quote: quoteHex, collateral, event_log, app_compose, x25519: randomBytes(32).toString("hex"), ed25519: randomBytes(32).toString("hex") };
writeFileSync(process.argv[2], JSON.stringify(args));
console.log("quote", quoteHex.length, "collateral", collateral.length, "events", event_log.length, "compose", app_compose.length, "args bytes", JSON.stringify(args).length);
