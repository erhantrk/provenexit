// usage: node scripts/capture-fixture.mjs <exit_url> <registry_id> <out_dir> [registration_tx] [revocation_tx]
//
// Captures a `plr vpn verify --fixture <dir>` directory (INTERFACES §3.3) from a live exit plus the NEAR registry:
//   meta.json  nonce.hex  bundle.json  registry.json
//
// compose + OS hashes are passed in from `plr vpn inspect` (they come from the verified bundle) and must match what
// this script derives from the bundle; a fixture whose quote does not bind the bundle's keys and the captured nonce
// would replay to E_REPORT_DATA_KEYS, so that is refused here instead of being written.
import { createHash, randomBytes } from "node:crypto";
import { mkdirSync, writeFileSync } from "node:fs";
import { NearRegistry } from "../client/dist/index.js";
import { keyHash, fromHex, toHex, osMeasurement, parseQuote, reportData } from "../packages/shared/dist/index.js";

const [exitUrl, registry, out, regTx = null, revTx = null] = process.argv.slice(2);
if (!exitUrl || !registry || !out) {
  console.error("usage: node scripts/capture-fixture.mjs <exit_url> <registry_id> <out_dir> [registration_tx] [revocation_tx]");
  process.exit(2);
}

const rpcUrl = process.env.PLR_NEAR_RPC ?? "https://rpc.testnet.fastnear.com";
const nonce = randomBytes(32).toString("hex");

const res = await fetch(`${exitUrl}/v1/attestation?nonce=${nonce}`);
if (!res.ok) throw new Error(`GET ${exitUrl}/v1/attestation -> HTTP ${res.status}`);
const bundle = await res.json();
if (bundle.root_kind !== "INTEL") throw new Error(`exit is not in INTEL mode (root_kind ${bundle.root_kind}); there is no fixture format for it`);

const r = new NearRegistry({ rpcUrl, contractId: registry });
const xp = fromHex(bundle.x25519, 32);
const ep = fromHex(bundle.ed25519, 32);
const kh = toHex(keyHash(xp, ep));
const root = await r.getRoot();
const inst = await r.getInstance(kh);

// compose + OS hashes come from the verified bundle: run `plr vpn inspect` first and pass them via env
const compose = [process.env.FIX_COMPOSE_HASH];
const os = [process.env.FIX_OS_MEASUREMENT];
if (!compose[0] || !os[0] || !inst) {
  throw new Error(`set FIX_COMPOSE_HASH / FIX_OS_MEASUREMENT and make sure the instance is registered (key_hash ${kh}${inst ? "" : " has no on-chain record"})`);
}

const parsed = parseQuote(fromHex(bundle.quote), "INTEL");
const derivedCompose = createHash("sha256").update(bundle.app_compose, "utf8").digest("hex");
const derivedOs = toHex(osMeasurement(parsed.report));
if (compose[0] !== derivedCompose) throw new Error(`FIX_COMPOSE_HASH ${compose[0]} is not sha256(app_compose) ${derivedCompose}`);
if (os[0] !== derivedOs) throw new Error(`FIX_OS_MEASUREMENT ${os[0]} is not the quote's os_measurement ${derivedOs}`);

const bound = toHex(reportData(xp, ep, fromHex(nonce, 32)));
if (toHex(parsed.report.reportData) !== bound) {
  throw new Error(`the quote's report_data is not key_hash(x25519, ed25519) ‖ session_nonce_digest(nonce): replay would fail E_REPORT_DATA_KEYS`);
}

if (!(await r.isComposeAllowed(compose[0])) || !(await r.isOsAllowed(os[0]))) throw new Error("not allowed on chain right now");

mkdirSync(out, { recursive: true });
writeFileSync(`${out}/nonce.hex`, nonce);
writeFileSync(`${out}/bundle.json`, JSON.stringify(bundle, null, 2));
writeFileSync(`${out}/registry.json`, JSON.stringify({ root, compose, os, instances: { [kh]: inst } }, null, 2));
writeFileSync(`${out}/meta.json`, JSON.stringify({
  captured_at_ms: Date.now(),
  exit_url: exitUrl,
  network: "testnet",
  registry,
  registration_tx: regTx,
  revocation_tx: revTx,
  note: "captured by scripts/capture-fixture.mjs",
}, null, 2));
console.log("fixture written to", out);
