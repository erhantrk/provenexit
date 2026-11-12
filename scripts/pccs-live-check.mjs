#!/usr/bin/env node
/**
 * T24 acceptance: verify the real TDX quote recorded on 2026-11-09 (fixtures/phala-spike, a dstack CVM on Phala)
 * with collateral fetched live from `PLR_PCCS_URL`, using the client's own `fetchPccsCollateral` +
 * `@plr/shared`'s production `DcapQvlVerifier` pinned to the Intel SGX Root CA.
 *
 * This is the live half of T24: `AttestationCache.attest()` feeds the same function's output to the verifier via the
 * bundle's `collateral` field (client/test/pccs.test.ts covers that wiring). A whole `plr vpn verify` needs a live
 * INTEL exit on real TDX (the live exit: `scripts/try-live.sh`).
 *
 * usage: PLR_PCCS_URL=https://pccs.phala.network node scripts/pccs-live-check.mjs
 *        (build first: npx tsc -b)
 */
import { readFileSync } from "node:fs";
import { DcapQvlVerifier, INTEL_ROOT_P256, PlrError, toHex } from "@plr/shared";
import { fetchPccsCollateral } from "../client/dist/pccs.js";

const url = process.env.PLR_PCCS_URL;
if (url === undefined || url === "") {
  console.error("✘ PLR_PCCS_URL must be set (e.g. https://pccs.phala.network)");
  process.exit(2);
}
const quote = new Uint8Array(Buffer.from(
  readFileSync(new URL("../fixtures/phala-spike/quote.hex", import.meta.url), "utf8").trim(),
  "hex",
));

try {
  const collateral = await fetchPccsCollateral(url, quote);
  const verifier = new DcapQvlVerifier(INTEL_ROOT_P256);
  verifier.verify(quote, { collateral });
  console.log(`✔ live PCCS verify: ${url}`);
  console.log(`  quote:      ${quote.length} bytes (sha256 ${toHex(new Uint8Array(await crypto.subtle.digest("SHA-256", quote)))})`);
  console.log(`  tcb:        ${verifier.lastStatus}`);
  console.log(`  root:       INTEL ROOT (Intel SGX Root CA) ${toHex(INTEL_ROOT_P256)}`);
  console.log(`  collateral: ${Object.keys(collateral).sort().join(", ")}`);
} catch (e) {
  console.error(`✘ live PCCS verify failed: ${e instanceof PlrError ? e.code : String(e)}`);
  process.exit(1);
}
