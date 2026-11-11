#!/usr/bin/env node
// Spike S2: measures `debug_verify_tdx` (dcap-qvl 0.7.1 inside the contract) on a real near-sandbox.
//
// Usage (repo root): node contracts/near/scripts/tdx-gas-smoke.mjs
// Builds target/near/plr_registry.wasm with --features tdx-test-clock unless that artifact is already present.
import { existsSync, readFileSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { Sandbox, DEFAULT_ACCOUNT_ID, DEFAULT_PRIVATE_KEY, DEFAULT_PUBLIC_KEY } from "near-sandbox";
import { Account, JsonRpcProvider } from "near-api-js";

const here = dirname(fileURLToPath(import.meta.url));
const contractDir = join(here, "..");
const wasmPath = join(contractDir, "target/near/plr_registry.wasm");
// `target/` is not committed and a deploy build (cargo near build WITHOUT the feature) overwrites the same file,
// so never trust whatever build ran last: build the test-clock wasm unless that exact artifact is already there.
const hasDebugVerify = (p) => existsSync(p) && readFileSync(p).includes(Buffer.from("debug_verify_tdx"));
if (!hasDebugVerify(wasmPath)) {
  console.log("building plr_registry.wasm with --features tdx-test-clock ...");
  const build = spawnSync("cargo", ["near", "build", "non-reproducible-wasm", "--no-abi", "--features", "tdx-test-clock"], {
    cwd: contractDir,
    stdio: "inherit",
  });
  if (build.status !== 0) throw new Error(`cargo near build failed (${build.status ?? build.signal})`);
  if (!hasDebugVerify(wasmPath)) throw new Error(`${wasmPath} does not export debug_verify_tdx`);
}
const wasm = readFileSync(wasmPath);
const GAS = 300_000_000_000_000n;
const NEAR = 10n ** 24n;
// P-256 base point (a valid point): MOCK mode never verifies against this root.
const MOCK_ROOT =
  "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5";

const gasOf = (tx) => [tx.transaction_outcome, ...tx.receipts_outcome].reduce((g, o) => g + BigInt(o.outcome.gas_burnt), 0n);

const port = Number(process.argv[2] ?? 3030 + Math.floor(Math.random() * 1000));
const sandbox = await Sandbox.start({ config: { rpcPort: port } });
try {
  const provider = new JsonRpcProvider({ url: sandbox.rpcUrl });
  const root = new Account(DEFAULT_ACCOUNT_ID, provider, DEFAULT_PRIVATE_KEY);
  const run = Date.now().toString(36);
  await root.createSubAccount({ accountOrPrefix: `registry-${run}`, publicKey: DEFAULT_PUBLIC_KEY, nearToTransfer: 20n * NEAR });
  const registry = new Account(`registry-${run}.${DEFAULT_ACCOUNT_ID}`, provider, DEFAULT_PRIVATE_KEY);
  const contractId = registry.accountId;
  const call = (methodName, args) => registry.callFunctionRaw({ contractId, methodName, args, gas: GAS, deposit: 0n });

  await registry.deployContract(wasm);
  await call("new", { owner_id: registry.accountId, root_kind: "MOCK", root_p256: MOCK_ROOT });

  const quoteHex = readFileSync(join(here, "../../../packages/shared/test/vectors/dcap/tdx_quote.bin")).toString("hex");
  const collateral = readFileSync(join(here, "../../../packages/shared/test/vectors/dcap/tdx_quote_collateral.json"), "utf8");
  const tx = await call("debug_verify_tdx", { quote_hex: quoteHex, collateral });
  if (!("SuccessValue" in tx.status)) throw new Error("debug_verify_tdx failed: " + JSON.stringify(tx.status));
  const status = JSON.parse(Buffer.from(tx.status.SuccessValue, "base64").toString());
  const gasTgas = Number(gasOf(tx)) / 1e12;
  if (status !== "UpToDate") throw new Error(`status ${JSON.stringify(status)} !== UpToDate`);
  if (gasTgas > 280) throw new Error(`gas ${gasTgas} Tgas > 280`);
  if (wasm.length >= 4194304) throw new Error(`wasm ${wasm.length} bytes >= 4194304`);
  console.log("status", JSON.stringify(status), "gas_tgas", gasTgas, "wasm_bytes", wasm.length);
} finally {
  await sandbox.tearDown(true);
}
