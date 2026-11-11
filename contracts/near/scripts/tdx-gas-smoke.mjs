#!/usr/bin/env node
// Spike S2: measures `debug_verify_tdx` (dcap-qvl 0.7.1 inside the contract) on a real near-sandbox.
//
// Usage (repo root, after the build with the test clock feature):
//   (cd contracts/near && cargo near build non-reproducible-wasm --no-abi --features tdx-test-clock)
//   node contracts/near/scripts/tdx-gas-smoke.mjs
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { Sandbox, DEFAULT_ACCOUNT_ID, DEFAULT_PRIVATE_KEY, DEFAULT_PUBLIC_KEY } from "near-sandbox";
import { Account, JsonRpcProvider } from "near-api-js";

const here = dirname(fileURLToPath(import.meta.url));
const wasm = readFileSync(join(here, "../target/near/plr_registry.wasm"));
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
  const status = Buffer.from(tx.status.SuccessValue, "base64").toString();
  console.log("status", status, "gas_tgas", Number(gasOf(tx)) / 1e12, "wasm_bytes", wasm.length);
} finally {
  await sandbox.tearDown(true);
}
