#!/usr/bin/env node
// Smoke test of the built wasm on a real near-sandbox (real host p256_verify / ed25519_verify, real gas).
// Not part of the gate (the locked e2e suite covers the contract on a sandbox); handy when changing the contract.
//
// Usage (repo root, after `cargo near build non-reproducible-wasm --no-abi` and `npx tsc -b packages/shared`):
//   node contracts/near/scripts/sandbox-smoke.mjs [rpcPort]            # starts its own near-sandbox
//   PLR_SMOKE_RPC=http://127.0.0.1:3030 PLR_SMOKE_HOME=<neard home> node contracts/near/scripts/sandbox-smoke.mjs
//     # reuses a running `near-sandbox --home <home> run` (root account test.near, key from validator_key.json)
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { Sandbox, DEFAULT_ACCOUNT_ID, DEFAULT_PRIVATE_KEY, DEFAULT_PUBLIC_KEY } from "near-sandbox";
import { Account, JsonRpcProvider } from "near-api-js";
import { p256 } from "@noble/curves/nist.js";
import { ed25519, x25519 } from "@noble/curves/ed25519.js";
import { randomBytes } from "@noble/hashes/utils.js";
import {
  MockRoot, MockTdxAttester, anchorMessage, keyHash, merkleRoot, mockOsReport, osMeasurement, registrationNonce,
  reportData, toHex, fromHex, utf8,
} from "../../../packages/shared/dist/index.js";

const here = dirname(fileURLToPath(import.meta.url));
const wasm = readFileSync(join(here, "../target/near/plr_registry.wasm"));
const GAS = 300_000_000_000_000n;
const DEPOSIT = 100_000_000_000_000_000_000_000n;
const NEAR = 10n ** 24n;

let sandbox, rpcUrl, rootId, rootKey, rootPub;
if (process.env.PLR_SMOKE_RPC) {
  const vk = JSON.parse(readFileSync(join(process.env.PLR_SMOKE_HOME ?? "", "validator_key.json"), "utf8"));
  [rpcUrl, rootId, rootKey, rootPub] = [process.env.PLR_SMOKE_RPC, vk.account_id, vk.secret_key ?? vk.private_key, vk.public_key];
} else {
  const port = Number(process.argv[2] ?? 3030 + Math.floor(Math.random() * 1000));
  sandbox = await Sandbox.start({ config: { rpcPort: port } });
  [rpcUrl, rootId, rootKey, rootPub] = [sandbox.rpcUrl, DEFAULT_ACCOUNT_ID, DEFAULT_PRIVATE_KEY, DEFAULT_PUBLIC_KEY];
}
const provider = new JsonRpcProvider({ url: rpcUrl });
const root = new Account(rootId, provider, rootKey);
let failures = 0;
const check = (ok, what) => { console.log(`${ok ? "✔" : "✘"} ${what}`); if (!ok) failures++; };
const gasOf = (tx) => [tx.transaction_outcome, ...tx.receipts_outcome].reduce((g, o) => g + BigInt(o.outcome.gas_burnt), 0n);
const expectFail = async (p, code, what) => {
  try { await p; check(false, `${what}: expected ${code}`); } catch (e) { check(String(e?.message ?? e).includes(code), `${what} → ${code}`); }
};

try {
  const run = Date.now().toString(36); // unique account names, so the script can rerun on the same node
  for (const name of ["registry", "owner", "operator", "stranger"]) {
    await root.createSubAccount({ accountOrPrefix: `${name}-${run}`, publicKey: rootPub, nearToTransfer: 20n * NEAR });
  }
  const acct = (n) => new Account(`${n}-${run}.${rootId}`, provider, rootKey);
  const [registry, owner, operator, stranger] = ["registry", "owner", "operator", "stranger"].map(acct);
  const contractId = registry.accountId;
  const call = (who, methodName, args, deposit = 0n) => who.callFunctionRaw({ contractId, methodName, args, gas: GAS, deposit });
  const view = (method, args = {}) => provider.callFunction({ contractId, method, args });

  const mockRoot = MockRoot.generate();
  await registry.deployContract(wasm);
  await expectFail(call(stranger, "new", { owner_id: owner.accountId, root_kind: "MOCK", root_p256: toHex(mockRoot.publicKey) }), "private", "init by a stranger");
  await call(registry, "new", { owner_id: owner.accountId, root_kind: "MOCK", root_p256: toHex(mockRoot.publicKey) });
  await expectFail(call(registry, "new", { owner_id: owner.accountId, root_kind: "MOCK", root_p256: toHex(mockRoot.publicKey) }), "already", "second init");
  check(JSON.stringify(await view("get_root")) === JSON.stringify({ kind: "MOCK", p256: toHex(mockRoot.publicKey) }), "get_root");

  const compose = utf8('{\n  "name": "plr-router"\n}\n');
  const attester = new MockTdxAttester({ root: mockRoot, composeBytes: compose });
  const composeHash = toHex(attester.composeHash), os = toHex(osMeasurement(mockOsReport()));
  await call(owner, "allow_compose", { hash: composeHash });
  await call(owner, "allow_os", { hash: os });
  await expectFail(call(owner, "allow_compose", { hash: composeHash, extra: 1 }), "unknown field", "unknown argument rejected");

  const xs = x25519.utils.randomSecretKey(), es = ed25519.utils.randomSecretKey();
  const xp = x25519.getPublicKey(xs), ep = ed25519.getPublicKey(es);
  const { quote, eventLog } = await attester.getQuote(reportData(xp, ep, registrationNonce(contractId)));
  const args = { quote: toHex(quote), event_log: eventLog, app_compose: new TextDecoder().decode(compose), x25519: toHex(xp), ed25519: toHex(ep) };

  // High-S variant of the (valid) quote signature: the real host accepts it, the contract must not.
  const n = p256.Point.CURVE().n, hs = quote.slice();
  hs.set(fromHex((n - BigInt("0x" + toHex(quote.slice(668, 700)))).toString(16).padStart(64, "0"), 32), 668);

  const before = await operator.getBalance();
  const reg = await call(operator, "register_instance", args, DEPOSIT);
  const regGas = gasOf(reg);
  const after = await operator.getBalance();
  console.log(`  register_instance gas burnt: ${Number(regGas) / 1e12} Tgas; operator paid ${Number(before - after) / 1e24} NEAR (deposit 0.1)`);
  check(before - after > 0n && before - after < DEPOSIT / 2n, "excess storage deposit refunded");
  const kh = toHex(keyHash(xp, ep));
  const rec = await view("get_instance", { key_hash: kh });
  check(rec?.operator === operator.accountId && rec.next_seq === 0 && rec.compose_hash === composeHash && typeof rec.expires_at_ms === "number", "get_instance record");
  check((await view("get_instance", { key_hash: toHex(randomBytes(32)) })) === null, "unknown instance is null");

  await expectFail(call(operator, "register_instance", { ...args, quote: toHex(hs) }, DEPOSIT), "E_QUOTE_SIG", "high-S quote_sig on the real host");
  {
    const xp2 = x25519.getPublicKey(x25519.utils.randomSecretKey()), ep2 = ed25519.getPublicKey(ed25519.utils.randomSecretKey());
    const q2 = await attester.getQuote(reportData(xp2, ep2, registrationNonce(contractId)));
    await expectFail(call(operator, "register_instance", { ...args, quote: toHex(q2.quote), x25519: toHex(xp2), ed25519: toHex(ep2) }), "E_DEPOSIT", "new instance without storage deposit");
  }
  await call(stranger, "register_instance", args); // replay/refresh: no new storage, so no deposit needed
  check((await view("get_instance", { key_hash: kh })).operator === operator.accountId, "refresh by a stranger keeps the operator");

  const rootHash = merkleRoot([randomBytes(32), randomBytes(32)]);
  const sig = ed25519.sign(anchorMessage({ contractId, keyHash: fromHex(kh), root: rootHash, firstSeq: 0n, count: 2n }), es);
  const anc = await call(stranger, "anchor_receipts", { key_hash: kh, root: toHex(rootHash), first_seq: 0, count: 2, sig: toHex(sig) });
  console.log(`  anchor_receipts gas burnt: ${Number(gasOf(anc)) / 1e12} Tgas`);
  const a = await view("get_anchor", { id: 0 });
  check(a?.root === toHex(rootHash) && a.first_seq === 0 && a.count === 2 && (await view("anchor_count")) === 1, "get_anchor / anchor_count");
  check((await view("get_instance", { key_hash: kh })).next_seq === 2, "next_seq advanced");
  await expectFail(call(stranger, "anchor_receipts", { key_hash: kh, root: toHex(rootHash), first_seq: 2, count: 2, sig: toHex(sig) }), "E_ANCHOR_SIG", "anchor sig over other fields (real host ed25519)");
  await expectFail(call(stranger, "anchor_receipts", { key_hash: kh, root: toHex(rootHash), first_seq: 0, count: 2, sig: toHex(sig) }), "E_SEQ", "anchor replay");
  const logs = anc.receipts_outcome.flatMap((o) => o.outcome.logs);
  check(logs.some((l) => l.startsWith('EVENT_JSON:{"standard":"plr","version":"1.0.0","event":"receipts_anchored"')), "NEP-297 receipts_anchored event");
} finally {
  await sandbox?.tearDown(true);
}
console.log(failures === 0 ? "sandbox smoke: OK" : `sandbox smoke: ${failures} failure(s)`);
process.exit(failures === 0 ? 0 : 1);
