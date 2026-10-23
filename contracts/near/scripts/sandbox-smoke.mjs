#!/usr/bin/env node
// Smoke test of the built wasm on a real near-sandbox (real host p256_verify / ed25519_verify, real gas).
// Not part of the gate (the locked e2e suite covers the contract on a sandbox); handy when changing the contract.
//
// Usage (repo root, after `cargo near build non-reproducible-wasm --no-abi` and `npx tsc -b packages/shared`):
//   node contracts/near/scripts/sandbox-smoke.mjs [rpcPort]            # starts its own near-sandbox
//   PLR_SMOKE_RPC=http://127.0.0.1:3030 PLR_SMOKE_HOME=<neard home> node contracts/near/scripts/sandbox-smoke.mjs
//     # reuses a running `near-sandbox --home <home> run` (root account test.near, key from validator_key.json)
//   PLR_SMOKE_OLD_WASM=<rev 1.2 plr_registry.wasm> node contracts/near/scripts/sandbox-smoke.mjs
//     # also checks the in-place rev 1.2 → rev 1.3 upgrade (old state refused until `migrate`, allowlist emptied).
//     # Build the old wasm from the last rev 1.2 commit, e.g.
//     #   git archive <rev> contracts/near | tar -x -C /tmp/old && (cd /tmp/old/contracts/near && cargo near build non-reproducible-wasm --no-abi)
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { Sandbox, DEFAULT_ACCOUNT_ID, DEFAULT_PRIVATE_KEY, DEFAULT_PUBLIC_KEY } from "near-sandbox";
import { Account, JsonRpcProvider, actions } from "near-api-js";
import { sha256 } from "@noble/hashes/sha2.js";
import { p256 } from "@noble/curves/nist.js";
import { ed25519, x25519 } from "@noble/curves/ed25519.js";
import { randomBytes } from "@noble/hashes/utils.js";
import {
  MockRoot, MockTdxAttester, anchorMessage, keyHash, merkleRoot, mockOsReport, osMeasurement, registrationNonce,
  registrationReportData, reportData, toHex, fromHex, utf8,
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
  for (const name of ["registry", "owner", "operator", "stranger", ...(process.env.PLR_SMOKE_OLD_WASM ? ["upgrade"] : [])]) {
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
  // Operator-bound registration quote (SPEC §5 rev 1.3).
  const { quote, eventLog } = await attester.getQuote(registrationReportData(xp, ep, contractId, operator.accountId));
  const args = { quote: toHex(quote), event_log: eventLog, app_compose: new TextDecoder().decode(compose), x25519: toHex(xp), ed25519: toHex(ep) };

  // High-S variant of the (valid) quote signature: the real host accepts it, the contract must not.
  const n = p256.Point.CURVE().n, hs = quote.slice();
  hs.set(fromHex((n - BigInt("0x" + toHex(quote.slice(668, 700)))).toString(16).padStart(64, "0"), 32), 668);

  const before = await operator.getBalance();
  const reg = await call(operator, "register_instance", args, DEPOSIT);
  const regGas = gasOf(reg);
  const after = await operator.getBalance();
  console.log(`  register_instance gas burnt: ${Number(regGas) / 1e12} Tgas; operator paid ${Number(before - after) / 1e24} NEAR (deposit 0.1)`);
  const kh = toHex(keyHash(xp, ep));
  // Paid = storage (≈0.0035 NEAR) + the capped anchor credit (0.05 NEAR) + gas; the rest of the 0.1 is refunded.
  const MAX_CREDIT = 50_000_000_000_000_000_000_000n;
  check((await view("get_anchor_credit", { key_hash: kh })) === MAX_CREDIT.toString(), "excess deposit kept as capped anchor credit");
  check(before - after > MAX_CREDIT && before - after < MAX_CREDIT + DEPOSIT / 10n, "rest of the excess deposit refunded");
  const rec = await view("get_instance", { key_hash: kh });
  check(rec?.operator === operator.accountId && rec.next_seq === 0 && rec.compose_hash === composeHash && typeof rec.expires_at_ms === "number", "get_instance record");
  check((await view("get_instance", { key_hash: toHex(randomBytes(32)) })) === null, "unknown instance is null");

  await expectFail(call(operator, "register_instance", { ...args, quote: toHex(hs) }, DEPOSIT), "E_QUOTE_SIG", "high-S quote_sig on the real host");
  {
    const xp2 = x25519.getPublicKey(x25519.utils.randomSecretKey()), ep2 = ed25519.getPublicKey(ed25519.utils.randomSecretKey());
    const q2 = await attester.getQuote(registrationReportData(xp2, ep2, contractId, operator.accountId));
    await expectFail(call(operator, "register_instance", { ...args, quote: toHex(q2.quote), x25519: toHex(xp2), ed25519: toHex(ep2) }), "E_DEPOSIT", "new instance without storage deposit");
  }
  // The quote is bound to `operator`: a stranger can neither replay it nor turn a session quote into a registration.
  await expectFail(call(stranger, "register_instance", args, DEPOSIT), "E_REPORT_DATA", "operator-bound quote submitted by a stranger");
  {
    const s = await attester.getQuote(reportData(xp, ep, registrationNonce(contractId, stranger.accountId)));
    await expectFail(call(stranger, "register_instance", { ...args, quote: toHex(s.quote), event_log: s.eventLog }, DEPOSIT), "E_REPORT_DATA", "session quote of the registration nonce");
  }
  await call(operator, "register_instance", args); // refresh: no new storage, so no deposit needed
  check((await view("get_instance", { key_hash: kh })).operator === operator.accountId, "refresh by the bound operator keeps the operator");

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

  // Operator organizations (SPEC §7 rev 1.2).
  check(rec.org_id === null, "get_instance org_id is null before approval");
  await expectFail(call(stranger, "approve_operator", { account_id: operator.accountId, org_id: "org-a" }), "E_UNAUTHORIZED", "approve_operator by a stranger");
  await expectFail(call(owner, "approve_operator", { account_id: operator.accountId, org_id: "Org-A" }), "E_BAD_INPUT", "bad org_id");
  const bal0 = await registry.getBalance();
  const appr = await call(owner, "approve_operator", { account_id: operator.accountId, org_id: "acme-hosting.eu" });
  console.log(`  approve_operator gas burnt: ${Number(gasOf(appr)) / 1e12} Tgas; contract balance Δ ${Number((await registry.getBalance()) - bal0) / 1e24} NEAR`);
  check((await view("get_operator", { account_id: operator.accountId })) === "acme-hosting.eu", "get_operator");
  check((await view("get_operator", { account_id: "NOT VALID" })) === null, "get_operator on a malformed account id is null");
  check((await view("get_instance", { key_hash: kh })).org_id === "acme-hosting.eu", "get_instance org_id is live");
  check(appr.receipts_outcome.flatMap((o) => o.outcome.logs).some((l) => l.includes('"event":"operator_approved"')), "NEP-297 operator_approved event");
  await call(owner, "revoke_operator", { account_id: operator.accountId });
  check((await view("get_operator", { account_id: operator.accountId })) === null && (await view("get_instance", { key_hash: kh })).org_id === null, "revoke_operator");

  // rev 1.2 → rev 1.3 in-place upgrade: fail closed until `migrate`, which empties the compose allowlist.
  if (process.env.PLR_SMOKE_OLD_WASM) {
    const up = acct("upgrade");
    const upId = up.accountId;
    const callUp = (who, methodName, a, deposit = 0n) => who.callFunctionRaw({ contractId: upId, methodName, args: a, gas: GAS, deposit });
    const viewUp = (method, a = {}) => provider.callFunction({ contractId: upId, method, args: a });
    await up.deployContract(readFileSync(process.env.PLR_SMOKE_OLD_WASM));
    await callUp(up, "new", { owner_id: owner.accountId, root_kind: "MOCK", root_p256: toHex(mockRoot.publicKey) });
    await callUp(owner, "allow_compose", { hash: composeHash });
    await callUp(owner, "allow_os", { hash: os });
    await callUp(owner, "approve_operator", { account_id: operator.accountId, org_id: "org-old" });
    // An instance registered under rev 1.2 rules: report_data = key_hash ‖ SHA256("PLR-v1/register" ‖ contract).
    const oldRd = new Uint8Array(64);
    oldRd.set(keyHash(xp, ep), 0);
    oldRd.set(sha256(utf8("PLR-v1/register" + upId)), 32);
    const oq = await attester.getQuote(oldRd);
    await callUp(operator, "register_instance", { ...args, quote: toHex(oq.quote), event_log: oq.eventLog }, DEPOSIT);
    check((await viewUp("get_instance", { key_hash: kh })).operator === operator.accountId, "rev 1.2 registry: old instance registered");

    await up.deployContract(wasm); // code only, no migration yet
    await expectFail(viewUp("is_compose_allowed", { hash: composeHash }), "Cannot deserialize", "rev 1.3 code over rev 1.2 state: views fail closed");
    const q13 = await attester.getQuote(registrationReportData(xp, ep, upId, stranger.accountId));
    await expectFail(callUp(stranger, "register_instance", { ...args, quote: toHex(q13.quote), event_log: q13.eventLog }, DEPOSIT), "Cannot deserialize", "rev 1.3 code over rev 1.2 state: register_instance fails closed");
    await expectFail(callUp(stranger, "migrate", {}), "private", "migrate by a stranger");
    // The recommended way: redeploy + migrate in one batch, so there is no window at all.
    const mig = await up.signAndSendTransaction({ receiverId: upId, actions: [actions.deployContract(wasm), actions.functionCall("migrate", {}, GAS, 0n)] });
    check(mig.receipts_outcome.flatMap((o) => o.outcome.logs).some((l) => l.includes('"event":"compose_allowlist_reset"')), "deploy + migrate batch; compose_allowlist_reset event");
    check((await viewUp("get_state_rev")) === 3, "get_state_rev after migrate");
    check((await viewUp("is_compose_allowed", { hash: composeHash })) === false, "migrate empties the compose allowlist");
    check((await viewUp("is_os_allowed", { hash: os })) === true, "migrate keeps the OS allowlist");
    check((await viewUp("get_operator", { account_id: operator.accountId })) === "org-old", "migrate keeps operator organizations");
    check((await viewUp("get_instance", { key_hash: kh }))?.operator === operator.accountId, "migrate keeps instances");
    await expectFail(callUp(up, "migrate", {}), "E_BAD_INPUT", "migrate twice");
    // The hijack the migration closes: a quote bound to the stranger cannot register while no build is approved.
    await expectFail(callUp(stranger, "register_instance", { ...args, quote: toHex(q13.quote), event_log: q13.eventLog }, DEPOSIT), "E_COMPOSE_NOT_ALLOWED", "no old build stays approved");
    await callUp(owner, "allow_compose", { hash: composeHash }); // owner re-approves a rev 1.3 build
    const q13op = await attester.getQuote(registrationReportData(xp, ep, upId, operator.accountId));
    await callUp(operator, "register_instance", { ...args, quote: toHex(q13op.quote), event_log: q13op.eventLog });
    check((await viewUp("get_instance", { key_hash: kh })).operator === operator.accountId, "rev 1.3 registration after migration");
  } else {
    console.log("  (PLR_SMOKE_OLD_WASM not set: rev 1.2 → rev 1.3 upgrade check skipped)");
  }
} finally {
  await sandbox?.tearDown(true);
}
console.log(failures === 0 ? "sandbox smoke: OK" : `sandbox smoke: ${failures} failure(s)`);
process.exit(failures === 0 ? 0 : 1);
