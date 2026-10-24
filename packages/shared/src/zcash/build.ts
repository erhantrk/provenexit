/** Builds and signs transparent-only v5 Zcash transactions (P2PKH inputs, SIGHASH_ALL, low-S DER). Pure. */
import { secp256k1 } from "@noble/curves/secp256k1.js";
import { PlrError } from "../errors.js";
import { concatBytes, isBytes } from "../bytes.js";
import { SIGHASH, ZCASH_TX, serializeTransparentTx, sighashDigest, type ZcashTx } from "./tx.js";
import { hash160, p2pkhScript, pushData } from "./script.js";

export interface TransparentInput {
  /** previous txid, internal byte order (see `zcashTxidFromRpc`) */
  txid: Uint8Array;
  vout: number;
  /** value of the coin spent (zatoshi) */
  amount: bigint;
  /** 32-byte secp256k1 secret key owning the P2PKH coin (compressed pubkey) */
  secretKey: Uint8Array;
}
export interface TransparentOutput {
  amount: bigint;
  script: Uint8Array;
}
export interface BuildTransparentTxParams {
  branchId: number;
  expiryHeight: number;
  lockTime?: number;
  inputs: TransparentInput[];
  outputs: TransparentOutput[];
}

const bad = (d: string): never => {
  throw new PlrError("E_BAD_INPUT", d);
};
const isU32 = (n: unknown): n is number => typeof n === "number" && Number.isInteger(n) && n >= 0 && n <= 0xffffffff;
const isAmount = (a: unknown): a is bigint => typeof a === "bigint" && a >= 0n && a <= ZCASH_TX.MAX_MONEY;
const MAX_INPUTS = 1000;
const MAX_OUTPUTS = 1000;

/**
 * Builds a v5 transaction spending P2PKH coins, each input signed with SIGHASH_ALL over its ZIP-244 digest
 * (scriptSig = `<DER low-S sig ‖ 0x01> <33-byte compressed pubkey>`). The fee is `Σinputs − Σoutputs`.
 * @throws PlrError E_BAD_INPUT on bad parameters, invalid keys or outputs exceeding inputs
 */
export function buildSignedTransparentTx(p: BuildTransparentTxParams): Uint8Array {
  if (typeof p !== "object" || p === null) return bad("params required");
  if (!isU32(p.branchId) || p.branchId === 0) bad("bad branch id");
  if (!isU32(p.expiryHeight) || p.expiryHeight > 499_999_999) bad("bad expiry height");
  const lockTime = p.lockTime ?? 0;
  if (!isU32(lockTime)) bad("bad lock time");
  if (!Array.isArray(p.inputs) || p.inputs.length === 0 || p.inputs.length > MAX_INPUTS) bad("bad inputs");
  if (!Array.isArray(p.outputs) || p.outputs.length === 0 || p.outputs.length > MAX_OUTPUTS) bad("bad outputs");
  let inSum = 0n;
  let outSum = 0n;
  const keys: { sk: Uint8Array; pub: Uint8Array; spk: Uint8Array }[] = [];
  for (const i of p.inputs) {
    if (typeof i !== "object" || i === null) bad("bad input");
    if (!isBytes(i.txid) || i.txid.length !== 32) bad("bad input txid");
    if (!isU32(i.vout)) bad("bad input vout");
    if (!isAmount(i.amount)) bad("bad input amount");
    if (!isBytes(i.secretKey) || i.secretKey.length !== 32 || !secp256k1.utils.isValidSecretKey(i.secretKey)) bad("bad secret key");
    inSum += i.amount;
    const pub = secp256k1.getPublicKey(i.secretKey, true);
    keys.push({ sk: i.secretKey, pub, spk: p2pkhScript(hash160(pub)) });
  }
  for (const o of p.outputs) {
    if (typeof o !== "object" || o === null || !isAmount(o.amount) || !isBytes(o.script) || o.script.length > 10_000) bad("bad output");
    outSum += o.amount;
  }
  if (inSum > ZCASH_TX.MAX_MONEY || outSum > inSum) bad("outputs exceed inputs");

  const tx: ZcashTx = {
    header: ZCASH_TX.HEADER_V5,
    versionGroupId: ZCASH_TX.VERSION_GROUP_ID_V5,
    consensusBranchId: p.branchId,
    lockTime,
    expiryHeight: p.expiryHeight,
    vin: p.inputs.map((i) => ({ prevTxid: i.txid.slice(), prevIndex: i.vout, scriptSig: new Uint8Array(0), sequence: ZCASH_TX.SEQUENCE_FINAL })),
    vout: p.outputs.map((o) => ({ value: o.amount, script: o.script.slice() })),
    sapling: { spends: [], outputs: [], valueBalance: 0n, anchor: null, spendProofs: [], spendAuthSigs: [], outputProofs: [], bindingSig: null },
    orchard: { actions: [], flags: 0, valueBalance: 0n, anchor: null, proofs: new Uint8Array(0), spendAuthSigs: [], bindingSig: null },
  };
  const amounts = p.inputs.map((i) => i.amount);
  const scriptPubKeys = keys.map((k) => k.spk);
  // ZIP-244 digests do not cover scriptSigs, so every input can be signed against the unsigned transaction.
  const scriptSigs = keys.map((k, idx) => {
    const digest = sighashDigest(tx, { inputIndex: idx, hashType: SIGHASH.ALL, amounts, scriptPubKeys });
    const der = secp256k1.sign(digest, k.sk, { prehash: false, lowS: true, format: "der" });
    return concatBytes(pushData(concatBytes(der, Uint8Array.of(SIGHASH.ALL))), pushData(k.pub));
  });
  tx.vin.forEach((i, idx) => {
    i.scriptSig = scriptSigs[idx]!;
  });
  return serializeTransparentTx(tx);
}
