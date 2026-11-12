/** Test-side attestation check of a launched exit (independent of @plr/client): fetch the bundle and verify it. */
import { randomBytes } from "@noble/hashes/utils.js";
import { sha256 } from "@noble/hashes/sha2.js";
import {
  MemoryRegistry, MockVerifier, fromHex, keyHash, osMeasurement, mockOsReport, toHex, verifyAttestation, type AttestationBundle,
  type VerifiedRouter,
} from "@plr/shared";

export async function attest(url: string, rootPub: Uint8Array, opts: { registered?: boolean } = {}): Promise<VerifiedRouter & { bundle: AttestationBundle }> {
  const nonce = randomBytes(32);
  const res = await fetch(`${url}/v1/attestation?nonce=${toHex(nonce)}`);
  if (res.status !== 200) throw new Error(`attestation status ${res.status}`);
  const bundle = (await res.json()) as AttestationBundle;
  const composeHash = toHex(sha256(new TextEncoder().encode(bundle.app_compose)));
  const os = toHex(osMeasurement(mockOsReport()));
  const xp = fromHex(bundle.x25519, 32), ep = fromHex(bundle.ed25519, 32);
  const kh = toHex(keyHash(xp, ep));
  const registry = new MemoryRegistry({
    root: { kind: "MOCK", p256: toHex(rootPub) },
    compose: [composeHash],
    os: [os],
    instances: opts.registered === false ? {} : {
      [kh]: { compose_hash: composeHash, os_measurement: os, x25519: bundle.x25519, ed25519: bundle.ed25519, operator: "op.test", org_id: null, registered_at_ms: Date.now(), expires_at_ms: Date.now() + 3_600_000, next_seq: 0 },
    },
  });
  const v = await verifyAttestation({ bundle, nonce, verifier: new MockVerifier(rootPub), registry, trustedRoot: rootPub });
  return { ...v, bundle };
}
