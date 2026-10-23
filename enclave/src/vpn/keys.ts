/** The VPN exit's per-boot keys (SPEC §5 binding, SPEC-VPN §4.1 tunnel keys, §5 receipts). */
import { signVpnReceipt, tunnelServerInit, type VpnReceipt } from "@plr/shared";
import { EnclaveKeys } from "../keys.js";

export class VpnKeys extends EnclaveKeys {
  static generate(): VpnKeys {
    return new VpnKeys(...EnclaveKeys.freshSecrets());
  }

  /**
   * Exit side of the tunnel handshake: parses the 65-byte hello and derives `th`, `k_c2s`, `k_s2c`.
   * @throws PlrError E_TUNNEL_PROTOCOL (malformed hello) / E_DECRYPT (low-order epk)
   */
  tunnelInit(hello: Uint8Array): { attNonce: Uint8Array; th: Uint8Array; kC2s: Uint8Array; kS2c: Uint8Array } {
    return this.withX25519Secret((xs) => tunnelServerInit({ xs, xp: this.x25519, ep: this.ed25519, hello }));
  }

  signVpnReceipt(r: VpnReceipt): string {
    return this.withEd25519Secret((es) => signVpnReceipt(r, es));
  }
}
