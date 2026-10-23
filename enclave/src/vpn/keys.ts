/** The VPN exit's per-boot keys (SPEC §5 binding, SPEC-VPN §4.1 tunnel keys, §5 receipts). */
import { signVpnReceipt, tunnelServerAccept, type TunnelServerHandshake, type VpnReceipt } from "@plr/shared";
import { EnclaveKeys } from "../keys.js";

export class VpnKeys extends EnclaveKeys {
  static generate(): VpnKeys {
    return new VpnKeys(...EnclaveKeys.freshSecrets());
  }

  /**
   * Exit side of handshake v2 (SPEC-VPN §4.1): parses the 65-byte hello, creates a fresh ephemeral key for this
   * tunnel (zeroed inside `tunnelServerAccept` once the keys are derived) and returns the `server_hello` to send
   * plus `th`, `k_c2s`, `k_s2c`. The same hello accepted twice yields unrelated keys (replay protection).
   * @throws PlrError E_TUNNEL_PROTOCOL (malformed hello) / E_DECRYPT (low-order epk_c)
   */
  tunnelAccept(hello: Uint8Array): TunnelServerHandshake {
    return this.withX25519Secret((xs) => tunnelServerAccept({ xs, xp: this.x25519, ep: this.ed25519, hello }));
  }

  signVpnReceipt(r: VpnReceipt): string {
    return this.withEd25519Secret((es) => signVpnReceipt(r, es));
  }
}
