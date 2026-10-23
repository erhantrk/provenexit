/**
 * VPN session receipts (SPEC-VPN §5): no destination, address, port, byte count or client IP — only the tunnel
 * hash, the build/key identity, a contiguous per-instance seq and the open/close timestamps. Only leaf hashes
 * are retained (the shared `LeafLog`, anchored by the shared `Anchorer`).
 */
import { toHex, vpnReceiptLeaf, type VpnReceipt } from "@plr/shared";
import { LeafLog } from "../receipts.js";

export class VpnReceiptLog extends LeafLog {
  /** Allocates the next seq, signs the receipt and retains only its leaf hash. */
  issue(p: { th: Uint8Array; composeHash: Uint8Array; keyHash: Uint8Array; tsOpenMs: number; tsCloseMs: number; sign: (r: VpnReceipt) => string }): {
    receipt: VpnReceipt;
    sig: string;
  } {
    const open = Math.floor(p.tsOpenMs);
    // Clocks can step backwards; a receipt always satisfies ts_open_ms ≤ ts_close_ms (SPEC-VPN §5).
    const close = Math.max(open, Math.floor(p.tsCloseMs));
    return this.append<VpnReceipt>(
      (seq) => ({ v: 1, th: toHex(p.th), compose_hash: toHex(p.composeHash), key_hash: toHex(p.keyHash), seq, ts_open_ms: open, ts_close_ms: close }),
      p.sign,
      vpnReceiptLeaf,
    );
  }
}
