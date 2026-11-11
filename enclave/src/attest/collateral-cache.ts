/** Intel collateral fetched from a PCCS and cached for the process (INTERFACES §4.3). */
import dcap from "@phala/dcap-qvl";
import { canonicalCollateral, type CollateralJson } from "@plr/shared";

export class CollateralCache {
  #v: CollateralJson | null = null;
  #at = 0;
  constructor(
    readonly pccsUrl: string,
    readonly ttlMs = 3_600_000,
    readonly clock = Date.now,
  ) {}

  /** One platform has one FMSPC, so a single cached value per process is correct. */
  async get(quote: Uint8Array): Promise<CollateralJson> {
    if (this.#v && this.clock() - this.#at < this.ttlMs) return this.#v;
    const raw = await dcap.getCollateral(this.pccsUrl, Buffer.from(quote));
    this.#v = canonicalCollateral(raw);
    this.#at = this.clock();
    return this.#v;
  }
}
