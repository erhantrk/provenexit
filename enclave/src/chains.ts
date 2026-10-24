/** `PLR_CHAIN` → registry writer (SPEC-CHAINS §4). NEAR keeps its existing writer unchanged. */
import type { RegistryConfig } from "./config.js";
import { NearRegistryWriter } from "./near.js";
import type { RegistryWriter } from "./registry-writer.js";
import { ZcashRegistryWriter } from "./zcash.js";

/** @throws PlrError E_BAD_INPUT on invalid settings (already validated by the config loaders) */
export function createRegistryWriter(c: RegistryConfig): RegistryWriter {
  switch (c.chain) {
    case "near":
      return new NearRegistryWriter(c.near);
    case "zcash":
      return new ZcashRegistryWriter({ rpc: c.zcash.rpcUrl, network: c.zcash.network, owner: c.zcash.owner, key: c.zcash.key, startHeight: c.zcash.startHeight });
  }
}
