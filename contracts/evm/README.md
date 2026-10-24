# PlrRegistry — EVM / Monad tier-B registry (SPEC-CHAINS §9)

One contract, deployable unchanged on any EVM chain (Monad included; 128 KB limit there, < 24 KB here so it also
fits Ethereum's EIP-170 limit). Solidity 0.8.30, `evm_version = cancun`.

- `src/PlrRegistry.sol` — owner policy, operator orgs, registration by approved operators (`operator = msg.sender`)
  with on-chain quote format + report_data checks (`keyHash ‖ registrationNonce(contractId(), lowercase-hex(sender))`,
  SPEC §5 rev 1.3) and the quote stored; contiguous anchors with the Ed25519 `sig` stored (verified by clients).
  Custom errors are named after the PLR codes (+ `E_OS_NOT_ALLOWED`).
- `test/PlrRegistry.t.sol` — every rule; `test/Vectors.sol` holds cross-implementation vectors generated with
  `@plr/shared` by `node script/gen-vectors.mjs` (needs `packages/shared/dist`).
- `script/Deploy.s.sol` — deploys one registry from env (see the file header).

```sh
forge build && forge test        # offline; solc 0.8.30 from ~/Library/Application Support/svm
node script/gen-vectors.mjs      # regenerate test/Vectors.sol
```

The e2e driver (`e2e/src/chains/evm.ts`) deploys from `out/PlrRegistry.sol/PlrRegistry.json`, so run `forge build`
before e2e.
