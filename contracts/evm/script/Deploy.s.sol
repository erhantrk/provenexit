// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

import {Script, console2} from "forge-std/Script.sol";
import {PlrRegistry} from "../src/PlrRegistry.sol";

/**
 * Deploys one PlrRegistry (run twice for the LLM and the VPN registry). Env:
 *   PLR_EVM_OWNER        registry owner address (required)
 *   PLR_ROOT_P256        attestation root public key, 64 bytes x‖y as 0x-hex (required)
 *   PLR_ROOT_KIND        1 = MOCK (default), 2 = INTEL
 *   PLR_INSTANCE_TTL_MS  registration lifetime (default 86 400 000)
 *
 *   forge script script/Deploy.s.sol:Deploy --rpc-url <rpc> --private-key <deployer> --broadcast
 *   (Monad testnet: --rpc-url https://testnet-rpc.monad.xyz, chain id 10143)
 *
 * Prints the address and the SPEC-CHAINS §3 contractId (`evm:<chainId>:<address>`) — the value clients use as
 * PLR_REGISTRY / PLR_VPN_REGISTRY; instances take the bare address as PLR_EVM_REGISTRY / PLR_EVM_VPN_REGISTRY.
 */
contract Deploy is Script {
    function run() external returns (PlrRegistry reg) {
        address owner = vm.envAddress("PLR_EVM_OWNER");
        bytes memory root = vm.envBytes("PLR_ROOT_P256");
        uint8 kind = uint8(vm.envOr("PLR_ROOT_KIND", uint256(1)));
        uint64 ttl = uint64(vm.envOr("PLR_INSTANCE_TTL_MS", uint256(86_400_000)));
        vm.startBroadcast();
        reg = new PlrRegistry(owner, kind, root, ttl);
        vm.stopBroadcast();
        console2.log("PlrRegistry", address(reg));
        console2.log("contractId", reg.contractId());
    }
}
