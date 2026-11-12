export { verifyVpnReceiptAnchored, parseProofReply, type AnchoredReceipt, type ProofReply } from "./anchored.js";
export { NearRegistry, NearRegistryError, isNearAccountId, isLoopbackHost, checkRpcUrl, type NearRegistryOptions, type NearFinality } from "./near-registry.js";
export { TracingRegistry, checkLines, formatCheckLine, type CheckLine, type CheckStatus } from "./verify-report.js";
export { runCli, loadVpnConfig, makeRegistry, ConfigError, inspectIntelBundle, type VpnCliConfig, type CliIo, type IntelInspection } from "./cli.js";
export { AttestationCache, recheckRegistry, type AttestationSession, type AttestationCacheOptions } from "./attestation.js";
export { fetchPccsCollateral, isPccsUrl } from "./pccs.js";
// PLR-VPN-v1 (SPEC-VPN §9.2)
export { VpnClient, VPN_ATTEST_TTL_MS, type VpnClientOptions, type VpnClientTimeouts } from "./vpn/client.js";
export { TunnelStream, TwoHopTunnelStream, type VpnStream, type TwoHopStream, type VpnReceiptResult, type TunnelStreamParams } from "./vpn/stream.js";
export { TwoHopClient, entryOrgOf, exitOrgOf, type TwoHopClientOptions, type TwoHopAttestation } from "./vpn/twohop.js";
export { startVpn, type VpnProxyOptions, type VpnProxyHandle, type VpnConnector } from "./vpn/socks5-server.js";
export { TUNNEL_UPGRADE, TransportError, type Lookup, type Dialer } from "./vpn/transport.js";
// status bundle (UI-BRIEF §4)
export { getStatus, getRegistryStatus, openExit, type OpenedExit, type Status, type StatusOptions, type StatusDefaults, type RegistryEvent, type AnchorEntry } from "./status.js";
export { verifyVpnReport, composeFacts, RECHECK_LINE, REMOTE_DNS_LINE, type VerifyReport, type VerifyCheck, type ComposeFacts } from "./vpn-report.js";
export { parseFixture, readFixture, verifyFixtureData, type RawFixture, type Fixture } from "./fixture.js";
