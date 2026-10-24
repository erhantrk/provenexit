export {
  PrivateClient,
  VERIFIED_TTL_MS,
  MAX_REQUEST_BODY,
  VERIFICATION_CODES,
  type ChatResult,
  type ChatOptions,
  type PrivateClientOptions,
  type PrivateClientTimeouts,
} from "./client.js";
export {
  verifyReceiptAnchored, verifyVpnReceiptAnchored, verifyAnchorSig, ed25519Verify, parseProofReply,
  type AnchoredReceipt, type AnchorSignerHint, type ProofReply,
} from "./anchored.js";
export { NearRegistry, NearRegistryError, isNearAccountId, isLoopbackHost, checkRpcUrl, type NearRegistryOptions, type NearFinality } from "./near-registry.js";
// PLR-CHAINS tier C (SPEC-CHAINS §5)
export { ZcashRegistry, ZcashRegistryError, parseZcashContractId, type ZcashRegistryOptions } from "./zcash-registry.js";
export { startProxy, type ProxyOptions, type ProxyHandle } from "./proxy.js";
export { normalizeChatRequest, encodeChatPlaintext, DEFAULT_MODEL, ROLES, MAX_MESSAGES, MAX_TOKENS_LIMIT, type ChatMessage, type ChatRequest } from "./chat-request.js";
export { SseParser, SseError, type SseLimits } from "./sse.js";
export { base64Encode, base64DecodeStrict } from "./base64.js";
export { TracingRegistry, checkLines, formatCheckLine, REGISTRATION_EVIDENCE_LABEL, type CheckLine, type CheckStatus } from "./verify-report.js";
export {
  runCli, loadConfig, loadVpnConfig, makeRegistry, registryTier, readStdinText, MAX_STDIN_PROMPT, ConfigError,
  type CliConfig, type VpnCliConfig, type CliIo, type CliChain, type ZcashCliConfig,
} from "./cli.js";
export { AttestationCache, recheckRegistry, type AttestationSession, type AttestationCacheOptions } from "./attestation.js";
// PLR-VPN-v1 (SPEC-VPN §9.2)
export { VpnClient, VPN_ATTEST_TTL_MS, type VpnClientOptions, type VpnClientTimeouts } from "./vpn/client.js";
export { TunnelStream, TwoHopTunnelStream, type VpnStream, type TwoHopStream, type VpnReceiptResult, type TunnelStreamParams } from "./vpn/stream.js";
export { TwoHopClient, entryOrgOf, exitOrgOf, type TwoHopClientOptions, type TwoHopAttestation } from "./vpn/twohop.js";
export { startVpn, type VpnProxyOptions, type VpnProxyHandle, type VpnConnector } from "./vpn/socks5-server.js";
export { TUNNEL_UPGRADE, TransportError, type Lookup, type Dialer } from "./vpn/transport.js";
