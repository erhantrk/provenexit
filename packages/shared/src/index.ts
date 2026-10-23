export { PlrError, ERROR_CODES, isPlrError, isPlrErrorCode, type PlrErrorCode } from "./errors.js";
export {
  DOMAIN, toHex, fromHex, isHex, concatBytes, equalBytes, isAllZero, utf8, u32le, u32be, u64be,
} from "./bytes.js";
export { parseJsonIntegers } from "./json.js";

export {
  QUOTE, MOCK_QE_VENDOR_ID, INTEL_QE_VENDOR_ID, encodeQuote, parseQuote, isDebug, osMeasurement, mockOsReport,
  type TdReport, type ParsedQuote, type RootKind,
} from "./tdx/quote.js";
export {
  EVENT_TYPE, EVENT_IMR, MAX_EVENTS, MAX_EVENT_PAYLOAD, BOOT_SEQUENCE, makeEvent, replayRtmr3, verifyEventLog, bootEvents,
  type TdxEvent,
} from "./tdx/eventlog.js";
export { keyHash, reportData, registrationNonce } from "./tdx/measure.js";

export type { Attester, QuoteVerifier } from "./attest/types.js";
export {
  MockRoot, MockTdxAttester, MockVerifier, MOCK_AK_CERT_PREFIX, p256VerifyLowS, isValidP256Pub,
  type MockTdxAttesterOptions,
} from "./attest/mock.js";
export { DstackAttester, DcapQvlVerifier } from "./attest/stubs.js";

export { deriveSession, clientSeal, serverOpen, TAG_LEN, type SessionKeys } from "./crypto/session.js";
export { sealFrame, openFrame, FrameReader } from "./crypto/frames.js";

export {
  receiptMessage, signReceipt, verifyReceipt, receiptLeaf, anchorMessage, isReceipt, type Receipt,
} from "./receipts/receipt.js";
export { merkleRoot, merkleProof, verifyMerkleProof, MAX_PROOF_LEN } from "./receipts/merkle.js";

export {
  MemoryRegistry, isHash32, isRegistryRoot, isInstanceRecord, isAnchorRecord, isOrgId, ORG_ID_RE,
  type RegistryReader, type RegistryRoot, type InstanceRecord, type AnchorRecord, type MemoryRegistryOptions,
} from "./registry.js";

export {
  verifyAttestation, CHECKS, MAX_APP_COMPOSE_BYTES,
  type AttestationBundle, type VerifiedRouter, type VerifyAttestationParams,
} from "./policy.js";

// PLR-VPN-v1 (SPEC-VPN §9.1)
export {
  VPN_DOMAIN, TUNNEL, FRAME, FRAME_RULES, MAX_CONNECT_PAYLOAD, TUNNEL_STEP_TIMEOUT_MS, TUNNEL_IDLE_TIMEOUT_MS,
  isTunnelDir, frameAllowed, type TunnelDir, type FrameType,
} from "./tunnel/constants.js";
export {
  deriveTunnel, encodeHello, parseHello, encodeServerHello, parseServerHello, tunnelClientStart, tunnelServerAccept,
  type TunnelKeys, type TunnelClientHandshake, type TunnelServerHandshake,
} from "./tunnel/keys.js";
export { TunnelWriter, TunnelReader, type TunnelFrame } from "./tunnel/frames.js";
export {
  CONNECT_ERR_CODES, CONNECT_PADDED_LEN, CONNECT_ERR_PADDED_LEN, isConnectErrCode, encodeConnect, parseConnect, encodeConnectErr, parseConnectErr,
  encodeReceiptPayload, parseReceiptPayload, type ConnectErrCode,
} from "./tunnel/payloads.js";
export {
  vpnReceiptMessage, signVpnReceipt, verifyVpnReceipt, vpnReceiptLeaf, isVpnReceipt, type VpnReceipt,
} from "./receipts/vpn-receipt.js";
export { parseIpv4, parseIpv6, formatIpv4, formatIpv6, isIpLiteral, MAX_IPV6_TEXT_LEN } from "./net/ip.js";
export {
  classifyIp, egressAllowed, egressIdentity, validateDestination, isEgressPolicy, isDnsName, isPort, MAX_DNS_NAME_LEN,
  type IpClass, type EgressPolicy,
} from "./net/egress.js";
export {
  SOCKS, SOCKS_REP, parseSocksGreeting, parseSocksRequest, encodeSocksReply, socksReplyFor, type SocksRequest,
} from "./net/socks5.js";
export { DNS, encodeDnsQuery, parseDnsResponse, isLocalhostName, type DnsType } from "./net/dns.js";
