// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

/**
 * @title PlrRegistry — PLR tier-B registry for any EVM chain (SPEC-CHAINS §9; Monad included).
 *
 * What the chain enforces (tier B, SPEC-CHAINS §1): owner policy (compose / OS allowlists, attestation root,
 * operator organizations, two-step ownership), registration only by owner-approved operators with
 * `operator = msg.sender`, the registration quote's format and its report_data binding to
 * (key hash, registrationNonce(contractId, operator)), the quote stored on-chain, and anchors with contiguous
 * `firstSeq` posted only by the instance's operator. The quote signature and the anchor Ed25519 signature are NOT
 * verified here (no such precompiles on a generic EVM): clients verify both (SPEC-CHAINS §2).
 *
 * Every state-changing function reverts with a custom error named after the PLR error code, so clients map the
 * revert selector back to the code. Times are milliseconds (`block.timestamp * 1000`).
 */
contract PlrRegistry {
    // ------------------------------------------------------------------------------------------- errors (PLR codes)
    error E_UNAUTHORIZED();
    error E_ZERO_HASH();
    error E_BAD_INPUT();
    error E_OPERATOR_UNAPPROVED();
    error E_REPORT_DATA();
    error E_QUOTE_FORMAT();
    error E_SEQ();
    error E_INSTANCE_NOT_REGISTERED();
    error E_COMPOSE_NOT_ALLOWED();
    /// Also a PLR code: an anchor of an instance whose OS measurement is no longer allowed.
    error E_OS_NOT_ALLOWED();

    // ------------------------------------------------------------------------------------------- events
    event ComposeAllowed(bytes32 indexed h);
    event ComposeRevoked(bytes32 indexed h);
    event OsAllowed(bytes32 indexed h);
    event OsRevoked(bytes32 indexed h);
    event RootSet(uint8 kind, bytes p256);
    event OperatorApproved(address indexed op, string orgId, string previousOrgId);
    event OperatorRevoked(address indexed op, string previousOrgId);
    event OwnerProposed(address indexed owner, address indexed next);
    event OwnerAccepted(address indexed previousOwner, address indexed newOwner);
    event InstanceRegistered(
        bytes32 indexed keyHash, address indexed operator, bytes32 composeHash, bytes32 osMeasurement, uint64 registeredAtMs, uint64 expiresAtMs
    );
    event InstanceRefreshed(bytes32 indexed keyHash, address indexed operator, bytes32 composeHash, bytes32 osMeasurement, uint64 expiresAtMs);
    event ReceiptsAnchored(
        uint256 indexed id, bytes32 indexed keyHash, bytes32 root, uint64 firstSeq, uint64 count, uint64 atMs, bytes sig
    );

    // ------------------------------------------------------------------------------------------- constants
    uint8 public constant ROOT_MOCK = 1;
    uint8 public constant ROOT_INTEL = 2;
    uint64 public constant MAX_ANCHOR_COUNT = 10_000;
    uint64 public constant MAX_INSTANCE_TTL_MS = 365 * 86_400_000;
    /// MOCK-mode TDX quote v4 length (SPEC §2): header 48 + body 584 + u32 sig_data_len + 192.
    uint256 public constant QUOTE_LEN = 828;
    uint256 internal constant REPORT_DATA_OFF = 568;
    bytes internal constant KEY_DOMAIN = "PLR-v1";
    bytes internal constant REG_NONCE_DOMAIN = "PLR-v1/register/2";

    // ------------------------------------------------------------------------------------------- state
    struct Instance {
        bytes32 composeHash;
        bytes32 osMeasurement;
        bytes32 x25519;
        bytes32 ed25519;
        address operator;
        uint64 registeredAtMs;
        uint64 expiresAtMs;
        uint64 nextSeq;
    }

    struct Anchor {
        bytes32 keyHash;
        bytes32 root;
        uint64 firstSeq;
        uint64 count;
        uint64 atMs;
        bytes sig;
    }

    address public owner;
    address public pendingOwner;
    uint64 public immutable instanceTtlMs;
    uint8 internal _rootKind;
    bytes internal _rootP256;
    mapping(bytes32 => bool) internal _compose;
    mapping(bytes32 => bool) internal _os;
    mapping(address => string) internal _operators;
    mapping(bytes32 => Instance) internal _instances;
    mapping(bytes32 => bytes) internal _quotes;
    Anchor[] internal _anchors;

    modifier onlyOwner() {
        if (msg.sender != owner) revert E_UNAUTHORIZED();
        _;
    }

    constructor(address owner_, uint8 rootKind, bytes memory rootP256, uint64 instanceTtlMs_) {
        if (owner_ == address(0)) revert E_BAD_INPUT();
        if (instanceTtlMs_ == 0 || instanceTtlMs_ > MAX_INSTANCE_TTL_MS) revert E_BAD_INPUT();
        _checkRoot(rootKind, rootP256);
        owner = owner_;
        instanceTtlMs = instanceTtlMs_;
        _rootKind = rootKind;
        _rootP256 = rootP256;
        emit RootSet(rootKind, rootP256);
    }

    // ------------------------------------------------------------------------------------------- owner policy

    function allowCompose(bytes32 h) external onlyOwner {
        if (h == bytes32(0)) revert E_ZERO_HASH();
        _compose[h] = true;
        emit ComposeAllowed(h);
    }

    function revokeCompose(bytes32 h) external onlyOwner {
        if (h == bytes32(0)) revert E_ZERO_HASH();
        delete _compose[h];
        emit ComposeRevoked(h);
    }

    function allowOs(bytes32 h) external onlyOwner {
        if (h == bytes32(0)) revert E_ZERO_HASH();
        _os[h] = true;
        emit OsAllowed(h);
    }

    function revokeOs(bytes32 h) external onlyOwner {
        if (h == bytes32(0)) revert E_ZERO_HASH();
        delete _os[h];
        emit OsRevoked(h);
    }

    function setRoot(uint8 kind, bytes calldata p256) external onlyOwner {
        _checkRoot(kind, p256);
        _rootKind = kind;
        _rootP256 = p256;
        emit RootSet(kind, p256);
    }

    /// Approves (or re-maps) `op` to organization `orgId` (`^[a-z0-9][a-z0-9._-]{0,63}$`). Live for its instances.
    function approveOperator(address op, string calldata orgId) external onlyOwner {
        if (op == address(0) || !_isOrgId(bytes(orgId))) revert E_BAD_INPUT();
        string memory previous = _operators[op];
        _operators[op] = orgId;
        emit OperatorApproved(op, orgId, previous);
    }

    /// Removes `op`'s organization: it can no longer register; its instances report no org.
    function revokeOperator(address op) external onlyOwner {
        if (op == address(0)) revert E_BAD_INPUT();
        string memory previous = _operators[op];
        delete _operators[op];
        emit OperatorRevoked(op, previous);
    }

    /// Step 1 of the ownership transfer; `address(0)` cancels a pending proposal.
    function proposeOwner(address next) external onlyOwner {
        pendingOwner = next;
        emit OwnerProposed(msg.sender, next);
    }

    /// Step 2: only the pending owner can accept.
    function acceptOwner() external {
        address p = pendingOwner;
        if (p == address(0) || msg.sender != p) revert E_UNAUTHORIZED();
        emit OwnerAccepted(owner, p);
        owner = p;
        pendingOwner = address(0);
    }

    // ------------------------------------------------------------------------------------------- operator

    /**
     * Registers (or, by its first registrant, refreshes) the instance with keys (`x25519`, `ed25519`). A record whose
     * operator the owner no longer approves may be taken over by another approved operator (fresh record, nextSeq 0). The quote's
     * report_data must be `keyHash ‖ registrationNonce(contractId(), lowercase-hex(msg.sender))` (SPEC §5 rev 1.3).
     * A refresh keeps `operator`, `registeredAtMs` and `nextSeq`, and replaces the measurements, expiry and quote.
     */
    function registerInstance(bytes32 x25519, bytes32 ed25519, bytes32 composeHash, bytes32 osMeasurement, bytes calldata quote)
        external
    {
        if (bytes(_operators[msg.sender]).length == 0) revert E_OPERATOR_UNAPPROVED();
        if (composeHash == bytes32(0) || osMeasurement == bytes32(0)) revert E_ZERO_HASH();
        bytes32 kh = sha256(abi.encodePacked(KEY_DOMAIN, x25519, ed25519));
        _checkQuoteFormat(quote);
        if (bytes32(quote[REPORT_DATA_OFF:REPORT_DATA_OFF + 32]) != kh) revert E_REPORT_DATA();
        bytes32 nonce = _registrationNonce(contractId(), _hexAddress(msg.sender));
        if (bytes32(quote[REPORT_DATA_OFF + 32:REPORT_DATA_OFF + 64]) != nonce) revert E_REPORT_DATA();

        uint64 now_ = _nowMs();
        uint64 expires = now_ + instanceTtlMs; // checked arithmetic: reverts (Panic) only on absurd timestamps
        Instance storage inst = _instances[kh];
        address current = inst.operator;
        // A key belongs to its first registrant while the owner approves that operator (SPEC-CHAINS §1: tier B accepts
        // instance records only from live-approved operators). Once the owner revokes it, another approved operator may
        // take the key over as a fresh record (nextSeq 0): the owner's remedy against a squatter that registered
        // someone else's public key hash with an unsigned quote.
        if (current == address(0) || (current != msg.sender && bytes(_operators[current]).length == 0)) {
            inst.x25519 = x25519;
            inst.ed25519 = ed25519;
            inst.operator = msg.sender;
            inst.registeredAtMs = now_;
            inst.composeHash = composeHash;
            inst.osMeasurement = osMeasurement;
            inst.expiresAtMs = expires;
            inst.nextSeq = 0;
            _quotes[kh] = quote;
            emit InstanceRegistered(kh, msg.sender, composeHash, osMeasurement, now_, expires);
        } else {
            if (current != msg.sender) revert E_UNAUTHORIZED();
            inst.composeHash = composeHash;
            inst.osMeasurement = osMeasurement;
            inst.expiresAtMs = expires;
            _quotes[kh] = quote;
            emit InstanceRefreshed(kh, msg.sender, composeHash, osMeasurement, expires);
        }
    }

    /// Anchors the Merkle root of receipts `[firstSeq, firstSeq + count)`; `sig` (Ed25519, 64 bytes) is stored for clients.
    function anchorReceipts(bytes32 keyHash, bytes32 root, uint64 firstSeq, uint64 count, bytes calldata sig) external {
        Instance storage inst = _instances[keyHash];
        uint64 now_ = _nowMs();
        if (inst.operator == address(0) || now_ >= inst.expiresAtMs) revert E_INSTANCE_NOT_REGISTERED();
        if (msg.sender != inst.operator) revert E_UNAUTHORIZED();
        if (!_compose[inst.composeHash]) revert E_COMPOSE_NOT_ALLOWED();
        if (!_os[inst.osMeasurement]) revert E_OS_NOT_ALLOWED();
        if (count == 0 || count > MAX_ANCHOR_COUNT) revert E_SEQ();
        if (firstSeq != inst.nextSeq) revert E_SEQ();
        if (sig.length != 64) revert E_BAD_INPUT();
        uint64 next = firstSeq + count; // firstSeq ≤ 2^64 - 1 - count unless overflow (reverts)
        inst.nextSeq = next;
        uint256 id = _anchors.length;
        _anchors.push(Anchor({keyHash: keyHash, root: root, firstSeq: firstSeq, count: count, atMs: now_, sig: sig}));
        emit ReceiptsAnchored(id, keyHash, root, firstSeq, count, now_, sig);
    }

    // ------------------------------------------------------------------------------------------- views

    /// SPEC-CHAINS §3: `"evm:<chainId decimal>:<0x lowercase address(this)>"`.
    function contractId() public view returns (string memory) {
        return string(abi.encodePacked("evm:", _decimal(block.chainid), ":", _hexAddress(address(this))));
    }

    function getRoot() external view returns (uint8 kind, bytes memory p256) {
        return (_rootKind, _rootP256);
    }

    function isComposeAllowed(bytes32 h) external view returns (bool) {
        return _compose[h];
    }

    function isOsAllowed(bytes32 h) external view returns (bool) {
        return _os[h];
    }

    /// The owner-approved organization of `op`, `""` if unapproved.
    function getOperator(address op) external view returns (string memory) {
        return _operators[op];
    }

    /// The instance record (`exists` false if never registered). Expiry is reported, not applied: readers check it.
    function getInstance(bytes32 keyHash)
        external
        view
        returns (
            bool exists,
            bytes32 composeHash,
            bytes32 osMeasurement,
            bytes32 x25519,
            bytes32 ed25519,
            address operator,
            uint64 registeredAtMs,
            uint64 expiresAtMs,
            uint64 nextSeq
        )
    {
        Instance storage i = _instances[keyHash];
        return (
            i.operator != address(0),
            i.composeHash,
            i.osMeasurement,
            i.x25519,
            i.ed25519,
            i.operator,
            i.registeredAtMs,
            i.expiresAtMs,
            i.nextSeq
        );
    }

    /// The latest registration quote stored for `keyHash` (empty if none).
    function getRegistrationQuote(bytes32 keyHash) external view returns (bytes memory) {
        return _quotes[keyHash];
    }

    function anchorCount() external view returns (uint256) {
        return _anchors.length;
    }

    /// Reverts `E_BAD_INPUT` for an unknown id.
    function getAnchor(uint256 id)
        external
        view
        returns (bytes32 keyHash, bytes32 root, uint64 firstSeq, uint64 count, uint64 atMs, bytes memory sig)
    {
        if (id >= _anchors.length) revert E_BAD_INPUT();
        Anchor storage a = _anchors[id];
        return (a.keyHash, a.root, a.firstSeq, a.count, a.atMs, a.sig);
    }

    /// `SHA256("PLR-v1/register/2" ‖ u8(len c) ‖ c ‖ u8(len o) ‖ o)` (SPEC §5 rev 1.3), exposed for clients and tests.
    function registrationNonce(string calldata cId, string calldata operatorId) external pure returns (bytes32) {
        return _registrationNonce(cId, operatorId);
    }

    // ------------------------------------------------------------------------------------------- internals

    function _nowMs() internal view returns (uint64) {
        return uint64(block.timestamp) * 1000;
    }

    function _checkRoot(uint8 kind, bytes memory p256) internal pure {
        if ((kind != ROOT_MOCK && kind != ROOT_INTEL) || p256.length != 64) revert E_BAD_INPUT();
    }

    /// Quote v4 (u16le), attestation key type 2 = ECDSA-P256 (u16le), TEE type 0x81 = TDX (u32le), MOCK length 828.
    function _checkQuoteFormat(bytes calldata q) internal pure {
        if (q.length != QUOTE_LEN) revert E_QUOTE_FORMAT();
        if (q[0] != 0x04 || q[1] != 0x00) revert E_QUOTE_FORMAT();
        if (q[2] != 0x02 || q[3] != 0x00) revert E_QUOTE_FORMAT();
        if (q[4] != 0x81 || q[5] != 0x00 || q[6] != 0x00 || q[7] != 0x00) revert E_QUOTE_FORMAT();
    }

    function _registrationNonce(string memory c, string memory o) internal pure returns (bytes32) {
        bytes memory cb = bytes(c);
        bytes memory ob = bytes(o);
        if (cb.length == 0 || cb.length > 64 || ob.length == 0 || ob.length > 64) revert E_BAD_INPUT();
        return sha256(abi.encodePacked(REG_NONCE_DOMAIN, uint8(cb.length), cb, uint8(ob.length), ob));
    }

    /// `^[a-z0-9][a-z0-9._-]{0,63}$`
    function _isOrgId(bytes memory s) internal pure returns (bool) {
        uint256 n = s.length;
        if (n == 0 || n > 64) return false;
        for (uint256 i = 0; i < n; i++) {
            bytes1 c = s[i];
            bool alnum = (c >= 0x61 && c <= 0x7a) || (c >= 0x30 && c <= 0x39);
            if (i == 0) {
                if (!alnum) return false;
            } else if (!alnum && c != 0x2e && c != 0x5f && c != 0x2d) {
                return false;
            }
        }
        return true;
    }

    /// `"0x"` + 40 lowercase hex digits.
    function _hexAddress(address a) internal pure returns (string memory) {
        bytes memory out = new bytes(42);
        bytes16 digits = "0123456789abcdef";
        out[0] = "0";
        out[1] = "x";
        uint160 v = uint160(a);
        for (uint256 i = 41; i > 1; i--) {
            out[i] = digits[v & 0xf];
            v >>= 4;
        }
        return string(out);
    }

    function _decimal(uint256 v) internal pure returns (string memory) {
        if (v == 0) return "0";
        uint256 len;
        for (uint256 t = v; t != 0; t /= 10) len++;
        bytes memory out = new bytes(len);
        for (uint256 i = len; i > 0; i--) {
            out[i - 1] = bytes1(uint8(48 + (v % 10)));
            v /= 10;
        }
        return string(out);
    }
}
