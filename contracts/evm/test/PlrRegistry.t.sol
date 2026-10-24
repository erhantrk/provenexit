// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

import {Test} from "forge-std/Test.sol";
import {PlrRegistry} from "../src/PlrRegistry.sol";
import {Vectors as V} from "./Vectors.sol";

/// SPEC-CHAINS §9 rules, with cross-implementation vectors produced by the shared TS package (test/Vectors.sol).
contract PlrRegistryTest is Test {
    PlrRegistry reg;
    address owner = makeAddr("owner");
    address stranger = makeAddr("stranger");
    uint64 constant TTL = 86_400_000;

    function setUp() public {
        vm.chainId(V.CHAIN_ID);
        vm.warp(1_760_000_000);
        deployCodeTo("PlrRegistry.sol:PlrRegistry", abi.encode(owner, uint8(1), V.ROOT_P256, TTL), V.REGISTRY);
        reg = PlrRegistry(V.REGISTRY);
    }

    // ------------------------------------------------------------------ helpers

    function _approve(address op, string memory org) internal {
        vm.prank(owner);
        reg.approveOperator(op, org);
    }

    function _allowBuild() internal {
        vm.startPrank(owner);
        reg.allowCompose(V.COMPOSE_HASH);
        reg.allowOs(V.OS_MEASUREMENT);
        vm.stopPrank();
    }

    function _register() internal {
        _approve(V.OPERATOR, "org-a");
        vm.prank(V.OPERATOR);
        reg.registerInstance(V.X25519, V.ED25519, V.COMPOSE_HASH, V.OS_MEASUREMENT, V.QUOTE);
    }

    function _sig() internal pure returns (bytes memory s) {
        s = new bytes(64);
        // forge-lint: disable-next-line(unsafe-typecast)
        for (uint256 i = 0; i < 64; i++) s[i] = bytes1(uint8(i + 1));
    }

    function _anchor(uint64 first, uint64 count) internal {
        vm.prank(V.OPERATOR);
        reg.anchorReceipts(V.KEY_HASH, V.ANCHOR_ROOT, first, count, _sig());
    }

    function _nextSeq() internal view returns (uint64 n) {
        (,,,,,,,, n) = reg.getInstance(V.KEY_HASH);
    }

    function _expires() internal view returns (uint64 e) {
        (,,,,,,, e,) = reg.getInstance(V.KEY_HASH);
    }

    // ------------------------------------------------------------------ cross-implementation vectors

    function test_vector_contractId() public view {
        assertEq(reg.contractId(), V.CONTRACT_ID);
    }

    function test_vector_registrationNonce() public view {
        assertEq(reg.registrationNonce(V.CONTRACT_ID, V.OPERATOR_ID), V.REG_NONCE);
        assertEq(reg.registrationNonce("registry.test.near", "operator.test.near"), V.REG_NONCE_NEAR);
    }

    function test_vector_quoteReportData() public pure {
        bytes memory q = V.QUOTE;
        assertEq(q.length, 828);
        bytes32 a;
        bytes32 b;
        assembly {
            a := mload(add(q, add(32, 568)))
            b := mload(add(q, add(32, 600)))
        }
        assertEq(a, V.KEY_HASH);
        assertEq(b, V.REG_NONCE);
    }

    function test_vector_registerComputesKeyHash() public {
        _register();
        (bool exists, bytes32 c, bytes32 o, bytes32 x, bytes32 e, address op, uint64 at, uint64 exp, uint64 next) = reg.getInstance(V.KEY_HASH);
        assertTrue(exists);
        assertEq(c, V.COMPOSE_HASH);
        assertEq(o, V.OS_MEASUREMENT);
        assertEq(x, V.X25519);
        assertEq(e, V.ED25519);
        assertEq(op, V.OPERATOR);
        assertEq(at, uint64(block.timestamp) * 1000);
        assertEq(exp, at + TTL);
        assertEq(next, 0);
        assertEq(reg.getRegistrationQuote(V.KEY_HASH), V.QUOTE);
    }

    function test_registrationNonce_boundsIds() public {
        vm.expectRevert(PlrRegistry.E_BAD_INPUT.selector);
        reg.registrationNonce("", "a");
        vm.expectRevert(PlrRegistry.E_BAD_INPUT.selector);
        reg.registrationNonce("a", string(new bytes(65)));
    }

    // ------------------------------------------------------------------ constructor & owner policy

    function test_constructor_validates() public {
        vm.expectRevert(PlrRegistry.E_BAD_INPUT.selector);
        new PlrRegistry(address(0), 1, V.ROOT_P256, TTL);
        vm.expectRevert(PlrRegistry.E_BAD_INPUT.selector);
        new PlrRegistry(owner, 3, V.ROOT_P256, TTL);
        vm.expectRevert(PlrRegistry.E_BAD_INPUT.selector);
        new PlrRegistry(owner, 1, hex"01", TTL);
        vm.expectRevert(PlrRegistry.E_BAD_INPUT.selector);
        new PlrRegistry(owner, 1, V.ROOT_P256, 0);
        vm.expectRevert(PlrRegistry.E_BAD_INPUT.selector);
        new PlrRegistry(owner, 1, V.ROOT_P256, 365 * 86_400_000 + 1);
    }

    function test_initialState() public view {
        assertEq(reg.owner(), owner);
        (uint8 kind, bytes memory p) = reg.getRoot();
        assertEq(kind, 1);
        assertEq(p, V.ROOT_P256);
        assertEq(reg.instanceTtlMs(), TTL);
        assertEq(reg.anchorCount(), 0);
        assertFalse(reg.isComposeAllowed(V.COMPOSE_HASH));
    }

    function test_ownerOnly() public {
        vm.startPrank(stranger);
        vm.expectRevert(PlrRegistry.E_UNAUTHORIZED.selector);
        reg.allowCompose(V.COMPOSE_HASH);
        vm.expectRevert(PlrRegistry.E_UNAUTHORIZED.selector);
        reg.revokeCompose(V.COMPOSE_HASH);
        vm.expectRevert(PlrRegistry.E_UNAUTHORIZED.selector);
        reg.allowOs(V.OS_MEASUREMENT);
        vm.expectRevert(PlrRegistry.E_UNAUTHORIZED.selector);
        reg.revokeOs(V.OS_MEASUREMENT);
        vm.expectRevert(PlrRegistry.E_UNAUTHORIZED.selector);
        reg.setRoot(2, V.ROOT_P256);
        vm.expectRevert(PlrRegistry.E_UNAUTHORIZED.selector);
        reg.approveOperator(stranger, "org");
        vm.expectRevert(PlrRegistry.E_UNAUTHORIZED.selector);
        reg.revokeOperator(stranger);
        vm.expectRevert(PlrRegistry.E_UNAUTHORIZED.selector);
        reg.proposeOwner(stranger);
        vm.expectRevert(PlrRegistry.E_UNAUTHORIZED.selector);
        reg.acceptOwner();
        vm.stopPrank();
    }

    function test_allowlists() public {
        vm.startPrank(owner);
        vm.expectEmit(true, false, false, true, address(reg));
        emit PlrRegistry.ComposeAllowed(V.COMPOSE_HASH);
        reg.allowCompose(V.COMPOSE_HASH);
        assertTrue(reg.isComposeAllowed(V.COMPOSE_HASH));
        vm.expectEmit(true, false, false, true, address(reg));
        emit PlrRegistry.ComposeRevoked(V.COMPOSE_HASH);
        reg.revokeCompose(V.COMPOSE_HASH);
        assertFalse(reg.isComposeAllowed(V.COMPOSE_HASH));
        reg.allowOs(V.OS_MEASUREMENT);
        assertTrue(reg.isOsAllowed(V.OS_MEASUREMENT));
        assertFalse(reg.isComposeAllowed(V.OS_MEASUREMENT)); // separate lists
        reg.revokeOs(V.OS_MEASUREMENT);
        assertFalse(reg.isOsAllowed(V.OS_MEASUREMENT));
        vm.stopPrank();
    }

    function test_zeroHash() public {
        vm.startPrank(owner);
        vm.expectRevert(PlrRegistry.E_ZERO_HASH.selector);
        reg.allowCompose(bytes32(0));
        vm.expectRevert(PlrRegistry.E_ZERO_HASH.selector);
        reg.revokeCompose(bytes32(0));
        vm.expectRevert(PlrRegistry.E_ZERO_HASH.selector);
        reg.allowOs(bytes32(0));
        vm.expectRevert(PlrRegistry.E_ZERO_HASH.selector);
        reg.revokeOs(bytes32(0));
        vm.stopPrank();
    }

    function test_setRoot() public {
        vm.startPrank(owner);
        vm.expectRevert(PlrRegistry.E_BAD_INPUT.selector);
        reg.setRoot(0, V.ROOT_P256);
        vm.expectRevert(PlrRegistry.E_BAD_INPUT.selector);
        reg.setRoot(2, new bytes(63));
        bytes memory p = new bytes(64);
        p[0] = 0xaa;
        vm.expectEmit(false, false, false, true, address(reg));
        emit PlrRegistry.RootSet(2, p);
        reg.setRoot(2, p);
        vm.stopPrank();
        (uint8 kind, bytes memory got) = reg.getRoot();
        assertEq(kind, 2);
        assertEq(got, p);
    }

    function test_operators() public {
        assertEq(reg.getOperator(V.OPERATOR), "");
        vm.expectEmit(true, false, false, true, address(reg));
        emit PlrRegistry.OperatorApproved(V.OPERATOR, "org-a", "");
        _approve(V.OPERATOR, "org-a");
        assertEq(reg.getOperator(V.OPERATOR), "org-a");
        _approve(V.OPERATOR, "org.b_2-x");
        assertEq(reg.getOperator(V.OPERATOR), "org.b_2-x");
        vm.prank(owner);
        reg.revokeOperator(V.OPERATOR);
        assertEq(reg.getOperator(V.OPERATOR), "");
    }

    function test_orgIdRules() public {
        string[6] memory bad = ["", "Org", ".org", "-org", "org a", unicode"orgé"];
        vm.startPrank(owner);
        for (uint256 i = 0; i < bad.length; i++) {
            vm.expectRevert(PlrRegistry.E_BAD_INPUT.selector);
            reg.approveOperator(V.OPERATOR, bad[i]);
        }
        bytes memory long = new bytes(65);
        for (uint256 i = 0; i < 65; i++) long[i] = "a";
        vm.expectRevert(PlrRegistry.E_BAD_INPUT.selector);
        reg.approveOperator(V.OPERATOR, string(long));
        assembly {
            mstore(long, 64)
        }
        reg.approveOperator(V.OPERATOR, string(long)); // 64 chars: ok
        reg.approveOperator(V.OPERATOR, "0"); // 1 char: ok
        vm.expectRevert(PlrRegistry.E_BAD_INPUT.selector);
        reg.approveOperator(address(0), "org");
        vm.expectRevert(PlrRegistry.E_BAD_INPUT.selector);
        reg.revokeOperator(address(0));
        vm.stopPrank();
    }

    function test_twoStepOwner() public {
        address next = makeAddr("next");
        vm.prank(owner);
        reg.proposeOwner(next);
        assertEq(reg.owner(), owner); // not yet
        vm.prank(stranger);
        vm.expectRevert(PlrRegistry.E_UNAUTHORIZED.selector);
        reg.acceptOwner();
        vm.prank(next);
        reg.acceptOwner();
        assertEq(reg.owner(), next);
        assertEq(reg.pendingOwner(), address(0));
        vm.prank(owner);
        vm.expectRevert(PlrRegistry.E_UNAUTHORIZED.selector);
        reg.allowCompose(V.COMPOSE_HASH);
        vm.prank(next);
        reg.allowCompose(V.COMPOSE_HASH);
        // cancel a proposal
        vm.prank(next);
        reg.proposeOwner(stranger);
        vm.prank(next);
        reg.proposeOwner(address(0));
        vm.prank(stranger);
        vm.expectRevert(PlrRegistry.E_UNAUTHORIZED.selector);
        reg.acceptOwner();
    }

    // ------------------------------------------------------------------ registration

    function test_register_requiresApprovedOperator() public {
        vm.prank(V.OPERATOR);
        vm.expectRevert(PlrRegistry.E_OPERATOR_UNAPPROVED.selector);
        reg.registerInstance(V.X25519, V.ED25519, V.COMPOSE_HASH, V.OS_MEASUREMENT, V.QUOTE);
        _approve(V.OPERATOR, "org-a");
        vm.prank(owner);
        reg.revokeOperator(V.OPERATOR);
        vm.prank(V.OPERATOR);
        vm.expectRevert(PlrRegistry.E_OPERATOR_UNAPPROVED.selector);
        reg.registerInstance(V.X25519, V.ED25519, V.COMPOSE_HASH, V.OS_MEASUREMENT, V.QUOTE);
    }

    function test_register_emits() public {
        _approve(V.OPERATOR, "org-a");
        uint64 nowMs = uint64(block.timestamp) * 1000;
        vm.expectEmit(true, true, false, true, address(reg));
        emit PlrRegistry.InstanceRegistered(V.KEY_HASH, V.OPERATOR, V.COMPOSE_HASH, V.OS_MEASUREMENT, nowMs, nowMs + TTL);
        vm.prank(V.OPERATOR);
        reg.registerInstance(V.X25519, V.ED25519, V.COMPOSE_HASH, V.OS_MEASUREMENT, V.QUOTE);
    }

    function test_register_zeroMeasurements() public {
        _approve(V.OPERATOR, "org-a");
        vm.startPrank(V.OPERATOR);
        vm.expectRevert(PlrRegistry.E_ZERO_HASH.selector);
        reg.registerInstance(V.X25519, V.ED25519, bytes32(0), V.OS_MEASUREMENT, V.QUOTE);
        vm.expectRevert(PlrRegistry.E_ZERO_HASH.selector);
        reg.registerInstance(V.X25519, V.ED25519, V.COMPOSE_HASH, bytes32(0), V.QUOTE);
        vm.stopPrank();
    }

    function _withByte(bytes memory q, uint256 i, bytes1 v) internal pure returns (bytes memory out) {
        out = bytes.concat(q);
        out[i] = v;
    }

    function test_register_quoteFormat() public {
        _approve(V.OPERATOR, "org-a");
        bytes[8] memory bad = [
            bytes.concat(V.QUOTE, hex"00"), // 829 bytes
            new bytes(827),
            _withByte(V.QUOTE, 0, 0x05), // version 5
            _withByte(V.QUOTE, 1, 0x01), // version 0x0104
            _withByte(V.QUOTE, 2, 0x03), // att key type 3
            _withByte(V.QUOTE, 4, 0x00), // tee type 0 (SGX)
            _withByte(V.QUOTE, 5, 0x01), // tee type 0x181
            _withByte(V.QUOTE, 7, 0x01) // tee type high byte
        ];
        vm.startPrank(V.OPERATOR);
        for (uint256 i = 0; i < bad.length; i++) {
            vm.expectRevert(PlrRegistry.E_QUOTE_FORMAT.selector);
            reg.registerInstance(V.X25519, V.ED25519, V.COMPOSE_HASH, V.OS_MEASUREMENT, bad[i]);
        }
        vm.expectRevert(PlrRegistry.E_QUOTE_FORMAT.selector);
        reg.registerInstance(V.X25519, V.ED25519, V.COMPOSE_HASH, V.OS_MEASUREMENT, "");
        vm.stopPrank();
    }

    function test_register_reportDataBinding() public {
        _approve(V.OPERATOR, "org-a");
        vm.startPrank(V.OPERATOR);
        // keys not the quote's
        vm.expectRevert(PlrRegistry.E_REPORT_DATA.selector);
        reg.registerInstance(V.ED25519, V.X25519, V.COMPOSE_HASH, V.OS_MEASUREMENT, V.QUOTE);
        // quote bound to another operator
        vm.expectRevert(PlrRegistry.E_REPORT_DATA.selector);
        reg.registerInstance(V.X25519, V.ED25519, V.COMPOSE_HASH, V.OS_MEASUREMENT, V.QUOTE_OTHER);
        // quote bound to another contract id (other chain)
        vm.expectRevert(PlrRegistry.E_REPORT_DATA.selector);
        reg.registerInstance(V.X25519, V.ED25519, V.COMPOSE_HASH, V.OS_MEASUREMENT, V.QUOTE_WRONG_CID);
        // tampered nonce byte / key-hash byte
        vm.expectRevert(PlrRegistry.E_REPORT_DATA.selector);
        reg.registerInstance(V.X25519, V.ED25519, V.COMPOSE_HASH, V.OS_MEASUREMENT, _withByte(V.QUOTE, 631, bytes1(uint8(V.QUOTE[631]) ^ 1)));
        vm.expectRevert(PlrRegistry.E_REPORT_DATA.selector);
        reg.registerInstance(V.X25519, V.ED25519, V.COMPOSE_HASH, V.OS_MEASUREMENT, _withByte(V.QUOTE, 568, bytes1(uint8(V.QUOTE[568]) ^ 1)));
        vm.stopPrank();
        // same quote replayed on another chain id (same address) is refused
        vm.chainId(1);
        vm.prank(V.OPERATOR);
        vm.expectRevert(PlrRegistry.E_REPORT_DATA.selector);
        reg.registerInstance(V.X25519, V.ED25519, V.COMPOSE_HASH, V.OS_MEASUREMENT, V.QUOTE);
    }

    function test_register_otherOperatorOwnQuote() public {
        _approve(V.OTHER, "org-b");
        vm.prank(V.OTHER);
        reg.registerInstance(V.X25519, V.ED25519, V.COMPOSE_HASH, V.OS_MEASUREMENT, V.QUOTE_OTHER);
        (,,,,, address op,,,) = reg.getInstance(V.KEY_HASH);
        assertEq(op, V.OTHER);
    }

    function test_register_firstRegistrantOwnsKey() public {
        _register();
        _approve(V.OTHER, "org-b");
        vm.prank(V.OTHER);
        vm.expectRevert(PlrRegistry.E_UNAUTHORIZED.selector);
        reg.registerInstance(V.X25519, V.ED25519, V.COMPOSE_HASH, V.OS_MEASUREMENT, V.QUOTE_OTHER);
    }

    function test_register_refreshKeepsSeqReplacesQuote() public {
        _register();
        _allowBuild();
        _anchor(0, 5);
        (,,,,,, uint64 at0,,) = reg.getInstance(V.KEY_HASH);
        vm.warp(block.timestamp + 3600);
        // a different (but still valid) quote of the same boot: flip a byte outside the checked fields
        bytes memory q2 = _withByte(V.QUOTE, 700, bytes1(uint8(V.QUOTE[700]) ^ 0xff));
        vm.prank(V.OPERATOR);
        reg.registerInstance(V.X25519, V.ED25519, V.COMPOSE_HASH, V.OS_MEASUREMENT, q2);
        (,,,,, address op, uint64 at1, uint64 exp1, uint64 next) = reg.getInstance(V.KEY_HASH);
        assertEq(op, V.OPERATOR);
        assertEq(at1, at0);
        assertEq(exp1, uint64(block.timestamp) * 1000 + TTL);
        assertEq(next, 5);
        assertEq(reg.getRegistrationQuote(V.KEY_HASH), q2);
    }

    function test_register_refreshAfterExpiryKeepsOwner() public {
        _register();
        vm.warp(block.timestamp + TTL / 1000 + 10);
        _approve(V.OTHER, "org-b");
        vm.prank(V.OTHER);
        vm.expectRevert(PlrRegistry.E_UNAUTHORIZED.selector);
        reg.registerInstance(V.X25519, V.ED25519, V.COMPOSE_HASH, V.OS_MEASUREMENT, V.QUOTE_OTHER);
        vm.prank(V.OPERATOR);
        reg.registerInstance(V.X25519, V.ED25519, V.COMPOSE_HASH, V.OS_MEASUREMENT, V.QUOTE);
        assertGt(_expires(), uint64(block.timestamp) * 1000);
    }

    /// A squatter (approved operator) registers an honest instance's public key hash with an unsigned quote bound to
    /// itself. While it stays approved the key is its (expiry does not free it); once the owner revokes it, the honest
    /// operator takes the key over as a fresh record.
    function test_register_ownerRevocationFreesSquattedKey() public {
        _allowBuild();
        _approve(V.OTHER, "org-squat");
        vm.prank(V.OTHER);
        reg.registerInstance(V.X25519, V.ED25519, V.COMPOSE_HASH, V.OS_MEASUREMENT, V.QUOTE_OTHER);
        vm.prank(V.OTHER);
        reg.anchorReceipts(V.KEY_HASH, V.ANCHOR_ROOT, 0, 7, _sig());
        _approve(V.OPERATOR, "org-a");
        vm.prank(V.OPERATOR);
        vm.expectRevert(PlrRegistry.E_UNAUTHORIZED.selector);
        reg.registerInstance(V.X25519, V.ED25519, V.COMPOSE_HASH, V.OS_MEASUREMENT, V.QUOTE);
        vm.warp(block.timestamp + 2 days);
        vm.prank(V.OPERATOR);
        vm.expectRevert(PlrRegistry.E_UNAUTHORIZED.selector);
        reg.registerInstance(V.X25519, V.ED25519, V.COMPOSE_HASH, V.OS_MEASUREMENT, V.QUOTE);

        vm.prank(owner);
        reg.revokeOperator(V.OTHER);
        vm.warp(block.timestamp + 60);
        vm.prank(V.OPERATOR);
        reg.registerInstance(V.X25519, V.ED25519, V.COMPOSE_HASH, V.OS_MEASUREMENT, V.QUOTE);
        (bool exists,,,,, address op, uint64 at, uint64 exp, uint64 next) = reg.getInstance(V.KEY_HASH);
        assertTrue(exists);
        assertEq(op, V.OPERATOR);
        assertEq(at, uint64(block.timestamp) * 1000);
        assertEq(exp, uint64(block.timestamp) * 1000 + TTL);
        assertEq(next, 0);
        assertEq(reg.getRegistrationQuote(V.KEY_HASH), V.QUOTE);
        _anchor(0, 1);
        // the revoked squatter cannot refresh or anchor; re-approving it does not give the key back
        vm.prank(V.OTHER);
        vm.expectRevert(PlrRegistry.E_OPERATOR_UNAPPROVED.selector);
        reg.registerInstance(V.X25519, V.ED25519, V.COMPOSE_HASH, V.OS_MEASUREMENT, V.QUOTE_OTHER);
        _approve(V.OTHER, "org-squat");
        vm.prank(V.OTHER);
        vm.expectRevert(PlrRegistry.E_UNAUTHORIZED.selector);
        reg.registerInstance(V.X25519, V.ED25519, V.COMPOSE_HASH, V.OS_MEASUREMENT, V.QUOTE_OTHER);
        vm.prank(V.OTHER);
        vm.expectRevert(PlrRegistry.E_UNAUTHORIZED.selector);
        reg.anchorReceipts(V.KEY_HASH, V.ANCHOR_ROOT, 1, 1, _sig());
    }

    function test_unknownInstance() public view {
        (bool exists,,,,, address op,,,) = reg.getInstance(V.KEY_HASH);
        assertFalse(exists);
        assertEq(op, address(0));
        assertEq(reg.getRegistrationQuote(V.KEY_HASH).length, 0);
    }

    // ------------------------------------------------------------------ anchors

    function test_anchor_happyPathContiguous() public {
        _register();
        _allowBuild();
        uint64 nowMs = uint64(block.timestamp) * 1000;
        vm.expectEmit(true, true, false, true, address(reg));
        emit PlrRegistry.ReceiptsAnchored(0, V.KEY_HASH, V.ANCHOR_ROOT, 0, 3, nowMs, _sig());
        _anchor(0, 3);
        _anchor(3, 10_000);
        assertEq(reg.anchorCount(), 2);
        assertEq(_nextSeq(), 10_003);
        (bytes32 kh, bytes32 root, uint64 first, uint64 count, uint64 at, bytes memory sig) = reg.getAnchor(1);
        assertEq(kh, V.KEY_HASH);
        assertEq(root, V.ANCHOR_ROOT);
        assertEq(first, 3);
        assertEq(count, 10_000);
        assertEq(at, nowMs);
        assertEq(sig, _sig());
        vm.expectRevert(PlrRegistry.E_BAD_INPUT.selector);
        reg.getAnchor(2);
    }

    function test_anchor_unregisteredOrExpired() public {
        _allowBuild();
        vm.expectRevert(PlrRegistry.E_INSTANCE_NOT_REGISTERED.selector);
        _anchor(0, 1);
        _register();
        vm.warp(block.timestamp + TTL / 1000);
        vm.expectRevert(PlrRegistry.E_INSTANCE_NOT_REGISTERED.selector);
        _anchor(0, 1);
    }

    function test_anchor_onlyOperator() public {
        _register();
        _allowBuild();
        _approve(V.OTHER, "org-a");
        vm.prank(V.OTHER);
        vm.expectRevert(PlrRegistry.E_UNAUTHORIZED.selector);
        reg.anchorReceipts(V.KEY_HASH, V.ANCHOR_ROOT, 0, 1, _sig());
        vm.prank(owner);
        vm.expectRevert(PlrRegistry.E_UNAUTHORIZED.selector);
        reg.anchorReceipts(V.KEY_HASH, V.ANCHOR_ROOT, 0, 1, _sig());
    }

    function test_anchor_policyLive() public {
        _register();
        vm.expectRevert(PlrRegistry.E_COMPOSE_NOT_ALLOWED.selector);
        _anchor(0, 1);
        vm.prank(owner);
        reg.allowCompose(V.COMPOSE_HASH);
        vm.expectRevert(PlrRegistry.E_OS_NOT_ALLOWED.selector);
        _anchor(0, 1);
        vm.prank(owner);
        reg.allowOs(V.OS_MEASUREMENT);
        _anchor(0, 1);
        vm.prank(owner);
        reg.revokeCompose(V.COMPOSE_HASH);
        vm.expectRevert(PlrRegistry.E_COMPOSE_NOT_ALLOWED.selector);
        _anchor(1, 1);
    }

    function test_anchor_seqAndCount() public {
        _register();
        _allowBuild();
        vm.expectRevert(PlrRegistry.E_SEQ.selector);
        _anchor(0, 0);
        vm.expectRevert(PlrRegistry.E_SEQ.selector);
        _anchor(0, 10_001);
        vm.expectRevert(PlrRegistry.E_SEQ.selector);
        _anchor(1, 1); // gap
        _anchor(0, 2);
        vm.expectRevert(PlrRegistry.E_SEQ.selector);
        _anchor(0, 2); // replay
        vm.expectRevert(PlrRegistry.E_SEQ.selector);
        _anchor(1, 1); // overlap
        _anchor(2, 1);
        assertEq(_nextSeq(), 3);
    }

    function test_anchor_sigLength() public {
        _register();
        _allowBuild();
        vm.startPrank(V.OPERATOR);
        vm.expectRevert(PlrRegistry.E_BAD_INPUT.selector);
        reg.anchorReceipts(V.KEY_HASH, V.ANCHOR_ROOT, 0, 1, new bytes(63));
        vm.expectRevert(PlrRegistry.E_BAD_INPUT.selector);
        reg.anchorReceipts(V.KEY_HASH, V.ANCHOR_ROOT, 0, 1, new bytes(65));
        vm.stopPrank();
    }

    // ------------------------------------------------------------------ misc

    function test_codeSizeUnderEip170() public view {
        assertLt(address(reg).code.length, 24_576);
    }

    function testFuzz_orgIdMatchesRegex(bytes calldata s) public {
        vm.assume(s.length <= 70);
        bool ok = s.length >= 1 && s.length <= 64;
        for (uint256 i = 0; ok && i < s.length; i++) {
            bytes1 c = s[i];
            bool alnum = (c >= "a" && c <= "z") || (c >= "0" && c <= "9");
            ok = i == 0 ? alnum : (alnum || c == "." || c == "_" || c == "-");
        }
        vm.prank(owner);
        if (!ok) vm.expectRevert(PlrRegistry.E_BAD_INPUT.selector);
        reg.approveOperator(V.OPERATOR, string(s));
    }
}
