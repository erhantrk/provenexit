//! Key binding and signed-message layouts (SPEC §5, §7). Mirrors `packages/shared/src/tdx/measure.ts` and
//! `anchorMessage` in `packages/shared/src/receipts/receipt.ts`.

use crate::hash::sha256_concat;

/// `utf8("PLR-v1")`
pub const DOMAIN: &[u8] = b"PLR-v1";
/// Domain of the operator-bound registration nonce (SPEC §5 rev 1.3). The rev 1.2 label `PLR-v1/register`
/// (contract id only) is no longer accepted.
pub const REGISTER_LABEL: &[u8] = b"PLR-v1/register/2";
/// Longest contract / operator account id the nonce encodes (NEAR account id limit; SPEC §5 rev 1.3).
pub const MAX_ACCOUNT_ID_BYTES: usize = 64;
pub const ANCHOR_LABEL: &[u8] = b"PLR-v1/anchor";
/// `utf8("PLR-MOCK-AK-v1")` — prefix of the root's AK certificate message (SPEC §2.3).
pub const MOCK_AK_CERT_PREFIX: &[u8] = b"PLR-MOCK-AK-v1";

/// `SHA256(DOMAIN ‖ x25519 ‖ ed25519)`
pub fn key_hash(x25519: &[u8; 32], ed25519: &[u8; 32]) -> [u8; 32] {
    sha256_concat(&[DOMAIN, x25519, ed25519])
}

/// Operator-bound registration nonce (SPEC §5 rev 1.3):
/// `SHA256(utf8("PLR-v1/register/2") ‖ u8(len c) ‖ c ‖ u8(len o) ‖ o)`, c = registry contract account id,
/// o = operator account id. The length prefixes make the (contract, operator) split unambiguous.
/// `None` unless both ids are 1..=64 bytes (a NEAR `AccountId` always is; fail closed otherwise).
pub fn registration_nonce(contract_id: &str, operator_id: &str) -> Option<[u8; 32]> {
    let (c, o) = (contract_id.as_bytes(), operator_id.as_bytes());
    let len_ok = |b: &[u8]| (1..=MAX_ACCOUNT_ID_BYTES).contains(&b.len());
    if !len_ok(c) || !len_ok(o) {
        return None;
    }
    // Both lengths are ≤ 64, so they fit a u8.
    Some(sha256_concat(&[REGISTER_LABEL, &[c.len() as u8], c, &[o.len() as u8], o]))
}

/// `key_hash(x25519, ed25519) ‖ registration_nonce(contract_id, operator_id)` — the only report_data a
/// registration submitted by `operator_id` to `contract_id` accepts. `None` as for [`registration_nonce`].
pub fn registration_report_data(x25519: &[u8; 32], ed25519: &[u8; 32], contract_id: &str, operator_id: &str) -> Option<[u8; 64]> {
    let nonce = registration_nonce(contract_id, operator_id)?;
    let mut rd = [0u8; 64];
    rd[..32].copy_from_slice(&key_hash(x25519, ed25519));
    rd[32..].copy_from_slice(&nonce);
    Some(rd)
}

/// `utf8("PLR-MOCK-AK-v1") ‖ ak_pub`
pub fn ak_cert_message(ak_pub: &[u8; 64]) -> Vec<u8> {
    [MOCK_AK_CERT_PREFIX, ak_pub].concat()
}

/// `utf8("PLR-v1/anchor") ‖ utf8(contract_id) ‖ key_hash ‖ root ‖ u64be(first_seq) ‖ u64be(count)`
pub fn anchor_message(contract_id: &str, key_hash: &[u8; 32], root: &[u8; 32], first_seq: u64, count: u64) -> Vec<u8> {
    [ANCHOR_LABEL, contract_id.as_bytes(), key_hash, root, &first_seq.to_be_bytes(), &count.to_be_bytes()].concat()
}
