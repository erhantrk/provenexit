//! Key binding and signed-message layouts (SPEC §5, §7). Mirrors `packages/shared/src/tdx/measure.ts` and
//! `anchorMessage` in `packages/shared/src/receipts/receipt.ts`.

use crate::hash::sha256_concat;

/// `utf8("PLR-v1")`
pub const DOMAIN: &[u8] = b"PLR-v1";
pub const REGISTER_LABEL: &[u8] = b"PLR-v1/register";
pub const ANCHOR_LABEL: &[u8] = b"PLR-v1/anchor";
/// `utf8("PLR-MOCK-AK-v1")` — prefix of the root's AK certificate message (SPEC §2.3).
pub const MOCK_AK_CERT_PREFIX: &[u8] = b"PLR-MOCK-AK-v1";

/// `SHA256(DOMAIN ‖ x25519 ‖ ed25519)`
pub fn key_hash(x25519: &[u8; 32], ed25519: &[u8; 32]) -> [u8; 32] {
    sha256_concat(&[DOMAIN, x25519, ed25519])
}

/// `SHA256(utf8("PLR-v1/register") ‖ utf8(contract_id))`
pub fn registration_nonce(contract_id: &str) -> [u8; 32] {
    sha256_concat(&[REGISTER_LABEL, contract_id.as_bytes()])
}

/// `key_hash(x25519, ed25519) ‖ registration_nonce(contract_id)` — the only report_data a registration accepts.
pub fn registration_report_data(x25519: &[u8; 32], ed25519: &[u8; 32], contract_id: &str) -> [u8; 64] {
    let mut rd = [0u8; 64];
    rd[..32].copy_from_slice(&key_hash(x25519, ed25519));
    rd[32..].copy_from_slice(&registration_nonce(contract_id));
    rd
}

/// `utf8("PLR-MOCK-AK-v1") ‖ ak_pub`
pub fn ak_cert_message(ak_pub: &[u8; 64]) -> Vec<u8> {
    [MOCK_AK_CERT_PREFIX, ak_pub].concat()
}

/// `utf8("PLR-v1/anchor") ‖ utf8(contract_id) ‖ key_hash ‖ root ‖ u64be(first_seq) ‖ u64be(count)`
pub fn anchor_message(contract_id: &str, key_hash: &[u8; 32], root: &[u8; 32], first_seq: u64, count: u64) -> Vec<u8> {
    [ANCHOR_LABEL, contract_id.as_bytes(), key_hash, root, &first_seq.to_be_bytes(), &count.to_be_bytes()].concat()
}
