//! Hash primitives: SHA-256 via the NEAR host (pure Rust off-chain), SHA-384 via the `sha2` crate (no host fn).

use sha2::{Digest, Sha384};

pub fn sha256(data: &[u8]) -> [u8; 32] {
    near_sdk::env::sha256_array(data)
}

/// SHA-256 over the concatenation of `parts` (no intermediate allocation by the caller).
pub fn sha256_concat(parts: &[&[u8]]) -> [u8; 32] {
    let mut buf = Vec::with_capacity(parts.iter().map(|p| p.len()).sum());
    for p in parts {
        buf.extend_from_slice(p);
    }
    sha256(&buf)
}

/// SHA-384 over the concatenation of `parts`.
pub fn sha384_concat(parts: &[&[u8]]) -> [u8; 48] {
    let mut h = Sha384::new();
    for p in parts {
        h.update(p);
    }
    h.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bytes::encode_hex;

    #[test]
    fn known_answers() {
        assert_eq!(
            encode_hex(&sha256(b"abc")),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(sha256_concat(&[b"a", b"bc"]), sha256(b"abc"));
        assert_eq!(
            encode_hex(&sha384_concat(&[b"a", b"", b"bc"])),
            "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7"
        );
    }
}
