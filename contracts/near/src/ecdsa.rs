//! ECDSA-P256-SHA256 verification for the MOCK attestation chain (SPEC §2.3, §7 NEAR notes).
//!
//! The NEAR host `p256_verify` takes a SHA-256 prehash and a 33-byte compressed key, and accepts high-S
//! signatures. This module therefore (a) validates `r`/`s` ranges and enforces low-S itself, (b) checks that the
//! 64-byte `x‖y` key is a valid curve point before compressing it (compression alone would silently map an
//! off-curve `y` to the real point with the same parity).

use near_sdk::env;
use p256::elliptic_curve::sec1::FromEncodedPoint;

use crate::hash::sha256;

/// P-256 group order n (big-endian).
pub const N: [u8; 32] = [
    0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xbc, 0xe6,
    0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84, 0xf3, 0xb9, 0xca, 0xc2, 0xfc, 0x63, 0x25, 0x51,
];
/// floor(n / 2) (big-endian). Low-S means `s <= HALF_N`.
pub const HALF_N: [u8; 32] = [
    0x7f, 0xff, 0xff, 0xff, 0x80, 0x00, 0x00, 0x00, 0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xde, 0x73,
    0x7d, 0x56, 0xd3, 0x8b, 0xcf, 0x42, 0x79, 0xdc, 0xe5, 0x61, 0x7e, 0x31, 0x92, 0xa8,
];

/// `r ∈ [1, n-1]` and `s ∈ [1, n/2]` (big-endian arrays compare numerically). Public data: no constant time needed.
pub fn is_canonical_low_s(sig: &[u8; 64]) -> bool {
    let r = &sig[..32];
    let s = &sig[32..];
    let zero = [0u8; 32];
    r != zero && r < &N[..] && s != zero && s <= &HALF_N[..]
}

/// True if `x‖y` is an affine point on P-256 with both coordinates < p (the identity has no such encoding).
pub fn is_valid_pub(pub64: &[u8; 64]) -> bool {
    let ep = p256::EncodedPoint::from_affine_coordinates((&pub64[..32]).into(), (&pub64[32..]).into(), false);
    bool::from(p256::AffinePoint::from_encoded_point(&ep).is_some())
}

/// SEC1 compressed encoding: `0x02 | (y & 1)` ‖ x.
pub fn compress(pub64: &[u8; 64]) -> [u8; 33] {
    let mut out = [0u8; 33];
    out[0] = 0x02 | (pub64[63] & 1);
    out[1..].copy_from_slice(&pub64[..32]);
    out
}

/// Verifies a 64-byte `r‖s` ECDSA-P256-SHA256 signature over `msg` under a 64-byte `x‖y` key.
/// Rejects high-S, out-of-range scalars and invalid keys. Never panics.
pub fn verify_low_s(sig: &[u8; 64], msg: &[u8], pub64: &[u8; 64]) -> bool {
    if !is_canonical_low_s(sig) || !is_valid_pub(pub64) {
        return false;
    }
    env::p256_verify(sig, &sha256(msg), &compress(pub64))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bytes::decode_hex_array;

    #[test]
    fn half_n_is_floor_n_over_2() {
        // HALF_N * 2 + 1 == N
        let mut acc = [0u8; 32];
        let mut carry = 1u16;
        for i in (0..32).rev() {
            let v = (HALF_N[i] as u16) * 2 + carry;
            acc[i] = (v & 0xff) as u8;
            carry = v >> 8;
        }
        assert_eq!(carry, 0);
        assert_eq!(acc, N);
    }

    #[test]
    fn scalar_ranges() {
        let mut sig = [0u8; 64];
        sig[31] = 1;
        sig[63] = 1;
        assert!(is_canonical_low_s(&sig));
        sig[32..].copy_from_slice(&HALF_N);
        assert!(is_canonical_low_s(&sig));
        sig[63] = sig[63].wrapping_add(1); // HALF_N + 1
        assert!(!is_canonical_low_s(&sig));
        sig[32..].copy_from_slice(&[0u8; 32]);
        assert!(!is_canonical_low_s(&sig), "s = 0");
        sig[63] = 1;
        sig[..32].copy_from_slice(&N);
        assert!(!is_canonical_low_s(&sig), "r = n");
        sig[..32].copy_from_slice(&[0u8; 32]);
        assert!(!is_canonical_low_s(&sig), "r = 0");
        sig[..32].copy_from_slice(&[0xff; 32]);
        assert!(!is_canonical_low_s(&sig), "r > n");
    }

    #[test]
    fn point_validation_and_compression() {
        // The P-256 generator G.
        let g: [u8; 64] = decode_hex_array(
            "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296\
             4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5",
        )
        .unwrap();
        assert!(is_valid_pub(&g));
        let c = compress(&g);
        assert_eq!(c[0], 0x03); // y is odd
        assert_eq!(&c[1..], &g[..32]);
        let mut bad = g;
        bad[63] ^= 0x02; // same parity, off-curve
        assert!(!is_valid_pub(&bad));
        assert!(!is_valid_pub(&[0u8; 64]));
        assert!(!is_valid_pub(&[0xff; 64]), "coordinates >= p");
        let mut even = g;
        even[63] &= 0xfe;
        assert_eq!(compress(&even)[0], 0x02);
    }
}
