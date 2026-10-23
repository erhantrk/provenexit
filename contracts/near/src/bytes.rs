//! Strict hex codec (SPEC notation: lowercase, no `0x`, even length) and constant-time byte helpers.

/// Decodes one lowercase hex digit.
#[inline]
fn nibble(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        _ => None,
    }
}

/// Strict decode into `out`; `s` must be exactly `2 * out.len()` lowercase hex chars.
fn decode_into(s: &str, out: &mut [u8]) -> bool {
    let b = s.as_bytes();
    if b.len() != out.len() * 2 {
        return false;
    }
    for (i, o) in out.iter_mut().enumerate() {
        match (nibble(b[2 * i]), nibble(b[2 * i + 1])) {
            (Some(hi), Some(lo)) => *o = (hi << 4) | lo,
            _ => return false,
        }
    }
    true
}

/// Strict decode of any even-length lowercase hex string.
pub fn decode_hex(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    let mut out = vec![0u8; s.len() / 2];
    decode_into(s, &mut out).then_some(out)
}

/// Strict decode of exactly `N` bytes.
pub fn decode_hex_array<const N: usize>(s: &str) -> Option<[u8; N]> {
    let mut out = [0u8; N];
    decode_into(s, &mut out).then_some(out)
}

/// Lowercase hex encoding.
pub fn encode_hex(b: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(b.len() * 2);
    for &x in b {
        s.push(DIGITS[(x >> 4) as usize] as char);
        s.push(DIGITS[(x & 0x0f) as usize] as char);
    }
    s
}

/// Constant-time (length-public) equality.
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    // Avoid an early-exit comparison the optimiser could reintroduce on `diff`.
    core::hint::black_box(diff) == 0
}

/// Constant-time all-zero check.
pub fn is_all_zero(a: &[u8]) -> bool {
    let mut acc = 0u8;
    for &x in a {
        acc |= x;
    }
    core::hint::black_box(acc) == 0
}

/// Copies `N` bytes at `off` out of `b`. Callers guarantee bounds (checked lengths only).
pub fn array_at<const N: usize>(b: &[u8], off: usize) -> [u8; N] {
    let mut out = [0u8; N];
    out.copy_from_slice(&b[off..off + N]);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_roundtrip_and_strictness() {
        assert_eq!(decode_hex("00ff10ab").unwrap(), vec![0x00, 0xff, 0x10, 0xab]);
        assert_eq!(encode_hex(&[0x00, 0xff, 0x10, 0xab]), "00ff10ab");
        assert_eq!(decode_hex("").unwrap(), Vec::<u8>::new());
        for bad in ["0", "abc", "AB", "aB", "0x00", " 0", "0g", "zz", "é0", "\u{0}0"] {
            assert!(decode_hex(bad).is_none(), "{bad:?} must be rejected");
        }
        assert_eq!(decode_hex_array::<2>("beef"), Some([0xbe, 0xef]));
        assert!(decode_hex_array::<2>("bee").is_none());
        assert!(decode_hex_array::<2>("beefee").is_none());
        assert!(decode_hex_array::<2>("BEEF").is_none());
        // Multi-byte UTF-8 whose byte length happens to match must still fail.
        assert!(decode_hex_array::<1>("é").is_none());
    }

    #[test]
    fn ct_helpers() {
        assert!(ct_eq(b"abc", b"abc"));
        assert!(!ct_eq(b"abc", b"abd"));
        assert!(!ct_eq(b"abc", b"ab"));
        assert!(is_all_zero(&[0; 32]));
        assert!(!is_all_zero(&[0, 0, 1]));
        assert!(is_all_zero(&[]));
    }
}
