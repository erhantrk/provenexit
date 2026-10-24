//! Pure registry rules (SPEC-CHAINS §9 semantics, §11 encoding), independent of accounts so they are unit-tested
//! natively. The processor only loads/stores accounts around these.
use crate::error::PlrError;
use crate::instruction::{MAX_ORG_LEN, QUOTE_LEN};
use crate::state::Instance;
use solana_program::hash::hashv;

/// `utf8("PLR-v1")` — key hash domain (SPEC §5).
pub const DOMAIN: &[u8] = b"PLR-v1";
/// Operator-bound registration nonce domain (SPEC §5 rev 1.3).
pub const REGISTER_LABEL: &[u8] = b"PLR-v1/register/2";
pub const MAX_ID_BYTES: usize = 64;
pub const MAX_ANCHOR_COUNT: u64 = 10_000;

pub const QUOTE_VERSION: u16 = 4;
pub const ATT_KEY_TYPE_ECDSA_P256: u16 = 2;
pub const TEE_TYPE_TDX: u32 = 0x81;
pub const REPORT_DATA_OFF: usize = 568;

pub const ROOT_MOCK: u8 = 1;
pub const ROOT_INTEL: u8 = 2;

pub fn is_zero(h: &[u8]) -> bool {
    h.iter().all(|b| *b == 0)
}

/// Rejects the all-zero hash (`E_ZERO_HASH`).
pub fn nonzero(h: &[u8; 32]) -> Result<(), PlrError> {
    if is_zero(h) {
        Err(PlrError::E_ZERO_HASH)
    } else {
        Ok(())
    }
}

/// `SHA256("PLR-v1" ‖ x25519 ‖ ed25519)` (sha256 syscall on-chain).
pub fn key_hash(x25519: &[u8; 32], ed25519: &[u8; 32]) -> [u8; 32] {
    hashv(&[DOMAIN, x25519, ed25519]).to_bytes()
}

/// `SHA256("PLR-v1/register/2" ‖ u8(len c) ‖ c ‖ u8(len o) ‖ o)`; None unless both ids are 1..=64 bytes.
pub fn registration_nonce(contract_id: &[u8], operator_id: &[u8]) -> Option<[u8; 32]> {
    let ok = |b: &[u8]| (1..=MAX_ID_BYTES).contains(&b.len());
    if !ok(contract_id) || !ok(operator_id) {
        return None;
    }
    Some(hashv(&[REGISTER_LABEL, &[contract_id.len() as u8], contract_id, &[operator_id.len() as u8], operator_id]).to_bytes())
}

const B58: &[u8; 58] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

/// Bitcoin-alphabet base58 of a 32-byte key (the standard Solana address text). At most 44 chars.
pub fn base58_32(bytes: &[u8; 32]) -> ([u8; 44], usize) {
    let mut digits = [0u8; 44]; // little-endian base-58 digits
    let mut n = 0usize;
    for &b in bytes.iter() {
        let mut carry = b as u32;
        for d in digits.iter_mut().take(n) {
            carry += (*d as u32) << 8;
            *d = (carry % 58) as u8;
            carry /= 58;
        }
        while carry > 0 {
            digits[n] = (carry % 58) as u8;
            n += 1;
            carry /= 58;
        }
    }
    let zeros = bytes.iter().take_while(|b| **b == 0).count();
    let mut out = [0u8; 44];
    let mut len = 0;
    for _ in 0..zeros {
        out[len] = b'1';
        len += 1;
    }
    for i in (0..n).rev() {
        out[len] = B58[digits[i] as usize];
        len += 1;
    }
    (out, len)
}

/// `"solana:" ‖ base58(state)` (SPEC-CHAINS §3), as bytes (≤ 51).
pub fn contract_id(state: &[u8; 32]) -> ([u8; 51], usize) {
    let (b, n) = base58_32(state);
    let mut out = [0u8; 51];
    out[..7].copy_from_slice(b"solana:");
    out[7..7 + n].copy_from_slice(&b[..n]);
    (out, 7 + n)
}

/// SPEC §7 rev 1.2 org id: `^[a-z0-9][a-z0-9._-]{0,63}$`.
pub fn valid_org(org: &[u8]) -> bool {
    let first = |c: u8| c.is_ascii_lowercase() || c.is_ascii_digit();
    !org.is_empty() && org.len() <= MAX_ORG_LEN && first(org[0]) && org[1..].iter().all(|&c| first(c) || c == b'.' || c == b'_' || c == b'-')
}

pub fn valid_root_kind(k: u8) -> bool {
    k == ROOT_MOCK || k == ROOT_INTEL
}

/// Registration-quote checks of §9: format (`E_QUOTE_FORMAT`), then `report_data == key_hash ‖ registration nonce`
/// (`E_REPORT_DATA`). The quote signature is NOT verified on-chain (tier B; clients verify it).
pub fn check_quote(quote: &[u8], key_hash: &[u8; 32], nonce: &[u8; 32]) -> Result<(), PlrError> {
    if quote.len() != QUOTE_LEN {
        return Err(PlrError::E_QUOTE_FORMAT);
    }
    let u16le = |o: usize| u16::from_le_bytes([quote[o], quote[o + 1]]);
    let u32le = |o: usize| u32::from_le_bytes([quote[o], quote[o + 1], quote[o + 2], quote[o + 3]]);
    if u16le(0) != QUOTE_VERSION || u16le(2) != ATT_KEY_TYPE_ECDSA_P256 || u32le(4) != TEE_TYPE_TDX {
        return Err(PlrError::E_QUOTE_FORMAT);
    }
    if quote[REPORT_DATA_OFF..REPORT_DATA_OFF + 32] != key_hash[..] || quote[REPORT_DATA_OFF + 32..REPORT_DATA_OFF + 64] != nonce[..] {
        return Err(PlrError::E_REPORT_DATA);
    }
    Ok(())
}

/// Inputs of a registration (after the operator-approval and quote checks).
pub struct Registration {
    pub x25519: [u8; 32],
    pub ed25519: [u8; 32],
    pub compose: [u8; 32],
    pub os: [u8; 32],
    pub operator: [u8; 32],
}

/// New / refreshed instance record: the first registrant of a key owns it while the owner approves that operator
/// (others ⇒ `E_UNAUTHORIZED`); a re-registration by that operator refreshes the expiry (and measurements; the quote
/// is replaced by the caller), keeping `next_seq`. Once the owner revokes the record's operator
/// (`existing_operator_approved == false`, SPEC-CHAINS §1: tier B accepts records only from live-approved operators),
/// another approved operator may take the key over as a fresh record (`next_seq` 0) — the owner's remedy against a
/// squatter that registered someone else's public key hash with an unsigned quote.
pub fn register(existing: Option<&Instance>, existing_operator_approved: bool, r: &Registration, now_ms: u64, ttl_ms: u64) -> Result<Instance, PlrError> {
    nonzero(&r.compose)?;
    nonzero(&r.os)?;
    let expires = now_ms.checked_add(ttl_ms).ok_or(PlrError::E_BAD_INPUT)?;
    let next_seq = match existing {
        Some(e) if e.operator != r.operator && !existing_operator_approved => 0,
        Some(e) => {
            if e.operator != r.operator || e.x25519 != r.x25519 || e.ed25519 != r.ed25519 {
                return Err(PlrError::E_UNAUTHORIZED);
            }
            e.next_seq
        }
        None => 0,
    };
    Ok(Instance {
        x25519: r.x25519,
        ed25519: r.ed25519,
        compose: r.compose,
        os: r.os,
        operator: r.operator,
        registered_at_ms: now_ms,
        expires_at_ms: expires,
        next_seq,
    })
}

/// Anchor rules of §9: instance exists and is unexpired, signer is its operator, compose and OS still allowed,
/// `first_seq == next_seq`, `1 ≤ count ≤ 10 000`. Returns the new `next_seq`.
pub fn anchor(inst: Option<&Instance>, signer: &[u8; 32], now_ms: u64, compose_allowed: bool, os_allowed: bool, first_seq: u64, count: u64) -> Result<u64, PlrError> {
    let i = inst.ok_or(PlrError::E_INSTANCE_NOT_REGISTERED)?;
    if now_ms >= i.expires_at_ms {
        return Err(PlrError::E_INSTANCE_NOT_REGISTERED);
    }
    if &i.operator != signer {
        return Err(PlrError::E_UNAUTHORIZED);
    }
    if !compose_allowed || !os_allowed {
        return Err(PlrError::E_COMPOSE_NOT_ALLOWED);
    }
    if !(1..=MAX_ANCHOR_COUNT).contains(&count) {
        return Err(PlrError::E_BAD_INPUT);
    }
    if first_seq != i.next_seq {
        return Err(PlrError::E_SEQ);
    }
    i.next_seq.checked_add(count).ok_or(PlrError::E_SEQ)
}

/// Clock `unix_timestamp` (s) → ms (`E_BAD_INPUT` if negative / overflowing).
pub fn clock_ms(unix_timestamp: i64) -> Result<u64, PlrError> {
    u64::try_from(unix_timestamp).ok().and_then(|s| s.checked_mul(1000)).ok_or(PlrError::E_BAD_INPUT)
}
