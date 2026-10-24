//! Account layouts (all little-endian, fixed size; byte 0 is the account kind tag). Readers (client/src/chains/solana.ts,
//! enclave/src/chains/solana.ts) decode exactly these offsets.
//!
//! | account | seeds | layout |
//! |---|---|---|
//! | state | (keypair, created by `Init`) | tag=1 ‖ owner 32 ‖ has_pending u8 ‖ pending_owner 32 ‖ root_kind u8 ‖ root_p256 64 ‖ ttl_ms u64 ‖ anchor_count u64 |
//! | compose | `["compose", state, hash]` | tag=2 ‖ allowed u8 |
//! | os | `["os", state, hash]` | tag=3 ‖ allowed u8 |
//! | operator | `["op", state, operator]` | tag=4 ‖ approved u8 ‖ org_len u8 ‖ org 64 (zero padded) |
//! | instance | `["inst", state, key_hash]` | tag=5 ‖ x25519 32 ‖ ed25519 32 ‖ compose 32 ‖ os 32 ‖ operator 32 ‖ registered_at_ms u64 ‖ expires_at_ms u64 ‖ next_seq u64 ‖ quote 828 |
//! | anchor | `["anchor", state, u64le(id)]` | tag=6 ‖ key_hash 32 ‖ root 32 ‖ first_seq u64 ‖ count u64 ‖ at_ms u64 ‖ sig 64 |
use crate::error::PlrError;
use crate::instruction::{MAX_ORG_LEN, QUOTE_LEN};

pub const TAG_STATE: u8 = 1;
pub const TAG_COMPOSE: u8 = 2;
pub const TAG_OS: u8 = 3;
pub const TAG_OPERATOR: u8 = 4;
pub const TAG_INSTANCE: u8 = 5;
pub const TAG_ANCHOR: u8 = 6;

pub const STATE_LEN: usize = 1 + 32 + 1 + 32 + 1 + 64 + 8 + 8;
pub const ITEM_LEN: usize = 2;
pub const OPERATOR_LEN: usize = 1 + 1 + 1 + MAX_ORG_LEN;
pub const INSTANCE_LEN: usize = 1 + 32 * 5 + 8 * 3 + QUOTE_LEN;
pub const ANCHOR_LEN: usize = 1 + 32 + 32 + 8 * 3 + 64;

pub const SEED_COMPOSE: &[u8] = b"compose";
pub const SEED_OS: &[u8] = b"os";
pub const SEED_OPERATOR: &[u8] = b"op";
pub const SEED_INSTANCE: &[u8] = b"inst";
pub const SEED_ANCHOR: &[u8] = b"anchor";

fn arr<const N: usize>(b: &[u8], o: usize) -> [u8; N] {
    let mut a = [0u8; N];
    a.copy_from_slice(&b[o..o + N]);
    a
}
fn u64_at(b: &[u8], o: usize) -> u64 {
    u64::from_le_bytes(arr::<8>(b, o))
}

/// Exact-size, right-tag check (a wrong kind of account is never misread).
fn check(b: &[u8], len: usize, tag: u8) -> Result<(), PlrError> {
    if b.len() != len || b[0] != tag {
        return Err(PlrError::E_BAD_INPUT);
    }
    Ok(())
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct State {
    pub owner: [u8; 32],
    pub pending_owner: Option<[u8; 32]>,
    pub root_kind: u8,
    pub root_p256: [u8; 64],
    pub ttl_ms: u64,
    pub anchor_count: u64,
}

impl State {
    pub fn unpack(b: &[u8]) -> Result<Self, PlrError> {
        check(b, STATE_LEN, TAG_STATE)?;
        let pending = match b[33] {
            0 => None,
            1 => Some(arr::<32>(b, 34)),
            _ => return Err(PlrError::E_BAD_INPUT),
        };
        Ok(State { owner: arr(b, 1), pending_owner: pending, root_kind: b[66], root_p256: arr(b, 67), ttl_ms: u64_at(b, 131), anchor_count: u64_at(b, 139) })
    }
    pub fn pack(&self, b: &mut [u8]) {
        b[0] = TAG_STATE;
        b[1..33].copy_from_slice(&self.owner);
        b[33] = self.pending_owner.is_some() as u8;
        b[34..66].copy_from_slice(&self.pending_owner.unwrap_or([0; 32]));
        b[66] = self.root_kind;
        b[67..131].copy_from_slice(&self.root_p256);
        b[131..139].copy_from_slice(&self.ttl_ms.to_le_bytes());
        b[139..147].copy_from_slice(&self.anchor_count.to_le_bytes());
    }
}

/// Compose / OS allowlist entry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Item {
    pub allowed: bool,
}

impl Item {
    pub fn unpack(b: &[u8], tag: u8) -> Result<Self, PlrError> {
        check(b, ITEM_LEN, tag)?;
        match b[1] {
            0 | 1 => Ok(Item { allowed: b[1] == 1 }),
            _ => Err(PlrError::E_BAD_INPUT),
        }
    }
    pub fn pack(&self, b: &mut [u8], tag: u8) {
        b[0] = tag;
        b[1] = self.allowed as u8;
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Operator {
    /// Empty = unapproved (revoked).
    pub org: Vec<u8>,
}

impl Operator {
    pub fn unpack(b: &[u8]) -> Result<Self, PlrError> {
        check(b, OPERATOR_LEN, TAG_OPERATOR)?;
        let (approved, n) = (b[1], b[2] as usize);
        if approved > 1 || n > MAX_ORG_LEN || (approved == 1) != (n > 0) {
            return Err(PlrError::E_BAD_INPUT);
        }
        Ok(Operator { org: b[3..3 + n].to_vec() })
    }
    pub fn pack(&self, b: &mut [u8]) {
        b[0] = TAG_OPERATOR;
        b[1] = !self.org.is_empty() as u8;
        b[2] = self.org.len() as u8;
        b[3..].fill(0);
        b[3..3 + self.org.len()].copy_from_slice(&self.org);
    }
    pub fn approved(&self) -> bool {
        !self.org.is_empty()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Instance {
    pub x25519: [u8; 32],
    pub ed25519: [u8; 32],
    pub compose: [u8; 32],
    pub os: [u8; 32],
    pub operator: [u8; 32],
    pub registered_at_ms: u64,
    pub expires_at_ms: u64,
    pub next_seq: u64,
}

/// Offset of the stored registration quote inside an instance account (`QUOTE_LEN` bytes, after the header that
/// [`Instance`] packs; kept out of the struct so the 4 KiB SBF stack never holds copies of it).
pub const QUOTE_OFF: usize = 185;

impl Instance {
    /// The stored registration quote of a (checked) instance account.
    pub fn quote(b: &[u8]) -> Result<&[u8], PlrError> {
        check(b, INSTANCE_LEN, TAG_INSTANCE)?;
        Ok(&b[QUOTE_OFF..QUOTE_OFF + QUOTE_LEN])
    }
    pub fn unpack(b: &[u8]) -> Result<Self, PlrError> {
        check(b, INSTANCE_LEN, TAG_INSTANCE)?;
        Ok(Instance {
            x25519: arr(b, 1),
            ed25519: arr(b, 33),
            compose: arr(b, 65),
            os: arr(b, 97),
            operator: arr(b, 129),
            registered_at_ms: u64_at(b, 161),
            expires_at_ms: u64_at(b, 169),
            next_seq: u64_at(b, 177),
        })
    }
    pub fn pack(&self, b: &mut [u8]) {
        b[0] = TAG_INSTANCE;
        b[1..33].copy_from_slice(&self.x25519);
        b[33..65].copy_from_slice(&self.ed25519);
        b[65..97].copy_from_slice(&self.compose);
        b[97..129].copy_from_slice(&self.os);
        b[129..161].copy_from_slice(&self.operator);
        b[161..169].copy_from_slice(&self.registered_at_ms.to_le_bytes());
        b[169..177].copy_from_slice(&self.expires_at_ms.to_le_bytes());
        b[177..185].copy_from_slice(&self.next_seq.to_le_bytes());
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Anchor {
    pub key_hash: [u8; 32],
    pub root: [u8; 32],
    pub first_seq: u64,
    pub count: u64,
    pub at_ms: u64,
    pub sig: [u8; 64],
}

impl Anchor {
    pub fn unpack(b: &[u8]) -> Result<Self, PlrError> {
        check(b, ANCHOR_LEN, TAG_ANCHOR)?;
        Ok(Anchor { key_hash: arr(b, 1), root: arr(b, 33), first_seq: u64_at(b, 65), count: u64_at(b, 73), at_ms: u64_at(b, 81), sig: arr(b, 89) })
    }
    pub fn pack(&self, b: &mut [u8]) {
        b[0] = TAG_ANCHOR;
        b[1..33].copy_from_slice(&self.key_hash);
        b[33..65].copy_from_slice(&self.root);
        b[65..73].copy_from_slice(&self.first_seq.to_le_bytes());
        b[73..81].copy_from_slice(&self.count.to_le_bytes());
        b[81..89].copy_from_slice(&self.at_ms.to_le_bytes());
        b[89..153].copy_from_slice(&self.sig);
    }
}
