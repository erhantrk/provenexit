//! Instruction data (SPEC-CHAINS §11): `u8 tag ‖ fields`, fixed-size little-endian, strings u8-length-prefixed.
//! Decoding is strict: unknown tags, short data and trailing bytes are `E_BAD_INPUT`.
//!
//! Accounts per instruction (`s` signer, `w` writable):
//! - `0 Init`              `[state (s,w)]` — `state` already allocated (`STATE_LEN`) and owned by this program
//! - `1..=4 Allow/Revoke`  `[state, owner (s,w: pays), item PDA (w), system_program]`
//! - `5 SetRoot`           `[state (w), owner (s)]`
//! - `6 ApproveOperator`   `[state, owner (s,w: pays), op PDA (w), system_program]`
//! - `7 RevokeOperator`    `[state, owner (s), op PDA (w)]`
//! - `8 ProposeOwner`      `[state (w), owner (s)]`
//! - `9 AcceptOwner`       `[state (w), proposed owner (s)]`
//! - `10 RegisterInstance` `[state, operator (s,w: pays), op PDA, inst PDA (w), system_program]`
//! - `11 AnchorReceipts`   `[state (w), operator (s,w: pays), inst PDA (w), anchor PDA (w), compose PDA, os PDA, system_program]`
use crate::error::PlrError;

pub const QUOTE_LEN: usize = 828;
pub const MAX_ORG_LEN: usize = 64;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RegistryInstruction<'a> {
    Init { owner: [u8; 32], root_kind: u8, root_p256: [u8; 64], ttl_ms: u64 },
    AllowCompose { h: [u8; 32] },
    RevokeCompose { h: [u8; 32] },
    AllowOs { h: [u8; 32] },
    RevokeOs { h: [u8; 32] },
    SetRoot { kind: u8, p256: [u8; 64] },
    ApproveOperator { op: [u8; 32], org: &'a [u8] },
    RevokeOperator { op: [u8; 32] },
    ProposeOwner { next: [u8; 32] },
    AcceptOwner,
    /// `quote` is the rest of the data; the rules require exactly [`QUOTE_LEN`] bytes (else `E_QUOTE_FORMAT`).
    RegisterInstance { x25519: [u8; 32], ed25519: [u8; 32], compose: [u8; 32], os: [u8; 32], quote: &'a [u8] },
    AnchorReceipts { key_hash: [u8; 32], root: [u8; 32], first_seq: u64, count: u64, sig: [u8; 64] },
}

struct Reader<'a> {
    b: &'a [u8],
}

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], PlrError> {
        if self.b.len() < n {
            return Err(PlrError::E_BAD_INPUT);
        }
        let (h, t) = self.b.split_at(n);
        self.b = t;
        Ok(h)
    }
    fn arr<const N: usize>(&mut self) -> Result<[u8; N], PlrError> {
        let mut a = [0u8; N];
        a.copy_from_slice(self.take(N)?);
        Ok(a)
    }
    fn u8(&mut self) -> Result<u8, PlrError> {
        Ok(self.take(1)?[0])
    }
    fn u64(&mut self) -> Result<u64, PlrError> {
        Ok(u64::from_le_bytes(self.arr::<8>()?))
    }
    fn str8(&mut self) -> Result<&'a [u8], PlrError> {
        let n = self.u8()? as usize;
        self.take(n)
    }
    fn rest(&mut self) -> &'a [u8] {
        let r = self.b;
        self.b = &[];
        r
    }
    fn end(&self) -> Result<(), PlrError> {
        if self.b.is_empty() {
            Ok(())
        } else {
            Err(PlrError::E_BAD_INPUT)
        }
    }
}

impl<'a> RegistryInstruction<'a> {
    pub fn tag(&self) -> u8 {
        match self {
            Self::Init { .. } => 0,
            Self::AllowCompose { .. } => 1,
            Self::RevokeCompose { .. } => 2,
            Self::AllowOs { .. } => 3,
            Self::RevokeOs { .. } => 4,
            Self::SetRoot { .. } => 5,
            Self::ApproveOperator { .. } => 6,
            Self::RevokeOperator { .. } => 7,
            Self::ProposeOwner { .. } => 8,
            Self::AcceptOwner => 9,
            Self::RegisterInstance { .. } => 10,
            Self::AnchorReceipts { .. } => 11,
        }
    }

    pub fn decode(data: &'a [u8]) -> Result<Self, PlrError> {
        let mut r = Reader { b: data };
        let ix = match r.u8()? {
            0 => Self::Init { owner: r.arr()?, root_kind: r.u8()?, root_p256: r.arr()?, ttl_ms: r.u64()? },
            1 => Self::AllowCompose { h: r.arr()? },
            2 => Self::RevokeCompose { h: r.arr()? },
            3 => Self::AllowOs { h: r.arr()? },
            4 => Self::RevokeOs { h: r.arr()? },
            5 => Self::SetRoot { kind: r.u8()?, p256: r.arr()? },
            6 => Self::ApproveOperator { op: r.arr()?, org: r.str8()? },
            7 => Self::RevokeOperator { op: r.arr()? },
            8 => Self::ProposeOwner { next: r.arr()? },
            9 => Self::AcceptOwner,
            10 => Self::RegisterInstance { x25519: r.arr()?, ed25519: r.arr()?, compose: r.arr()?, os: r.arr()?, quote: r.rest() },
            11 => Self::AnchorReceipts { key_hash: r.arr()?, root: r.arr()?, first_seq: r.u64()?, count: r.u64()?, sig: r.arr()? },
            _ => return Err(PlrError::E_BAD_INPUT),
        };
        r.end()?;
        Ok(ix)
    }

    /// The wire encoding (used by tests and off-chain tooling; the TypeScript writer mirrors it).
    pub fn encode(&self) -> Vec<u8> {
        let mut v = vec![self.tag()];
        match self {
            Self::Init { owner, root_kind, root_p256, ttl_ms } => {
                v.extend_from_slice(owner);
                v.push(*root_kind);
                v.extend_from_slice(root_p256);
                v.extend_from_slice(&ttl_ms.to_le_bytes());
            }
            Self::AllowCompose { h } | Self::RevokeCompose { h } | Self::AllowOs { h } | Self::RevokeOs { h } => v.extend_from_slice(h),
            Self::SetRoot { kind, p256 } => {
                v.push(*kind);
                v.extend_from_slice(p256);
            }
            Self::ApproveOperator { op, org } => {
                v.extend_from_slice(op);
                v.push(org.len() as u8);
                v.extend_from_slice(org);
            }
            Self::RevokeOperator { op } => v.extend_from_slice(op),
            Self::ProposeOwner { next } => v.extend_from_slice(next),
            Self::AcceptOwner => {}
            Self::RegisterInstance { x25519, ed25519, compose, os, quote } => {
                for f in [x25519, ed25519, compose, os] {
                    v.extend_from_slice(f);
                }
                v.extend_from_slice(quote);
            }
            Self::AnchorReceipts { key_hash, root, first_seq, count, sig } => {
                v.extend_from_slice(key_hash);
                v.extend_from_slice(root);
                v.extend_from_slice(&first_seq.to_le_bytes());
                v.extend_from_slice(&count.to_le_bytes());
                v.extend_from_slice(sig);
            }
        }
        v
    }
}
