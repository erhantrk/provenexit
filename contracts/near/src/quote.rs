//! Intel TDX Quote v4 layout, MOCK signature mode (SPEC §2). Mirrors `packages/shared/src/tdx/quote.ts`.

use crate::bytes::{array_at, ct_eq, is_all_zero};
use crate::errors::{Error, E_QUOTE_FORMAT};
use crate::hash::sha256;

pub const HEADER_LEN: usize = 48;
pub const BODY_LEN: usize = 584;
pub const SIGNED_LEN: usize = HEADER_LEN + BODY_LEN; // 632
pub const SIG_LEN_OFF: usize = 632;
pub const SIG_DATA_OFF: usize = 636;
pub const MOCK_SIG_DATA_LEN: usize = 192;
pub const MOCK_LEN: usize = SIG_DATA_OFF + MOCK_SIG_DATA_LEN; // 828

pub const VERSION: u16 = 4;
pub const ATT_KEY_TYPE_ECDSA_P256: u16 = 2;
pub const TEE_TYPE_TDX: u32 = 0x81;
pub const MOCK_QE_VENDOR_ID: &[u8; 16] = b"PLR-MOCK-QE-0001";

pub mod off {
    pub const VERSION: usize = 0;
    pub const ATT_KEY_TYPE: usize = 2;
    pub const TEE_TYPE: usize = 4;
    pub const RESERVED: usize = 8;
    pub const QE_VENDOR_ID: usize = 12;
    pub const TD_ATTRIBUTES: usize = 168;
    pub const MR_TD: usize = 184;
    pub const RTMR0: usize = 376;
    pub const RTMR1: usize = 424;
    pub const RTMR2: usize = 472;
    pub const RTMR3: usize = 520;
    pub const REPORT_DATA: usize = 568;
    /// Offsets inside `sig_data`.
    pub const SD_QUOTE_SIG: usize = 0;
    pub const SD_AK_PUB: usize = 64;
    pub const SD_AK_CERT_SIG: usize = 128;
}

/// A structurally valid MOCK quote (exactly [`MOCK_LEN`] bytes). Field accessors copy out fixed-size arrays.
pub struct MockQuote<'a> {
    q: &'a [u8],
}

fn u16le(b: &[u8], off: usize) -> u16 {
    u16::from_le_bytes([b[off], b[off + 1]])
}

fn u32le(b: &[u8], off: usize) -> u32 {
    u32::from_le_bytes([b[off], b[off + 1], b[off + 2], b[off + 3]])
}

const fn fmt_err(detail: &'static str) -> Error {
    Error::new(E_QUOTE_FORMAT, detail)
}

/// Parses a quote in MOCK mode (SPEC §2.1-2.3). Every structural problem, including a non-TDX TEE type, is
/// `E_QUOTE_FORMAT` (the registry's step-1 code, SPEC §7).
pub fn parse_mock(q: &[u8]) -> Result<MockQuote<'_>, Error> {
    if q.len() < SIG_DATA_OFF {
        return Err(fmt_err("length"));
    }
    if u16le(q, off::VERSION) != VERSION {
        return Err(fmt_err("version"));
    }
    if u16le(q, off::ATT_KEY_TYPE) != ATT_KEY_TYPE_ECDSA_P256 {
        return Err(fmt_err("att_key_type"));
    }
    if u32le(q, off::TEE_TYPE) != TEE_TYPE_TDX {
        return Err(fmt_err("tee_type"));
    }
    if !is_all_zero(&q[off::RESERVED..off::RESERVED + 4]) {
        return Err(fmt_err("reserved"));
    }
    if !ct_eq(&q[off::QE_VENDOR_ID..off::QE_VENDOR_ID + 16], MOCK_QE_VENDOR_ID) {
        return Err(fmt_err("qe_vendor_id"));
    }
    if u32le(q, SIG_LEN_OFF) as usize != MOCK_SIG_DATA_LEN || q.len() != MOCK_LEN {
        return Err(fmt_err("sig_data length"));
    }
    Ok(MockQuote { q })
}

// ---------- INTEL mode (INTERFACES §1.1): TDX quote v4 with a real Intel signature ----------

/// `qe_vendor_id` of an Intel QE (INTERFACES §0; SPEC §2.1).
pub const INTEL_QE_VENDOR_ID: [u8; 16] =
    [0x93, 0x9a, 0x72, 0x33, 0xf7, 0x9c, 0x4c, 0xa9, 0x94, 0x0a, 0x0d, 0xb3, 0x95, 0x7f, 0x06, 0x07];
/// `MAX_TDX_QUOTE_BYTES`: real quotes are about 5 000 bytes, dstack's carry zero padding.
pub const MAX_INTEL_LEN: usize = 8192;
/// `mr_signer_seam` (48 bytes): the TD is signed by the Intel TDX module, so the seam is zero.
pub const MR_SIGNER_SEAM: usize = 112;

/// Parses a quote in INTEL mode (INTERFACES §1.1): the same fixed v4 header/body offsets as [`parse_mock`], plus
/// the Intel QE vendor id, a bounded `sig_data` and its zero padding, and a zero `mr_signer_seam`. Every
/// structural problem is `E_QUOTE_FORMAT`. The signature itself is checked by `dcap-qvl` (off-chain or T11).
pub fn parse_intel(q: &[u8]) -> Result<MockQuote<'_>, Error> {
    if q.len() < SIG_DATA_OFF || q.len() > MAX_INTEL_LEN {
        return Err(fmt_err("length"));
    }
    if u16le(q, off::VERSION) != VERSION {
        return Err(fmt_err("version"));
    }
    if u16le(q, off::ATT_KEY_TYPE) != ATT_KEY_TYPE_ECDSA_P256 {
        return Err(fmt_err("att_key_type"));
    }
    if u32le(q, off::TEE_TYPE) != TEE_TYPE_TDX {
        return Err(fmt_err("tee_type"));
    }
    if !is_all_zero(&q[off::RESERVED..off::RESERVED + 4]) {
        return Err(fmt_err("reserved"));
    }
    if !ct_eq(&q[off::QE_VENDOR_ID..off::QE_VENDOR_ID + 16], &INTEL_QE_VENDOR_ID) {
        return Err(fmt_err("qe_vendor_id"));
    }
    let sl = u32le(q, SIG_LEN_OFF) as usize;
    if sl == 0 || sl > q.len() - SIG_DATA_OFF {
        return Err(fmt_err("sig_data length"));
    }
    if !is_all_zero(&q[SIG_DATA_OFF + sl..]) {
        return Err(fmt_err("trailing bytes"));
    }
    if !is_all_zero(&q[MR_SIGNER_SEAM..MR_SIGNER_SEAM + 48]) {
        return Err(fmt_err("mr_signer_seam"));
    }
    Ok(MockQuote { q })
}

impl MockQuote<'_> {
    /// `quote[0:632]`, the bytes covered by `quote_sig`.
    pub fn signed_bytes(&self) -> &[u8] {
        &self.q[..SIGNED_LEN]
    }

    /// DEBUG = bit 0 of byte 168 (first byte of td_attributes).
    pub fn is_debug(&self) -> bool {
        self.q[off::TD_ATTRIBUTES] & 0x01 == 0x01
    }

    pub fn mr_td(&self) -> [u8; 48] {
        array_at(self.q, off::MR_TD)
    }

    /// `rtmr[i]` for i in 0..4.
    pub fn rtmr(&self, i: usize) -> [u8; 48] {
        let o = [off::RTMR0, off::RTMR1, off::RTMR2, off::RTMR3][i];
        array_at(self.q, o)
    }

    pub fn report_data(&self) -> [u8; 64] {
        array_at(self.q, off::REPORT_DATA)
    }

    pub fn quote_sig(&self) -> [u8; 64] {
        array_at(self.q, SIG_DATA_OFF + off::SD_QUOTE_SIG)
    }

    pub fn ak_pub(&self) -> [u8; 64] {
        array_at(self.q, SIG_DATA_OFF + off::SD_AK_PUB)
    }

    pub fn ak_cert_sig(&self) -> [u8; 64] {
        array_at(self.q, SIG_DATA_OFF + off::SD_AK_CERT_SIG)
    }

    /// `SHA256(mr_td ‖ rtmr0 ‖ rtmr1 ‖ rtmr2)` (SPEC §2.5).
    pub fn os_measurement(&self) -> [u8; 32] {
        let mut buf = Vec::with_capacity(4 * 48);
        buf.extend_from_slice(&self.mr_td());
        for i in 0..3 {
            buf.extend_from_slice(&self.rtmr(i));
        }
        sha256(&buf)
    }
}
