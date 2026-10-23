//! On-chain verification of a registration (SPEC §7 `register_instance`, steps 1-7, in order).

use near_sdk::serde_json::Value;

use crate::binding::{ak_cert_message, key_hash, registration_report_data};
use crate::bytes::ct_eq;
use crate::ecdsa::verify_low_s;
use crate::errors::{
    Error, E_COMPOSE_MISMATCH, E_COMPOSE_NOT_ALLOWED, E_DEBUG_TD, E_OS_NOT_ALLOWED, E_QUOTE_SIG, E_REPORT_DATA,
};
use crate::eventlog::{compose_matches, verify_event_log};
use crate::quote::parse_mock;

/// Kind of the trusted attestation root stored in the registry.
#[near_sdk::near(serializers = [borsh])]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RootKind {
    Mock,
    Intel,
}

impl RootKind {
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "MOCK" => Some(Self::Mock),
            "INTEL" => Some(Self::Intel),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Mock => "MOCK",
            Self::Intel => "INTEL",
        }
    }
}

/// Everything `register_instance` needs to know about the caller's submission.
pub struct Registration<'a> {
    pub quote: &'a [u8],
    pub event_log: &'a Value,
    pub app_compose: &'a [u8],
    pub x25519: &'a [u8; 32],
    pub ed25519: &'a [u8; 32],
}

/// The registry policy consulted during verification.
pub trait Policy {
    fn root(&self) -> (RootKind, [u8; 64]);
    fn compose_allowed(&self, h: &[u8; 32]) -> bool;
    fn os_allowed(&self, h: &[u8; 32]) -> bool;
}

/// Facts proven by a successful verification.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Verified {
    pub key_hash: [u8; 32],
    pub compose_hash: [u8; 32],
    pub os_measurement: [u8; 32],
}

/// Runs SPEC §7 steps 1-7. `contract_id` is the registry's own account id and `operator_id` the account
/// submitting the registration (`predecessor_account_id`): the quote must be bound to both (SPEC §5 rev 1.3).
pub fn verify_registration(
    reg: &Registration<'_>,
    policy: &impl Policy,
    contract_id: &str,
    operator_id: &str,
) -> Result<Verified, Error> {
    // 1. structure (MOCK mode).
    let q = parse_mock(reg.quote)?;

    // 2. root → AK certificate → quote signature. Only a MOCK root can certify MOCK quotes; INTEL-root
    //    verification (DCAP) is out of scope for milestone 1, so it fails closed here.
    let (kind, root) = policy.root();
    if kind != RootKind::Mock {
        return Err(Error::new(E_QUOTE_SIG, "root kind cannot verify MOCK quotes"));
    }
    let ak_pub = q.ak_pub();
    if !verify_low_s(&q.ak_cert_sig(), &ak_cert_message(&ak_pub), &root) {
        return Err(Error::new(E_QUOTE_SIG, "AK certificate"));
    }
    if !verify_low_s(&q.quote_sig(), q.signed_bytes(), &ak_pub) {
        return Err(Error::new(E_QUOTE_SIG, "quote signature"));
    }

    // 3. production TD only.
    if q.is_debug() {
        return Err(Error::new(E_DEBUG_TD, ""));
    }

    // 4. event log → RTMR3 + boot sequence.
    let boot = verify_event_log(reg.event_log, &q.rtmr(3))?;

    // 5. the published compose is the measured one (hash of the bytes received).
    if !compose_matches(reg.app_compose, &boot.compose_hash) {
        return Err(Error::new(E_COMPOSE_MISMATCH, ""));
    }

    // 6. owner policy.
    let os_measurement = q.os_measurement();
    if !policy.compose_allowed(&boot.compose_hash) {
        return Err(Error::new(E_COMPOSE_NOT_ALLOWED, ""));
    }
    if !policy.os_allowed(&os_measurement) {
        return Err(Error::new(E_OS_NOT_ALLOWED, ""));
    }

    // 7. report_data binds exactly these keys, this registry and this operator (SPEC §5 rev 1.3). A session
    //    quote (`SHA256("PLR-v1/session-nonce" ‖ nonce)`) or a rev 1.2 registration nonce can never match.
    let expected = registration_report_data(reg.x25519, reg.ed25519, contract_id, operator_id)
        .ok_or_else(|| Error::new(E_REPORT_DATA, "account id length"))?;
    if !ct_eq(&q.report_data(), &expected) {
        return Err(Error::new(E_REPORT_DATA, ""));
    }

    Ok(Verified { key_hash: key_hash(reg.x25519, reg.ed25519), compose_hash: boot.compose_hash, os_measurement })
}
