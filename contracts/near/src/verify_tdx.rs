//! INTEL-mode registration: on-chain Intel DCAP verification (dcap-qvl) + dstack event log (SPEC-TDX §2.3).

use dcap_qvl::{verify::QuoteVerifier, QuoteCollateralV3};
use near_sdk::serde_json::Value;

use crate::binding::{key_hash, registration_report_data};
use crate::bytes::ct_eq;
use crate::errors::*;
use crate::eventlog::{compose_matches, verify_event_log_dstack};
use crate::quote::{parse_intel, MockQuote};
use crate::verify::{Policy, RootKind, Verified};

/// Everything `register_instance_tdx` hands to the verifier (the arguments are already size- and hex-checked).
pub struct TdxRegistration<'a> {
    pub quote: &'a [u8],
    pub collateral: &'a QuoteCollateralV3,
    pub event_log: &'a Value,
    pub app_compose: &'a [u8],
    pub x25519: &'a [u8; 32],
    pub ed25519: &'a [u8; 32],
}

/// Verification time in seconds since the epoch: the block timestamp on chain, the TV-Q1 validity instant
/// (2025-06-20T00:00:00Z) under the test-only `tdx-test-clock` feature.
pub fn now_secs() -> u64 {
    #[cfg(feature = "tdx-test-clock")]
    {
        1_750_377_600
    }
    #[cfg(not(feature = "tdx-test-clock"))]
    {
        crate::ctx::block_timestamp_ms() / 1_000
    }
}

/// Check 8 (SPEC-TDX §2.3): the Intel TCB status of the verified quote must be accepted.
pub fn check_tcb_status(status: &str) -> Result<(), Error> {
    if crate::ACCEPTED_TCB_STATUSES.contains(&status) {
        Ok(())
    } else {
        Err(Error::new(E_TCB_STATUS, ""))
    }
}

/// Runs SPEC-TDX §2.3 checks 5-7: registry root, INTEL structural parse, Intel DCAP signature.
pub fn verify_registration_tdx(
    reg: &TdxRegistration<'_>,
    policy: &impl Policy,
    contract_id: &str,
    operator_id: &str,
    now: u64,
) -> Result<(Verified, String), Error> {
    // 5. only the Intel root may verify INTEL-mode quotes, and it must be Intel's own.
    let (kind, root) = policy.root();
    if kind != RootKind::Intel || crate::bytes::encode_hex(&root) != crate::INTEL_ROOT_P256_HEX {
        return Err(Error::new(E_QUOTE_SIG, "registry root is not the Intel root"));
    }
    // 6. quote structure (version, TEE type, QE vendor id, sig_data bounds and zero padding, mr_signer_seam).
    let q = parse_intel(reg.quote)?;
    // 7. the Intel signature chain to the root.
    let report = QuoteVerifier::new_prod()
        .verify(reg.quote, reg.collateral, now)
        .map_err(|_| Error::new(E_QUOTE_SIG, "dcap"))?;
    // 8-13. everything after the DCAP call.
    let v = verify_quote_tdx(
        &q,
        &report.status,
        reg.event_log,
        reg.app_compose,
        reg.x25519,
        reg.ed25519,
        policy,
        contract_id,
        operator_id,
    )?;
    Ok((v, report.status))
}

/// Runs SPEC-TDX §2.3 checks 8-13 on a structurally parsed quote whose Intel signature was already verified
/// (checks 6-7): TCB status, DEBUG, dstack event log + RTMR3, compose hash, allowlists, report_data binding.
/// No DCAP call, so it is unit-testable with a hand-built quote.
pub fn verify_quote_tdx(
    q: &MockQuote<'_>,
    tcb_status: &str,
    event_log: &Value,
    app_compose: &[u8],
    x25519: &[u8; 32],
    ed25519: &[u8; 32],
    policy: &impl Policy,
    contract_id: &str,
    operator_id: &str,
) -> Result<Verified, Error> {
    // 8. accepted TCB status.
    check_tcb_status(tcb_status)?;
    // 9. production TD only.
    if q.is_debug() {
        return Err(Error::new(E_DEBUG_TD, ""));
    }
    // 10. dstack boot sequence, payloads and RTMR3 replay.
    let boot = verify_event_log_dstack(event_log, &q.rtmr(3))?;
    // 11. the published app-compose is the measured one.
    if !compose_matches(app_compose, &boot.compose_hash) {
        return Err(Error::new(E_COMPOSE_MISMATCH, ""));
    }
    // 12. owner policy.
    let os_measurement = q.os_measurement();
    if !policy.compose_allowed(&boot.compose_hash) {
        return Err(Error::new(E_COMPOSE_NOT_ALLOWED, ""));
    }
    if !policy.os_allowed(&os_measurement) {
        return Err(Error::new(E_OS_NOT_ALLOWED, ""));
    }
    // 13. report_data binds exactly these keys, this registry and this operator (SPEC §5 rev 1.3).
    let expected = registration_report_data(x25519, ed25519, contract_id, operator_id)
        .ok_or_else(|| Error::new(E_REPORT_DATA, "account id length"))?;
    if !ct_eq(&q.report_data(), &expected) {
        return Err(Error::new(E_REPORT_DATA, ""));
    }
    Ok(Verified { key_hash: key_hash(x25519, ed25519), compose_hash: boot.compose_hash, os_measurement })
}
