//! SPEC error codes. Every contract panic message starts with exactly one of these codes, optionally followed
//! by `": "` and a static, content-free detail (never caller-supplied data).

use core::fmt;

// Generic input validation.
pub const E_BAD_HEX: &str = "E_BAD_HEX";
pub const E_BAD_INPUT: &str = "E_BAD_INPUT";
pub const E_ZERO_HASH: &str = "E_ZERO_HASH";
// Access control and payments.
pub const E_UNAUTHORIZED: &str = "E_UNAUTHORIZED";
pub const E_DEPOSIT: &str = "E_DEPOSIT";
// register_instance (SPEC §7, steps 1-7).
pub const E_QUOTE_FORMAT: &str = "E_QUOTE_FORMAT";
pub const E_QUOTE_SIG: &str = "E_QUOTE_SIG";
pub const E_DEBUG_TD: &str = "E_DEBUG_TD";
pub const E_EVENT_LOG: &str = "E_EVENT_LOG";
pub const E_RTMR3: &str = "E_RTMR3";
pub const E_COMPOSE_MISMATCH: &str = "E_COMPOSE_MISMATCH";
pub const E_COMPOSE_NOT_ALLOWED: &str = "E_COMPOSE_NOT_ALLOWED";
pub const E_OS_NOT_ALLOWED: &str = "E_OS_NOT_ALLOWED";
pub const E_REPORT_DATA: &str = "E_REPORT_DATA";
// INTEL mode (INTERFACES §0/§1): Intel DCAP verification and the dstack compose policy.
pub const E_TCB_STATUS: &str = "E_TCB_STATUS";
/// Client-side only (`checkDstackComposePolicy`, INTERFACES §3.1); kept here so both sides share one code list.
pub const E_COMPOSE_POLICY: &str = "E_COMPOSE_POLICY";
pub const E_COLLATERAL: &str = "E_COLLATERAL";
// anchor_receipts.
pub const E_INSTANCE_NOT_REGISTERED: &str = "E_INSTANCE_NOT_REGISTERED";
pub const E_SEQ: &str = "E_SEQ";
pub const E_ANCHOR_SIG: &str = "E_ANCHOR_SIG";

/// A verification failure: SPEC code plus a static detail.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Error {
    pub code: &'static str,
    pub detail: &'static str,
}

impl Error {
    pub const fn new(code: &'static str, detail: &'static str) -> Self {
        Self { code, detail }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.detail.is_empty() {
            f.write_str(self.code)
        } else {
            write!(f, "{}: {}", self.code, self.detail)
        }
    }
}

/// Aborts the current call with `err`'s message (state changes are rolled back by the runtime).
pub fn fail(err: Error) -> ! {
    let msg = err.to_string();
    #[cfg(target_arch = "wasm32")]
    {
        near_sdk::env::panic_str(&msg)
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        // Native builds (unit tests): a regular Rust panic carrying the message, so tests can assert on it.
        panic!("{msg}")
    }
}

/// `fail(Error::new(code, detail))`
pub fn fail_with(code: &'static str, detail: &'static str) -> ! {
    fail(Error::new(code, detail))
}

/// Unwraps a verification result, aborting the call with the error's code on failure.
pub trait OrFail<T> {
    fn or_fail(self) -> T;
}

impl<T> OrFail<T> for Result<T, Error> {
    fn or_fail(self) -> T {
        match self {
            Ok(v) => v,
            Err(e) => fail(e),
        }
    }
}
