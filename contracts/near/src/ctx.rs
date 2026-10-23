//! The NEAR execution context, read through one seam.
//!
//! On chain these are plain `env::*` calls. near-sdk caches context values process-wide when its
//! `unit-testing` feature is off (it is: that feature's dependency tree is not available to this build), so
//! native unit tests substitute a per-thread context set by `crate::test_host`.

use near_sdk::{AccountId, NearToken};

pub fn current_account_id() -> AccountId {
    imp::current_account_id()
}
pub fn predecessor_account_id() -> AccountId {
    imp::predecessor_account_id()
}
pub fn attached_deposit() -> NearToken {
    imp::attached_deposit()
}
pub fn block_timestamp_ms() -> u64 {
    imp::block_timestamp_ms()
}

#[cfg(not(test))]
mod imp {
    use near_sdk::{env, AccountId, NearToken};

    pub fn current_account_id() -> AccountId {
        env::current_account_id()
    }
    pub fn predecessor_account_id() -> AccountId {
        env::predecessor_account_id()
    }
    pub fn attached_deposit() -> NearToken {
        env::attached_deposit()
    }
    pub fn block_timestamp_ms() -> u64 {
        env::block_timestamp_ms()
    }
}

#[cfg(test)]
mod imp {
    pub use crate::test_host::ctx::{attached_deposit, block_timestamp_ms, current_account_id, predecessor_account_id};
}
