//! Native stand-in for the NEAR runtime, used only by `cargo test`.
//!
//! near-sdk's own mocked blockchain (`unit-testing` feature) needs `near-vm-runner`, which is not available to
//! this offline build, so the tests link this module instead: it defines the `near_sys` host functions the
//! contract reaches (registers, storage with NEAR's storage-usage accounting, logs, promises, P-256 and Ed25519
//! verification) on per-thread state, plus the execution context read through `crate::ctx`.
//!
//! The crypto host functions mirror nearcore: `p256_verify` takes a 32-byte prehash, a 64-byte `r‖s` signature
//! and a 33-byte compressed SEC1 key and — like the real host — does NOT reject high-S signatures (so the
//! contract's own low-S check is what the tests exercise); `ed25519_verify` uses ed25519-dalek's `verify`.
#![allow(clippy::missing_safety_doc)]

use std::cell::RefCell;
use std::collections::HashMap;

/// NEAR's per-record storage overhead (`num_extra_bytes_record`).
pub const STORAGE_RECORD_OVERHEAD: u64 = 40;

#[derive(Default)]
pub struct HostState {
    registers: HashMap<u64, Vec<u8>>,
    storage: HashMap<Vec<u8>, Vec<u8>>,
    storage_usage: u64,
    pub logs: Vec<String>,
    /// (receiver, transferred yoctoNEAR) per created transfer.
    pub transfers: Vec<(String, u128)>,
    promises: Vec<String>,
    pub ctx: Ctx,
}

#[derive(Clone)]
pub struct Ctx {
    pub current_account_id: String,
    pub predecessor_account_id: String,
    pub attached_deposit: u128,
    pub block_timestamp_ms: u64,
}

impl Default for Ctx {
    fn default() -> Self {
        Self {
            current_account_id: "registry.test.near".into(),
            predecessor_account_id: "owner.test.near".into(),
            attached_deposit: 0,
            block_timestamp_ms: 1_700_000_000_000,
        }
    }
}

thread_local! {
    static HOST: RefCell<HostState> = RefCell::new(HostState::default());
}

pub fn with_host<R>(f: impl FnOnce(&mut HostState) -> R) -> R {
    HOST.with(|h| f(&mut h.borrow_mut()))
}

/// Resets the whole host (storage, logs, promises, context) for a fresh test.
pub fn reset() {
    with_host(|h| *h = HostState::default());
}

pub fn set_ctx(f: impl FnOnce(&mut Ctx)) {
    with_host(|h| f(&mut h.ctx));
}

pub fn take_logs() -> Vec<String> {
    with_host(|h| std::mem::take(&mut h.logs))
}

pub fn take_transfers() -> Vec<(String, u128)> {
    with_host(|h| std::mem::take(&mut h.transfers))
}

pub fn storage_usage_now() -> u64 {
    with_host(|h| h.storage_usage)
}

/// Context accessors used by `crate::ctx` under `cfg(test)`.
pub mod ctx {
    use super::with_host;
    use near_sdk::{AccountId, NearToken};

    pub fn current_account_id() -> AccountId {
        with_host(|h| h.ctx.current_account_id.parse().expect("valid account id"))
    }
    pub fn predecessor_account_id() -> AccountId {
        with_host(|h| h.ctx.predecessor_account_id.parse().expect("valid account id"))
    }
    pub fn attached_deposit() -> NearToken {
        NearToken::from_yoctonear(with_host(|h| h.ctx.attached_deposit))
    }
    pub fn block_timestamp_ms() -> u64 {
        with_host(|h| h.ctx.block_timestamp_ms)
    }
}

// ---------------- raw memory helpers ----------------

unsafe fn slice<'a>(len: u64, ptr: u64) -> &'a [u8] {
    if len == 0 {
        return &[];
    }
    unsafe { std::slice::from_raw_parts(ptr as usize as *const u8, len as usize) }
}

fn set_register(id: u64, data: Vec<u8>) {
    with_host(|h| {
        h.registers.insert(id, data);
    });
}

fn record_size(key: &[u8], value: &[u8]) -> u64 {
    key.len() as u64 + value.len() as u64 + STORAGE_RECORD_OVERHEAD
}

// ---------------- near_sys host functions ----------------

#[no_mangle]
pub unsafe extern "C" fn read_register(register_id: u64, ptr: u64) {
    let data = with_host(|h| h.registers.get(&register_id).cloned()).unwrap_or_else(|| std::process::abort());
    unsafe { std::ptr::copy_nonoverlapping(data.as_ptr(), ptr as usize as *mut u8, data.len()) };
}

#[no_mangle]
pub extern "C" fn register_len(register_id: u64) -> u64 {
    with_host(|h| h.registers.get(&register_id).map(|d| d.len() as u64).unwrap_or(u64::MAX))
}

#[no_mangle]
pub unsafe extern "C" fn write_register(register_id: u64, data_len: u64, data_ptr: u64) {
    set_register(register_id, unsafe { slice(data_len, data_ptr) }.to_vec());
}

#[no_mangle]
pub extern "C" fn storage_usage() -> u64 {
    storage_usage_now()
}

#[no_mangle]
pub unsafe extern "C" fn storage_write(key_len: u64, key_ptr: u64, value_len: u64, value_ptr: u64, register_id: u64) -> u64 {
    let key = unsafe { slice(key_len, key_ptr) }.to_vec();
    let value = unsafe { slice(value_len, value_ptr) }.to_vec();
    let old = with_host(|h| {
        let added = record_size(&key, &value);
        let old = h.storage.insert(key.clone(), value);
        if let Some(o) = &old {
            h.storage_usage -= record_size(&key, o);
        }
        h.storage_usage += added;
        old
    });
    match old {
        Some(o) => {
            set_register(register_id, o);
            1
        }
        None => 0,
    }
}

#[no_mangle]
pub unsafe extern "C" fn storage_read(key_len: u64, key_ptr: u64, register_id: u64) -> u64 {
    let key = unsafe { slice(key_len, key_ptr) };
    match with_host(|h| h.storage.get(key).cloned()) {
        Some(v) => {
            set_register(register_id, v);
            1
        }
        None => 0,
    }
}

#[no_mangle]
pub unsafe extern "C" fn storage_remove(key_len: u64, key_ptr: u64, register_id: u64) -> u64 {
    let key = unsafe { slice(key_len, key_ptr) };
    let old = with_host(|h| {
        let old = h.storage.remove(key);
        if let Some(o) = &old {
            h.storage_usage -= record_size(key, o);
        }
        old
    });
    match old {
        Some(o) => {
            set_register(register_id, o);
            1
        }
        None => 0,
    }
}

#[no_mangle]
pub unsafe extern "C" fn storage_has_key(key_len: u64, key_ptr: u64) -> u64 {
    let key = unsafe { slice(key_len, key_ptr) };
    u64::from(with_host(|h| h.storage.contains_key(key)))
}

#[no_mangle]
pub unsafe extern "C" fn log_utf8(len: u64, ptr: u64) {
    let s = String::from_utf8(unsafe { slice(len, ptr) }.to_vec()).unwrap_or_else(|_| std::process::abort());
    with_host(|h| h.logs.push(s));
}

#[no_mangle]
pub unsafe extern "C" fn promise_batch_create(account_id_len: u64, account_id_ptr: u64) -> u64 {
    let id = String::from_utf8(unsafe { slice(account_id_len, account_id_ptr) }.to_vec()).unwrap_or_else(|_| std::process::abort());
    with_host(|h| {
        h.promises.push(id);
        (h.promises.len() - 1) as u64
    })
}

#[no_mangle]
pub unsafe extern "C" fn promise_batch_action_transfer(promise_index: u64, amount_ptr: u64) {
    let mut buf = [0u8; 16];
    buf.copy_from_slice(unsafe { slice(16, amount_ptr) });
    let amount = u128::from_le_bytes(buf);
    with_host(|h| {
        let to = h.promises.get(promise_index as usize).cloned().unwrap_or_else(|| std::process::abort());
        h.transfers.push((to, amount));
    });
}

#[no_mangle]
pub unsafe extern "C" fn p256_verify(sig_len: u64, sig_ptr: u64, msg_len: u64, msg_ptr: u64, pk_len: u64, pk_ptr: u64) -> u64 {
    use p256::ecdsa::signature::hazmat::PrehashVerifier;
    use p256::ecdsa::{Signature, VerifyingKey};
    let (sig, msg, pk) = unsafe { (slice(sig_len, sig_ptr), slice(msg_len, msg_ptr), slice(pk_len, pk_ptr)) };
    if sig.len() != 64 || msg.len() != 32 || pk.len() != 33 {
        return 0;
    }
    let Ok(key) = VerifyingKey::from_sec1_bytes(pk) else { return 0 };
    let Ok(sig) = Signature::from_slice(sig) else { return 0 };
    // `verify_prehash` accepts both S forms (it normalises internally), matching the NEAR host behaviour.
    u64::from(key.verify_prehash(msg, &sig).is_ok())
}

#[no_mangle]
pub unsafe extern "C" fn ed25519_verify(sig_len: u64, sig_ptr: u64, msg_len: u64, msg_ptr: u64, pk_len: u64, pk_ptr: u64) -> u64 {
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};
    let (sig, msg, pk) = unsafe { (slice(sig_len, sig_ptr), slice(msg_len, msg_ptr), slice(pk_len, pk_ptr)) };
    let (Ok(sig), Ok(pk)) = (<[u8; 64]>::try_from(sig), <[u8; 32]>::try_from(pk)) else { return 0 };
    let Ok(key) = VerifyingKey::from_bytes(&pk) else { return 0 };
    u64::from(key.verify(msg, &Signature::from_bytes(&sig)).is_ok())
}

// ---------------- host functions near-sdk links against but this contract never calls ----------------

/// Reaching one of these means the contract started using a host function the test host does not model.
fn unsupported(name: &str) -> ! {
    eprintln!("test_host: unsupported host function {name}");
    std::process::abort()
}

macro_rules! unsupported_host_fns {
    ($($name:ident),* $(,)?) => {$(
        #[no_mangle]
        pub extern "C" fn $name() {
            unsupported(stringify!($name))
        }
    )*};
}

unsupported_host_fns!(
    promise_and,
    promise_batch_then,
    promise_return,
    promise_batch_action_create_account,
    promise_batch_action_deploy_contract,
    promise_batch_action_deploy_global_contract,
    promise_batch_action_deploy_global_contract_by_account_id,
    promise_batch_action_use_global_contract,
    promise_batch_action_use_global_contract_by_account_id,
    promise_batch_action_function_call,
    promise_batch_action_function_call_weight,
    promise_batch_action_stake,
    promise_batch_action_add_key_with_full_access,
    promise_batch_action_add_key_with_function_call,
    promise_batch_action_add_gas_key_with_full_access,
    promise_batch_action_add_gas_key_with_function_call,
    promise_batch_action_transfer_to_gas_key,
    promise_batch_action_delete_key,
    promise_batch_action_delete_account,
);
