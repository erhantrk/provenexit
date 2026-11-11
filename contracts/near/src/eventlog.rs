//! dstack-compatible RTMR3 event log verification (SPEC §3). Mirrors `verifyEventLog` in
//! `packages/shared/src/tdx/eventlog.ts`: strict JSON shape, every digest recomputed, exact boot sequence,
//! reserved names never reused, limits enforced, then replay == rtmr3.

use near_sdk::serde_json::{Map, Value};

use crate::bytes::{ct_eq, decode_hex, decode_hex_array};
use crate::errors::{Error, E_EVENT_LOG, E_RTMR3};
use crate::hash::{sha256, sha384_concat};

pub const EVENT_TYPE: u32 = 0x0800_0001;
pub const EVENT_IMR: u64 = 3;
pub const MAX_EVENTS: usize = 64;
pub const MAX_EVENT_PAYLOAD: usize = 256;
/// INTEL mode: dstack's `key-provider` payload is JSON (INTERFACES §0).
pub const DSTACK_MAX_EVENT_PAYLOAD: usize = 4096;
pub const MAX_EVENT_NAME: usize = 128;
pub const BOOT_SEQUENCE: [&str; 5] = ["system-preparing", "app-id", "compose-hash", "instance-id", "boot-mr-done"];
const EVENT_KEYS: [&str; 5] = ["imr", "event_type", "digest", "event", "event_payload"];

/// Facts established by a verified boot sequence.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BootInfo {
    pub compose_hash: [u8; 32],
    pub app_id: [u8; 20],
    pub instance_id: [u8; 20],
}

struct CheckedEvent<'a> {
    name: &'a str,
    payload: Vec<u8>,
    digest: [u8; 48],
}

const fn log_err(detail: &'static str) -> Error {
    Error::new(E_EVENT_LOG, detail)
}

/// Event names: 1..128 printable ASCII, no space and no ':' (the digest separator) — same rule as the TS library.
fn is_valid_name(s: &str) -> bool {
    !s.is_empty() && s.len() <= MAX_EVENT_NAME && s.bytes().all(|c| (0x21..=0x7e).contains(&c) && c != b':')
}

/// `SHA384(u32le(event_type) ‖ ":" ‖ name ‖ ":" ‖ payload)`
pub fn event_digest(name: &str, payload: &[u8]) -> [u8; 48] {
    sha384_concat(&[&EVENT_TYPE.to_le_bytes(), b":", name.as_bytes(), b":", payload])
}

fn checked_event_max(v: &Value, max_payload: usize) -> Result<CheckedEvent<'_>, Error> {
    let obj: &Map<String, Value> = v.as_object().ok_or(log_err("event is not an object"))?;
    if obj.len() != EVENT_KEYS.len() || !obj.keys().all(|k| EVENT_KEYS.contains(&k.as_str())) {
        return Err(log_err("event fields"));
    }
    if obj.get("imr").and_then(Value::as_u64) != Some(EVENT_IMR) {
        return Err(log_err("imr"));
    }
    if obj.get("event_type").and_then(Value::as_u64) != Some(EVENT_TYPE as u64) {
        return Err(log_err("event_type"));
    }
    let name = obj.get("event").and_then(Value::as_str).ok_or(log_err("event name"))?;
    if !is_valid_name(name) {
        return Err(log_err("event name"));
    }
    let digest_hex = obj.get("digest").and_then(Value::as_str).ok_or(log_err("digest encoding"))?;
    let digest: [u8; 48] = decode_hex_array(digest_hex).ok_or(log_err("digest encoding"))?;
    let payload_hex = obj.get("event_payload").and_then(Value::as_str).ok_or(log_err("payload encoding"))?;
    if payload_hex.len() > max_payload * 2 {
        return Err(log_err("payload size"));
    }
    let payload = decode_hex(payload_hex).ok_or(log_err("payload encoding"))?;
    if !ct_eq(&event_digest(name, &payload), &digest) {
        return Err(log_err("digest mismatch"));
    }
    Ok(CheckedEvent { name, payload, digest })
}

/// SPEC §3 (MOCK mode): the MOCK event-log rule, whose boot events are positions 0..4 and never repeat.
fn checked_event(v: &Value) -> Result<CheckedEvent<'_>, Error> {
    checked_event_max(v, MAX_EVENT_PAYLOAD)
}

/// Verifies `events` (the caller-supplied JSON `event_log`) against the quote's RTMR3.
/// Errors: `E_EVENT_LOG` for any content problem, `E_RTMR3` if a well-formed log does not replay to `rtmr3`.
pub fn verify_event_log(events: &Value, rtmr3: &[u8; 48]) -> Result<BootInfo, Error> {
    let arr = events.as_array().ok_or(log_err("not an array"))?;
    if arr.len() < BOOT_SEQUENCE.len() || arr.len() > MAX_EVENTS {
        return Err(log_err("event count"));
    }
    let checked = arr.iter().map(checked_event).collect::<Result<Vec<_>, _>>()?;
    for (i, ev) in checked.iter().enumerate() {
        match BOOT_SEQUENCE.get(i) {
            Some(expected) if ev.name != *expected => return Err(log_err("boot sequence")),
            None if BOOT_SEQUENCE.contains(&ev.name) => return Err(log_err("reserved event name reused")),
            _ => {}
        }
    }
    let (prep, app_id, compose, instance, done) = (&checked[0], &checked[1], &checked[2], &checked[3], &checked[4]);
    if !prep.payload.is_empty() {
        return Err(log_err("system-preparing payload"));
    }
    let compose_hash: [u8; 32] = compose.payload.as_slice().try_into().map_err(|_| log_err("compose-hash payload"))?;
    let app_id: [u8; 20] = app_id.payload.as_slice().try_into().map_err(|_| log_err("app-id payload"))?;
    if !ct_eq(&app_id, &compose_hash[..20]) {
        return Err(log_err("app-id payload"));
    }
    let instance_id: [u8; 20] = instance.payload.as_slice().try_into().map_err(|_| log_err("instance-id payload"))?;
    if !done.payload.is_empty() {
        return Err(log_err("boot-mr-done payload"));
    }

    let mut rt = [0u8; 48];
    for ev in &checked {
        rt = sha384_concat(&[&rt, &ev.digest]);
    }
    if !ct_eq(&rt, rtmr3) {
        return Err(Error::new(E_RTMR3, ""));
    }
    Ok(BootInfo { compose_hash, app_id, instance_id })
}

/// Verifies a real dstack RTMR3 event log (INTERFACES §1.3, INTEL mode). Same shape, digest rule (V1 only), limits
/// and replay as [`verify_event_log`], with three differences: the boot events may sit anywhere in the log (dstack
/// emits `key-provider`, `os-image-hash`, … around them), only their relative order is fixed; any other name may
/// appear any number of times; and payloads may be up to [`DSTACK_MAX_EVENT_PAYLOAD`] bytes. There is no
/// `app-id == compose_hash[0:20]` rule: on Phala Cloud the app id comes from the deployment.
/// Errors: `E_EVENT_LOG` for any content problem, `E_RTMR3` if a well-formed log does not replay to `rtmr3`.
pub fn verify_event_log_dstack(events: &Value, rtmr3: &[u8; 48]) -> Result<BootInfo, Error> {
    let arr = events.as_array().ok_or(log_err("not an array"))?;
    if arr.len() < BOOT_SEQUENCE.len() || arr.len() > MAX_EVENTS {
        return Err(log_err("event count"));
    }
    let mut idx: [Option<usize>; 5] = [None; 5];
    let mut checked = Vec::with_capacity(arr.len());
    for (i, v) in arr.iter().enumerate() {
        let ev = checked_event_max(v, DSTACK_MAX_EVENT_PAYLOAD)?;
        if let Some(k) = BOOT_SEQUENCE.iter().position(|n| *n == ev.name) {
            if idx[k].is_some() {
                return Err(log_err("boot event repeated"));
            }
            idx[k] = Some(i);
        }
        checked.push(ev);
    }
    let mut last: Option<usize> = None;
    for k in 0..5 {
        let i = idx[k].ok_or(log_err("boot sequence"))?;
        if let Some(l) = last {
            if i <= l {
                return Err(log_err("boot sequence"));
            }
        }
        last = Some(i);
    }
    let get = |k: usize| &checked[idx[k].unwrap()];
    if !get(0).payload.is_empty() || !get(4).payload.is_empty() {
        return Err(log_err("empty payload"));
    }
    let app_id: [u8; 20] = get(1).payload.as_slice().try_into().map_err(|_| log_err("app-id payload"))?;
    let compose_hash: [u8; 32] = get(2).payload.as_slice().try_into().map_err(|_| log_err("compose-hash payload"))?;
    let instance_id: [u8; 20] = get(3).payload.as_slice().try_into().map_err(|_| log_err("instance-id payload"))?;
    let mut rt = [0u8; 48];
    for c in &checked {
        rt = sha384_concat(&[&rt, &c.digest]);
    }
    if !ct_eq(&rt, rtmr3) {
        return Err(Error::new(E_RTMR3, ""));
    }
    Ok(BootInfo { compose_hash, app_id, instance_id })
}

/// `SHA256(compose_bytes) == compose_hash`, comparing in constant time.
pub fn compose_matches(app_compose: &[u8], compose_hash: &[u8; 32]) -> bool {
    ct_eq(&sha256(app_compose), compose_hash)
}
