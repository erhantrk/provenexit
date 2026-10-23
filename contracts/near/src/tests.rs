//! Contract tests on the native test host (`crate::test_host`), driven by cross-implementation vectors produced
//! with the TypeScript reference library (`fixtures/gen.mjs` → `fixtures/vectors.json`).

use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::{Once, OnceLock};

use near_sdk::serde_json::{self, json, Value};
use near_sdk::NearToken;

use crate::binding::{ak_cert_message, anchor_message, key_hash, registration_nonce, registration_report_data, MAX_ACCOUNT_ID_BYTES};
use crate::bytes::{decode_hex, decode_hex_array, encode_hex};
use crate::ecdsa::{self, compress, verify_low_s};
use crate::errors::*;
use crate::eventlog::{event_digest, verify_event_log};
use crate::hash::{sha256, sha384_concat};
use crate::quote::{parse_mock, MOCK_LEN};
use crate::test_host::{self, set_ctx, take_logs, take_transfers};
use crate::*;

const OWNER: &str = "owner.test.near";
const OPERATOR: &str = "operator.test.near";
const STRANGER: &str = "stranger.test.near";
const DEPOSIT: u128 = 100_000_000_000_000_000_000_000; // 0.1 NEAR
const BYTE_COST: u128 = 10_000_000_000_000_000_000; // env::storage_byte_cost()

// ---------------- fixtures ----------------

fn fx() -> &'static Value {
    static FX: OnceLock<Value> = OnceLock::new();
    FX.get_or_init(|| serde_json::from_str(include_str!("../fixtures/vectors.json")).expect("fixtures/vectors.json"))
}

fn fs(key: &str) -> String {
    fx()[key].as_str().unwrap_or_else(|| panic!("fixture {key}")).to_string()
}

fn reg_case(name: &str) -> &'static Value {
    fx()["registrations"].as_array().unwrap().iter().find(|c| c["name"] == name).unwrap_or_else(|| panic!("case {name}"))
}

struct RegArgs {
    quote: String,
    event_log: Value,
    app_compose: String,
    x25519: String,
    ed25519: String,
}

fn args_of(c: &Value) -> RegArgs {
    RegArgs {
        quote: c["quote"].as_str().unwrap().into(),
        event_log: c["event_log"].clone(),
        app_compose: c["app_compose"].as_str().unwrap().into(),
        x25519: c["x25519"].as_str().unwrap().into(),
        ed25519: c["ed25519"].as_str().unwrap().into(),
    }
}

fn ok_args() -> RegArgs {
    args_of(reg_case("ok_mock_tdx_attester"))
}

/// The account a fixture case is submitted by (`predecessor_account_id`); OPERATOR unless the case says otherwise.
fn predecessor_of(c: &Value) -> &str {
    c.get("predecessor").map(|p| p.as_str().expect("predecessor is a string")).unwrap_or(OPERATOR)
}

// ---------------- harness ----------------

/// Silences the expected `E_*` contract panics; anything else (assertion failures) prints normally.
fn quiet_contract_panics() {
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        let default = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |info| {
            let msg = panic_message(info.payload());
            if !msg.starts_with("E_") {
                default(info);
            }
        }));
    });
}

fn panic_message(p: &(dyn std::any::Any + Send)) -> String {
    p.downcast_ref::<String>().cloned().or_else(|| p.downcast_ref::<&str>().map(|s| s.to_string())).unwrap_or_default()
}

/// Runs `f`, expecting a contract panic; returns its message.
fn panics<R>(f: impl FnOnce() -> R) -> String {
    quiet_contract_panics();
    match catch_unwind(AssertUnwindSafe(f)) {
        Ok(_) => panic!("expected the call to fail"),
        Err(p) => panic_message(&*p),
    }
}

/// Asserts that `f` fails with exactly SPEC code `code` (message is `code` or `code: detail`).
#[track_caller]
fn fails_with<R>(code: &str, f: impl FnOnce() -> R) {
    let msg = panics(f);
    let got = msg.split(':').next().unwrap_or_default();
    assert_eq!(got, code, "unexpected failure message {msg:?}");
}

fn caller(who: &str, deposit: u128) {
    set_ctx(|c| {
        c.predecessor_account_id = who.into();
        c.attached_deposit = deposit;
    });
}

fn now_ms() -> u64 {
    test_host::with_host(|h| h.ctx.block_timestamp_ms)
}

fn advance_ms(ms: u64) {
    set_ctx(|c| c.block_timestamp_ms += ms);
}

/// Fresh host + registry initialised by the contract account with the fixture MOCK root; nothing allowed yet.
fn fresh_bare() -> Registry {
    test_host::reset();
    caller("registry.test.near", 0);
    let c = Registry::new(OWNER.parse().unwrap(), "MOCK".into(), fs("root_p256"), None);
    take_logs();
    c
}

/// `fresh_bare` + the fixture build's compose hash and OS measurement allowed.
fn fresh() -> Registry {
    let mut c = fresh_bare();
    caller(OWNER, 0);
    c.allow_compose(fs("compose_hash"));
    c.allow_os(fs("os_measurement"));
    take_logs();
    c
}

fn register(c: &mut Registry, a: &RegArgs) -> String {
    c.register_instance(a.quote.clone(), a.event_log.clone(), a.app_compose.clone(), a.x25519.clone(), a.ed25519.clone())
}

fn events_named(logs: &[String], name: &str) -> Vec<Value> {
    logs.iter()
        .filter_map(|l| l.strip_prefix("EVENT_JSON:"))
        .map(|j| serde_json::from_str::<Value>(j).expect("event JSON"))
        .filter(|e| e["event"] == name)
        .collect()
}

fn assert_single_event(logs: &[String], name: &str) -> Value {
    let evs = events_named(logs, name);
    assert_eq!(evs.len(), 1, "expected one {name} event in {logs:?}");
    let e = &evs[0];
    assert_eq!(e["standard"], "plr");
    assert_eq!(e["version"], "1.0.0");
    let data = e["data"].as_array().expect("data array");
    assert_eq!(data.len(), 1);
    data[0].clone()
}

// ---------------- init & views ----------------

#[test]
fn init_sets_root_owner_and_defaults() {
    test_host::reset();
    caller("registry.test.near", 0);
    let c = Registry::new(OWNER.parse().unwrap(), "MOCK".into(), fs("root_p256"), None);
    let ev = assert_single_event(&take_logs(), events::ROOT_SET);
    assert_eq!(ev, json!({ "kind": "MOCK", "p256": fs("root_p256") }));
    assert_eq!(c.get_root(), RootView { kind: "MOCK".into(), p256: fs("root_p256") });
    assert_eq!(serde_json::to_value(c.get_root()).unwrap(), json!({ "kind": "MOCK", "p256": fs("root_p256") }));
    assert_eq!(c.anchor_count(), 0);
    assert_eq!(c.get_anchor(0), None);
    assert_eq!(c.get_owner().as_str(), OWNER);
    assert_eq!(c.get_pending_owner(), None);
    assert_eq!(c.get_instance_ttl_ms(), DEFAULT_INSTANCE_TTL_MS);
    let c2 = Registry::new(OWNER.parse().unwrap(), "INTEL".into(), fs("root_p256"), Some(60_000));
    assert_eq!(c2.get_root().kind, "INTEL");
    assert_eq!(c2.get_instance_ttl_ms(), 60_000);
}

#[test]
fn init_validates_arguments() {
    test_host::reset();
    let root = fs("root_p256");
    let new = |kind: &str, p256: &str, ttl: Option<u64>| Registry::new(OWNER.parse().unwrap(), kind.into(), p256.into(), ttl);
    fails_with(E_BAD_INPUT, || new("mock", &root, None));
    fails_with(E_BAD_INPUT, || new("SGX", &root, None));
    fails_with(E_BAD_HEX, || new("MOCK", &root.to_uppercase(), None));
    fails_with(E_BAD_HEX, || new("MOCK", &root[..126], None));
    fails_with(E_BAD_HEX, || new("MOCK", &format!("04{root}"), None));
    fails_with(E_BAD_INPUT, || new("MOCK", &"11".repeat(64), None)); // not a curve point
    fails_with(E_BAD_INPUT, || new("MOCK", &"00".repeat(64), None));
    fails_with(E_BAD_INPUT, || new("MOCK", &root, Some(0)));
    fails_with(E_BAD_INPUT, || new("MOCK", &root, Some(MAX_INSTANCE_TTL_MS + 1)));
    new("MOCK", &root, Some(MAX_INSTANCE_TTL_MS));
}

// ---------------- owner policy ----------------

#[test]
fn only_the_owner_changes_policy() {
    let mut c = fresh_bare();
    let h = "ab".repeat(32);
    for who in [STRANGER, OPERATOR, "registry.test.near"] {
        caller(who, 0);
        fails_with(E_UNAUTHORIZED, || c.allow_compose(h.clone()));
        fails_with(E_UNAUTHORIZED, || c.revoke_compose(h.clone()));
        fails_with(E_UNAUTHORIZED, || c.allow_os(h.clone()));
        fails_with(E_UNAUTHORIZED, || c.revoke_os(h.clone()));
        fails_with(E_UNAUTHORIZED, || c.set_root("MOCK".into(), "11".repeat(64)));
        fails_with(E_UNAUTHORIZED, || c.propose_owner(STRANGER.parse().unwrap()));
        fails_with(E_UNAUTHORIZED, || c.approve_operator(OPERATOR.parse().unwrap(), "org-a".into()));
        fails_with(E_UNAUTHORIZED, || c.revoke_operator(OPERATOR.parse().unwrap()));
    }
    assert_eq!(c.get_operator(OPERATOR.into()), None);
    assert!(!c.is_compose_allowed(h.clone()));
    assert!(take_logs().is_empty());
}

#[test]
fn rejects_zero_and_malformed_hashes() {
    let mut c = fresh_bare();
    caller(OWNER, 0);
    let bad_hex = ["AB".repeat(32), "ab".repeat(31), "ab".repeat(33), format!("0x{}", "ab".repeat(31)), "a".repeat(63), String::new(), format!("{}g", "a".repeat(63))];
    for f in [Registry::allow_compose, Registry::revoke_compose, Registry::allow_os, Registry::revoke_os] {
        fails_with(E_ZERO_HASH, || f(&mut c, "00".repeat(32)));
        for b in &bad_hex {
            fails_with(E_BAD_HEX, || f(&mut c, b.clone()));
        }
    }
    // Views never panic: malformed or zero input is simply not allowed.
    for b in bad_hex.iter().chain([&"00".repeat(32)]) {
        assert!(!c.is_compose_allowed(b.clone()));
        assert!(!c.is_os_allowed(b.clone()));
        assert!(!c.is_allowed(b.clone(), b.clone()));
        assert_eq!(c.get_instance(b.clone()), None);
    }
}

#[test]
fn allow_revoke_round_trip_with_events() {
    let mut c = fresh_bare();
    caller(OWNER, 0);
    let (h, o) = ("ab".repeat(32), "cd".repeat(32));
    assert!(!c.is_compose_allowed(h.clone()));
    c.allow_compose(h.clone());
    assert_eq!(assert_single_event(&take_logs(), events::COMPOSE_ALLOWED), json!({ "hash": h }));
    assert!(c.is_compose_allowed(h.clone()));
    assert!(!c.is_allowed(h.clone(), o.clone()), "OS not yet allowed");
    c.allow_os(o.clone());
    assert_eq!(assert_single_event(&take_logs(), events::OS_ALLOWED), json!({ "hash": o }));
    assert!(c.is_allowed(h.clone(), o.clone()));
    assert!(!c.is_allowed(o.clone(), h.clone()), "sets are separate");
    c.allow_compose(h.clone()); // idempotent
    c.revoke_compose(h.clone());
    let logs = take_logs();
    assert_eq!(assert_single_event(&logs, events::COMPOSE_REVOKED), json!({ "hash": h }));
    assert!(!c.is_compose_allowed(h.clone()));
    assert!(!c.is_allowed(h.clone(), o.clone()));
    c.revoke_os(o.clone());
    assert_eq!(assert_single_event(&take_logs(), events::OS_REVOKED), json!({ "hash": o }));
    assert!(!c.is_os_allowed(o.clone()));
    c.revoke_os(o.clone()); // revoking an absent hash is a no-op
    assert!(!c.is_os_allowed(o));
}

#[test]
fn set_root_validates_and_switches_trust() {
    let mut c = fresh();
    caller(OWNER, 0);
    fails_with(E_BAD_INPUT, || c.set_root("TPM".into(), fs("root_p256")));
    fails_with(E_BAD_HEX, || c.set_root("MOCK".into(), fs("root_p256").to_uppercase()));
    fails_with(E_BAD_INPUT, || c.set_root("MOCK".into(), "11".repeat(64)));
    take_logs();

    // Another MOCK root: quotes certified by the old root no longer verify.
    c.set_root("MOCK".into(), fs("other_root_p256"));
    assert_eq!(assert_single_event(&take_logs(), events::ROOT_SET), json!({ "kind": "MOCK", "p256": fs("other_root_p256") }));
    assert_eq!(c.get_root().p256, fs("other_root_p256"));
    caller(OPERATOR, DEPOSIT);
    fails_with(E_QUOTE_SIG, || register(&mut c, &ok_args()));

    // An INTEL root cannot verify MOCK quotes on-chain (milestone 1): fail closed.
    caller(OWNER, 0);
    c.set_root("INTEL".into(), fs("root_p256"));
    caller(OPERATOR, DEPOSIT);
    fails_with(E_QUOTE_SIG, || register(&mut c, &ok_args()));

    caller(OWNER, 0);
    c.set_root("MOCK".into(), fs("root_p256"));
    caller(OPERATOR, DEPOSIT);
    register(&mut c, &ok_args());
}

// ---------------- ownership ----------------

#[test]
fn two_step_ownership_transfer() {
    let mut c = fresh_bare();
    caller(STRANGER, 0);
    fails_with(E_UNAUTHORIZED, || c.accept_owner());
    caller(OWNER, 0);
    fails_with(E_UNAUTHORIZED, || c.accept_owner()); // nothing pending, even for the owner
    c.propose_owner(STRANGER.parse().unwrap());
    assert_eq!(assert_single_event(&take_logs(), events::OWNER_PROPOSED), json!({ "owner": OWNER, "pending_owner": STRANGER }));
    assert_eq!(c.get_pending_owner().unwrap().as_str(), STRANGER);
    assert_eq!(c.get_owner().as_str(), OWNER, "ownership does not move until accepted");
    caller(OPERATOR, 0);
    fails_with(E_UNAUTHORIZED, || c.accept_owner());
    caller(STRANGER, 0);
    fails_with(E_UNAUTHORIZED, || c.allow_compose("cd".repeat(32))); // not yet owner
    c.accept_owner();
    assert_eq!(assert_single_event(&take_logs(), events::OWNER_ACCEPTED), json!({ "old_owner": OWNER, "new_owner": STRANGER }));
    assert_eq!(c.get_owner().as_str(), STRANGER);
    assert_eq!(c.get_pending_owner(), None);
    fails_with(E_UNAUTHORIZED, || c.accept_owner()); // single use
    caller(OWNER, 0);
    fails_with(E_UNAUTHORIZED, || c.allow_compose("cd".repeat(32)));
    caller(STRANGER, 0);
    c.allow_compose("cd".repeat(32));
    assert!(c.is_compose_allowed("cd".repeat(32)));
}

#[test]
fn re_proposing_replaces_the_pending_owner() {
    let mut c = fresh_bare();
    caller(OWNER, 0);
    c.propose_owner(STRANGER.parse().unwrap());
    c.propose_owner(OPERATOR.parse().unwrap());
    caller(STRANGER, 0);
    fails_with(E_UNAUTHORIZED, || c.accept_owner());
    caller(OPERATOR, 0);
    c.accept_owner();
    assert_eq!(c.get_owner().as_str(), OPERATOR);
}

// ---------------- register_instance: cross-implementation vectors ----------------

#[test]
fn every_registration_vector_matches_the_ts_reference() {
    let cases = fx()["registrations"].as_array().unwrap();
    assert!(cases.len() >= 70, "fixture set unexpectedly small");
    assert_eq!((fs("operator_id").as_str(), fs("stranger_id").as_str()), (OPERATOR, STRANGER), "fixture accounts");
    for case in cases {
        let name = case["name"].as_str().unwrap();
        let expect = case["expect"].as_str().unwrap();
        let mut c = fresh();
        let submitter = predecessor_of(case);
        caller(submitter, DEPOSIT);
        let a = args_of(case);
        quiet_contract_panics();
        let res = catch_unwind(AssertUnwindSafe(|| register(&mut c, &a)));
        match (expect, res) {
            ("ok", Ok(kh)) => {
                let kh_expected = encode_hex(&key_hash(&decode_hex_array(&a.x25519).unwrap(), &decode_hex_array(&a.ed25519).unwrap()));
                assert_eq!(kh, kh_expected, "{name}: returned key hash");
                let rec = c.get_instance(kh).unwrap_or_else(|| panic!("{name}: instance missing"));
                assert_eq!(rec.compose_hash, fs("compose_hash"), "{name}");
                assert_eq!(rec.os_measurement, fs("os_measurement"), "{name}");
                assert_eq!((rec.x25519.as_str(), rec.ed25519.as_str()), (a.x25519.as_str(), a.ed25519.as_str()), "{name}");
                assert_eq!(rec.operator.as_str(), submitter, "{name}: operator is the bound submitter");
            }
            ("ok", Err(p)) => panic!("{name}: expected success, got {:?}", panic_message(&*p)),
            (code, Ok(_)) => panic!("{name}: expected {code}, but registration succeeded"),
            (code, Err(p)) => {
                let msg = panic_message(&*p);
                assert_eq!(msg.split(':').next().unwrap(), code, "{name}: message {msg:?}");
                assert_eq!(c.get_instance(fs("key_hash")), None, "{name}: nothing registered");
                let kh = key_hash(&decode_hex_array(&a.x25519).unwrap_or([1; 32]), &decode_hex_array(&a.ed25519).unwrap_or([1; 32]));
                assert_eq!(c.get_instance(encode_hex(&kh)), None, "{name}: claimed keys not registered");
            }
        }
    }
}

#[test]
fn registration_records_instance_emits_event_and_refunds() {
    let mut c = fresh();
    caller(OPERATOR, DEPOSIT);
    let before = test_host::storage_usage_now();
    let kh = register(&mut c, &ok_args());
    let added = test_host::storage_usage_now() - before;
    assert!(added > 100, "instance record stored");
    assert_eq!(kh, fs("key_hash"));
    let a = ok_args();
    let rec = c.get_instance(kh.clone()).unwrap();
    let expect = InstanceView {
        compose_hash: fs("compose_hash"),
        os_measurement: fs("os_measurement"),
        x25519: a.x25519.clone(),
        ed25519: a.ed25519.clone(),
        operator: OPERATOR.parse().unwrap(),
        org_id: None,
        registered_at_ms: now_ms(),
        expires_at_ms: now_ms() + DEFAULT_INSTANCE_TTL_MS,
        next_seq: 0,
    };
    assert_eq!(rec, expect);
    // SPEC §10 InstanceRecord JSON: exact keys, u64 fields as JSON numbers.
    assert_eq!(
        serde_json::to_value(&rec).unwrap(),
        json!({
            "compose_hash": fs("compose_hash"), "os_measurement": fs("os_measurement"),
            "x25519": a.x25519, "ed25519": a.ed25519, "operator": OPERATOR, "org_id": null,
            "registered_at_ms": now_ms(), "expires_at_ms": now_ms() + DEFAULT_INSTANCE_TTL_MS, "next_seq": 0,
        })
    );
    let ev = assert_single_event(&take_logs(), events::INSTANCE_REGISTERED);
    assert_eq!(ev["key_hash"], kh);
    assert_eq!(ev["compose_hash"], fs("compose_hash"));
    assert_eq!(ev["operator"], OPERATOR);
    assert_eq!(ev["refreshed"], false);
    // Deposit = storage actually added (instance + anchor-credit entry) + capped anchor credit + refund.
    assert_eq!(c.get_anchor_credit(kh.clone()), MAX_ANCHOR_CREDIT_YOCTO.to_string());
    assert_eq!(
        take_transfers(),
        vec![(OPERATOR.to_string(), DEPOSIT - u128::from(added) * BYTE_COST - MAX_ANCHOR_CREDIT_YOCTO)]
    );
}

/// Storage of one anchor-credit map entry: 1-byte prefix ‖ 32-byte key, a borsh u128 value, record overhead.
const CREDIT_ENTRY_BYTES: u64 = 1 + 32 + 16 + test_host::STORAGE_RECORD_OVERHEAD;

/// Storage cost of the instance record alone (a registration with a large deposit also stores a credit entry).
fn instance_storage_cost() -> u128 {
    let mut c = fresh();
    caller(OPERATOR, DEPOSIT);
    let before = test_host::storage_usage_now();
    register(&mut c, &ok_args());
    u128::from(test_host::storage_usage_now() - before - CREDIT_ENTRY_BYTES) * BYTE_COST
}

#[test]
fn storage_deposit_is_required_and_exact_deposit_needs_no_refund() {
    let cost = instance_storage_cost();

    let mut c = fresh();
    caller(OPERATOR, 0);
    fails_with(E_DEPOSIT, || register(&mut c, &ok_args()));
    let mut c = fresh();
    caller(OPERATOR, cost - 1);
    fails_with(E_DEPOSIT, || register(&mut c, &ok_args()));
    let mut c = fresh();
    caller(OPERATOR, cost);
    take_transfers();
    register(&mut c, &ok_args());
    assert!(take_transfers().is_empty(), "no refund for an exact deposit");
}

#[test]
fn re_registration_refreshes_expiry_and_keeps_seq_and_operator() {
    let mut c = fresh();
    caller(OPERATOR, DEPOSIT);
    let kh = register(&mut c, &ok_args());
    let t0 = now_ms();
    anchor(&mut c, &anchor_step("first_batch"));
    assert_eq!(c.get_instance(kh.clone()).unwrap().next_seq, 3);

    advance_ms(1_000);
    take_logs();
    take_transfers();
    // The quote is bound to OPERATOR (SPEC §5 rev 1.3): nobody else can even replay it.
    caller(STRANGER, DEPOSIT);
    fails_with(E_REPORT_DATA, || register(&mut c, &ok_args()));
    assert!(take_logs().is_empty() && take_transfers().is_empty());
    caller(OPERATOR, 0); // refreshing needs no deposit (no new storage)
    register(&mut c, &ok_args());
    let rec = c.get_instance(kh.clone()).unwrap();
    assert_eq!(rec.next_seq, 3);
    assert_eq!(rec.operator.as_str(), OPERATOR);
    assert_eq!(rec.registered_at_ms, t0);
    assert_eq!(rec.expires_at_ms, t0 + 1_000 + DEFAULT_INSTANCE_TTL_MS);
    assert_eq!(assert_single_event(&take_logs(), events::INSTANCE_REGISTERED)["refreshed"], true);
    assert!(take_transfers().is_empty());
}

#[test]
fn expired_instances_are_invisible_until_refreshed() {
    let mut c = fresh();
    caller(OPERATOR, DEPOSIT);
    let kh = register(&mut c, &ok_args());
    anchor(&mut c, &anchor_step("first_batch"));
    advance_ms(DEFAULT_INSTANCE_TTL_MS - 1);
    assert!(c.get_instance(kh.clone()).is_some());
    advance_ms(1);
    assert_eq!(c.get_instance(kh.clone()), None, "expires_at_ms is exclusive");
    fails_with(E_INSTANCE_NOT_REGISTERED, || anchor(&mut c, &anchor_step("second_batch")));
    caller(OPERATOR, DEPOSIT);
    register(&mut c, &ok_args());
    let rec = c.get_instance(kh).unwrap();
    assert_eq!(rec.next_seq, 3, "next_seq survives expiry");
    anchor(&mut c, &anchor_step("second_batch"));
}

#[test]
fn registration_argument_bounds() {
    let mut c = fresh();
    caller(OPERATOR, DEPOSIT);
    let a = ok_args();
    let call = |c: &mut Registry, q: &str, log: Value, comp: &str, x: &str, e: &str| {
        c.register_instance(q.into(), log, comp.into(), x.into(), e.into())
    };
    let (q, l, comp, x, e) = (&a.quote, &a.event_log, &a.app_compose, &a.x25519, &a.ed25519);
    fails_with(E_QUOTE_FORMAT, || call(&mut c, &"00".repeat(MAX_QUOTE_HEX_LEN / 2 + 1), l.clone(), comp, x, e));
    fails_with(E_BAD_INPUT, || call(&mut c, q, l.clone(), "", x, e));
    fails_with(E_BAD_INPUT, || call(&mut c, q, l.clone(), &" ".repeat(MAX_APP_COMPOSE_LEN + 1), x, e));
    fails_with(E_BAD_HEX, || call(&mut c, q, l.clone(), comp, &x.to_uppercase(), e));
    fails_with(E_BAD_HEX, || call(&mut c, q, l.clone(), comp, x, &e[..62]));
    fails_with(E_BAD_INPUT, || call(&mut c, q, l.clone(), comp, &"00".repeat(32), e));
    fails_with(E_BAD_INPUT, || call(&mut c, q, l.clone(), comp, x, &"00".repeat(32)));
    fails_with(E_EVENT_LOG, || call(&mut c, q, json!(null), comp, x, e));
    // Non-integer JSON numbers are not accepted where integers are required.
    let mut l2 = l.clone();
    l2[0]["imr"] = json!(3.0);
    fails_with(E_EVENT_LOG, || call(&mut c, q, l2, comp, x, e));
    let mut l3 = l.clone();
    l3[0]["event_type"] = json!("134217729");
    fails_with(E_EVENT_LOG, || call(&mut c, q, l3, comp, x, e));
    call(&mut c, q, l.clone(), comp, x, e);
}

#[test]
fn allowlist_changes_apply_to_registration() {
    let mut c = fresh();
    caller(OWNER, 0);
    c.revoke_os(fs("os_measurement"));
    caller(OPERATOR, DEPOSIT);
    fails_with(E_OS_NOT_ALLOWED, || register(&mut c, &ok_args()));
    caller(OWNER, 0);
    c.allow_os(fs("os_measurement"));
    c.revoke_compose(fs("compose_hash"));
    caller(OPERATOR, DEPOSIT);
    fails_with(E_COMPOSE_NOT_ALLOWED, || register(&mut c, &ok_args()));
}

#[test]
fn every_single_bit_flip_of_the_quote_is_rejected() {
    let a = ok_args();
    let q = decode_hex(&a.quote).unwrap();
    assert_eq!(q.len(), MOCK_LEN);
    let mut c = fresh();
    caller(OPERATOR, DEPOSIT);
    for i in 0..q.len() {
        let mut m = q.clone();
        m[i] ^= 0x01;
        let expect = match i {
            0..=27 | 632..=635 => E_QUOTE_FORMAT, // header fields checked structurally, sig_data_len
            _ => E_QUOTE_SIG,                    // anything signed, or the signatures / AK themselves
        };
        let mq = encode_hex(&m);
        let msg = panics(|| c.register_instance(mq, a.event_log.clone(), a.app_compose.clone(), a.x25519.clone(), a.ed25519.clone()));
        assert!(msg.starts_with(expect), "byte {i}: {msg}");
    }
    // user_data (28..48) is signed but unconstrained: flipping it still breaks the signature.
    register(&mut c, &a);
}

#[test]
fn every_event_field_mutation_is_rejected() {
    let a = ok_args();
    let mut c = fresh();
    caller(OPERATOR, DEPOSIT);
    let events = a.event_log.as_array().unwrap().clone();
    for (i, ev) in events.iter().enumerate() {
        let muts: Vec<(&str, Value)> = vec![
            ("imr", json!(4)),
            ("event_type", json!(134217728)),
            ("digest", json!(format!("{}0", &ev["digest"].as_str().unwrap()[..95]))),
            ("event", json!(format!("{}x", ev["event"].as_str().unwrap()))),
            ("event_payload", json!(format!("{}00", ev["event_payload"].as_str().unwrap()))),
        ];
        for (field, val) in muts {
            let mut log = a.event_log.clone();
            if log[i][field] == val {
                continue;
            }
            log[i][field] = val;
            let msg = panics(|| c.register_instance(a.quote.clone(), log, a.app_compose.clone(), a.x25519.clone(), a.ed25519.clone()));
            assert!(msg.starts_with(E_EVENT_LOG) || msg.starts_with(E_RTMR3), "event {i} field {field}: {msg}");
        }
    }
    register(&mut c, &a);
}

#[test]
fn host_p256_accepts_high_s_so_the_contract_must_not() {
    let hs = decode_hex(reg_case("sig_high_s_quote_sig")["quote"].as_str().unwrap()).unwrap();
    let q = parse_mock(&hs).unwrap();
    let digest = sha256(q.signed_bytes());
    // The (mock) host accepts the high-S signature, like nearcore's p256_verify ...
    assert!(near_sdk::env::p256_verify(&q.quote_sig(), &digest, &compress(&q.ak_pub())));
    // ... and the contract's verifier rejects it.
    assert!(!verify_low_s(&q.quote_sig(), q.signed_bytes(), &q.ak_pub()));
    assert!(!ecdsa::is_canonical_low_s(&q.quote_sig()));
}

// ---------------- anchor_receipts ----------------

fn anchor_step(name: &str) -> Value {
    fx()["anchors"].as_array().unwrap().iter().find(|s| s["name"] == name).unwrap_or_else(|| panic!("anchor {name}")).clone()
}

fn anchor(c: &mut Registry, s: &Value) -> u64 {
    caller(STRANGER, 0); // anyone may submit
    c.anchor_receipts(
        s["key_hash"].as_str().unwrap().into(),
        s["root"].as_str().unwrap().into(),
        s["first_seq"].as_u64().unwrap(),
        s["count"].as_u64().unwrap(),
        s["sig"].as_str().unwrap().into(),
    )
}

fn registered() -> Registry {
    let mut c = fresh();
    caller(OPERATOR, DEPOSIT);
    register(&mut c, &ok_args());
    take_logs();
    c
}

// ---------------- anchor storage is never paid by the contract ----------------

/// Runs `f` and returns (storage bytes it added, transfers it created).
fn measured<R>(f: impl FnOnce() -> R) -> (R, u64, Vec<(String, u128)>) {
    take_transfers();
    let before = test_host::storage_usage_now();
    let r = f();
    let added = test_host::storage_usage_now() - before;
    (r, added, take_transfers())
}

fn credit(c: &Registry) -> u128 {
    c.get_anchor_credit(fs("key_hash")).parse().unwrap()
}

#[test]
fn anchor_storage_is_paid_from_the_prepaid_credit_when_no_deposit_is_attached() {
    let mut c = registered();
    let before = credit(&c);
    assert_eq!(before, MAX_ANCHOR_CREDIT_YOCTO);
    let (_, added, transfers) = measured(|| anchor(&mut c, &anchor_step("first_batch")));
    assert!(added > 80, "the anchor record is stored");
    assert!(transfers.is_empty());
    assert_eq!(credit(&c), before - u128::from(added) * BYTE_COST, "exactly the added storage is charged to the credit");
}

#[test]
fn anchor_storage_is_paid_by_an_attached_deposit_with_the_excess_refunded() {
    let mut c = registered();
    let before = credit(&c);
    let s = anchor_step("first_batch");
    let (_, added, transfers) = measured(|| {
        caller(STRANGER, DEPOSIT);
        c.anchor_receipts(
            s["key_hash"].as_str().unwrap().into(),
            s["root"].as_str().unwrap().into(),
            s["first_seq"].as_u64().unwrap(),
            s["count"].as_u64().unwrap(),
            s["sig"].as_str().unwrap().into(),
        )
    });
    assert_eq!(credit(&c), before, "credit untouched when the deposit covers the storage");
    assert_eq!(transfers, vec![(STRANGER.to_string(), DEPOSIT - u128::from(added) * BYTE_COST)]);
}

#[test]
fn anchoring_without_credit_or_deposit_fails_with_e_deposit() {
    // Register with the exact storage cost: no credit is kept.
    let cost = instance_storage_cost();
    let mut c = fresh();
    caller(OPERATOR, cost);
    take_transfers();
    register(&mut c, &ok_args());
    assert!(take_transfers().is_empty());
    assert_eq!(credit(&c), 0);
    fails_with(E_DEPOSIT, || anchor(&mut c, &anchor_step("first_batch")));

    // Excess too small to pay for a credit entry is refunded in full, no entry is created.
    let mut c = fresh();
    caller(OPERATOR, cost + u128::from(CREDIT_ENTRY_BYTES) * BYTE_COST);
    let (_, added, transfers) = measured(|| register(&mut c, &ok_args()));
    assert_eq!(u128::from(added) * BYTE_COST, cost);
    assert_eq!(transfers, vec![(OPERATOR.to_string(), u128::from(CREDIT_ENTRY_BYTES) * BYTE_COST)]);
    assert_eq!(credit(&c), 0);
}

#[test]
fn credit_is_capped_and_topped_up_by_re_registration() {
    let mut c = registered();
    anchor(&mut c, &anchor_step("first_batch"));
    let spent = MAX_ANCHOR_CREDIT_YOCTO - credit(&c);
    assert!(spent > 0);
    // A refresh with a deposit tops the credit back up to the cap; the rest is refunded.
    caller(OPERATOR, DEPOSIT);
    let (_, added, transfers) = measured(|| register(&mut c, &ok_args()));
    assert_eq!(added, 0);
    assert_eq!(credit(&c), MAX_ANCHOR_CREDIT_YOCTO);
    assert_eq!(transfers, vec![(OPERATOR.to_string(), DEPOSIT - spent)]);
}

// ---------------- JSON number literals (cross-implementation, fixtures/gen.mjs) ----------------

#[test]
fn event_log_number_literals_match_the_typescript_verifier() {
    let cases = fx()["number_literals"].as_array().expect("number_literals");
    assert!(cases.len() >= 5);
    for case in cases {
        let name = case["name"].as_str().unwrap();
        // Parsed exactly as near-sdk parses call arguments (serde_json → Value).
        let log: Value = serde_json::from_str(case["event_log_json"].as_str().unwrap()).unwrap();
        let mut a = ok_args();
        a.event_log = log.clone();
        let mut c = fresh();
        caller(OPERATOR, DEPOSIT);
        match case["expect"].as_str().unwrap() {
            "ok" => {
                assert_eq!(register(&mut c, &a), fs("key_hash"), "{name}");
            }
            code => {
                fails_with(code, || register(&mut c, &a));
                let q = decode_hex(&a.quote).unwrap();
                let rtmr3 = parse_mock(&q).unwrap().rtmr(3);
                assert_eq!(verify_event_log(&log, &rtmr3).map(|_| ()).unwrap_err().code, code, "{name}");
            }
        }
    }
}

#[test]
fn anchor_vectors_in_order() {
    let mut c = registered();
    let mut ok_count = 0u64;
    let mut seq = 0u64;
    for s in fx()["anchors"].as_array().unwrap() {
        let name = s["name"].as_str().unwrap();
        match s["expect"].as_str().unwrap() {
            "ok" => {
                let t = now_ms();
                let id = anchor(&mut c, s);
                assert_eq!(id, ok_count, "{name}");
                ok_count += 1;
                seq += s["count"].as_u64().unwrap();
                assert_eq!(c.anchor_count(), ok_count);
                let view = c.get_anchor(id).unwrap();
                let expect = AnchorView {
                    id,
                    key_hash: fs("key_hash"),
                    root: s["root"].as_str().unwrap().into(),
                    first_seq: s["first_seq"].as_u64().unwrap(),
                    count: s["count"].as_u64().unwrap(),
                    at_ms: t,
                };
                assert_eq!(view, expect, "{name}");
                assert_eq!(
                    serde_json::to_value(&view).unwrap(),
                    json!({ "id": id, "key_hash": fs("key_hash"), "root": s["root"], "first_seq": s["first_seq"], "count": s["count"], "at_ms": t })
                );
                let ev = assert_single_event(&take_logs(), events::RECEIPTS_ANCHORED);
                assert_eq!(ev["id"], id);
                assert_eq!(ev["root"], s["root"]);
                assert_eq!(c.get_instance(fs("key_hash")).unwrap().next_seq, seq, "{name}");
                advance_ms(5);
            }
            code => {
                fails_with(code, || anchor(&mut c, s));
                assert_eq!(c.anchor_count(), ok_count, "{name}: no anchor stored");
                assert_eq!(c.get_instance(fs("key_hash")).unwrap().next_seq, seq, "{name}: next_seq unchanged");
            }
        }
    }
    assert_eq!(ok_count, 3);
    assert_eq!(c.get_anchor(ok_count), None);
    assert_eq!(c.get_anchor(u64::from(u32::MAX) + 1), None);
}

#[test]
fn anchor_requires_live_policy() {
    let mut c = registered();
    caller(OWNER, 0);
    c.revoke_compose(fs("compose_hash"));
    fails_with(E_COMPOSE_NOT_ALLOWED, || anchor(&mut c, &anchor_step("first_batch")));
    caller(OWNER, 0);
    c.allow_compose(fs("compose_hash"));
    c.revoke_os(fs("os_measurement"));
    fails_with(E_OS_NOT_ALLOWED, || anchor(&mut c, &anchor_step("first_batch")));
    caller(OWNER, 0);
    c.allow_os(fs("os_measurement"));
    assert_eq!(anchor(&mut c, &anchor_step("first_batch")), 0);
}

#[test]
fn anchor_argument_validation() {
    let mut c = registered();
    let s = anchor_step("first_batch");
    let (kh, root, sig) = (s["key_hash"].as_str().unwrap(), s["root"].as_str().unwrap(), s["sig"].as_str().unwrap());
    let call = |c: &mut Registry, kh: &str, root: &str, first: u64, count: u64, sig: &str| {
        c.anchor_receipts(kh.into(), root.into(), first, count, sig.into())
    };
    fails_with(E_BAD_HEX, || call(&mut c, &kh.to_uppercase(), root, 0, 3, sig));
    fails_with(E_ZERO_HASH, || call(&mut c, &"00".repeat(32), root, 0, 3, sig));
    fails_with(E_BAD_HEX, || call(&mut c, kh, &root[..62], 0, 3, sig));
    fails_with(E_ZERO_HASH, || call(&mut c, kh, &"00".repeat(32), 0, 3, sig));
    fails_with(E_BAD_HEX, || call(&mut c, kh, root, 0, 3, &sig.to_uppercase()));
    fails_with(E_BAD_HEX, || call(&mut c, kh, root, 0, 3, &sig[..126]));
    // Any change to a signed field, or to the signature, breaks it.
    let mut flipped = decode_hex(sig).unwrap();
    flipped[10] ^= 1;
    fails_with(E_ANCHOR_SIG, || call(&mut c, kh, root, 0, 3, &encode_hex(&flipped)));
    fails_with(E_ANCHOR_SIG, || call(&mut c, kh, root, 0, 2, sig));
    fails_with(E_ANCHOR_SIG, || call(&mut c, kh, &"11".repeat(32), 0, 3, sig));
    fails_with(E_ANCHOR_SIG, || call(&mut c, kh, root, 0, 3, &"00".repeat(64)));
    assert_eq!(c.anchor_count(), 0);
    assert_eq!(call(&mut c, kh, root, 0, 3, sig), 0);
}

// ---------------- primitive cross-checks ----------------

#[test]
fn primitive_vectors_match_ts() {
    let v = &fx()["vectors"];
    for kv in v["key_hash"].as_array().unwrap() {
        let x = decode_hex_array(kv["x25519"].as_str().unwrap()).unwrap();
        let e = decode_hex_array(kv["ed25519"].as_str().unwrap()).unwrap();
        assert_eq!(encode_hex(&key_hash(&x, &e)), kv["key_hash"].as_str().unwrap());
    }
    for n in v["registration_nonce"].as_array().unwrap() {
        let (cid, oid) = (n["contract_id"].as_str().unwrap(), n["operator_id"].as_str().unwrap());
        assert_eq!(encode_hex(&registration_nonce(cid, oid).unwrap()), n["nonce"].as_str().unwrap(), "{cid} / {oid}");
    }
    for r in v["registration_report_data"].as_array().unwrap() {
        let x = decode_hex_array(r["x25519"].as_str().unwrap()).unwrap();
        let e = decode_hex_array(r["ed25519"].as_str().unwrap()).unwrap();
        let rd = registration_report_data(&x, &e, r["contract_id"].as_str().unwrap(), r["operator_id"].as_str().unwrap()).unwrap();
        assert_eq!(encode_hex(&rd), r["report_data"].as_str().unwrap());
    }
    for d in v["event_digests"].as_array().unwrap() {
        let payload = decode_hex(d["event_payload"].as_str().unwrap()).unwrap();
        assert_eq!(encode_hex(&event_digest(d["event"].as_str().unwrap(), &payload)), d["digest"].as_str().unwrap());
    }
    let rt: [u8; 48] = decode_hex_array(v["rtmr3"]["rtmr3"].as_str().unwrap()).unwrap();
    let boot = verify_event_log(&v["rtmr3"]["events"], &rt).unwrap();
    assert_eq!(encode_hex(&boot.compose_hash), fs("compose_hash"));
    assert_eq!(&boot.app_id[..], &boot.compose_hash[..20]);
    let mut wrong = rt;
    wrong[0] ^= 1;
    assert_eq!(verify_event_log(&v["rtmr3"]["events"], &wrong).unwrap_err().code, E_RTMR3);
    // Replay by hand equals the TS replay.
    let mut acc = [0u8; 48];
    for e in v["rtmr3"]["events"].as_array().unwrap() {
        acc = sha384_concat(&[&acc, &decode_hex(e["digest"].as_str().unwrap()).unwrap()]);
    }
    assert_eq!(acc, rt);
    // AK certificate from MockRoot.certifyAk verifies under the root.
    let ak: [u8; 64] = decode_hex_array(v["ak_pub"].as_str().unwrap()).unwrap();
    let cert: [u8; 64] = decode_hex_array(v["ak_cert"].as_str().unwrap()).unwrap();
    let root: [u8; 64] = decode_hex_array(&fs("root_p256")).unwrap();
    let other: [u8; 64] = decode_hex_array(&fs("other_root_p256")).unwrap();
    assert!(verify_low_s(&cert, &ak_cert_message(&ak), &root));
    assert!(!verify_low_s(&cert, &ak_cert_message(&ak), &other));
    // Anchor message layout.
    for s in fx()["anchors"].as_array().unwrap().iter().filter(|s| s["name"] != "other_contract") {
        let m = anchor_message(
            "registry.test.near",
            &decode_hex_array(s["key_hash"].as_str().unwrap()).unwrap(),
            &decode_hex_array(s["root"].as_str().unwrap()).unwrap(),
            s["first_seq"].as_u64().unwrap(),
            s["count"].as_u64().unwrap(),
        );
        assert_eq!(encode_hex(&m), s["msg"].as_str().unwrap());
    }
    // OS measurement of the TS mock report.
    let q = decode_hex(&ok_args().quote).unwrap();
    assert_eq!(encode_hex(&parse_mock(&q).unwrap().os_measurement()), fs("os_measurement"));
}

#[test]
fn deposit_amounts_are_exact_tokens() {
    // Guards the constant used in assertions above against near-sdk changes.
    assert_eq!(near_sdk::env::storage_byte_cost(), NearToken::from_yoctonear(BYTE_COST));
}

// ---------------- operator organizations (SPEC §7 rev 1.2) ----------------

#[test]
fn org_id_syntax_matches_the_spec_regex() {
    let max = format!("a{}", "-".repeat(MAX_ORG_ID_LEN - 1));
    for ok in ["a", "0", "org-a", "acme-hosting.eu", "a_b.c-d", "9lives", "a.", "a-", "a_", max.as_str()] {
        assert!(is_valid_org_id(ok), "{ok:?} should be valid");
    }
    let too_long = "o".repeat(MAX_ORG_ID_LEN + 1);
    for bad in [
        "", "Org-A", "-org", ".org", "_org", "org a", "org/a", "org:a", "org\n", " org", "orgé", "org\u{0}", "ÿ",
        "a\u{212a}", // KELVIN SIGN: lowercases to 'k' under Unicode rules, must not pass the ASCII check
        too_long.as_str(),
    ] {
        assert!(!is_valid_org_id(bad), "{bad:?} should be invalid");
    }
}

#[test]
fn approve_operator_validates_org_id_and_leaves_no_trace_on_failure() {
    let mut c = fresh_bare();
    caller(OWNER, 0);
    let before = test_host::storage_usage_now();
    for bad in ["", "Org-A", "-org", "org a", &"o".repeat(65), "org/a"] {
        let msg = panics(|| c.approve_operator(OPERATOR.parse().unwrap(), bad.to_string()));
        assert!(msg.starts_with(E_BAD_INPUT), "{bad:?}: {msg:?}");
        if !bad.is_empty() {
            assert!(!msg.contains(bad), "panic message must not echo the input: {msg:?}");
        }
    }
    assert_eq!(c.get_operator(OPERATOR.into()), None);
    assert_eq!(test_host::storage_usage_now(), before);
    assert!(take_logs().is_empty());
}

#[test]
fn approve_change_and_revoke_operator_with_events() {
    let mut c = fresh_bare();
    caller(OWNER, 0);
    c.approve_operator(OPERATOR.parse().unwrap(), "acme-hosting.eu".into());
    assert_eq!(
        assert_single_event(&take_logs(), events::OPERATOR_APPROVED),
        json!({ "account_id": OPERATOR, "org_id": "acme-hosting.eu", "previous_org_id": null })
    );
    assert_eq!(c.get_operator(OPERATOR.into()).as_deref(), Some("acme-hosting.eu"));
    assert_eq!(c.get_operator(STRANGER.into()), None, "per account");

    // Re-approve = change of organization.
    c.approve_operator(OPERATOR.parse().unwrap(), "acme-2".into());
    assert_eq!(
        assert_single_event(&take_logs(), events::OPERATOR_APPROVED),
        json!({ "account_id": OPERATOR, "org_id": "acme-2", "previous_org_id": "acme-hosting.eu" })
    );
    assert_eq!(c.get_operator(OPERATOR.into()).as_deref(), Some("acme-2"));

    c.approve_operator(STRANGER.parse().unwrap(), "other-org".into());
    take_logs();
    c.revoke_operator(OPERATOR.parse().unwrap());
    assert_eq!(
        assert_single_event(&take_logs(), events::OPERATOR_REVOKED),
        json!({ "account_id": OPERATOR, "previous_org_id": "acme-2" })
    );
    assert_eq!(c.get_operator(OPERATOR.into()), None);
    assert_eq!(c.get_operator(STRANGER.into()).as_deref(), Some("other-org"), "revocation is per account");

    // Revoking an account that is not approved is a no-op (event with previous_org_id null).
    c.revoke_operator(OPERATOR.parse().unwrap());
    assert_eq!(
        assert_single_event(&take_logs(), events::OPERATOR_REVOKED),
        json!({ "account_id": OPERATOR, "previous_org_id": null })
    );
    assert_eq!(c.get_operator(OPERATOR.into()), None);
}

#[test]
fn operator_storage_is_released_on_revoke() {
    let mut c = fresh_bare();
    caller(OWNER, 0);
    let before = test_host::storage_usage_now();
    c.approve_operator(OPERATOR.parse().unwrap(), "org-a".into());
    let one = test_host::storage_usage_now() - before;
    assert!(one > 0);
    c.approve_operator(OPERATOR.parse().unwrap(), "org-b".into()); // same length: a change adds nothing
    assert_eq!(test_host::storage_usage_now() - before, one);
    c.revoke_operator(OPERATOR.parse().unwrap());
    assert_eq!(test_host::storage_usage_now(), before);
    assert!(take_transfers().is_empty(), "owner methods move no tokens");
}

#[test]
fn get_operator_never_panics_on_malformed_account_ids() {
    let mut c = fresh_bare();
    caller(OWNER, 0);
    c.approve_operator(OPERATOR.parse().unwrap(), "org-a".into());
    for bad in ["", "UPPER.near", "a", "has space.near", "x".repeat(65).as_str(), "..", "op@near"] {
        assert_eq!(c.get_operator(bad.to_string()), None, "{bad:?}");
    }
}

#[test]
fn get_instance_carries_the_operators_live_org_id() {
    let mut c = registered();
    let kh = fs("key_hash");
    assert_eq!(c.get_instance(kh.clone()).unwrap().org_id, None);
    assert_eq!(serde_json::to_value(c.get_instance(kh.clone()).unwrap()).unwrap()["org_id"], Value::Null);

    caller(OWNER, 0);
    c.approve_operator(STRANGER.parse().unwrap(), "not-the-operator".into());
    assert_eq!(c.get_instance(kh.clone()).unwrap().org_id, None, "only the registering operator's org counts");

    c.approve_operator(OPERATOR.parse().unwrap(), "acme-hosting.eu".into());
    let rec = c.get_instance(kh.clone()).unwrap();
    assert_eq!(rec.org_id.as_deref(), Some("acme-hosting.eu"));
    assert_eq!(serde_json::to_value(&rec).unwrap()["org_id"], "acme-hosting.eu");

    c.approve_operator(OPERATOR.parse().unwrap(), "acme-2".into());
    assert_eq!(c.get_instance(kh.clone()).unwrap().org_id.as_deref(), Some("acme-2"), "re-approve = change, live");

    // Only the bound operator can refresh (rev 1.3); a refresh keeps its org.
    advance_ms(1_000);
    caller(STRANGER, 0);
    fails_with(E_REPORT_DATA, || register(&mut c, &ok_args()));
    caller(OPERATOR, 0);
    register(&mut c, &ok_args());
    assert_eq!(c.get_instance(kh.clone()).unwrap().org_id.as_deref(), Some("acme-2"));

    caller(OWNER, 0);
    c.revoke_operator(OPERATOR.parse().unwrap());
    assert_eq!(c.get_instance(kh.clone()).unwrap().org_id, None);

    // Expired instances stay invisible regardless of the operator's org.
    c.approve_operator(OPERATOR.parse().unwrap(), "acme-3".into());
    advance_ms(DEFAULT_INSTANCE_TTL_MS);
    assert_eq!(c.get_instance(kh), None);
}

#[test]
fn approving_an_operator_does_not_affect_registration_or_anchoring_policy() {
    let mut c = fresh();
    caller(OWNER, 0);
    c.approve_operator(OPERATOR.parse().unwrap(), "org-a".into());
    take_logs();
    // Org approval is metadata for clients, not an authorization: unapproved accounts still register
    // (with a quote their enclave bound to them, rev 1.3).
    caller(STRANGER, DEPOSIT);
    let kh = register(&mut c, &args_of(reg_case("ok_bound_to_and_submitted_by_stranger")));
    assert_eq!(c.get_instance(kh.clone()).unwrap().operator.as_str(), STRANGER);
    assert_eq!(c.get_instance(kh).unwrap().org_id, None);
    caller(OPERATOR, DEPOSIT);
    let kh = register(&mut c, &ok_args());
    assert_eq!(c.get_instance(kh).unwrap().org_id.as_deref(), Some("org-a"));
    anchor(&mut c, &anchor_step("first_batch"));
}

// ---------------- operator-bound registration (SPEC §5/§7 rev 1.3) ----------------

#[test]
fn registration_nonce_is_length_prefixed_and_bounded() {
    let n = |c: &str, o: &str| registration_nonce(c, o);
    // u8(len) prefixes make the (contract, operator) split unambiguous.
    assert_ne!(n("ab", "c"), n("a", "bc"));
    assert_ne!(n(OPERATOR, "registry.test.near"), n("registry.test.near", OPERATOR), "order matters");
    let parts: [&[u8]; 5] = [b"PLR-v1/register/2", &[2], b"ab", &[1], b"c"];
    let manual = sha256(&parts.concat());
    assert_eq!(n("ab", "c"), Some(manual));
    // Both ids must be 1..=64 bytes (the NEAR account id limit); fail closed otherwise.
    let max = "x".repeat(MAX_ACCOUNT_ID_BYTES);
    let over = "x".repeat(MAX_ACCOUNT_ID_BYTES + 1);
    assert!(n(&max, &max).is_some());
    for (c, o) in [("", OPERATOR), ("registry.test.near", ""), (over.as_str(), OPERATOR), ("registry.test.near", over.as_str())] {
        assert_eq!(n(c, o), None, "{c:?} / {o:?}");
        assert_eq!(registration_report_data(&[1; 32], &[2; 32], c, o), None);
    }
    // 256-byte ids would wrap a u8 length: still rejected, never truncated.
    assert_eq!(n(&"x".repeat(256 + 2), "ab"), None);
}

/// The quote's report_data (bytes 568..632) of a fixture case.
fn report_data_of(case: &str) -> [u8; 64] {
    parse_mock(&decode_hex(reg_case(case)["quote"].as_str().unwrap()).unwrap()).unwrap().report_data()
}

#[test]
fn a_registration_quote_only_registers_for_the_operator_it_is_bound_to() {
    let kh = fs("key_hash");
    // Bound to OPERATOR, submitted by STRANGER: E_REPORT_DATA, no trace, no transfer.
    let mut c = fresh();
    caller(STRANGER, DEPOSIT);
    let before = test_host::storage_usage_now();
    take_transfers();
    fails_with(E_REPORT_DATA, || register(&mut c, &ok_args()));
    assert_eq!(c.get_instance(kh.clone()), None);
    assert_eq!(test_host::storage_usage_now(), before);
    assert!(take_logs().is_empty() && take_transfers().is_empty());
    // Nor by the registry contract itself or the owner.
    for who in ["registry.test.near", OWNER] {
        caller(who, DEPOSIT);
        fails_with(E_REPORT_DATA, || register(&mut c, &ok_args()));
    }
    // Bound to STRANGER, submitted by OPERATOR (the wrong-operator quote): E_REPORT_DATA.
    caller(OPERATOR, DEPOSIT);
    fails_with(E_REPORT_DATA, || register(&mut c, &args_of(reg_case("report_data_stranger_quote_submitted_by_operator"))));
    // The bound operator succeeds and becomes the instance's operator.
    register(&mut c, &ok_args());
    assert_eq!(c.get_instance(kh.clone()).unwrap().operator.as_str(), OPERATOR);
    // The quote binds exactly what registration_report_data(keys, contract, OPERATOR) says.
    let a = ok_args();
    let expected = registration_report_data(
        &decode_hex_array(&a.x25519).unwrap(),
        &decode_hex_array(&a.ed25519).unwrap(),
        "registry.test.near",
        OPERATOR,
    )
    .unwrap();
    assert_eq!(report_data_of("ok_mock_tdx_attester"), expected);
}

#[test]
fn the_same_quote_is_rejected_by_another_registry_account() {
    // Deploying the same code under another account id changes current_account_id, hence the nonce.
    let mut c = fresh();
    set_ctx(|x| x.current_account_id = "other.test.near".into());
    caller(OPERATOR, DEPOSIT);
    fails_with(E_REPORT_DATA, || register(&mut c, &ok_args()));
    // ... while a quote bound to that account (and OPERATOR) registers there.
    let kh = register(&mut c, &args_of(reg_case("report_data_other_registry")));
    assert_eq!(kh, fs("key_hash"));
}

#[test]
fn session_domain_quotes_never_register() {
    // What /v1/attestation produces: key_hash ‖ SHA256("PLR-v1/session-nonce" ‖ nonce) — even when the client picks
    // the registration nonce itself as its nonce (the hijack the rev 1.3 change closes), for either submitter.
    let session = fx()["vectors"]["session_report_data_of_registration_nonce"].as_str().unwrap();
    assert_eq!(encode_hex(&report_data_of("report_data_session_quote_of_registration_nonce")), session);
    let reg = encode_hex(&report_data_of("ok_mock_tdx_attester"));
    assert_eq!(session[..64], reg[..64], "same keys");
    assert_ne!(session[64..], reg[64..], "different purpose");
    for (case, who) in [
        ("report_data_session_nonce", OPERATOR),
        ("report_data_session_quote_of_registration_nonce", OPERATOR),
        ("report_data_session_quote_of_registration_nonce_by_stranger", STRANGER),
    ] {
        let mut c = fresh();
        caller(who, DEPOSIT);
        fails_with(E_REPORT_DATA, || register(&mut c, &args_of(reg_case(case))));
        assert_eq!(c.get_instance(fs("key_hash")), None, "{case}");
    }
}

#[test]
fn rev_1_2_registration_nonces_are_no_longer_accepted() {
    // rev 1.2: report_data[32..] = SHA256("PLR-v1/register" ‖ contract_id), no operator binding.
    let parts: [&[u8]; 2] = [b"PLR-v1/register", b"registry.test.near"];
    let old = sha256(&parts.concat());
    assert_eq!(report_data_of("report_data_rev12_registration_nonce")[32..], old);
    for case in ["report_data_rev12_registration_nonce", "report_data_rev12_label_with_prefixes", "report_data_no_length_prefixes"] {
        let mut c = fresh();
        caller(OPERATOR, DEPOSIT);
        fails_with(E_REPORT_DATA, || register(&mut c, &args_of(reg_case(case))));
    }
}

// ---------------- rev 1.3 upgrade: fail closed, then drop every old compose approval ----------------

/// A rev 1.2 state as it would sit on chain: `registered()`'s instance/anchors/credit/operators plus a compose
/// approval under the rev 1.2 `AllowedCompose` prefix. Returns its borsh bytes (also written as the contract state).
fn rev12_state() -> Vec<u8> {
    let mut c = registered();
    caller(OWNER, 0);
    c.approve_operator(OPERATOR.parse().unwrap(), "org-a".into());
    assert_eq!(anchor(&mut c, &anchor_step("first_batch")), 0);
    // `fresh()` approved the build under the rev 1.3 prefix; a real rev 1.2 state has nothing there.
    caller(OWNER, 0);
    c.revoke_compose(fs("compose_hash"));
    let mut old_compose = LookupSet::new(StorageKey::AllowedCompose);
    old_compose.insert(decode_hex_array::<32>(&fs("compose_hash")).unwrap());
    let old = RegistryRev12 {
        owner: c.owner,
        pending_owner: c.pending_owner,
        root_kind: c.root_kind,
        root_p256: c.root_p256,
        allowed_compose: old_compose,
        allowed_os: c.allowed_os,
        instances: c.instances,
        anchors: c.anchors,
        instance_ttl_ms: c.instance_ttl_ms,
        anchor_credit: c.anchor_credit,
        operators: c.operators,
    };
    near_sdk::env::state_write(&old);
    take_logs();
    near_sdk::borsh::to_vec(&old).unwrap()
}

#[test]
fn rev_1_2_state_does_not_load_until_migrated() {
    // Redeploying rev 1.3 code over a rev 1.2 registry must not keep old builds approved: the state no longer
    // deserializes, so every method (incl. register_instance) fails until the contract account runs `migrate`.
    let raw = rev12_state();
    assert!(near_sdk::borsh::from_slice::<Registry>(&raw).is_err(), "rev 1.2 state must not load as rev 1.3");
    let c = fresh();
    let new_raw = near_sdk::borsh::to_vec(&c).unwrap();
    assert!(near_sdk::borsh::from_slice::<RegistryRev12>(&new_raw).is_err());
    assert_eq!(near_sdk::borsh::from_slice::<Registry>(&new_raw).unwrap().get_state_rev(), STATE_REV);
    assert_eq!(c.get_state_rev(), 3);
}

#[test]
fn migrate_empties_the_compose_allowlist_and_keeps_everything_else() {
    rev12_state();
    caller("registry.test.near", 0);
    let mut m = Registry::migrate();
    assert_single_event(&take_logs(), "compose_allowlist_reset");
    assert_eq!(m.get_state_rev(), STATE_REV);
    // No pre-rev-1.3 build stays approved ...
    assert!(!m.is_compose_allowed(fs("compose_hash")));
    assert!(!m.is_allowed(fs("compose_hash"), fs("os_measurement")));
    // ... everything else survives.
    assert_eq!(m.get_owner().as_str(), OWNER);
    assert_eq!(m.get_root().p256, fs("root_p256"));
    assert!(m.is_os_allowed(fs("os_measurement")));
    assert_eq!(m.get_instance_ttl_ms(), DEFAULT_INSTANCE_TTL_MS);
    assert_eq!(m.anchor_count(), 1);
    assert_eq!(m.get_operator(OPERATOR.into()).as_deref(), Some("org-a"));
    let inst = m.get_instance(fs("key_hash")).expect("instance kept");
    assert_eq!(inst.operator.as_str(), OPERATOR);
    assert_eq!(inst.next_seq, anchor_step("first_batch")["count"].as_u64().unwrap());
    assert!(credit(&m) > 0);
    // Old instances can neither anchor nor (re-)register until the owner approves a rev 1.3 build.
    fails_with(E_COMPOSE_NOT_ALLOWED, || anchor(&mut m, &anchor_step("second_batch")));
    caller(OPERATOR, DEPOSIT);
    fails_with(E_COMPOSE_NOT_ALLOWED, || register(&mut m, &ok_args()));
    caller(OWNER, 0);
    m.allow_compose(fs("compose_hash"));
    caller(OPERATOR, DEPOSIT);
    assert_eq!(register(&mut m, &ok_args()), fs("key_hash"));
    assert_eq!(m.get_instance(fs("key_hash")).unwrap().operator.as_str(), OPERATOR);
}

#[test]
fn migrate_runs_once_and_only_on_a_rev_1_2_state() {
    rev12_state();
    caller("registry.test.near", 0);
    let m = Registry::migrate();
    near_sdk::env::state_write(&m);
    fails_with(E_BAD_INPUT, Registry::migrate); // already rev 1.3
    test_host::reset();
    caller("registry.test.near", 0);
    fails_with(E_BAD_INPUT, Registry::migrate); // no state at all
    near_sdk::env::storage_write(b"STATE", b"garbage");
    fails_with(E_BAD_INPUT, Registry::migrate);
}
