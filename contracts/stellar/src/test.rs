//! Rule-by-rule tests of the Soroban registry (SPEC-CHAINS §9/§10), with vectors from @plr/shared (src/vectors.rs).
extern crate std;

use crate::vectors as v;
use crate::*;
use soroban_sdk::testutils::storage::{Instance as _, Persistent as _};
use soroban_sdk::testutils::{Address as _, Events as _, Ledger as _, MockAuth, MockAuthInvoke};
use soroban_sdk::{Address, Bytes, BytesN, Env, IntoVal, String};

const TTL_MS: u64 = 86_400_000;
const T0: u64 = 1_800_000_000; // ledger seconds

struct T {
    env: Env,
    c: PlrRegistryClient<'static>,
    id: Address,
    owner: Address,
    op: Address,
    stranger: Address,
}

fn b32(env: &Env, a: &[u8; 32]) -> BytesN<32> {
    BytesN::from_array(env, a)
}
fn h(env: &Env, n: u8) -> BytesN<32> {
    BytesN::from_array(env, &[n; 32])
}
fn sig(env: &Env) -> BytesN<64> {
    BytesN::from_array(env, &v::ANCHOR_SIG)
}

fn setup() -> T {
    let env = Env::default();
    env.ledger().set_timestamp(T0);
    env.mock_all_auths();
    let id = Address::from_str(&env, v::CONTRACT);
    let owner = Address::generate(&env);
    let root = BytesN::from_array(&env, &v::ROOT_P256);
    env.register_at(&id, PlrRegistry, (owner.clone(), ROOT_MOCK, root, TTL_MS));
    let c = PlrRegistryClient::new(&env, &id);
    let op = Address::from_str(&env, v::OPERATOR);
    let stranger = Address::from_str(&env, v::STRANGER);
    T { env, c, id, owner, op, stranger }
}

impl T {
    fn approve(&self, a: &Address, org: &str) {
        self.c.approve_operator(a, &String::from_str(&self.env, org));
    }
    fn quote(&self) -> Bytes {
        Bytes::from_array(&self.env, &v::QUOTE)
    }
    fn register_with(&self, op: &Address, q: &Bytes) -> Result<(), Error> {
        let e = &self.env;
        match self.c.try_register_instance(op, &b32(e, &v::X25519), &b32(e, &v::ED25519), &b32(e, &v::COMPOSE_HASH), &h(e, 7), q) {
            Ok(Ok(())) => Ok(()),
            Err(Ok(err)) => Err(err),
            other => panic!("unexpected {:?}", other),
        }
    }
    fn register(&self) -> Result<(), Error> {
        self.register_with(&self.op, &self.quote())
    }
    fn ready(&self) {
        self.approve(&self.op, "org-a");
        self.c.allow_compose(&b32(&self.env, &v::COMPOSE_HASH));
        self.c.allow_os(&h(&self.env, 7));
        self.register().unwrap();
    }
    fn kh(&self) -> BytesN<32> {
        b32(&self.env, &v::KEY_HASH)
    }
    fn anchor(&self, op: &Address, first: u64, count: u64) -> Result<u64, Error> {
        let e = &self.env;
        match self.c.try_anchor_receipts(op, &self.kh(), &b32(e, &v::ANCHOR_ROOT), &first, &count, &sig(e)) {
            Ok(Ok(id)) => Ok(id),
            Err(Ok(err)) => Err(err),
            other => panic!("unexpected {:?}", other),
        }
    }
}

// ------------------------------------------------------------------------------------------------ vectors

#[test]
fn contract_id_matches_spec_and_ts() {
    let t = setup();
    assert_eq!(t.c.contract_id(), String::from_str(&t.env, v::CONTRACT_ID));
    assert_eq!(v::CONTRACT_ID.len(), 64);
}

#[test]
fn key_hash_and_nonce_match_plr_shared() {
    let t = setup();
    let e = &t.env;
    assert_eq!(key_hash(e, &b32(e, &v::X25519), &b32(e, &v::ED25519)), b32(e, &v::KEY_HASH));
    let n = registration_nonce(e, v::CONTRACT_ID.as_bytes(), v::OPERATOR.as_bytes());
    assert_eq!(n, b32(e, &v::NONCE_OPERATOR));
    let n2 = registration_nonce(e, v::CONTRACT_ID.as_bytes(), v::STRANGER.as_bytes());
    assert_eq!(n2, b32(e, &v::NONCE_STRANGER));
    // The TS quote's report_data is exactly keyHash ‖ nonce(contract, operator).
    assert_eq!(&v::QUOTE[568..600], &v::KEY_HASH);
    assert_eq!(&v::QUOTE[600..632], &v::NONCE_OPERATOR);
    assert_eq!(v::QUOTE.len(), 828);
}

// ------------------------------------------------------------------------------------------------ owner policy

#[test]
fn constructor_state() {
    let t = setup();
    assert_eq!(t.c.get_root(), (ROOT_MOCK, BytesN::from_array(&t.env, &v::ROOT_P256)));
    assert_eq!(t.c.owner(), t.owner);
    assert_eq!(t.c.anchor_count(), 0);
}

#[test]
fn constructor_rejects_bad_root_and_ttl() {
    let env = Env::default();
    let owner = Address::generate(&env);
    let root = BytesN::from_array(&env, &v::ROOT_P256);
    let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        env.register(PlrRegistry, (owner.clone(), 3u32, root.clone(), TTL_MS));
    }));
    assert!(r.is_err());
    let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        env.register(PlrRegistry, (owner.clone(), ROOT_MOCK, root.clone(), 0u64));
    }));
    assert!(r.is_err());
}

#[test]
fn allowlists() {
    let t = setup();
    let e = &t.env;
    assert!(!t.c.is_compose_allowed(&h(e, 1)));
    t.c.allow_compose(&h(e, 1));
    assert!(t.c.is_compose_allowed(&h(e, 1)));
    assert!(!t.c.is_os_allowed(&h(e, 1)));
    t.c.revoke_compose(&h(e, 1));
    assert!(!t.c.is_compose_allowed(&h(e, 1)));
    t.c.allow_os(&h(e, 2));
    assert!(t.c.is_os_allowed(&h(e, 2)));
    t.c.revoke_os(&h(e, 2));
    assert!(!t.c.is_os_allowed(&h(e, 2)));
}

#[test]
fn zero_hashes_refused() {
    let t = setup();
    let z = h(&t.env, 0);
    assert_eq!(t.c.try_allow_compose(&z), Err(Ok(Error::E_ZERO_HASH)));
    assert_eq!(t.c.try_revoke_compose(&z), Err(Ok(Error::E_ZERO_HASH)));
    assert_eq!(t.c.try_allow_os(&z), Err(Ok(Error::E_ZERO_HASH)));
    assert_eq!(t.c.try_revoke_os(&z), Err(Ok(Error::E_ZERO_HASH)));
    assert!(!t.c.is_compose_allowed(&z));
}

#[test]
fn owner_methods_require_owner_auth() {
    let t = setup();
    let e = &t.env;
    t.c.allow_compose(&h(e, 1));
    // The owner's authorization was the one required.
    let auths = e.auths();
    assert_eq!(auths.len(), 1);
    assert_eq!(auths[0].0, t.owner);

    // A stranger's own signature is not the owner's: refused by the host.
    let stranger = Address::generate(e);
    let x = h(e, 9);
    let r = t
        .c
        .mock_auths(&[MockAuth {
            address: &stranger,
            invoke: &MockAuthInvoke { contract: &t.id, fn_name: "allow_compose", args: (x.clone(),).into_val(e), sub_invokes: &[] },
        }])
        .try_allow_compose(&x);
    assert!(r.is_err());
    assert!(!t.c.is_compose_allowed(&x));
    let r = t
        .c
        .mock_auths(&[MockAuth {
            address: &stranger,
            invoke: &MockAuthInvoke {
                contract: &t.id,
                fn_name: "approve_operator",
                args: (stranger.clone(), String::from_str(e, "evil")).into_val(e),
                sub_invokes: &[],
            },
        }])
        .try_approve_operator(&stranger, &String::from_str(e, "evil"));
    assert!(r.is_err());
    assert_eq!(t.c.get_operator(&stranger), None);
}

#[test]
fn set_root_rules() {
    let t = setup();
    let e = &t.env;
    let p = BytesN::from_array(e, &[5u8; 64]);
    t.c.set_root(&ROOT_INTEL, &p);
    assert_eq!(t.c.get_root(), (ROOT_INTEL, p.clone()));
    assert_eq!(t.c.try_set_root(&0, &p), Err(Ok(Error::E_BAD_INPUT)));
    assert_eq!(t.c.try_set_root(&3, &p), Err(Ok(Error::E_BAD_INPUT)));
    assert_eq!(t.c.try_set_root(&ROOT_MOCK, &BytesN::from_array(e, &[0u8; 64])), Err(Ok(Error::E_BAD_INPUT)));
}

#[test]
fn operator_orgs() {
    let t = setup();
    let e = &t.env;
    assert_eq!(t.c.get_operator(&t.op), None);
    t.approve(&t.op, "org-a");
    assert_eq!(t.c.get_operator(&t.op), Some(String::from_str(e, "org-a")));
    t.approve(&t.op, "org.b_1-x");
    assert_eq!(t.c.get_operator(&t.op), Some(String::from_str(e, "org.b_1-x")));
    t.c.revoke_operator(&t.op);
    assert_eq!(t.c.get_operator(&t.op), None);
    let long_ok = "a".repeat(64);
    t.approve(&t.op, &long_ok);
    for bad in ["", "-a", ".a", "Org", "a b", "a/b", &"a".repeat(65), "é"] {
        assert_eq!(t.c.try_approve_operator(&t.op, &String::from_str(e, bad)), Err(Ok(Error::E_BAD_INPUT)), "{bad:?}");
    }
}

#[test]
fn two_step_owner_transfer() {
    let t = setup();
    let e = &t.env;
    let next = Address::generate(e);
    assert_eq!(t.c.try_accept_owner(), Err(Ok(Error::E_UNAUTHORIZED)));
    t.c.propose_owner(&next);
    assert_eq!(t.c.owner(), t.owner);
    t.c.accept_owner();
    assert_eq!(e.auths()[0].0, next);
    assert_eq!(t.c.owner(), next);
    // the old owner is no longer asked for (the new one is)
    t.c.allow_compose(&h(e, 3));
    assert_eq!(e.auths()[0].0, next);
    assert_eq!(t.c.try_accept_owner(), Err(Ok(Error::E_UNAUTHORIZED)));
}

// ------------------------------------------------------------------------------------------------ registration

#[test]
fn register_happy_path_stores_quote() {
    let t = setup();
    t.ready();
    let e = &t.env;
    assert_eq!(e.auths()[0].0, t.op);
    let i = t.c.get_instance(&t.kh()).unwrap();
    assert_eq!(i.operator, t.op);
    assert_eq!(i.compose_hash, b32(e, &v::COMPOSE_HASH));
    assert_eq!(i.os_measurement, h(e, 7));
    assert_eq!(i.x25519, b32(e, &v::X25519));
    assert_eq!(i.ed25519, b32(e, &v::ED25519));
    assert_eq!(i.registered_at_ms, T0 * 1000);
    assert_eq!(i.expires_at_ms, T0 * 1000 + TTL_MS);
    assert_eq!(i.next_seq, 0);
    assert_eq!(t.c.get_registration_quote(&t.kh()), Some(t.quote()));
    t.register().unwrap(); // refresh: publishes InstanceRegistered
    assert!(!e.events().all().events().is_empty());
}

#[test]
fn register_requires_approved_operator() {
    let t = setup();
    assert_eq!(t.register(), Err(Error::E_OPERATOR_UNAPPROVED));
    t.approve(&t.op, "org-a");
    t.c.revoke_operator(&t.op);
    assert_eq!(t.register(), Err(Error::E_OPERATOR_UNAPPROVED));
    assert_eq!(t.c.get_instance(&t.kh()), None);
}

#[test]
fn register_requires_operator_auth() {
    let t = setup();
    t.approve(&t.op, "org-a");
    let e = &t.env;
    // Only another account signs: the operator's require_auth fails.
    let stranger = Address::generate(e);
    let args = (t.op.clone(), b32(e, &v::X25519), b32(e, &v::ED25519), b32(e, &v::COMPOSE_HASH), h(e, 7), t.quote());
    let r = t
        .c
        .mock_auths(&[MockAuth {
            address: &stranger,
            invoke: &MockAuthInvoke { contract: &t.id, fn_name: "register_instance", args: args.clone().into_val(e), sub_invokes: &[] },
        }])
        .try_register_instance(&args.0, &args.1, &args.2, &args.3, &args.4, &args.5);
    assert!(r.is_err());
    assert_eq!(t.c.get_instance(&t.kh()), None);
}

#[test]
fn register_quote_format() {
    let t = setup();
    t.approve(&t.op, "org-a");
    let e = &t.env;
    let mut short = v::QUOTE.to_vec();
    short.pop();
    assert_eq!(t.register_with(&t.op, &Bytes::from_slice(e, &short)), Err(Error::E_QUOTE_FORMAT));
    let mut long = v::QUOTE.to_vec();
    long.push(0);
    assert_eq!(t.register_with(&t.op, &Bytes::from_slice(e, &long)), Err(Error::E_QUOTE_FORMAT));
    for (off, val) in [(0usize, 5u8), (1, 1), (2, 3), (3, 1), (4, 0x80), (5, 1), (7, 1)] {
        let mut q = v::QUOTE;
        q[off] = val;
        assert_eq!(t.register_with(&t.op, &Bytes::from_slice(e, &q)), Err(Error::E_QUOTE_FORMAT), "offset {off}");
    }
}

#[test]
fn register_report_data_binding() {
    let t = setup();
    t.approve(&t.op, "org-a");
    t.approve(&t.stranger, "org-s");
    let e = &t.env;
    // Bound to the operator but submitted by another (approved) account.
    assert_eq!(t.register_with(&t.stranger, &t.quote()), Err(Error::E_REPORT_DATA));
    // Bound to the stranger, submitted by the operator.
    assert_eq!(t.register_with(&t.op, &Bytes::from_array(e, &v::QUOTE_STRANGER)), Err(Error::E_REPORT_DATA));
    // Key hash or nonce byte flipped.
    for off in [568usize, 599, 600, 631] {
        let mut q = v::QUOTE;
        q[off] ^= 1;
        assert_eq!(t.register_with(&t.op, &Bytes::from_slice(e, &q)), Err(Error::E_REPORT_DATA), "offset {off}");
    }
    // Other keys than the quote's.
    let r = t.c.try_register_instance(&t.op, &h(e, 1), &b32(e, &v::ED25519), &b32(e, &v::COMPOSE_HASH), &h(e, 7), &t.quote());
    assert_eq!(r, Err(Ok(Error::E_REPORT_DATA)));
    // Same quote, but the registry at another address (the nonce binds contract_id()).
    let other = e.register(PlrRegistry, (t.owner.clone(), ROOT_MOCK, BytesN::from_array(e, &v::ROOT_P256), TTL_MS));
    let c2 = PlrRegistryClient::new(e, &other);
    c2.approve_operator(&t.op, &String::from_str(e, "org-a"));
    let r = c2.try_register_instance(&t.op, &b32(e, &v::X25519), &b32(e, &v::ED25519), &b32(e, &v::COMPOSE_HASH), &h(e, 7), &t.quote());
    assert_eq!(r, Err(Ok(Error::E_REPORT_DATA)));
}

#[test]
fn register_zero_measurements_refused() {
    let t = setup();
    t.approve(&t.op, "org-a");
    let e = &t.env;
    let r = t.c.try_register_instance(&t.op, &b32(e, &v::X25519), &b32(e, &v::ED25519), &h(e, 0), &h(e, 7), &t.quote());
    assert_eq!(r, Err(Ok(Error::E_ZERO_HASH)));
    let r = t.c.try_register_instance(&t.op, &b32(e, &v::X25519), &b32(e, &v::ED25519), &b32(e, &v::COMPOSE_HASH), &h(e, 0), &t.quote());
    assert_eq!(r, Err(Ok(Error::E_ZERO_HASH)));
}

#[test]
fn refresh_keeps_next_seq_and_extends() {
    let t = setup();
    t.ready();
    t.anchor(&t.op, 0, 3).unwrap();
    t.env.ledger().set_timestamp(T0 + 100);
    t.register().unwrap();
    let i = t.c.get_instance(&t.kh()).unwrap();
    assert_eq!(i.next_seq, 3);
    assert_eq!(i.registered_at_ms, T0 * 1000);
    assert_eq!(i.expires_at_ms, (T0 + 100) * 1000 + TTL_MS);
}

#[test]
fn instance_expires() {
    let t = setup();
    t.ready();
    t.env.ledger().set_timestamp(T0 + TTL_MS / 1000 - 1);
    assert!(t.c.get_instance(&t.kh()).is_some());
    t.env.ledger().set_timestamp(T0 + TTL_MS / 1000);
    assert_eq!(t.c.get_instance(&t.kh()), None);
    assert_eq!(t.anchor(&t.op, 0, 1), Err(Error::E_INSTANCE_NOT_REGISTERED));
    // the first registrant re-registers (expired record refreshed)
    t.register().unwrap();
    assert!(t.c.get_instance(&t.kh()).is_some());
}

// ------------------------------------------------------------------------------------------------ anchors

#[test]
fn anchors_contiguous() {
    let t = setup();
    t.ready();
    let e = &t.env;
    assert_eq!(t.anchor(&t.op, 0, 3), Ok(0));
    assert_eq!(t.anchor(&t.op, 0, 3), Err(Error::E_SEQ));
    assert_eq!(t.anchor(&t.op, 4, 1), Err(Error::E_SEQ));
    assert_eq!(t.anchor(&t.op, 3, 0), Err(Error::E_BAD_INPUT));
    assert_eq!(t.anchor(&t.op, 3, 10_001), Err(Error::E_BAD_INPUT));
    assert_eq!(t.anchor(&t.op, 3, 10_000), Ok(1));
    assert_eq!(t.c.anchor_count(), 2);
    assert_eq!(t.c.get_instance(&t.kh()).unwrap().next_seq, 10_003);
    let a = t.c.get_anchor(&0).unwrap();
    assert_eq!(a.key_hash, t.kh());
    assert_eq!(a.root, b32(e, &v::ANCHOR_ROOT));
    assert_eq!(a.first_seq, 0);
    assert_eq!(a.count, 3);
    assert_eq!(a.at_ms, T0 * 1000);
    assert_eq!(a.sig, sig(e));
    assert_eq!(t.c.get_anchor(&2), None);
}

#[test]
fn anchors_only_by_the_instance_operator() {
    let t = setup();
    t.ready();
    t.approve(&t.stranger, "org-s");
    assert_eq!(t.anchor(&t.stranger, 0, 1), Err(Error::E_UNAUTHORIZED));
    // Key owned by the first registrant: the stranger cannot take it over.
    assert_eq!(t.register_with(&t.stranger, &Bytes::from_array(&t.env, &v::QUOTE_STRANGER)), Err(Error::E_UNAUTHORIZED));
    assert_eq!(t.c.get_instance(&t.kh()).unwrap().operator, t.op);
}

#[test]
fn owner_revocation_frees_a_squatted_key() {
    let t = setup();
    let e = &t.env;
    t.c.allow_compose(&b32(e, &v::COMPOSE_HASH));
    t.c.allow_os(&h(e, 7));
    // the stranger (approved) squats the honest instance's public key hash with an unsigned quote bound to itself
    t.approve(&t.stranger, "org-squat");
    t.register_with(&t.stranger, &Bytes::from_array(e, &v::QUOTE_STRANGER)).unwrap();
    assert_eq!(t.anchor(&t.stranger, 0, 7), Ok(0));
    t.approve(&t.op, "org-a");
    assert_eq!(t.register(), Err(Error::E_UNAUTHORIZED));
    // expiry alone does not free the key while the squatter stays approved
    e.ledger().set_timestamp(T0 + 2 * 86_400);
    assert_eq!(t.register(), Err(Error::E_UNAUTHORIZED));
    // after the owner revokes the squatter the honest operator takes the key over as a fresh record
    t.c.revoke_operator(&t.stranger);
    t.register().unwrap();
    let i = t.c.get_instance(&t.kh()).unwrap();
    assert_eq!(i.operator, t.op);
    assert_eq!(i.next_seq, 0);
    assert_eq!(i.registered_at_ms, (T0 + 2 * 86_400) * 1000);
    assert_eq!(i.expires_at_ms, (T0 + 2 * 86_400) * 1000 + TTL_MS);
    assert_eq!(t.c.get_registration_quote(&t.kh()), Some(t.quote()));
    assert_eq!(t.anchor(&t.op, 0, 1), Ok(1));
    // re-approving the squatter does not give the key back
    t.approve(&t.stranger, "org-squat");
    assert_eq!(t.register_with(&t.stranger, &Bytes::from_array(e, &v::QUOTE_STRANGER)), Err(Error::E_UNAUTHORIZED));
    assert_eq!(t.anchor(&t.stranger, 1, 1), Err(Error::E_UNAUTHORIZED));
}

#[test]
fn anchors_require_allowed_build() {
    let t = setup();
    t.ready();
    let e = &t.env;
    t.c.revoke_compose(&b32(e, &v::COMPOSE_HASH));
    assert_eq!(t.anchor(&t.op, 0, 1), Err(Error::E_COMPOSE_NOT_ALLOWED));
    t.c.allow_compose(&b32(e, &v::COMPOSE_HASH));
    t.c.revoke_os(&h(e, 7));
    assert_eq!(t.anchor(&t.op, 0, 1), Err(Error::E_COMPOSE_NOT_ALLOWED));
    t.c.allow_os(&h(e, 7));
    assert_eq!(t.anchor(&t.op, 0, 1), Ok(0));
}

#[test]
fn anchor_unknown_instance() {
    let t = setup();
    t.approve(&t.op, "org-a");
    assert_eq!(t.anchor(&t.op, 0, 1), Err(Error::E_INSTANCE_NOT_REGISTERED));
}

#[test]
fn error_codes_are_spec_numbers() {
    assert_eq!(Error::E_UNAUTHORIZED as u32, 1);
    assert_eq!(Error::E_ZERO_HASH as u32, 2);
    assert_eq!(Error::E_BAD_INPUT as u32, 3);
    assert_eq!(Error::E_OPERATOR_UNAPPROVED as u32, 4);
    assert_eq!(Error::E_REPORT_DATA as u32, 5);
    assert_eq!(Error::E_QUOTE_FORMAT as u32, 6);
    assert_eq!(Error::E_SEQ as u32, 7);
    assert_eq!(Error::E_INSTANCE_NOT_REGISTERED as u32, 8);
    assert_eq!(Error::E_COMPOSE_NOT_ALLOWED as u32, 9);
}

#[test]
fn ttl_extended_on_writes() {
    let t = setup();
    t.ready();
    let e = &t.env;
    let want = (TTL_MS / 1000) as u32;
    e.as_contract(&t.id, || {
        let p = e.storage().persistent();
        for k in [
            DataKey::Instance(t.kh()),
            DataKey::Quote(t.kh()),
            DataKey::Operator(t.op.clone()),
            DataKey::Compose(b32(e, &v::COMPOSE_HASH)),
            DataKey::Os(h(e, 7)),
        ] {
            assert!(p.get_ttl(&k) >= want, "{k:?}");
        }
        assert!(e.storage().instance().get_ttl() >= want);
    });
}
