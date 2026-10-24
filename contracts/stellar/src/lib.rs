//! PLR registry on Stellar Soroban — tier B (SPEC-CHAINS §1, §10; same semantics as the EVM registry of §9).
//!
//! What the chain enforces: owner policy (compose / OS allowlists, MOCK|INTEL root, operator organizations, two-step
//! ownership transfer), registration only by **owner-approved operators** that authorize the call themselves
//! (`operator.require_auth()`), the registration quote's on-chain format and `report_data` binding
//! (`keyHash ‖ registrationNonce(contract_id(), operator strkey)`, SPEC §5 rev 1.3), the quote itself stored on-chain,
//! and anchors with contiguous `first_seq` posted only by the instance's operator while its build is still allowed.
//!
//! What it does NOT do (tier B): verify the quote signature or the anchor's Ed25519 signature. Clients verify both
//! (SPEC-CHAINS §2) from the stored quote / signature.
//!
//! Storage: configuration in instance storage, every item in persistent storage; each write extends the TTL of what it
//! wrote and of the entries the read path needs (contract instance, compose/OS/operator entries of a registration) to
//! at least the instance TTL (assuming ≥ 1 s per ledger) plus a week of 5 s ledgers, capped at the network maximum.
#![no_std]

use soroban_sdk::{
    contract, contracterror, contractevent, contractimpl, contracttype, panic_with_error, Address, Bytes, BytesN, Env, String,
};

/// SPEC-CHAINS §10 error codes (variant names are the PLR codes; clients map the number back to the name).
#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
#[allow(non_camel_case_types)]
pub enum Error {
    E_UNAUTHORIZED = 1,
    E_ZERO_HASH = 2,
    E_BAD_INPUT = 3,
    E_OPERATOR_UNAPPROVED = 4,
    E_REPORT_DATA = 5,
    E_QUOTE_FORMAT = 6,
    E_SEQ = 7,
    E_INSTANCE_NOT_REGISTERED = 8,
    E_COMPOSE_NOT_ALLOWED = 9,
}

/// Mock/real TDX quote v4 layout (SPEC §2): only the fields the contract checks.
pub const QUOTE_LEN: u32 = 828;
pub const QUOTE_VERSION: u8 = 4;
pub const ATT_KEY_TYPE_ECDSA_P256: u8 = 2;
pub const TEE_TYPE_TDX: u8 = 0x81;
pub const REPORT_DATA_OFF: u32 = 568;
pub const MAX_ANCHOR_COUNT: u64 = 10_000;
pub const ROOT_MOCK: u32 = 1;
pub const ROOT_INTEL: u32 = 2;
/// `utf8("PLR-v1")` (SPEC §5 key hash domain).
pub const DOMAIN: &[u8] = b"PLR-v1";
/// SPEC §5 rev 1.3 registration-nonce domain.
pub const REGISTRATION_NONCE_DOMAIN: &[u8] = b"PLR-v1/register/2";
/// Strkeys (G… / C…) are 56 characters; `"stellar:" ‖ C…` is 64 bytes (SPEC-CHAINS §3: ≤ 64).
pub const STRKEY_LEN: usize = 56;
const CONTRACT_ID_PREFIX: &[u8] = b"stellar:";
/// TTL headroom on top of the instance TTL: one week of 5 s ledgers.
const TTL_HEADROOM_LEDGERS: u64 = 120_960;

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InstanceView {
    pub compose_hash: BytesN<32>,
    pub os_measurement: BytesN<32>,
    pub x25519: BytesN<32>,
    pub ed25519: BytesN<32>,
    pub operator: Address,
    pub registered_at_ms: u64,
    pub expires_at_ms: u64,
    pub next_seq: u64,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AnchorView {
    pub key_hash: BytesN<32>,
    pub root: BytesN<32>,
    pub first_seq: u64,
    pub count: u64,
    pub at_ms: u64,
    pub sig: BytesN<64>,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DataKey {
    // instance storage
    Owner,
    PendingOwner,
    Root,
    TtlMs,
    AnchorCount,
    // persistent storage
    Compose(BytesN<32>),
    Os(BytesN<32>),
    Operator(Address),
    Instance(BytesN<32>),
    Quote(BytesN<32>),
    Anchor(u64),
}

// ------------------------------------------------------------------------------------------------ events

#[contractevent]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ComposeSet {
    #[topic]
    pub hash: BytesN<32>,
    pub allowed: bool,
}

#[contractevent]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OsSet {
    #[topic]
    pub hash: BytesN<32>,
    pub allowed: bool,
}

#[contractevent]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RootSet {
    pub kind: u32,
    pub p256: BytesN<64>,
}

#[contractevent]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OperatorApproved {
    #[topic]
    pub operator: Address,
    pub org_id: String,
}

#[contractevent]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OperatorRevoked {
    #[topic]
    pub operator: Address,
}

#[contractevent]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OwnerProposed {
    pub next: Address,
}

#[contractevent]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OwnerChanged {
    pub owner: Address,
}

#[contractevent]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InstanceRegistered {
    #[topic]
    pub key_hash: BytesN<32>,
    pub operator: Address,
    pub expires_at_ms: u64,
    pub refreshed: bool,
}

#[contractevent]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReceiptsAnchored {
    #[topic]
    pub key_hash: BytesN<32>,
    pub id: u64,
    pub first_seq: u64,
    pub count: u64,
}

// ------------------------------------------------------------------------------------------------ helpers

fn is_zero32(h: &BytesN<32>) -> bool {
    h.to_array().iter().all(|b| *b == 0)
}

/// SPEC §7 rev 1.2 `^[a-z0-9][a-z0-9._-]{0,63}$`.
pub fn is_org_id(s: &String) -> bool {
    let n = s.len() as usize;
    if n == 0 || n > 64 {
        return false;
    }
    let mut buf = [0u8; 64];
    s.copy_into_slice(&mut buf[..n]);
    buf[..n].iter().enumerate().all(|(i, c)| {
        c.is_ascii_lowercase() || c.is_ascii_digit() || (i > 0 && (*c == b'.' || *c == b'_' || *c == b'-'))
    })
}

/// The 56-character strkey of an address (G… account or C… contract).
fn strkey(a: &Address) -> [u8; STRKEY_LEN] {
    let s = a.to_string();
    let mut out = [0u8; STRKEY_LEN];
    if s.len() as usize != STRKEY_LEN {
        panic_with_error!(a.env(), Error::E_BAD_INPUT);
    }
    s.copy_into_slice(&mut out);
    out
}

/// `"stellar:" ‖ C…` as bytes (64).
fn contract_id_bytes(env: &Env) -> [u8; 64] {
    let mut out = [0u8; 64];
    out[..8].copy_from_slice(CONTRACT_ID_PREFIX);
    out[8..].copy_from_slice(&strkey(&env.current_contract_address()));
    out
}

/// `SHA256("PLR-v1" ‖ x25519 ‖ ed25519)` (SPEC §5).
pub fn key_hash(env: &Env, x25519: &BytesN<32>, ed25519: &BytesN<32>) -> BytesN<32> {
    let mut b = Bytes::from_slice(env, DOMAIN);
    b.extend_from_array(&x25519.to_array());
    b.extend_from_array(&ed25519.to_array());
    env.crypto().sha256(&b).to_bytes()
}

/// `SHA256("PLR-v1/register/2" ‖ u8(len c) ‖ c ‖ u8(len o) ‖ o)` (SPEC §5 rev 1.3); ids are 1..64 bytes.
pub fn registration_nonce(env: &Env, contract_id: &[u8], operator_id: &[u8]) -> BytesN<32> {
    if contract_id.is_empty() || contract_id.len() > 64 || operator_id.is_empty() || operator_id.len() > 64 {
        panic_with_error!(env, Error::E_BAD_INPUT);
    }
    let mut b = Bytes::from_slice(env, REGISTRATION_NONCE_DOMAIN);
    b.push_back(contract_id.len() as u8);
    b.extend_from_slice(contract_id);
    b.push_back(operator_id.len() as u8);
    b.extend_from_slice(operator_id);
    env.crypto().sha256(&b).to_bytes()
}

fn byte(q: &Bytes, i: u32) -> u8 {
    q.get(i).unwrap_or(0)
}

/// Quote v4, ECDSA-P256 attestation key, TDX TEE, exact MOCK length (SPEC-CHAINS §9 rules, reused by §10).
fn check_quote_format(q: &Bytes) -> Result<(), Error> {
    let ok = q.len() == QUOTE_LEN
        && byte(q, 0) == QUOTE_VERSION
        && byte(q, 1) == 0
        && byte(q, 2) == ATT_KEY_TYPE_ECDSA_P256
        && byte(q, 3) == 0
        && byte(q, 4) == TEE_TYPE_TDX
        && byte(q, 5) == 0
        && byte(q, 6) == 0
        && byte(q, 7) == 0;
    if ok {
        Ok(())
    } else {
        Err(Error::E_QUOTE_FORMAT)
    }
}

fn now_ms(env: &Env) -> u64 {
    env.ledger().timestamp().saturating_mul(1000)
}

fn ttl_ms(env: &Env) -> u64 {
    env.storage().instance().get(&DataKey::TtlMs).unwrap_or(0)
}

/// Ledgers every written / read-path entry is kept alive for (≥ instance TTL at ≥ 1 s per ledger, capped by the network).
fn keep_ledgers(env: &Env) -> u32 {
    let want = (ttl_ms(env) / 1000).saturating_add(TTL_HEADROOM_LEDGERS);
    let max = env.storage().max_ttl() as u64;
    want.min(max).min(u32::MAX as u64) as u32
}

fn bump_instance(env: &Env) {
    let t = keep_ledgers(env);
    env.storage().instance().extend_ttl(t, t);
}

fn bump(env: &Env, key: &DataKey) {
    let p = env.storage().persistent();
    if p.has(key) {
        let t = keep_ledgers(env);
        p.extend_ttl(key, t, t);
    }
}

fn set_persistent<V: soroban_sdk::IntoVal<Env, soroban_sdk::Val>>(env: &Env, key: &DataKey, v: &V) {
    env.storage().persistent().set(key, v);
    bump(env, key);
}

fn owner(env: &Env) -> Address {
    match env.storage().instance().get(&DataKey::Owner) {
        Some(o) => o,
        None => panic_with_error!(env, Error::E_UNAUTHORIZED),
    }
}

fn require_owner(env: &Env) {
    owner(env).require_auth();
    bump_instance(env);
}

fn check_root(kind: u32, p256: &BytesN<64>) -> Result<(), Error> {
    if kind != ROOT_MOCK && kind != ROOT_INTEL {
        return Err(Error::E_BAD_INPUT);
    }
    if p256.to_array().iter().all(|b| *b == 0) {
        return Err(Error::E_BAD_INPUT);
    }
    Ok(())
}

fn live_instance(env: &Env, key_hash: &BytesN<32>) -> Option<InstanceView> {
    let rec: InstanceView = env.storage().persistent().get(&DataKey::Instance(key_hash.clone()))?;
    if rec.expires_at_ms <= now_ms(env) {
        None
    } else {
        Some(rec)
    }
}

fn set_allowed(env: &Env, key: DataKey, allowed: bool) {
    if allowed {
        set_persistent(env, &key, &true);
    } else {
        env.storage().persistent().remove(&key);
    }
}

// ------------------------------------------------------------------------------------------------ contract

#[contract]
pub struct PlrRegistry;

#[contractimpl]
impl PlrRegistry {
    pub fn __constructor(env: Env, owner: Address, root_kind: u32, root_p256: BytesN<64>, instance_ttl_ms: u64) {
        if let Err(e) = check_root(root_kind, &root_p256) {
            panic_with_error!(&env, e);
        }
        if instance_ttl_ms == 0 || instance_ttl_ms > 365 * 86_400_000 {
            panic_with_error!(&env, Error::E_BAD_INPUT);
        }
        let s = env.storage().instance();
        s.set(&DataKey::Owner, &owner);
        s.set(&DataKey::Root, &(root_kind, root_p256));
        s.set(&DataKey::TtlMs, &instance_ttl_ms);
        s.set(&DataKey::AnchorCount, &0u64);
        bump_instance(&env);
    }

    // ---------------------------------------------------------------------------------------- owner

    pub fn allow_compose(env: Env, h: BytesN<32>) -> Result<(), Error> {
        require_owner(&env);
        if is_zero32(&h) {
            return Err(Error::E_ZERO_HASH);
        }
        set_allowed(&env, DataKey::Compose(h.clone()), true);
        ComposeSet { hash: h, allowed: true }.publish(&env);
        Ok(())
    }

    pub fn revoke_compose(env: Env, h: BytesN<32>) -> Result<(), Error> {
        require_owner(&env);
        if is_zero32(&h) {
            return Err(Error::E_ZERO_HASH);
        }
        set_allowed(&env, DataKey::Compose(h.clone()), false);
        ComposeSet { hash: h, allowed: false }.publish(&env);
        Ok(())
    }

    pub fn allow_os(env: Env, h: BytesN<32>) -> Result<(), Error> {
        require_owner(&env);
        if is_zero32(&h) {
            return Err(Error::E_ZERO_HASH);
        }
        set_allowed(&env, DataKey::Os(h.clone()), true);
        OsSet { hash: h, allowed: true }.publish(&env);
        Ok(())
    }

    pub fn revoke_os(env: Env, h: BytesN<32>) -> Result<(), Error> {
        require_owner(&env);
        if is_zero32(&h) {
            return Err(Error::E_ZERO_HASH);
        }
        set_allowed(&env, DataKey::Os(h.clone()), false);
        OsSet { hash: h, allowed: false }.publish(&env);
        Ok(())
    }

    pub fn set_root(env: Env, kind: u32, p256: BytesN<64>) -> Result<(), Error> {
        require_owner(&env);
        check_root(kind, &p256)?;
        env.storage().instance().set(&DataKey::Root, &(kind, p256.clone()));
        RootSet { kind, p256 }.publish(&env);
        Ok(())
    }

    pub fn approve_operator(env: Env, op: Address, org_id: String) -> Result<(), Error> {
        require_owner(&env);
        if !is_org_id(&org_id) {
            return Err(Error::E_BAD_INPUT);
        }
        set_persistent(&env, &DataKey::Operator(op.clone()), &org_id);
        OperatorApproved { operator: op, org_id }.publish(&env);
        Ok(())
    }

    pub fn revoke_operator(env: Env, op: Address) -> Result<(), Error> {
        require_owner(&env);
        env.storage().persistent().remove(&DataKey::Operator(op.clone()));
        OperatorRevoked { operator: op }.publish(&env);
        Ok(())
    }

    pub fn propose_owner(env: Env, next: Address) -> Result<(), Error> {
        require_owner(&env);
        env.storage().instance().set(&DataKey::PendingOwner, &next);
        OwnerProposed { next }.publish(&env);
        Ok(())
    }

    pub fn accept_owner(env: Env) -> Result<(), Error> {
        let next: Address = env.storage().instance().get(&DataKey::PendingOwner).ok_or(Error::E_UNAUTHORIZED)?;
        next.require_auth();
        let s = env.storage().instance();
        s.set(&DataKey::Owner, &next);
        s.remove(&DataKey::PendingOwner);
        bump_instance(&env);
        OwnerChanged { owner: next }.publish(&env);
        Ok(())
    }

    // ---------------------------------------------------------------------------------------- operator

    /// Registers (or, by its first registrant, refreshes) the instance `keyHash(x25519, ed25519)` with its registration
    /// quote. A record whose operator the owner no longer approves may be taken over by another approved operator. The quote signature is not verified here (tier B): clients verify the stored quote (SPEC-CHAINS §2).
    pub fn register_instance(
        env: Env,
        operator: Address,
        x25519: BytesN<32>,
        ed25519: BytesN<32>,
        compose_hash: BytesN<32>,
        os_measurement: BytesN<32>,
        quote: Bytes,
    ) -> Result<(), Error> {
        operator.require_auth();
        let op_key = DataKey::Operator(operator.clone());
        if !env.storage().persistent().has(&op_key) {
            return Err(Error::E_OPERATOR_UNAPPROVED);
        }
        if is_zero32(&compose_hash) || is_zero32(&os_measurement) {
            return Err(Error::E_ZERO_HASH);
        }
        check_quote_format(&quote)?;
        let kh = key_hash(&env, &x25519, &ed25519);
        let nonce = registration_nonce(&env, &contract_id_bytes(&env), &strkey(&operator));
        let rd = quote.slice(REPORT_DATA_OFF..REPORT_DATA_OFF + 64);
        let mut want = Bytes::from_array(&env, &kh.to_array());
        want.extend_from_array(&nonce.to_array());
        if rd != want {
            return Err(Error::E_REPORT_DATA);
        }

        let now = now_ms(&env);
        let expires = now.saturating_add(ttl_ms(&env));
        let inst_key = DataKey::Instance(kh.clone());
        let prev: Option<InstanceView> = env.storage().persistent().get(&inst_key);
        // A key belongs to its first registrant while the owner approves that operator (SPEC-CHAINS §1: tier B accepts
        // records only from live-approved operators). Once the owner revokes it, another approved operator may take
        // the key over as a fresh record (next_seq 0): the owner's remedy against a squatter that registered someone
        // else's public key hash with an unsigned quote.
        let prev = match prev {
            Some(p) if p.operator != operator && !env.storage().persistent().has(&DataKey::Operator(p.operator.clone())) => None,
            other => other,
        };
        let refreshed = prev.is_some();
        let rec = match prev {
            Some(p) => {
                if p.operator != operator {
                    return Err(Error::E_UNAUTHORIZED);
                }
                InstanceView { compose_hash: compose_hash.clone(), os_measurement: os_measurement.clone(), expires_at_ms: expires, ..p }
            }
            None => InstanceView {
                compose_hash: compose_hash.clone(),
                os_measurement: os_measurement.clone(),
                x25519,
                ed25519,
                operator: operator.clone(),
                registered_at_ms: now,
                expires_at_ms: expires,
                next_seq: 0,
            },
        };
        set_persistent(&env, &inst_key, &rec);
        set_persistent(&env, &DataKey::Quote(kh.clone()), &quote);
        // Keep what readers of this instance need alive at least as long as the registration.
        bump_instance(&env);
        bump(&env, &op_key);
        bump(&env, &DataKey::Compose(compose_hash));
        bump(&env, &DataKey::Os(os_measurement));
        InstanceRegistered { key_hash: kh, operator, expires_at_ms: expires, refreshed }.publish(&env);
        Ok(())
    }

    /// Appends an anchor of `count` receipts from `first_seq` (= the instance's `next_seq`). Returns the anchor id.
    /// `sig` (Ed25519 over SPEC §7 `anchorMessage`) is stored for clients to verify (tier B).
    pub fn anchor_receipts(
        env: Env,
        operator: Address,
        key_hash: BytesN<32>,
        root: BytesN<32>,
        first_seq: u64,
        count: u64,
        sig: BytesN<64>,
    ) -> Result<u64, Error> {
        operator.require_auth();
        let mut rec = live_instance(&env, &key_hash).ok_or(Error::E_INSTANCE_NOT_REGISTERED)?;
        if rec.operator != operator {
            return Err(Error::E_UNAUTHORIZED);
        }
        let compose_key = DataKey::Compose(rec.compose_hash.clone());
        let os_key = DataKey::Os(rec.os_measurement.clone());
        let p = env.storage().persistent();
        if !p.has(&compose_key) || !p.has(&os_key) {
            return Err(Error::E_COMPOSE_NOT_ALLOWED);
        }
        if first_seq != rec.next_seq {
            return Err(Error::E_SEQ);
        }
        if count < 1 || count > MAX_ANCHOR_COUNT {
            return Err(Error::E_BAD_INPUT);
        }
        let s = env.storage().instance();
        let id: u64 = s.get(&DataKey::AnchorCount).unwrap_or(0);
        rec.next_seq = first_seq.checked_add(count).ok_or(Error::E_SEQ)?;
        let inst_key = DataKey::Instance(key_hash.clone());
        set_persistent(&env, &inst_key, &rec);
        set_persistent(&env, &DataKey::Anchor(id), &AnchorView { key_hash: key_hash.clone(), root, first_seq, count, at_ms: now_ms(&env), sig });
        s.set(&DataKey::AnchorCount, &(id + 1));
        bump_instance(&env);
        bump(&env, &DataKey::Quote(key_hash.clone()));
        bump(&env, &DataKey::Operator(operator));
        bump(&env, &compose_key);
        bump(&env, &os_key);
        ReceiptsAnchored { key_hash, id, first_seq, count }.publish(&env);
        Ok(id)
    }

    // ---------------------------------------------------------------------------------------- views

    /// `"stellar:" + current_contract_address strkey` (SPEC-CHAINS §3).
    pub fn contract_id(env: Env) -> String {
        String::from_bytes(&env, &contract_id_bytes(&env))
    }

    pub fn owner(env: Env) -> Address {
        owner(&env)
    }

    pub fn get_root(env: Env) -> (u32, BytesN<64>) {
        match env.storage().instance().get(&DataKey::Root) {
            Some(r) => r,
            None => panic_with_error!(&env, Error::E_BAD_INPUT),
        }
    }

    pub fn is_compose_allowed(env: Env, h: BytesN<32>) -> bool {
        !is_zero32(&h) && env.storage().persistent().has(&DataKey::Compose(h))
    }

    pub fn is_os_allowed(env: Env, h: BytesN<32>) -> bool {
        !is_zero32(&h) && env.storage().persistent().has(&DataKey::Os(h))
    }

    pub fn get_operator(env: Env, op: Address) -> Option<String> {
        env.storage().persistent().get(&DataKey::Operator(op))
    }

    /// The instance record, or None if unknown or expired (ledger time).
    pub fn get_instance(env: Env, key_hash: BytesN<32>) -> Option<InstanceView> {
        live_instance(&env, &key_hash)
    }

    pub fn get_registration_quote(env: Env, key_hash: BytesN<32>) -> Option<Bytes> {
        env.storage().persistent().get(&DataKey::Quote(key_hash))
    }

    pub fn anchor_count(env: Env) -> u64 {
        env.storage().instance().get(&DataKey::AnchorCount).unwrap_or(0)
    }

    pub fn get_anchor(env: Env, id: u64) -> Option<AnchorView> {
        env.storage().persistent().get(&DataKey::Anchor(id))
    }
}

#[cfg(test)]
mod vectors;
#[cfg(test)]
mod test;
