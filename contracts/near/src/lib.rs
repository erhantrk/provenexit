//! PLR-v1 registry contract (SPEC §7): owner-governed allowlist of compose hashes and OS measurements, on-chain
//! verification of MOCK TDX registration quotes, and Ed25519-authorised Merkle anchoring of receipts.
//!
//! Every failure panics with a SPEC error code (see [`errors`]); panic messages never echo caller input.

pub mod binding;
pub mod bytes;
mod ctx;
pub mod ecdsa;
pub mod errors;
pub mod events;
pub mod eventlog;
pub mod hash;
pub mod quote;
pub mod verify;
mod verify_tdx;

#[cfg(test)]
mod test_host;
#[cfg(test)]
mod tests;

use dcap_qvl::QuoteCollateralV3;
use near_sdk::serde_json::{json, Value};
use near_sdk::store::{LookupMap, LookupSet, Vector};
use near_sdk::{env, near, AccountId, BorshStorageKey, NearToken, PanicOnDefault, Promise};

use crate::binding::anchor_message;
use crate::bytes::{decode_hex, decode_hex_array, encode_hex, is_all_zero};
use crate::errors::*;
use crate::verify::{verify_registration, Policy, Registration, RootKind, Verified};
use crate::verify_tdx::{now_secs, verify_registration_tdx, TdxRegistration};

/// Default instance TTL: 24 h.
pub const DEFAULT_INSTANCE_TTL_MS: u64 = 86_400_000;
/// Upper bound for the instance TTL: 365 days.
pub const MAX_INSTANCE_TTL_MS: u64 = 365 * 86_400_000;
/// `quote` argument bound: 4 KiB of hex (SPEC §7 NEAR notes).
pub const MAX_QUOTE_HEX_LEN: usize = 4096;
/// `app_compose` argument bound: 8 KiB (SPEC §7 NEAR notes).
pub const MAX_APP_COMPOSE_LEN: usize = 8 * 1024;
/// `anchor_receipts` batch size bounds.
pub const MAX_ANCHOR_COUNT: u64 = 10_000;
/// Upper bound of the per-instance anchor storage prepayment kept from a registration deposit (0.05 NEAR,
/// roughly 35 anchors); any deposit beyond registration storage + this credit is refunded.
pub const MAX_ANCHOR_CREDIT_YOCTO: u128 = 50_000_000_000_000_000_000_000;
/// Maximum `org_id` length (SPEC §7 rev 1.2: `^[a-z0-9][a-z0-9._-]{0,63}$`).
pub const MAX_ORG_ID_LEN: usize = 64;
/// Intel SGX Root CA public key, x‖y (SPEC-TDX §0). A registry with root_kind INTEL must store exactly this.
pub const INTEL_ROOT_P256_HEX: &str = "0ba9c4c0c0c86193a3fe23d6b02cda10a8bbd4e88e48b4458561a36e705525f567918e2edc88e40d860bd0cc4ee26aacc988e505a953558c453f6b0904ae7394";
/// `quote` argument bound of `register_instance_tdx`, in hex chars (SPEC-TDX §1.1: 8 192 bytes).
pub const MAX_TDX_QUOTE_HEX_LEN: usize = 16_384;
/// `collateral` argument bound of `register_instance_tdx`, in bytes of JSON text (SPEC-TDX §1.2).
pub const MAX_COLLATERAL_LEN: usize = 32_768;
/// `app_compose` argument bound of `register_instance_tdx`: the dstack app-compose text (SPEC-TDX §1.4).
pub const MAX_DSTACK_COMPOSE_LEN: usize = 32_768;
/// Intel TCB statuses `register_instance_tdx` accepts (SPEC-TDX §0).
pub const ACCEPTED_TCB_STATUSES: [&str; 2] = ["UpToDate", "SWHardeningNeeded"];

#[derive(BorshStorageKey)]
#[near(serializers = [borsh])]
enum StorageKey {
    AllowedCompose,
    AllowedOs,
    Instances,
    Anchors,
    AnchorCredit,
    /// rev 1.2. Appended last: borsh enum indices of the existing prefixes must not move.
    Operators,
    /// rev 1.3: the compose allowlist starts empty under a new prefix, so no pre-rev-1.3 build stays approved
    /// (see [`Registry::migrate`]). The rev ≤ 1.2 `AllowedCompose` entries are orphaned, never read again.
    AllowedComposeRev13,
}

/// State layout revision written by this code (SPEC rev 1.3). The trailing `state_rev` field makes a rev ≤ 1.2
/// state fail to deserialize, so redeploying this code over an old registry fails closed until [`Registry::migrate`].
pub const STATE_REV: u8 = 3;

/// The rev 1.2 contract state, read only by [`Registry::migrate`]. Field order = the rev 1.2 borsh layout.
#[near(serializers = [borsh])]
struct RegistryRev12 {
    owner: AccountId,
    pending_owner: Option<AccountId>,
    root_kind: RootKind,
    root_p256: [u8; 64],
    allowed_compose: LookupSet<[u8; 32]>,
    allowed_os: LookupSet<[u8; 32]>,
    instances: LookupMap<[u8; 32], Instance>,
    anchors: Vector<Anchor>,
    instance_ttl_ms: u64,
    anchor_credit: LookupMap<[u8; 32], u128>,
    operators: LookupMap<AccountId, String>,
}

/// A registered router instance (SPEC §7 `Instance`).
#[near(serializers = [borsh])]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Instance {
    pub compose_hash: [u8; 32],
    pub os_measurement: [u8; 32],
    pub x25519: [u8; 32],
    pub ed25519: [u8; 32],
    pub operator: AccountId,
    pub registered_at_ms: u64,
    pub expires_at_ms: u64,
    pub next_seq: u64,
}

/// An anchored receipt batch (SPEC §7 `Anchor`; `id` is its index).
#[near(serializers = [borsh])]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Anchor {
    pub key_hash: [u8; 32],
    pub root: [u8; 32],
    pub first_seq: u64,
    pub count: u64,
    pub at_ms: u64,
}

/// `get_root` view.
#[near(serializers = [json])]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RootView {
    pub kind: String,
    pub p256: String,
}

/// `get_tdx_policy` view (SPEC-TDX §2.4): what `register_instance_tdx` enforces, whatever the stored root is.
#[near(serializers = [json])]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TdxPolicyView {
    pub intel_root_p256: String,
    pub accepted_tcb_statuses: Vec<String>,
    pub dcap_qvl_version: String,
}

/// `get_instance` view (SPEC §10 `InstanceRecord`; u64 fields as JSON numbers).
#[near(serializers = [json])]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InstanceView {
    pub compose_hash: String,
    pub os_measurement: String,
    pub x25519: String,
    pub ed25519: String,
    pub operator: AccountId,
    /// rev 1.2: the operator's organization at read time (live lookup in `operators`), or `null`.
    pub org_id: Option<String>,
    pub registered_at_ms: u64,
    pub expires_at_ms: u64,
    pub next_seq: u64,
}

/// `get_anchor` view.
#[near(serializers = [json])]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AnchorView {
    pub id: u64,
    pub key_hash: String,
    pub root: String,
    pub first_seq: u64,
    pub count: u64,
    pub at_ms: u64,
}

impl InstanceView {
    /// The view of `i`, with `org_id` = the operator's organization as approved right now.
    fn new(i: &Instance, org_id: Option<String>) -> Self {
        Self {
            compose_hash: encode_hex(&i.compose_hash),
            os_measurement: encode_hex(&i.os_measurement),
            x25519: encode_hex(&i.x25519),
            ed25519: encode_hex(&i.ed25519),
            operator: i.operator.clone(),
            org_id,
            registered_at_ms: i.registered_at_ms,
            expires_at_ms: i.expires_at_ms,
            next_seq: i.next_seq,
        }
    }
}

#[near(contract_state)]
#[derive(PanicOnDefault)]
pub struct Registry {
    owner: AccountId,
    pending_owner: Option<AccountId>,
    root_kind: RootKind,
    root_p256: [u8; 64],
    allowed_compose: LookupSet<[u8; 32]>,
    allowed_os: LookupSet<[u8; 32]>,
    instances: LookupMap<[u8; 32], Instance>,
    anchors: Vector<Anchor>,
    instance_ttl_ms: u64,
    /// Prepaid anchor storage per instance (yoctoNEAR), funded from registration deposits. `anchor_receipts`
    /// draws on it when the caller attaches no (or too little) deposit, so the contract balance never pays.
    anchor_credit: LookupMap<[u8; 32], u128>,
    /// rev 1.2: owner-approved operator organizations, `account → org_id`. Two-hop clients require
    /// `entry.org_id != exit.org_id` (SPEC-VPN).
    operators: LookupMap<AccountId, String>,
    /// rev 1.3: always [`STATE_REV`]. Appended last; see [`STATE_REV`] and [`Registry::migrate`].
    state_rev: u8,
}

// ---------- argument parsing (fail closed, never echo input) ----------

/// A 32-byte hash argument: strict lowercase hex (`E_BAD_HEX`), never all-zero (`E_ZERO_HASH`).
fn hash32_arg(s: &str) -> [u8; 32] {
    let h: [u8; 32] = decode_hex_array(s).unwrap_or_else(|| fail_with(E_BAD_HEX, "expected 32-byte lowercase hex"));
    if is_all_zero(&h) {
        fail_with(E_ZERO_HASH, "zero hash");
    }
    h
}

/// A 32-byte public key argument: strict lowercase hex (`E_BAD_HEX`), never all-zero (`E_BAD_INPUT`).
fn key32_arg(s: &str) -> [u8; 32] {
    let k: [u8; 32] = decode_hex_array(s).unwrap_or_else(|| fail_with(E_BAD_HEX, "expected 32-byte lowercase hex key"));
    if is_all_zero(&k) {
        fail_with(E_BAD_INPUT, "zero key");
    }
    k
}

/// View-side hash parsing: malformed or zero hashes are simply "not present" (fail closed, no panic).
fn hash32_view(s: &str) -> Option<[u8; 32]> {
    decode_hex_array::<32>(s).filter(|h| !is_all_zero(h))
}

/// Root key arguments: kind `MOCK`|`INTEL` and a valid P-256 point as 128 hex chars.
fn root_args(kind: &str, p256: &str) -> (RootKind, [u8; 64]) {
    let kind = RootKind::parse(kind).unwrap_or_else(|| fail_with(E_BAD_INPUT, "root kind must be MOCK or INTEL"));
    let key: [u8; 64] = decode_hex_array(p256).unwrap_or_else(|| fail_with(E_BAD_HEX, "root p256 must be 64-byte hex"));
    if !ecdsa::is_valid_pub(&key) {
        fail_with(E_BAD_INPUT, "root p256 is not a valid P-256 point");
    }
    (kind, key)
}

/// `org_id` argument: `^[a-z0-9][a-z0-9._-]{0,63}$` (ASCII only), else `E_BAD_INPUT`.
fn org_id_arg(s: &str) -> String {
    if !is_valid_org_id(s) {
        fail_with(E_BAD_INPUT, "org_id must match ^[a-z0-9][a-z0-9._-]{0,63}$");
    }
    s.to_string()
}

/// SPEC §7 rev 1.2 organization id syntax: `^[a-z0-9][a-z0-9._-]{0,63}$`.
pub fn is_valid_org_id(s: &str) -> bool {
    let b = s.as_bytes();
    let head = |c: u8| c.is_ascii_lowercase() || c.is_ascii_digit();
    match b.split_first() {
        Some((&first, rest)) => {
            b.len() <= MAX_ORG_ID_LEN && head(first) && rest.iter().all(|&c| head(c) || matches!(c, b'.' | b'_' | b'-'))
        }
        None => false,
    }
}

/// View-side account parsing: an invalid account id is simply "not present" (views never panic on input).
fn account_view(s: &str) -> Option<AccountId> {
    s.parse::<AccountId>().ok()
}

fn ttl_arg(ttl: Option<u64>) -> u64 {
    let ttl = ttl.unwrap_or(DEFAULT_INSTANCE_TTL_MS);
    if ttl == 0 || ttl > MAX_INSTANCE_TTL_MS {
        fail_with(E_BAD_INPUT, "instance_ttl_ms out of range");
    }
    ttl
}

impl Policy for Registry {
    fn root(&self) -> (RootKind, [u8; 64]) {
        (self.root_kind, self.root_p256)
    }
    fn compose_allowed(&self, h: &[u8; 32]) -> bool {
        self.allowed_compose.contains(h)
    }
    fn os_allowed(&self, h: &[u8; 32]) -> bool {
        self.allowed_os.contains(h)
    }
}

#[near]
impl Registry {
    /// Initialises the registry. `#[private]`: only the contract account itself may initialise (no front-running
    /// between deploy and init). `instance_ttl_ms` defaults to 86 400 000.
    #[init]
    #[private]
    #[deny_unknown_arguments]
    pub fn new(owner_id: AccountId, root_kind: String, root_p256: String, instance_ttl_ms: Option<u64>) -> Self {
        let (kind, key) = root_args(&root_kind, &root_p256);
        let this = Self {
            owner: owner_id,
            pending_owner: None,
            root_kind: kind,
            root_p256: key,
            allowed_compose: LookupSet::new(StorageKey::AllowedComposeRev13),
            allowed_os: LookupSet::new(StorageKey::AllowedOs),
            instances: LookupMap::new(StorageKey::Instances),
            anchors: Vector::new(StorageKey::Anchors),
            instance_ttl_ms: ttl_arg(instance_ttl_ms),
            anchor_credit: LookupMap::new(StorageKey::AnchorCredit),
            operators: LookupMap::new(StorageKey::Operators),
            state_rev: STATE_REV,
        };
        events::emit(events::ROOT_SET, json!({ "kind": kind.as_str(), "p256": encode_hex(&key) }));
        this
    }

    /// One-time upgrade of a rev 1.2 registry to rev 1.3, called by the contract account itself right after the
    /// rev 1.3 code is deployed (every other method fails until then: the old state does not deserialize).
    ///
    /// A pre-rev-1.3 router or exit put the raw client nonce into its `/v1/attestation` quotes, so anyone could
    /// ask it for a quote over `registration_nonce(this registry, attacker)` and register its keys under their own
    /// account. The rev 1.3 check cannot tell which build produced a quote, so the migration **empties the compose
    /// allowlist**: the owner re-approves only rev 1.3 builds. Owner, pending owner, root, OS allowlist, instances,
    /// anchors, credits, TTL and operator organizations are kept. Instances of old builds stay readable but their
    /// compose is no longer allowed, so clients reject them and they cannot anchor. Running it on anything but a
    /// rev 1.2 state (incl. a second time) fails with `E_BAD_INPUT`.
    #[init(ignore_state)]
    #[private]
    pub fn migrate() -> Self {
        let raw = env::storage_read(b"STATE").unwrap_or_else(|| fail_with(E_BAD_INPUT, "no state to migrate"));
        let old: RegistryRev12 = near_sdk::borsh::from_slice(&raw)
            .unwrap_or_else(|_| fail_with(E_BAD_INPUT, "state is not a rev 1.2 registry"));
        events::emit(events::COMPOSE_ALLOWLIST_RESET, json!({ "state_rev": STATE_REV }));
        Self {
            owner: old.owner,
            pending_owner: old.pending_owner,
            root_kind: old.root_kind,
            root_p256: old.root_p256,
            allowed_compose: LookupSet::new(StorageKey::AllowedComposeRev13),
            allowed_os: old.allowed_os,
            instances: old.instances,
            anchors: old.anchors,
            instance_ttl_ms: old.instance_ttl_ms,
            anchor_credit: old.anchor_credit,
            operators: old.operators,
            state_rev: STATE_REV,
        }
    }

    // ---------- owner policy ----------

    #[deny_unknown_arguments]
    pub fn allow_compose(&mut self, hash: String) {
        self.assert_owner();
        let h = hash32_arg(&hash);
        self.allowed_compose.insert(h);
        events::emit(events::COMPOSE_ALLOWED, json!({ "hash": encode_hex(&h) }));
    }

    #[deny_unknown_arguments]
    pub fn revoke_compose(&mut self, hash: String) {
        self.assert_owner();
        let h = hash32_arg(&hash);
        self.allowed_compose.remove(&h);
        events::emit(events::COMPOSE_REVOKED, json!({ "hash": encode_hex(&h) }));
    }

    #[deny_unknown_arguments]
    pub fn allow_os(&mut self, hash: String) {
        self.assert_owner();
        let h = hash32_arg(&hash);
        self.allowed_os.insert(h);
        events::emit(events::OS_ALLOWED, json!({ "hash": encode_hex(&h) }));
    }

    #[deny_unknown_arguments]
    pub fn revoke_os(&mut self, hash: String) {
        self.assert_owner();
        let h = hash32_arg(&hash);
        self.allowed_os.remove(&h);
        events::emit(events::OS_REVOKED, json!({ "hash": encode_hex(&h) }));
    }

    #[deny_unknown_arguments]
    pub fn set_root(&mut self, kind: String, p256: String) {
        self.assert_owner();
        let (kind, key) = root_args(&kind, &p256);
        self.root_kind = kind;
        self.root_p256 = key;
        events::emit(events::ROOT_SET, json!({ "kind": kind.as_str(), "p256": encode_hex(&key) }));
    }

    /// Step 1 of the two-step ownership transfer. Proposing again replaces the pending owner.
    #[deny_unknown_arguments]
    pub fn propose_owner(&mut self, id: AccountId) {
        self.assert_owner();
        events::emit(events::OWNER_PROPOSED, json!({ "owner": self.owner, "pending_owner": id }));
        self.pending_owner = Some(id);
    }

    /// Step 2: only the pending owner can accept.
    pub fn accept_owner(&mut self) {
        let caller = ctx::predecessor_account_id();
        if self.pending_owner.as_ref() != Some(&caller) {
            fail_with(E_UNAUTHORIZED, "caller is not the pending owner");
        }
        events::emit(events::OWNER_ACCEPTED, json!({ "old_owner": self.owner, "new_owner": caller }));
        self.owner = caller;
        self.pending_owner = None;
    }

    // ---------- operator organizations (SPEC §7 rev 1.2) ----------

    /// Approves `account_id` as an operator of organization `org_id`. Approving an already approved account
    /// changes its organization (the event carries the previous one). Takes effect immediately for every
    /// instance that account registered (`get_instance` looks the org up live). Like the other owner methods,
    /// the few hundred bytes of storage are paid from the contract balance (owner-only, so not a drain vector).
    #[deny_unknown_arguments]
    pub fn approve_operator(&mut self, account_id: AccountId, org_id: String) {
        self.assert_owner();
        let org = org_id_arg(&org_id);
        let previous = self.operators.insert(account_id.clone(), org.clone());
        self.operators.flush();
        events::emit(events::OPERATOR_APPROVED, json!({ "account_id": account_id, "org_id": org, "previous_org_id": previous }));
    }

    /// Removes `account_id`'s organization; its instances then report `org_id: null`. Revoking an account that
    /// is not approved is a no-op (the event still records it, with `previous_org_id: null`).
    #[deny_unknown_arguments]
    pub fn revoke_operator(&mut self, account_id: AccountId) {
        self.assert_owner();
        let previous = self.operators.remove(&account_id);
        self.operators.flush();
        events::emit(events::OPERATOR_REVOKED, json!({ "account_id": account_id, "previous_org_id": previous }));
    }

    // ---------- instances ----------

    /// Verifies a registration quote on-chain (SPEC §7 steps 1-7) and records/refreshes the instance.
    /// The caller pays for the storage it adds. Deposit beyond that tops up the instance's anchor storage credit
    /// (up to [`MAX_ANCHOR_CREDIT_YOCTO`]); the rest is refunded. Returns the key hash (hex).
    #[payable]
    #[deny_unknown_arguments]
    pub fn register_instance(
        &mut self,
        quote: String,
        event_log: Value,
        app_compose: String,
        x25519: String,
        ed25519: String,
    ) -> String {
        if quote.len() > MAX_QUOTE_HEX_LEN {
            fail_with(E_QUOTE_FORMAT, "quote too large");
        }
        let quote = decode_hex(&quote).unwrap_or_else(|| fail_with(E_QUOTE_FORMAT, "quote is not lowercase hex"));
        if app_compose.is_empty() || app_compose.len() > MAX_APP_COMPOSE_LEN {
            fail_with(E_BAD_INPUT, "app_compose size");
        }
        let xp = key32_arg(&x25519);
        let ep = key32_arg(&ed25519);
        let contract_id = ctx::current_account_id();
        // The enclave bound its registration quote to this operator account (SPEC §5/§7 rev 1.3).
        let operator = ctx::predecessor_account_id();

        let reg = Registration { quote: &quote, event_log: &event_log, app_compose: app_compose.as_bytes(), x25519: &xp, ed25519: &ep };
        let v = verify_registration(&reg, &*self, contract_id.as_str(), operator.as_str()).or_fail();

        let (expires_at_ms, refreshed) = self.record_instance(&v, xp, ep, &operator);

        events::emit(
            events::INSTANCE_REGISTERED,
            json!({
                "key_hash": encode_hex(&v.key_hash),
                "compose_hash": encode_hex(&v.compose_hash),
                "os_measurement": encode_hex(&v.os_measurement),
                "x25519": encode_hex(&xp),
                "ed25519": encode_hex(&ep),
                "operator": operator,
                "expires_at_ms": expires_at_ms,
                "refreshed": refreshed,
            }),
        );
        encode_hex(&v.key_hash)
    }

    /// Verifies an Intel DCAP (TDX) registration quote and records/refreshes the instance (SPEC-TDX §2.3).
    /// Checks 1-4 run here on the arguments, 5-13 in [`verify_registration_tdx`]. Same deposit and refund rules
    /// as [`Registry::register_instance`]. Returns the key hash (hex).
    #[payable]
    #[deny_unknown_arguments]
    pub fn register_instance_tdx(
        &mut self,
        quote: String,
        collateral: String,
        event_log: Value,
        app_compose: String,
        x25519: String,
        ed25519: String,
    ) -> String {
        if quote.len() > MAX_TDX_QUOTE_HEX_LEN {
            fail_with(E_QUOTE_FORMAT, "quote too large");
        }
        let quote = decode_hex(&quote).unwrap_or_else(|| fail_with(E_QUOTE_FORMAT, "quote is not lowercase hex"));
        if collateral.len() > MAX_COLLATERAL_LEN {
            fail_with(E_COLLATERAL, "collateral too large");
        }
        let collateral: QuoteCollateralV3 = near_sdk::serde_json::from_str(&collateral).unwrap_or_else(|_| fail_with(E_COLLATERAL, "parse"));
        if app_compose.is_empty() || app_compose.len() > MAX_DSTACK_COMPOSE_LEN {
            fail_with(E_BAD_INPUT, "app_compose size");
        }
        let xp = key32_arg(&x25519);
        let ep = key32_arg(&ed25519);
        let contract_id = ctx::current_account_id();
        // The enclave bound its registration quote to this operator account (SPEC §5/§7 rev 1.3).
        let operator = ctx::predecessor_account_id();

        let reg = TdxRegistration {
            quote: &quote,
            collateral: &collateral,
            event_log: &event_log,
            app_compose: app_compose.as_bytes(),
            x25519: &xp,
            ed25519: &ep,
        };
        let (v, tcb_status) =
            verify_registration_tdx(&reg, &*self, contract_id.as_str(), operator.as_str(), now_secs()).or_fail();

        self.finish_tdx_registration(v, &tcb_status, xp, ep, &operator)
    }

    // ---------- receipts ----------

    /// Anchors the Merkle root of receipts `[first_seq, first_seq + count)` for an instance. Returns the anchor id.
    ///
    /// The storage the anchor adds is paid by the attached deposit (excess refunded to the caller) and, for
    /// any shortfall, by the instance's prepaid anchor credit; otherwise `E_DEPOSIT`. The contract's own
    /// balance never pays, so a registered instance cannot drain it.
    #[payable]
    #[deny_unknown_arguments]
    pub fn anchor_receipts(&mut self, key_hash: String, root: String, first_seq: u64, count: u64, sig: String) -> u64 {
        let kh = hash32_arg(&key_hash);
        let root = hash32_arg(&root);
        let sig: [u8; 64] = decode_hex_array(&sig).unwrap_or_else(|| fail_with(E_BAD_HEX, "sig must be 64-byte hex"));
        let now = ctx::block_timestamp_ms();

        let inst = match self.instances.get(&kh) {
            Some(i) if now < i.expires_at_ms => i.clone(),
            _ => fail_with(E_INSTANCE_NOT_REGISTERED, ""),
        };
        if !self.allowed_compose.contains(&inst.compose_hash) {
            fail_with(E_COMPOSE_NOT_ALLOWED, "");
        }
        if !self.allowed_os.contains(&inst.os_measurement) {
            fail_with(E_OS_NOT_ALLOWED, "");
        }
        if count == 0 || count > MAX_ANCHOR_COUNT {
            fail_with(E_SEQ, "count out of range");
        }
        let msg = anchor_message(ctx::current_account_id().as_str(), &kh, &root, first_seq, count);
        if !env::ed25519_verify(&sig, &msg, &inst.ed25519) {
            fail_with(E_ANCHOR_SIG, "");
        }
        if first_seq != inst.next_seq {
            fail_with(E_SEQ, "first_seq != next_seq");
        }
        let next = first_seq.checked_add(count).unwrap_or_else(|| fail_with(E_SEQ, "sequence overflow"));

        let id = u64::from(self.anchors.len());
        if self.anchors.len() == u32::MAX {
            fail_with(E_SEQ, "anchor log full");
        }
        let storage_before = env::storage_usage();
        if let Some(rec) = self.instances.get_mut(&kh) {
            rec.next_seq = next;
        }
        self.instances.flush();
        self.anchors.push(Anchor { key_hash: kh, root, first_seq, count, at_ms: now });
        self.anchors.flush();
        let added = env::storage_usage().saturating_sub(storage_before);
        self.pay_anchor_storage(&kh, storage_cost(added));
        events::emit(
            events::RECEIPTS_ANCHORED,
            json!({
                "id": id,
                "key_hash": encode_hex(&kh),
                "root": encode_hex(&root),
                "first_seq": first_seq,
                "count": count,
                "at_ms": now,
            }),
        );
        id
    }

    /// TEST-ONLY (spike S2): verifies TV-Q1 with dcap-qvl at the fixed test clock 2025-06-20. Compiled only under
    /// `--features tdx-test-clock`, which also freezes `now_secs` (expired collateral would pass): never deploy such a build.
    #[cfg(feature = "tdx-test-clock")]
    pub fn debug_verify_tdx(&self, quote_hex: String, collateral: String) -> String {
        let quote = crate::bytes::decode_hex(&quote_hex).unwrap_or_else(|| near_sdk::env::panic_str("hex"));
        let c: dcap_qvl::QuoteCollateralV3 = near_sdk::serde_json::from_str(&collateral).unwrap_or_else(|_| near_sdk::env::panic_str("collateral"));
        let r = dcap_qvl::verify::QuoteVerifier::new_prod().verify(&quote, &c, 1_750_377_600).unwrap_or_else(|_| near_sdk::env::panic_str("E_QUOTE_SIG"));
        r.status
    }

    // ---------- views ----------

    pub fn is_allowed(&self, compose_hash: String, os_measurement: String) -> bool {
        self.is_compose_allowed(compose_hash) && self.is_os_allowed(os_measurement)
    }

    pub fn is_compose_allowed(&self, hash: String) -> bool {
        hash32_view(&hash).is_some_and(|h| self.allowed_compose.contains(&h))
    }

    pub fn is_os_allowed(&self, hash: String) -> bool {
        hash32_view(&hash).is_some_and(|h| self.allowed_os.contains(&h))
    }

    /// The live instance for `key_hash`, or `null` if unknown, expired, or `key_hash` is malformed.
    pub fn get_instance(&self, key_hash: String) -> Option<InstanceView> {
        let kh = hash32_view(&key_hash)?;
        let now = ctx::block_timestamp_ms();
        self.instances.get(&kh).filter(|i| now < i.expires_at_ms).map(|i| InstanceView::new(i, self.operators.get(&i.operator).cloned()))
    }

    /// rev 1.2: the organization `account_id` is approved for, or `null` (also for a malformed account id).
    pub fn get_operator(&self, account_id: String) -> Option<String> {
        self.operators.get(&account_view(&account_id)?).cloned()
    }

    pub fn get_root(&self) -> RootView {
        RootView { kind: self.root_kind.as_str().to_string(), p256: encode_hex(&self.root_p256) }
    }

    /// The INTEL-mode policy this code enforces (SPEC-TDX §2.4). Never panics.
    pub fn get_tdx_policy(&self) -> TdxPolicyView {
        TdxPolicyView {
            intel_root_p256: INTEL_ROOT_P256_HEX.to_string(),
            accepted_tcb_statuses: ACCEPTED_TCB_STATUSES.iter().map(|s| s.to_string()).collect(),
            dcap_qvl_version: "0.7.1".to_string(),
        }
    }

    pub fn get_anchor(&self, id: u64) -> Option<AnchorView> {
        let idx = u32::try_from(id).ok()?;
        self.anchors.get(idx).map(|a| AnchorView {
            id,
            key_hash: encode_hex(&a.key_hash),
            root: encode_hex(&a.root),
            first_seq: a.first_seq,
            count: a.count,
            at_ms: a.at_ms,
        })
    }

    pub fn anchor_count(&self) -> u64 {
        u64::from(self.anchors.len())
    }

    pub fn get_owner(&self) -> AccountId {
        self.owner.clone()
    }

    pub fn get_pending_owner(&self) -> Option<AccountId> {
        self.pending_owner.clone()
    }

    pub fn get_instance_ttl_ms(&self) -> u64 {
        self.instance_ttl_ms
    }

    /// State layout revision ([`STATE_REV`] = 3 for rev 1.3). Lets the owner check that [`Registry::migrate`] ran.
    pub fn get_state_rev(&self) -> u8 {
        self.state_rev
    }

    /// Remaining prepaid anchor storage credit of an instance, in yoctoNEAR (decimal string).
    pub fn get_anchor_credit(&self, key_hash: String) -> String {
        hash32_view(&key_hash).and_then(|kh| self.anchor_credit.get(&kh).copied()).unwrap_or(0).to_string()
    }
}

/// Cost of `bytes` of contract storage in yoctoNEAR.
fn storage_cost(bytes: u64) -> u128 {
    env::storage_byte_cost()
        .as_yoctonear()
        .checked_mul(u128::from(bytes))
        .unwrap_or_else(|| fail_with(E_DEPOSIT, "storage cost overflow"))
}

impl Registry {
    fn assert_owner(&self) {
        if ctx::predecessor_account_id() != self.owner {
            fail_with(E_UNAUTHORIZED, "only the owner");
        }
    }

    /// Records a verified INTEL-mode registration exactly as [`Registry::register_instance_tdx`] does after
    /// verification: the shared storage/deposit/refund path of [`Registry::record_instance`], then the
    /// `instance_registered` event carrying the two INTEL keys. Returns the key hash hex.
    fn finish_tdx_registration(
        &mut self,
        v: Verified,
        tcb_status: &str,
        xp: [u8; 32],
        ep: [u8; 32],
        operator: &AccountId,
    ) -> String {
        let (expires_at_ms, refreshed) = self.record_instance(&v, xp, ep, operator);
        events::emit(
            events::INSTANCE_REGISTERED,
            json!({
                "key_hash": encode_hex(&v.key_hash),
                "compose_hash": encode_hex(&v.compose_hash),
                "os_measurement": encode_hex(&v.os_measurement),
                "x25519": encode_hex(&xp),
                "ed25519": encode_hex(&ep),
                "operator": operator,
                "expires_at_ms": expires_at_ms,
                "refreshed": refreshed,
                "root_kind": RootKind::Intel.as_str(),
                "tcb_status": tcb_status,
            }),
        );
        encode_hex(&v.key_hash)
    }

    /// Records or refreshes `v`'s instance: storage, deposit and refund. Shared by [`Registry::register_instance`]
    /// (MOCK) and [`Registry::register_instance_tdx`] (INTEL), so both have identical economics.
    /// Returns `(expires_at_ms, refreshed)`.
    fn record_instance(&mut self, v: &Verified, xp: [u8; 32], ep: [u8; 32], operator: &AccountId) -> (u64, bool) {
        let now = ctx::block_timestamp_ms();
        let expires_at_ms = now.checked_add(self.instance_ttl_ms).unwrap_or_else(|| fail_with(E_BAD_INPUT, "time overflow"));
        let storage_before = env::storage_usage();
        let refreshed = match self.instances.get_mut(&v.key_hash) {
            Some(rec) => {
                // Same keys ⇒ same enclave boot, and step 7 bound the quote to its submitter, so only the operator
                // that enclave chose can refresh. Keep operator, registered_at_ms and next_seq; refresh the rest.
                rec.compose_hash = v.compose_hash;
                rec.os_measurement = v.os_measurement;
                rec.expires_at_ms = expires_at_ms;
                true
            }
            None => {
                self.instances.insert(
                    v.key_hash,
                    Instance {
                        compose_hash: v.compose_hash,
                        os_measurement: v.os_measurement,
                        x25519: xp,
                        ed25519: ep,
                        operator: operator.clone(),
                        registered_at_ms: now,
                        expires_at_ms,
                        next_seq: 0,
                    },
                );
                false
            }
        };
        self.instances.flush();
        let added = env::storage_usage().saturating_sub(storage_before);
        let deposit = ctx::attached_deposit().as_yoctonear();
        let cost = storage_cost(added);
        if deposit < cost {
            fail_with(E_DEPOSIT, "attached deposit does not cover storage");
        }
        let mut excess = deposit - cost;
        if excess > 0 {
            // Top up the anchor credit. Its own map entry costs storage too, paid from the same excess.
            let existing = self.anchor_credit.get(&v.key_hash).copied();
            let credit = existing.unwrap_or(0);
            let room = MAX_ANCHOR_CREDIT_YOCTO.saturating_sub(credit);
            if room > 0 {
                let before = env::storage_usage();
                self.anchor_credit.insert(v.key_hash, credit);
                self.anchor_credit.flush();
                let entry_cost = storage_cost(env::storage_usage().saturating_sub(before));
                if excess > entry_cost {
                    let add = (excess - entry_cost).min(room);
                    self.anchor_credit.insert(v.key_hash, credit + add);
                    self.anchor_credit.flush();
                    excess -= entry_cost + add;
                } else if existing.is_none() {
                    // Not enough to pay for a credit entry: undo it and refund everything.
                    self.anchor_credit.remove(&v.key_hash);
                    self.anchor_credit.flush();
                }
            }
        }
        if excess > 0 {
            Promise::new(operator.clone()).transfer(NearToken::from_yoctonear(excess)).detach();
        }
        (expires_at_ms, refreshed)
    }

    /// Pays `cost` yoctoNEAR of anchor storage: attached deposit first (excess refunded to the caller), then
    /// the instance's prepaid credit. Panics with `E_DEPOSIT` (rolling the anchor back) if neither suffices.
    fn pay_anchor_storage(&mut self, kh: &[u8; 32], cost: u128) {
        let deposit = ctx::attached_deposit().as_yoctonear();
        if deposit >= cost {
            let refund = deposit - cost;
            if refund > 0 {
                Promise::new(ctx::predecessor_account_id()).transfer(NearToken::from_yoctonear(refund)).detach();
            }
            return;
        }
        let shortfall = cost - deposit;
        let credit = self.anchor_credit.get(kh).copied().unwrap_or(0);
        if credit < shortfall {
            fail_with(E_DEPOSIT, "attach a deposit: anchor storage credit exhausted");
        }
        self.anchor_credit.insert(*kh, credit - shortfall);
        self.anchor_credit.flush();
    }
}

#[cfg(target_arch = "wasm32")]
fn plr_no_getrandom(_buf: &mut [u8]) -> Result<(), getrandom::Error> {
    Err(getrandom::Error::UNSUPPORTED)
}
#[cfg(target_arch = "wasm32")]
getrandom::register_custom_getrandom!(plr_no_getrandom);
