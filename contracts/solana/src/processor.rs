//! Account plumbing around [`crate::rules`]: loads and checks every account (owner = this program, exact size and
//! tag, PDA address re-derived from its seeds), runs the rule, stores the result. Fails closed: any unexpected
//! account is `E_BAD_INPUT`, a missing/wrong signature is `E_UNAUTHORIZED`.
use crate::error::PlrError;
use crate::instruction::{RegistryInstruction, QUOTE_LEN};
use crate::rules::{self, Registration};
use crate::state::*;
use solana_program::{
    account_info::AccountInfo,
    clock::Clock,
    entrypoint::ProgramResult,
    instruction::{AccountMeta, Instruction},
    msg,
    program::invoke_signed,
    pubkey::Pubkey,
    rent::Rent,
    sysvar::Sysvar,
};

/// The system program (all-zero address).
pub const SYSTEM_PROGRAM_ID: Pubkey = Pubkey::new_from_array([0u8; 32]);

/// What the processor needs from the runtime: time, rent and system-program CPIs. On-chain it is [`Syscalls`];
/// native unit tests inject a fake that emulates the system program.
pub trait Runtime {
    /// Clock `unix_timestamp` (seconds).
    fn unix_timestamp(&self) -> Result<i64, PlrError>;
    fn rent_exempt_minimum(&self, len: usize) -> Result<u64, PlrError>;
    fn invoke_signed(&self, ix: &Instruction, accounts: &[AccountInfo], seeds: &[&[&[u8]]]) -> Result<(), PlrError>;
}

/// The real runtime (Clock / Rent sysvars, `invoke_signed`).
pub struct Syscalls;

impl Runtime for Syscalls {
    fn unix_timestamp(&self) -> Result<i64, PlrError> {
        Ok(Clock::get().map_err(|_| PlrError::E_BAD_INPUT)?.unix_timestamp)
    }
    fn rent_exempt_minimum(&self, len: usize) -> Result<u64, PlrError> {
        Ok(Rent::get().map_err(|_| PlrError::E_BAD_INPUT)?.minimum_balance(len))
    }
    fn invoke_signed(&self, ix: &Instruction, accounts: &[AccountInfo], seeds: &[&[&[u8]]]) -> Result<(), PlrError> {
        invoke_signed(ix, accounts, seeds).map_err(|_| PlrError::E_BAD_INPUT)
    }
}

pub fn process_instruction(program_id: &Pubkey, accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
    process(&Syscalls, program_id, accounts, data)
}

pub fn process(rt: &dyn Runtime, program_id: &Pubkey, accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
    let ix = RegistryInstruction::decode(data)?;
    let r = match ix {
        RegistryInstruction::Init { owner, root_kind, root_p256, ttl_ms } => init(program_id, accounts, owner, root_kind, root_p256, ttl_ms),
        RegistryInstruction::AllowCompose { h } => set_item(rt, program_id, accounts, SEED_COMPOSE, TAG_COMPOSE, h, true),
        RegistryInstruction::RevokeCompose { h } => set_item(rt, program_id, accounts, SEED_COMPOSE, TAG_COMPOSE, h, false),
        RegistryInstruction::AllowOs { h } => set_item(rt, program_id, accounts, SEED_OS, TAG_OS, h, true),
        RegistryInstruction::RevokeOs { h } => set_item(rt, program_id, accounts, SEED_OS, TAG_OS, h, false),
        RegistryInstruction::SetRoot { kind, p256 } => set_root(program_id, accounts, kind, p256),
        RegistryInstruction::ApproveOperator { op, org } => set_operator(rt, program_id, accounts, op, Some(org)),
        RegistryInstruction::RevokeOperator { op } => set_operator(rt, program_id, accounts, op, None),
        RegistryInstruction::ProposeOwner { next } => propose_owner(program_id, accounts, next),
        RegistryInstruction::AcceptOwner => accept_owner(program_id, accounts),
        RegistryInstruction::RegisterInstance { x25519, ed25519, compose, os, quote } => register(rt, program_id, accounts, x25519, ed25519, compose, os, quote),
        RegistryInstruction::AnchorReceipts { key_hash, root, first_seq, count, sig } => anchor(rt, program_id, accounts, key_hash, root, first_seq, count, sig),
    };
    if let Err(e) = &r {
        msg!("plr: {}", e.name());
    }
    r.map_err(Into::into)
}

type R<T = ()> = Result<T, PlrError>;

fn acc<'a, 'b>(accounts: &'a [AccountInfo<'b>], i: usize) -> R<&'a AccountInfo<'b>> {
    accounts.get(i).ok_or(PlrError::E_BAD_INPUT)
}

fn now_ms(rt: &dyn Runtime) -> R<u64> {
    rules::clock_ms(rt.unix_timestamp()?)
}

/// The registry state account (owned by this program, initialized).
fn load_state(program_id: &Pubkey, a: &AccountInfo) -> R<State> {
    if a.owner != program_id {
        return Err(PlrError::E_BAD_INPUT);
    }
    let d = a.try_borrow_data().map_err(|_| PlrError::E_BAD_INPUT)?;
    State::unpack(&d)
}

fn store_state(a: &AccountInfo, s: &State) -> R {
    let mut d = a.try_borrow_mut_data().map_err(|_| PlrError::E_BAD_INPUT)?;
    if d.len() != STATE_LEN {
        return Err(PlrError::E_BAD_INPUT);
    }
    s.pack(&mut d);
    Ok(())
}

/// `signer` signed and is the registry owner.
fn require_owner(state: &State, signer: &AccountInfo) -> R {
    if !signer.is_signer || signer.key.to_bytes() != state.owner {
        return Err(PlrError::E_UNAUTHORIZED);
    }
    Ok(())
}

/// Checks `a` is the PDA of `seeds`; returns its bump.
fn check_pda(program_id: &Pubkey, a: &AccountInfo, seeds: &[&[u8]]) -> R<u8> {
    let (addr, bump) = Pubkey::find_program_address(seeds, program_id);
    if *a.key != addr {
        return Err(PlrError::E_BAD_INPUT);
    }
    Ok(bump)
}

/// Whether a (checked) PDA already holds our data: owned by this program with the expected size. A PDA that is
/// system-owned with no data (possibly pre-funded by anyone) does not exist yet; anything else is malformed.
fn exists(program_id: &Pubkey, a: &AccountInfo, len: usize) -> R<bool> {
    if a.owner == program_id {
        return if a.data_len() == len { Ok(true) } else { Err(PlrError::E_BAD_INPUT) };
    }
    if *a.owner == SYSTEM_PROGRAM_ID && a.data_len() == 0 {
        return Ok(false);
    }
    Err(PlrError::E_BAD_INPUT)
}

fn sys_ix(accounts: Vec<AccountMeta>, data: Vec<u8>) -> Instruction {
    Instruction { program_id: SYSTEM_PROGRAM_ID, accounts, data }
}

/// Creates the PDA `a` (rent-exempt, `len` bytes, owned by this program) paid by `payer`. Works when the address was
/// pre-funded by someone else (top-up + allocate + assign instead of `CreateAccount`, which would fail).
fn create_pda<'b>(rt: &dyn Runtime, program_id: &Pubkey, payer: &AccountInfo<'b>, a: &AccountInfo<'b>, system: &AccountInfo<'b>, len: usize, seeds: &[&[u8]], bump: u8) -> R {
    if *system.key != SYSTEM_PROGRAM_ID || !payer.is_signer {
        return Err(PlrError::E_BAD_INPUT);
    }
    let bump_b = [bump];
    let mut s: Vec<&[u8]> = seeds.to_vec();
    s.push(&bump_b);
    let signer: &[&[&[u8]]] = &[&s];
    let need = rt.rent_exempt_minimum(len)?;
    let cpi = |ix: Instruction, accs: &[AccountInfo<'b>]| rt.invoke_signed(&ix, accs, signer);
    let have = a.lamports();
    if have == 0 {
        // SystemInstruction::CreateAccount { lamports, space, owner }
        let mut d = 0u32.to_le_bytes().to_vec();
        d.extend_from_slice(&need.to_le_bytes());
        d.extend_from_slice(&(len as u64).to_le_bytes());
        d.extend_from_slice(program_id.as_ref());
        let metas = vec![AccountMeta::new(*payer.key, true), AccountMeta::new(*a.key, true)];
        return cpi(sys_ix(metas, d), &[payer.clone(), a.clone(), system.clone()]);
    }
    if have < need {
        // SystemInstruction::Transfer { lamports }
        let mut d = 2u32.to_le_bytes().to_vec();
        d.extend_from_slice(&(need - have).to_le_bytes());
        let metas = vec![AccountMeta::new(*payer.key, true), AccountMeta::new(*a.key, false)];
        cpi(sys_ix(metas, d), &[payer.clone(), a.clone(), system.clone()])?;
    }
    // SystemInstruction::Allocate { space }, then Assign { owner }
    let mut d = 8u32.to_le_bytes().to_vec();
    d.extend_from_slice(&(len as u64).to_le_bytes());
    cpi(sys_ix(vec![AccountMeta::new(*a.key, true)], d), &[a.clone(), system.clone()])?;
    let mut d = 1u32.to_le_bytes().to_vec();
    d.extend_from_slice(program_id.as_ref());
    cpi(sys_ix(vec![AccountMeta::new(*a.key, true)], d), &[a.clone(), system.clone()])
}

fn with_data<T>(a: &AccountInfo, f: impl FnOnce(&mut [u8]) -> T) -> R<T> {
    let mut d = a.try_borrow_mut_data().map_err(|_| PlrError::E_BAD_INPUT)?;
    Ok(f(&mut d))
}

// ------------------------------------------------------------------------------------------------- owner

fn init(program_id: &Pubkey, accounts: &[AccountInfo], owner: [u8; 32], root_kind: u8, root_p256: [u8; 64], ttl_ms: u64) -> R {
    let st = acc(accounts, 0)?;
    if !st.is_signer {
        return Err(PlrError::E_UNAUTHORIZED);
    }
    if st.owner != program_id || st.data_len() != STATE_LEN {
        return Err(PlrError::E_BAD_INPUT);
    }
    if st.try_borrow_data().map_err(|_| PlrError::E_BAD_INPUT)?[0] != 0 {
        return Err(PlrError::E_UNAUTHORIZED); // already initialized
    }
    if !rules::valid_root_kind(root_kind) || ttl_ms == 0 || rules::is_zero(&owner) {
        return Err(PlrError::E_BAD_INPUT);
    }
    store_state(st, &State { owner, pending_owner: None, root_kind, root_p256, ttl_ms, anchor_count: 0 })
}

fn set_item(rt: &dyn Runtime, program_id: &Pubkey, accounts: &[AccountInfo], seed: &[u8], tag: u8, h: [u8; 32], allowed: bool) -> R {
    let (st, owner, item) = (acc(accounts, 0)?, acc(accounts, 1)?, acc(accounts, 2)?);
    let state = load_state(program_id, st)?;
    require_owner(&state, owner)?;
    rules::nonzero(&h)?;
    let seeds: &[&[u8]] = &[seed, st.key.as_ref(), &h];
    let bump = check_pda(program_id, item, seeds)?;
    if exists(program_id, item, ITEM_LEN)? {
        Item::unpack(&item.try_borrow_data().map_err(|_| PlrError::E_BAD_INPUT)?, tag)?;
    } else if allowed {
        create_pda(rt, program_id, owner, item, acc(accounts, 3)?, ITEM_LEN, seeds, bump)?;
    } else {
        return Ok(()); // revoking an unknown hash: nothing to do
    }
    with_data(item, |d| Item { allowed }.pack(d, tag))
}

fn set_root(program_id: &Pubkey, accounts: &[AccountInfo], kind: u8, p256: [u8; 64]) -> R {
    let (st, owner) = (acc(accounts, 0)?, acc(accounts, 1)?);
    let mut state = load_state(program_id, st)?;
    require_owner(&state, owner)?;
    if !rules::valid_root_kind(kind) {
        return Err(PlrError::E_BAD_INPUT);
    }
    state.root_kind = kind;
    state.root_p256 = p256;
    store_state(st, &state)
}

fn set_operator(rt: &dyn Runtime, program_id: &Pubkey, accounts: &[AccountInfo], op: [u8; 32], org: Option<&[u8]>) -> R {
    let (st, owner, opa) = (acc(accounts, 0)?, acc(accounts, 1)?, acc(accounts, 2)?);
    let state = load_state(program_id, st)?;
    require_owner(&state, owner)?;
    if let Some(o) = org {
        if !rules::valid_org(o) {
            return Err(PlrError::E_BAD_INPUT);
        }
    }
    let seeds: &[&[u8]] = &[SEED_OPERATOR, st.key.as_ref(), &op];
    let bump = check_pda(program_id, opa, seeds)?;
    if exists(program_id, opa, OPERATOR_LEN)? {
        Operator::unpack(&opa.try_borrow_data().map_err(|_| PlrError::E_BAD_INPUT)?)?;
    } else if org.is_some() {
        create_pda(rt, program_id, owner, opa, acc(accounts, 3)?, OPERATOR_LEN, seeds, bump)?;
    } else {
        return Ok(());
    }
    let rec = Operator { org: org.map(|o| o.to_vec()).unwrap_or_default() };
    with_data(opa, |d| rec.pack(d))
}

fn propose_owner(program_id: &Pubkey, accounts: &[AccountInfo], next: [u8; 32]) -> R {
    let (st, owner) = (acc(accounts, 0)?, acc(accounts, 1)?);
    let mut state = load_state(program_id, st)?;
    require_owner(&state, owner)?;
    if rules::is_zero(&next) {
        return Err(PlrError::E_BAD_INPUT);
    }
    state.pending_owner = Some(next);
    store_state(st, &state)
}

fn accept_owner(program_id: &Pubkey, accounts: &[AccountInfo]) -> R {
    let (st, next) = (acc(accounts, 0)?, acc(accounts, 1)?);
    let mut state = load_state(program_id, st)?;
    match state.pending_owner {
        Some(p) if next.is_signer && next.key.to_bytes() == p => {
            state.owner = p;
            state.pending_owner = None;
            store_state(st, &state)
        }
        _ => Err(PlrError::E_UNAUTHORIZED),
    }
}

// ------------------------------------------------------------------------------------------------- operator

fn register(rt: &dyn Runtime, program_id: &Pubkey, accounts: &[AccountInfo], x25519: [u8; 32], ed25519: [u8; 32], compose: [u8; 32], os: [u8; 32], quote: &[u8]) -> R {
    let (st, operator, opa, inst) = (acc(accounts, 0)?, acc(accounts, 1)?, acc(accounts, 2)?, acc(accounts, 3)?);
    if !operator.is_signer {
        return Err(PlrError::E_UNAUTHORIZED);
    }
    let state = load_state(program_id, st)?;
    let op_key = operator.key.to_bytes();
    check_pda(program_id, opa, &[SEED_OPERATOR, st.key.as_ref(), &op_key])?;
    let approved = exists(program_id, opa, OPERATOR_LEN)? && Operator::unpack(&opa.try_borrow_data().map_err(|_| PlrError::E_BAD_INPUT)?)?.approved();
    if !approved {
        return Err(PlrError::E_OPERATOR_UNAPPROVED);
    }
    let kh = rules::key_hash(&x25519, &ed25519);
    let (cid, cn) = rules::contract_id(&st.key.to_bytes());
    let (oid, on) = rules::base58_32(&op_key);
    let nonce = rules::registration_nonce(&cid[..cn], &oid[..on]).ok_or(PlrError::E_BAD_INPUT)?;
    rules::check_quote(quote, &kh, &nonce)?;

    let seeds: &[&[u8]] = &[SEED_INSTANCE, st.key.as_ref(), &kh];
    let bump = check_pda(program_id, inst, seeds)?;
    let existing = if exists(program_id, inst, INSTANCE_LEN)? { Some(Instance::unpack(&inst.try_borrow_data().map_err(|_| PlrError::E_BAD_INPUT)?)?) } else { None };
    // Optional account 5: the op PDA of the record's current operator, when it is not the signer. A takeover needs
    // it to prove that operator is no longer approved; without it the current operator counts as approved.
    let existing_operator_approved = match (&existing, accounts.get(5)) {
        (Some(e), Some(prev)) if e.operator != op_key => {
            check_pda(program_id, prev, &[SEED_OPERATOR, st.key.as_ref(), &e.operator])?;
            exists(program_id, prev, OPERATOR_LEN)? && Operator::unpack(&prev.try_borrow_data().map_err(|_| PlrError::E_BAD_INPUT)?)?.approved()
        }
        _ => true,
    };
    let rec = rules::register(existing.as_ref(), existing_operator_approved, &Registration { x25519, ed25519, compose, os, operator: op_key }, now_ms(rt)?, state.ttl_ms)?;
    if existing.is_none() {
        create_pda(rt, program_id, operator, inst, acc(accounts, 4)?, INSTANCE_LEN, seeds, bump)?;
    }
    with_data(inst, |d| {
        rec.pack(d);
        d[QUOTE_OFF..QUOTE_OFF + QUOTE_LEN].copy_from_slice(quote);
    })
}

/// Allowlist entry `h` under `seed`: allowed iff its PDA exists with `allowed = 1`.
fn item_allowed(program_id: &Pubkey, state_key: &Pubkey, a: &AccountInfo, seed: &[u8], tag: u8, h: &[u8; 32]) -> R<bool> {
    check_pda(program_id, a, &[seed, state_key.as_ref(), h])?;
    Ok(exists(program_id, a, ITEM_LEN)? && Item::unpack(&a.try_borrow_data().map_err(|_| PlrError::E_BAD_INPUT)?, tag)?.allowed)
}

fn anchor(rt: &dyn Runtime, program_id: &Pubkey, accounts: &[AccountInfo], key_hash: [u8; 32], root: [u8; 32], first_seq: u64, count: u64, sig: [u8; 64]) -> R {
    let (st, operator, inst, anc) = (acc(accounts, 0)?, acc(accounts, 1)?, acc(accounts, 2)?, acc(accounts, 3)?);
    let (ca, oa) = (acc(accounts, 4)?, acc(accounts, 5)?);
    if !operator.is_signer {
        return Err(PlrError::E_UNAUTHORIZED);
    }
    let mut state = load_state(program_id, st)?;
    check_pda(program_id, inst, &[SEED_INSTANCE, st.key.as_ref(), &key_hash])?;
    let mut rec = if exists(program_id, inst, INSTANCE_LEN)? { Some(Instance::unpack(&inst.try_borrow_data().map_err(|_| PlrError::E_BAD_INPUT)?)?) } else { None };
    let (compose_ok, os_ok) = match &rec {
        Some(r) => (item_allowed(program_id, st.key, ca, SEED_COMPOSE, TAG_COMPOSE, &r.compose)?, item_allowed(program_id, st.key, oa, SEED_OS, TAG_OS, &r.os)?),
        None => (false, false),
    };
    let next = rules::anchor(rec.as_ref(), &operator.key.to_bytes(), now_ms(rt)?, compose_ok, os_ok, first_seq, count)?;

    let id = state.anchor_count;
    let id_le = id.to_le_bytes();
    let seeds: &[&[u8]] = &[SEED_ANCHOR, st.key.as_ref(), &id_le];
    let bump = check_pda(program_id, anc, seeds)?;
    if exists(program_id, anc, ANCHOR_LEN)? {
        return Err(PlrError::E_BAD_INPUT);
    }
    create_pda(rt, program_id, operator, anc, acc(accounts, 6)?, ANCHOR_LEN, seeds, bump)?;
    let at_ms = now_ms(rt)?;
    with_data(anc, |d| Anchor { key_hash, root, first_seq, count, at_ms, sig }.pack(d))?;

    if let Some(r) = rec.as_mut() {
        r.next_seq = next;
        with_data(inst, |d| r.pack(d))?;
    }
    state.anchor_count = id.checked_add(1).ok_or(PlrError::E_BAD_INPUT)?;
    store_state(st, &state)
}
