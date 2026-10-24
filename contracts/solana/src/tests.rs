//! Native unit tests: instruction encoding, account layouts, pure rules, and full instruction flows through the
//! processor with a fake runtime that emulates the system program (CreateAccount / Transfer / Allocate / Assign,
//! checking the PDA signer seeds like the runtime does).
use crate::error::PlrError;
use crate::instruction::{RegistryInstruction as Ix, QUOTE_LEN};
use crate::processor::{process, Runtime, SYSTEM_PROGRAM_ID};
use crate::rules;
use crate::state::*;
use solana_program::account_info::AccountInfo;
use solana_program::instruction::Instruction;
use solana_program::program_error::ProgramError;
use solana_program::pubkey::Pubkey;
use std::cell::Cell;
use std::collections::HashMap;

const PROGRAM: Pubkey = Pubkey::new_from_array([7u8; 32]);
const TTL: u64 = 3_600_000;

fn key(n: u8) -> Pubkey {
    let mut b = [0u8; 32];
    b[0] = n;
    b[31] = 0xa5;
    Pubkey::new_from_array(b)
}
fn h(n: u8) -> [u8; 32] {
    [n; 32]
}

// ------------------------------------------------------------------------------------------------- encoding

#[test]
fn error_numbering_matches_spec_section_10() {
    let names: Vec<&str> = PlrError::ALL.iter().map(|e| e.name()).collect();
    assert_eq!(
        names,
        ["E_UNAUTHORIZED", "E_ZERO_HASH", "E_BAD_INPUT", "E_OPERATOR_UNAPPROVED", "E_REPORT_DATA", "E_QUOTE_FORMAT", "E_SEQ", "E_INSTANCE_NOT_REGISTERED", "E_COMPOSE_NOT_ALLOWED"]
    );
    for (i, e) in PlrError::ALL.iter().enumerate() {
        assert_eq!(e.code(), i as u32 + 1);
        assert_eq!(ProgramError::from(*e), ProgramError::Custom(i as u32 + 1));
    }
}

#[test]
fn instruction_encoding_roundtrips_with_spec_tags_and_sizes() {
    let q = vec![9u8; QUOTE_LEN];
    let cases: Vec<(Ix, u8, usize)> = vec![
        (Ix::Init { owner: h(1), root_kind: 1, root_p256: [2; 64], ttl_ms: 5 }, 0, 1 + 32 + 1 + 64 + 8),
        (Ix::AllowCompose { h: h(1) }, 1, 33),
        (Ix::RevokeCompose { h: h(1) }, 2, 33),
        (Ix::AllowOs { h: h(1) }, 3, 33),
        (Ix::RevokeOs { h: h(1) }, 4, 33),
        (Ix::SetRoot { kind: 2, p256: [3; 64] }, 5, 66),
        (Ix::ApproveOperator { op: h(4), org: b"org-a" }, 6, 1 + 32 + 1 + 5),
        (Ix::RevokeOperator { op: h(4) }, 7, 33),
        (Ix::ProposeOwner { next: h(5) }, 8, 33),
        (Ix::AcceptOwner, 9, 1),
        (Ix::RegisterInstance { x25519: h(1), ed25519: h(2), compose: h(3), os: h(4), quote: &q }, 10, 1 + 128 + QUOTE_LEN),
        (Ix::AnchorReceipts { key_hash: h(1), root: h(2), first_seq: 7, count: 3, sig: [8; 64] }, 11, 1 + 64 + 16 + 64),
    ];
    for (ix, tag, len) in cases {
        let b = ix.encode();
        assert_eq!(b[0], tag);
        assert_eq!(b.len(), len, "{ix:?}");
        assert_eq!(Ix::decode(&b).unwrap(), ix);
        // strict: trailing bytes (except the quote, which is the tail) and truncation are rejected
        if tag != 10 {
            let mut t = b.clone();
            t.push(0);
            assert_eq!(Ix::decode(&t), Err(PlrError::E_BAD_INPUT));
        }
        if len > 1 {
            assert_eq!(Ix::decode(&b[..b.len() - 1]).map(|_| ()), if tag == 10 { Ok(()) } else { Err(PlrError::E_BAD_INPUT) });
        }
    }
    // little-endian u64 fields
    let b = Ix::AnchorReceipts { key_hash: h(0), root: h(0), first_seq: 0x0102, count: 1, sig: [0; 64] }.encode();
    assert_eq!(&b[65..73], &[2, 1, 0, 0, 0, 0, 0, 0]);
    assert_eq!(Ix::decode(&[]), Err(PlrError::E_BAD_INPUT));
    assert_eq!(Ix::decode(&[12]), Err(PlrError::E_BAD_INPUT));
    assert_eq!(Ix::decode(&[6, 0]), Err(PlrError::E_BAD_INPUT));
    // org length prefix beyond the data
    let mut a = vec![6u8];
    a.extend_from_slice(&h(1));
    a.extend_from_slice(&[5, b'a']);
    assert_eq!(Ix::decode(&a), Err(PlrError::E_BAD_INPUT));
}

#[test]
fn account_layouts_roundtrip() {
    let s = State { owner: h(1), pending_owner: Some(h(2)), root_kind: 1, root_p256: [3; 64], ttl_ms: 9, anchor_count: 4 };
    let mut b = vec![0u8; STATE_LEN];
    s.pack(&mut b);
    assert_eq!(State::unpack(&b).unwrap(), s);
    assert_eq!(STATE_LEN, 147);
    assert_eq!(INSTANCE_LEN, 1013);
    assert_eq!(ANCHOR_LEN, 153);
    assert_eq!(OPERATOR_LEN, 67);
    assert_eq!(State::unpack(&b[..STATE_LEN - 1]), Err(PlrError::E_BAD_INPUT));
    let i = Instance { x25519: h(1), ed25519: h(2), compose: h(3), os: h(4), operator: h(5), registered_at_ms: 6, expires_at_ms: 7, next_seq: 8 };
    let mut b = vec![0u8; INSTANCE_LEN];
    i.pack(&mut b);
    assert_eq!(Instance::unpack(&b).unwrap(), i);
    b[0] = TAG_ANCHOR;
    assert_eq!(Instance::unpack(&b), Err(PlrError::E_BAD_INPUT), "wrong kind of account");
    let o = Operator { org: b"org-a".to_vec() };
    let mut b = vec![0u8; OPERATOR_LEN];
    o.pack(&mut b);
    assert_eq!(Operator::unpack(&b).unwrap(), o);
    Operator { org: vec![] }.pack(&mut b);
    assert!(!Operator::unpack(&b).unwrap().approved());
}

// ------------------------------------------------------------------------------------------------- rules

#[test]
fn base58_matches_the_reference_encoder() {
    assert_eq!(b58(&[0; 32]), "11111111111111111111111111111111");
    let mut seed = 0x1234_5678_9abc_def0u64;
    for _ in 0..200 {
        let mut b = [0u8; 32];
        for x in b.iter_mut() {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            *x = seed as u8;
        }
        if seed % 5 == 0 {
            b[0] = 0;
            b[1] = 0;
        }
        assert_eq!(b58(&b), Pubkey::new_from_array(b).to_string());
    }
}
fn b58(b: &[u8; 32]) -> String {
    let (o, n) = rules::base58_32(b);
    String::from_utf8(o[..n].to_vec()).unwrap()
}

#[test]
fn key_hash_and_registration_nonce_follow_spec_5() {
    use solana_program::hash::hash;
    let manual = hash(&[b"PLR-v1".as_slice(), &h(1), &h(2)].concat()).to_bytes();
    assert_eq!(rules::key_hash(&h(1), &h(2)), manual);
    let parts: [&[u8]; 5] = [b"PLR-v1/register/2", &[2], b"ab", &[1], b"c"];
    assert_eq!(rules::registration_nonce(b"ab", b"c"), Some(hash(&parts.concat()).to_bytes()));
    assert_ne!(rules::registration_nonce(b"ab", b"c"), rules::registration_nonce(b"a", b"bc"));
    assert!(rules::registration_nonce(b"", b"c").is_none());
    assert!(rules::registration_nonce(&[b'x'; 65], b"c").is_none());
    assert!(rules::registration_nonce(&[b'x'; 64], &[b'y'; 64]).is_some());
    let (c, n) = rules::contract_id(&key(3).to_bytes());
    assert_eq!(std::str::from_utf8(&c[..n]).unwrap(), format!("solana:{}", key(3)));
}

#[test]
fn org_ids_follow_spec_7() {
    for ok in ["a", "org-a", "0", "a.b_c-d", &"a".repeat(64)] {
        assert!(rules::valid_org(ok.as_bytes()), "{ok}");
    }
    for bad in ["", "-a", ".a", "A", "org a", "orgé", &"a".repeat(65), "_x"] {
        assert!(!rules::valid_org(bad.as_bytes()), "{bad}");
    }
}

fn quote_for(kh: &[u8; 32], nonce: &[u8; 32]) -> Vec<u8> {
    let mut q = vec![0u8; QUOTE_LEN];
    q[0..2].copy_from_slice(&4u16.to_le_bytes());
    q[2..4].copy_from_slice(&2u16.to_le_bytes());
    q[4..8].copy_from_slice(&0x81u32.to_le_bytes());
    q[568..600].copy_from_slice(kh);
    q[600..632].copy_from_slice(nonce);
    q
}

#[test]
fn quote_format_and_report_data_checks() {
    let (kh, n) = (h(1), h(2));
    let q = quote_for(&kh, &n);
    assert_eq!(rules::check_quote(&q, &kh, &n), Ok(()));
    assert_eq!(rules::check_quote(&q[..827], &kh, &n), Err(PlrError::E_QUOTE_FORMAT));
    let mut long = q.clone();
    long.push(0);
    assert_eq!(rules::check_quote(&long, &kh, &n), Err(PlrError::E_QUOTE_FORMAT));
    for (off, v) in [(0usize, 3u8), (2, 3), (4, 0x80)] {
        let mut b = q.clone();
        b[off] = v;
        assert_eq!(rules::check_quote(&b, &kh, &n), Err(PlrError::E_QUOTE_FORMAT), "offset {off}");
    }
    assert_eq!(rules::check_quote(&q, &h(9), &n), Err(PlrError::E_REPORT_DATA));
    assert_eq!(rules::check_quote(&q, &kh, &h(9)), Err(PlrError::E_REPORT_DATA));
}

#[test]
fn clock_ms_is_checked() {
    assert_eq!(rules::clock_ms(2), Ok(2000));
    assert_eq!(rules::clock_ms(-1), Err(PlrError::E_BAD_INPUT));
    assert_eq!(rules::clock_ms(i64::MAX), Err(PlrError::E_BAD_INPUT));
}

// ------------------------------------------------------------------------------------------------- processor

#[derive(Clone)]
struct Acct {
    lamports: u64,
    data: Vec<u8>,
    owner: Pubkey,
}

struct FakeRt {
    now_s: Cell<i64>,
}

fn find<'a, 'b>(accs: &'a [AccountInfo<'b>], k: &Pubkey) -> &'a AccountInfo<'b> {
    accs.iter().find(|a| a.key == k).expect("CPI account missing")
}

impl Runtime for FakeRt {
    fn unix_timestamp(&self) -> Result<i64, PlrError> {
        Ok(self.now_s.get())
    }
    fn rent_exempt_minimum(&self, len: usize) -> Result<u64, PlrError> {
        Ok(1000 + len as u64 * 10)
    }
    fn invoke_signed(&self, ix: &Instruction, accs: &[AccountInfo], seeds: &[&[&[u8]]]) -> Result<(), PlrError> {
        assert_eq!(ix.program_id, SYSTEM_PROGRAM_ID);
        assert!(accs.iter().any(|a| a.key == &SYSTEM_PROGRAM_ID), "system program account passed");
        let pdas: Vec<Pubkey> = seeds.iter().map(|s| Pubkey::create_program_address(s, &PROGRAM).unwrap()).collect();
        let signed = |k: &Pubkey| pdas.contains(k) || find(accs, k).is_signer;
        for m in &ix.accounts {
            if m.is_signer {
                assert!(signed(&m.pubkey), "CPI signer {} not signed", m.pubkey);
            }
        }
        let tag = u32::from_le_bytes(ix.data[0..4].try_into().unwrap());
        let u64at = |o: usize| u64::from_le_bytes(ix.data[o..o + 8].try_into().unwrap());
        let leak = |n: usize| -> &'static mut [u8] { Box::leak(vec![0u8; n].into_boxed_slice()) };
        match tag {
            0 => {
                let (from, to) = (find(accs, &ix.accounts[0].pubkey), find(accs, &ix.accounts[1].pubkey));
                assert_eq!(**to.lamports.borrow(), 0);
                let (lamports, space) = (u64at(4), u64at(12) as usize);
                **from.lamports.borrow_mut() -= lamports;
                **to.lamports.borrow_mut() += lamports;
                *to.data.borrow_mut() = leak(space);
                to.assign(&Pubkey::new_from_array(ix.data[20..52].try_into().unwrap()));
            }
            2 => {
                let (from, to) = (find(accs, &ix.accounts[0].pubkey), find(accs, &ix.accounts[1].pubkey));
                **from.lamports.borrow_mut() -= u64at(4);
                **to.lamports.borrow_mut() += u64at(4);
            }
            8 => {
                let a = find(accs, &ix.accounts[0].pubkey);
                assert_eq!(a.data_len(), 0);
                *a.data.borrow_mut() = leak(u64at(4) as usize);
            }
            1 => find(accs, &ix.accounts[0].pubkey).assign(&Pubkey::new_from_array(ix.data[4..36].try_into().unwrap())),
            t => panic!("unexpected system instruction {t}"),
        }
        Ok(())
    }
}

/// A tiny ledger: transactions are atomic (state written back only on success).
struct World {
    accts: HashMap<Pubkey, Acct>,
    rt: FakeRt,
    state: Pubkey,
}

impl World {
    fn get(&self, k: &Pubkey) -> Acct {
        self.accts.get(k).cloned().unwrap_or(Acct { lamports: 0, data: vec![], owner: SYSTEM_PROGRAM_ID })
    }

    fn call(&mut self, signers: &[Pubkey], keys: &[Pubkey], data: &[u8]) -> Result<(), u32> {
        let mut infos = Vec::new();
        for k in keys {
            let a = self.get(k);
            let key: &'static Pubkey = Box::leak(Box::new(*k));
            let lamports: &'static mut u64 = Box::leak(Box::new(a.lamports));
            let d: &'static mut [u8] = Box::leak(a.data.into_boxed_slice());
            let owner: &'static Pubkey = Box::leak(Box::new(a.owner));
            infos.push(AccountInfo::new(key, signers.contains(k), true, lamports, d, owner, false));
        }
        match process(&self.rt, &PROGRAM, &infos, data) {
            Ok(()) => {
                for i in &infos {
                    self.accts.insert(*i.key, Acct { lamports: **i.lamports.borrow(), data: i.data.borrow().to_vec(), owner: *i.owner });
                }
                Ok(())
            }
            Err(ProgramError::Custom(n)) => Err(n),
            Err(e) => panic!("non-custom error {e:?}"),
        }
    }

    fn new() -> World {
        let state = key(100);
        let mut w = World { accts: HashMap::new(), rt: FakeRt { now_s: Cell::new(1_700_000_000) }, state };
        for n in [1u8, 2, 3, 4] {
            w.accts.insert(key(n), Acct { lamports: 1_000_000_000, data: vec![], owner: SYSTEM_PROGRAM_ID });
        }
        w.accts.insert(state, Acct { lamports: 10_000, data: vec![0; STATE_LEN], owner: PROGRAM });
        let init = Ix::Init { owner: OWNER.to_bytes(), root_kind: 1, root_p256: [5; 64], ttl_ms: TTL }.encode();
        w.call(&[state], &[state], &init).unwrap();
        w
    }

    fn pda(&self, seed: &[u8], x: &[u8]) -> Pubkey {
        Pubkey::find_program_address(&[seed, self.state.as_ref(), x], &PROGRAM).0
    }
    fn st(&self) -> State {
        State::unpack(&self.get(&self.state).data).unwrap()
    }
    fn item(&mut self, signer: Pubkey, seed: &[u8], ix: Ix) -> Result<(), u32> {
        let hh = match &ix {
            Ix::AllowCompose { h } | Ix::RevokeCompose { h } | Ix::AllowOs { h } | Ix::RevokeOs { h } => *h,
            _ => unreachable!(),
        };
        let (s, p) = (self.state, self.pda(seed, &hh));
        self.call(&[signer], &[s, signer, p, SYSTEM_PROGRAM_ID], &ix.encode())
    }
    fn allowed(&self, seed: &[u8], tag: u8, hh: &[u8; 32]) -> bool {
        let a = self.get(&self.pda(seed, hh));
        a.owner == PROGRAM && Item::unpack(&a.data, tag).unwrap().allowed
    }
    fn approve(&mut self, signer: Pubkey, op: Pubkey, org: &[u8]) -> Result<(), u32> {
        let (s, p) = (self.state, self.pda(SEED_OPERATOR, op.as_ref()));
        self.call(&[signer], &[s, signer, p, SYSTEM_PROGRAM_ID], &Ix::ApproveOperator { op: op.to_bytes(), org }.encode())
    }
    fn revoke_op(&mut self, op: Pubkey) -> Result<(), u32> {
        let (s, p) = (self.state, self.pda(SEED_OPERATOR, op.as_ref()));
        self.call(&[OWNER], &[s, OWNER, p], &Ix::RevokeOperator { op: op.to_bytes() }.encode())
    }
    fn contract_id(&self) -> String {
        format!("solana:{}", self.state)
    }
    /// A well-formed quote of keys (x, ed) bound to (this registry, `bound_to`).
    fn quote(&self, x: &[u8; 32], ed: &[u8; 32], bound_to: &Pubkey) -> Vec<u8> {
        let nonce = rules::registration_nonce(self.contract_id().as_bytes(), bound_to.to_string().as_bytes()).unwrap();
        quote_for(&rules::key_hash(x, ed), &nonce)
    }
    fn register_q(&mut self, op: Pubkey, x: [u8; 32], ed: [u8; 32], q: &[u8]) -> Result<(), u32> {
        let kh = rules::key_hash(&x, &ed);
        let keys = [self.state, op, self.pda(SEED_OPERATOR, op.as_ref()), self.pda(SEED_INSTANCE, &kh), SYSTEM_PROGRAM_ID];
        self.call(&[op], &keys, &Ix::RegisterInstance { x25519: x, ed25519: ed, compose: h(0xc0), os: h(0x05), quote: q }.encode())
    }
    fn register(&mut self, op: Pubkey) -> Result<(), u32> {
        let q = self.quote(&X, &ED, &op);
        self.register_q(op, X, ED, &q)
    }
    fn inst(&self) -> Option<Instance> {
        let a = self.get(&self.pda(SEED_INSTANCE, &kh()));
        (a.owner == PROGRAM).then(|| Instance::unpack(&a.data).unwrap())
    }
    fn anchor(&mut self, signer: Pubkey, first_seq: u64, count: u64) -> Result<(), u32> {
        let id = self.st().anchor_count;
        let keys = [
            self.state,
            signer,
            self.pda(SEED_INSTANCE, &kh()),
            self.pda(SEED_ANCHOR, &id.to_le_bytes()),
            self.pda(SEED_COMPOSE, &h(0xc0)),
            self.pda(SEED_OS, &h(0x05)),
            SYSTEM_PROGRAM_ID,
        ];
        self.call(&[signer], &keys, &Ix::AnchorReceipts { key_hash: kh(), root: h(0xaa), first_seq, count, sig: [0x5a; 64] }.encode())
    }
    fn ready(&mut self) {
        self.item(OWNER, SEED_COMPOSE, Ix::AllowCompose { h: h(0xc0) }).unwrap();
        self.item(OWNER, SEED_OS, Ix::AllowOs { h: h(0x05) }).unwrap();
        self.approve(OWNER, OPERATOR, b"org-a").unwrap();
        self.register(OPERATOR).unwrap();
    }
}

const OWNER: Pubkey = Pubkey::new_from_array([1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xa5]);
const OPERATOR: Pubkey = Pubkey::new_from_array([2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xa5]);
const OPERATOR2: Pubkey = Pubkey::new_from_array([3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xa5]);
const STRANGER: Pubkey = Pubkey::new_from_array([4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xa5]);
const X: [u8; 32] = [0x11; 32];
const ED: [u8; 32] = [0x22; 32];
fn kh() -> [u8; 32] {
    rules::key_hash(&X, &ED)
}

const E_UNAUTHORIZED: Result<(), u32> = Err(1);

#[test]
fn init_sets_state_once_and_needs_the_state_signature() {
    let mut w = World::new();
    assert_eq!(key(1), OWNER);
    let s = w.st();
    assert_eq!((s.owner, s.root_kind, s.root_p256, s.ttl_ms, s.anchor_count, s.pending_owner), (OWNER.to_bytes(), 1, [5; 64], TTL, 0, None));
    let init = Ix::Init { owner: STRANGER.to_bytes(), root_kind: 1, root_p256: [5; 64], ttl_ms: TTL }.encode();
    let st = w.state;
    assert_eq!(w.call(&[st], &[st], &init), E_UNAUTHORIZED, "already initialized");
    let fresh = key(101);
    w.accts.insert(fresh, Acct { lamports: 1, data: vec![0; STATE_LEN], owner: PROGRAM });
    assert_eq!(w.call(&[], &[fresh], &init), E_UNAUTHORIZED, "state must sign");
    let bad = Ix::Init { owner: STRANGER.to_bytes(), root_kind: 3, root_p256: [5; 64], ttl_ms: TTL }.encode();
    assert_eq!(w.call(&[fresh], &[fresh], &bad), Err(3));
    let bad = Ix::Init { owner: STRANGER.to_bytes(), root_kind: 1, root_p256: [5; 64], ttl_ms: 0 }.encode();
    assert_eq!(w.call(&[fresh], &[fresh], &bad), Err(3));
    let other = key(102);
    w.accts.insert(other, Acct { lamports: 1, data: vec![0; STATE_LEN], owner: SYSTEM_PROGRAM_ID });
    assert_eq!(w.call(&[other], &[other], &init), Err(3), "state must be owned by the program");
}

#[test]
fn owner_policy_and_stranger_refusal() {
    let mut w = World::new();
    assert_eq!(w.item(OWNER, SEED_COMPOSE, Ix::AllowCompose { h: h(9) }), Ok(()));
    assert!(w.allowed(SEED_COMPOSE, TAG_COMPOSE, &h(9)));
    assert!(!w.allowed(SEED_OS, TAG_OS, &[0x77; 32]));
    assert_eq!(w.item(OWNER, SEED_COMPOSE, Ix::RevokeCompose { h: h(9) }), Ok(()));
    assert!(!w.allowed(SEED_COMPOSE, TAG_COMPOSE, &h(9)));
    assert_eq!(w.item(OWNER, SEED_COMPOSE, Ix::AllowCompose { h: h(9) }), Ok(()), "re-allow reuses the PDA");
    assert!(w.allowed(SEED_COMPOSE, TAG_COMPOSE, &h(9)));
    assert_eq!(w.item(OWNER, SEED_OS, Ix::AllowOs { h: h(9) }), Ok(()));
    assert!(w.allowed(SEED_OS, TAG_OS, &h(9)));
    assert_eq!(w.item(OWNER, SEED_OS, Ix::RevokeOs { h: h(8) }), Ok(()), "revoking an unknown hash is a no-op");
    assert_eq!(w.item(STRANGER, SEED_COMPOSE, Ix::AllowCompose { h: h(10) }), E_UNAUTHORIZED);
    assert_eq!(w.item(STRANGER, SEED_COMPOSE, Ix::RevokeCompose { h: h(9) }), E_UNAUTHORIZED);
    assert!(w.allowed(SEED_COMPOSE, TAG_COMPOSE, &h(9)));
    assert_eq!(w.item(OWNER, SEED_COMPOSE, Ix::AllowCompose { h: [0; 32] }), Err(2), "E_ZERO_HASH");
    // owner key without its signature
    let (s, p) = (w.state, w.pda(SEED_COMPOSE, &h(11)));
    assert_eq!(w.call(&[], &[s, OWNER, p, SYSTEM_PROGRAM_ID], &Ix::AllowCompose { h: h(11) }.encode()), E_UNAUTHORIZED);
    // a PDA of another hash is refused
    let wrong = w.pda(SEED_COMPOSE, &h(12));
    assert_eq!(w.call(&[OWNER], &[s, OWNER, wrong, SYSTEM_PROGRAM_ID], &Ix::AllowCompose { h: h(11) }.encode()), Err(3));
    // compose entries never satisfy OS seeds (different seed prefix)
    assert_ne!(w.pda(SEED_COMPOSE, &h(9)), w.pda(SEED_OS, &h(9)));
}

#[test]
fn prefunded_pda_is_still_created() {
    let mut w = World::new();
    let p = w.pda(SEED_COMPOSE, &h(13));
    w.accts.insert(p, Acct { lamports: 5, data: vec![], owner: SYSTEM_PROGRAM_ID });
    assert_eq!(w.item(OWNER, SEED_COMPOSE, Ix::AllowCompose { h: h(13) }), Ok(()));
    assert!(w.allowed(SEED_COMPOSE, TAG_COMPOSE, &h(13)));
    assert_eq!(w.get(&p).lamports, 1000 + ITEM_LEN as u64 * 10);
}

#[test]
fn root_and_two_step_ownership() {
    let mut w = World::new();
    let s = w.state;
    assert_eq!(w.call(&[OWNER], &[s, OWNER], &Ix::SetRoot { kind: 2, p256: [6; 64] }.encode()), Ok(()));
    assert_eq!((w.st().root_kind, w.st().root_p256), (2, [6; 64]));
    assert_eq!(w.call(&[OWNER], &[s, OWNER], &Ix::SetRoot { kind: 0, p256: [6; 64] }.encode()), Err(3));
    assert_eq!(w.call(&[STRANGER], &[s, STRANGER], &Ix::SetRoot { kind: 1, p256: [6; 64] }.encode()), E_UNAUTHORIZED);
    assert_eq!(w.call(&[STRANGER], &[s, STRANGER], &Ix::ProposeOwner { next: STRANGER.to_bytes() }.encode()), E_UNAUTHORIZED);
    assert_eq!(w.call(&[OWNER], &[s, OWNER], &Ix::ProposeOwner { next: OPERATOR2.to_bytes() }.encode()), Ok(()));
    assert_eq!(w.call(&[STRANGER], &[s, STRANGER], &Ix::AcceptOwner.encode()), E_UNAUTHORIZED);
    assert_eq!(w.call(&[], &[s, OPERATOR2], &Ix::AcceptOwner.encode()), E_UNAUTHORIZED, "must sign");
    assert_eq!(w.st().owner, OWNER.to_bytes());
    assert_eq!(w.call(&[OPERATOR2], &[s, OPERATOR2], &Ix::AcceptOwner.encode()), Ok(()));
    assert_eq!((w.st().owner, w.st().pending_owner), (OPERATOR2.to_bytes(), None));
    assert_eq!(w.item(OWNER, SEED_COMPOSE, Ix::AllowCompose { h: h(1) }), E_UNAUTHORIZED, "old owner lost its rights");
    assert_eq!(w.item(OPERATOR2, SEED_COMPOSE, Ix::AllowCompose { h: h(1) }), Ok(()));
}

#[test]
fn operators_are_owner_approved_with_valid_orgs() {
    let mut w = World::new();
    assert_eq!(w.approve(OWNER, OPERATOR, b"Org"), Err(3));
    assert_eq!(w.approve(STRANGER, OPERATOR, b"org-a"), E_UNAUTHORIZED);
    assert_eq!(w.approve(OWNER, OPERATOR, b"org-a"), Ok(()));
    let rec = |w: &World| Operator::unpack(&w.get(&w.pda(SEED_OPERATOR, OPERATOR.as_ref())).data).unwrap();
    assert_eq!(rec(&w).org, b"org-a");
    assert_eq!(w.approve(OWNER, OPERATOR, b"org-b"), Ok(()));
    assert_eq!(rec(&w).org, b"org-b");
    assert_eq!(w.revoke_op(OPERATOR), Ok(()));
    assert!(!rec(&w).approved());
    assert_eq!(w.revoke_op(OPERATOR2), Ok(()), "revoking an unknown operator is a no-op");
}

#[test]
fn registration_rules() {
    let mut w = World::new();
    assert_eq!(w.register(OPERATOR), Err(4), "E_OPERATOR_UNAPPROVED");
    w.approve(OWNER, OPERATOR, b"org-a").unwrap();
    // quote bound to another operator / another registry / malformed
    let q = w.quote(&X, &ED, &OPERATOR2);
    assert_eq!(w.register_q(OPERATOR, X, ED, &q), Err(5), "E_REPORT_DATA");
    let mut q = w.quote(&X, &ED, &OPERATOR);
    q[4] = 0;
    assert_eq!(w.register_q(OPERATOR, X, ED, &q), Err(6), "E_QUOTE_FORMAT");
    let q = w.quote(&X, &ED, &OPERATOR);
    assert_eq!(w.register_q(OPERATOR, X, ED, &q[..800]), Err(6), "short quote");
    let q2 = w.quote(&X, &[0x23; 32], &OPERATOR);
    assert_eq!(w.register_q(OPERATOR, X, ED, &q2), Err(5), "keys must hash to report_data[0:32]");
    // operator must sign
    let keys = [w.state, OPERATOR, w.pda(SEED_OPERATOR, OPERATOR.as_ref()), w.pda(SEED_INSTANCE, &kh()), SYSTEM_PROGRAM_ID];
    assert_eq!(w.call(&[], &keys, &Ix::RegisterInstance { x25519: X, ed25519: ED, compose: h(0xc0), os: h(0x05), quote: &q }.encode()), E_UNAUTHORIZED);
    // another operator's (approved) op PDA does not stand in for ours
    w.approve(OWNER, OPERATOR2, b"org-b").unwrap();
    let keys = [w.state, OPERATOR, w.pda(SEED_OPERATOR, OPERATOR2.as_ref()), w.pda(SEED_INSTANCE, &kh()), SYSTEM_PROGRAM_ID];
    assert_eq!(w.call(&[OPERATOR], &keys, &Ix::RegisterInstance { x25519: X, ed25519: ED, compose: h(0xc0), os: h(0x05), quote: &q }.encode()), Err(3));

    assert_eq!(w.register(OPERATOR), Ok(()));
    let i = w.inst().unwrap();
    let now = 1_700_000_000_000u64;
    assert_eq!((i.operator, i.x25519, i.ed25519, i.compose, i.os), (OPERATOR.to_bytes(), X, ED, h(0xc0), h(0x05)));
    assert_eq!((i.registered_at_ms, i.expires_at_ms, i.next_seq), (now, now + TTL, 0));
    let data = w.get(&w.pda(SEED_INSTANCE, &kh())).data;
    assert_eq!(Instance::quote(&data).unwrap(), &q[..]);

    // first registrant owns the key
    assert_eq!(w.register(OPERATOR2), E_UNAUTHORIZED);
    // revoked operator cannot (re-)register
    w.revoke_op(OPERATOR).unwrap();
    assert_eq!(w.register(OPERATOR), Err(4));
    w.approve(OWNER, OPERATOR, b"org-a").unwrap();
    // zero compose hash
    let keys = [w.state, OPERATOR, w.pda(SEED_OPERATOR, OPERATOR.as_ref()), w.pda(SEED_INSTANCE, &kh()), SYSTEM_PROGRAM_ID];
    assert_eq!(w.call(&[OPERATOR], &keys, &Ix::RegisterInstance { x25519: X, ed25519: ED, compose: [0; 32], os: h(0x05), quote: &q }.encode()), Err(2));
}

#[test]
fn owner_revocation_frees_a_squatted_key() {
    let mut w = World::new();
    w.item(OWNER, SEED_COMPOSE, Ix::AllowCompose { h: h(0xc0) }).unwrap();
    w.item(OWNER, SEED_OS, Ix::AllowOs { h: h(0x05) }).unwrap();
    // OPERATOR2 (approved) squats the honest instance's public key hash with an unsigned quote bound to itself
    w.approve(OWNER, OPERATOR2, b"org-squat").unwrap();
    w.register(OPERATOR2).unwrap();
    w.anchor(OPERATOR2, 0, 7).unwrap();
    w.approve(OWNER, OPERATOR, b"org-a").unwrap();
    let q = w.quote(&X, &ED, &OPERATOR);
    let prev = w.pda(SEED_OPERATOR, OPERATOR2.as_ref());
    let keys = [w.state, OPERATOR, w.pda(SEED_OPERATOR, OPERATOR.as_ref()), w.pda(SEED_INSTANCE, &kh()), SYSTEM_PROGRAM_ID, prev];
    let ix = Ix::RegisterInstance { x25519: X, ed25519: ED, compose: h(0xc0), os: h(0x05), quote: &q }.encode();
    // while the squatter is approved the key is its own, with or without the previous-operator account, even expired
    assert_eq!(w.register(OPERATOR), E_UNAUTHORIZED);
    assert_eq!(w.call(&[OPERATOR], &keys, &ix), E_UNAUTHORIZED);
    w.rt.now_s.set(1_700_000_000 + 2 * 86_400);
    assert_eq!(w.call(&[OPERATOR], &keys, &ix), E_UNAUTHORIZED);
    // a wrong previous-operator account is refused
    let wrong = [w.state, OPERATOR, w.pda(SEED_OPERATOR, OPERATOR.as_ref()), w.pda(SEED_INSTANCE, &kh()), SYSTEM_PROGRAM_ID, w.pda(SEED_OPERATOR, STRANGER.as_ref())];
    w.revoke_op(OPERATOR2).unwrap();
    assert_eq!(w.call(&[OPERATOR], &wrong, &ix), Err(3), "E_BAD_INPUT");
    // without the previous-operator account the current operator counts as approved
    assert_eq!(w.register(OPERATOR), E_UNAUTHORIZED);
    // after revocation the honest operator takes the key over as a fresh record
    assert_eq!(w.call(&[OPERATOR], &keys, &ix), Ok(()));
    let i = w.inst().unwrap();
    let now = (1_700_000_000u64 + 2 * 86_400) * 1000;
    assert_eq!((i.operator, i.registered_at_ms, i.expires_at_ms, i.next_seq), (OPERATOR.to_bytes(), now, now + TTL, 0));
    assert_eq!(Instance::quote(&w.get(&w.pda(SEED_INSTANCE, &kh())).data).unwrap(), &q[..]);
    w.anchor(OPERATOR, 0, 1).unwrap();
    // re-approving the squatter does not give the key back
    w.approve(OWNER, OPERATOR2, b"org-squat").unwrap();
    let keys2 = [w.state, OPERATOR2, w.pda(SEED_OPERATOR, OPERATOR2.as_ref()), w.pda(SEED_INSTANCE, &kh()), SYSTEM_PROGRAM_ID, w.pda(SEED_OPERATOR, OPERATOR.as_ref())];
    let q2 = w.quote(&X, &ED, &OPERATOR2);
    assert_eq!(w.call(&[OPERATOR2], &keys2, &Ix::RegisterInstance { x25519: X, ed25519: ED, compose: h(0xc0), os: h(0x05), quote: &q2 }.encode()), E_UNAUTHORIZED);
    assert_eq!(w.anchor(OPERATOR2, 1, 1), E_UNAUTHORIZED);
}

#[test]
fn refresh_keeps_next_seq_and_replaces_the_quote() {
    let mut w = World::new();
    w.ready();
    w.anchor(OPERATOR, 0, 5).unwrap();
    w.rt.now_s.set(1_700_000_100);
    let mut q = w.quote(&X, &ED, &OPERATOR);
    q[700] = 0x42; // a different (fresh) quote of the same binding
    assert_eq!(w.register_q(OPERATOR, X, ED, &q), Ok(()));
    let i = w.inst().unwrap();
    assert_eq!((i.next_seq, i.registered_at_ms, i.expires_at_ms), (5, 1_700_000_100_000, 1_700_000_100_000 + TTL));
    assert_eq!(Instance::quote(&w.get(&w.pda(SEED_INSTANCE, &kh())).data).unwrap()[700], 0x42);
}

#[test]
fn anchor_rules() {
    let mut w = World::new();
    assert_eq!(w.anchor(OPERATOR, 0, 1), Err(8), "E_INSTANCE_NOT_REGISTERED");
    w.ready();
    assert_eq!(w.anchor(OPERATOR, 1, 1), Err(7), "E_SEQ");
    assert_eq!(w.anchor(OPERATOR, 0, 0), Err(3));
    assert_eq!(w.anchor(OPERATOR, 0, 10_001), Err(3));
    assert_eq!(w.anchor(STRANGER, 0, 1), E_UNAUTHORIZED);
    assert_eq!(w.anchor(OPERATOR, 0, 10_000), Ok(()));
    assert_eq!(w.anchor(OPERATOR, 10_000, 2), Ok(()));
    assert_eq!(w.st().anchor_count, 2);
    assert_eq!(w.inst().unwrap().next_seq, 10_002);
    let a = Anchor::unpack(&w.get(&w.pda(SEED_ANCHOR, &1u64.to_le_bytes())).data).unwrap();
    assert_eq!(a, Anchor { key_hash: kh(), root: h(0xaa), first_seq: 10_000, count: 2, at_ms: 1_700_000_000_000, sig: [0x5a; 64] });
    // wrong anchor id PDA
    let keys = [w.state, OPERATOR, w.pda(SEED_INSTANCE, &kh()), w.pda(SEED_ANCHOR, &0u64.to_le_bytes()), w.pda(SEED_COMPOSE, &h(0xc0)), w.pda(SEED_OS, &h(0x05)), SYSTEM_PROGRAM_ID];
    assert_eq!(w.call(&[OPERATOR], &keys, &Ix::AnchorReceipts { key_hash: kh(), root: h(1), first_seq: 10_002, count: 1, sig: [0; 64] }.encode()), Err(3));
    // compose / OS revocation stops anchoring
    w.item(OWNER, SEED_COMPOSE, Ix::RevokeCompose { h: h(0xc0) }).unwrap();
    assert_eq!(w.anchor(OPERATOR, 10_002, 1), Err(9), "E_COMPOSE_NOT_ALLOWED");
    w.item(OWNER, SEED_COMPOSE, Ix::AllowCompose { h: h(0xc0) }).unwrap();
    w.item(OWNER, SEED_OS, Ix::RevokeOs { h: h(0x05) }).unwrap();
    assert_eq!(w.anchor(OPERATOR, 10_002, 1), Err(9));
    w.item(OWNER, SEED_OS, Ix::AllowOs { h: h(0x05) }).unwrap();
    assert_eq!(w.anchor(OPERATOR, 10_002, 1), Ok(()));
    // expiry (Clock time)
    w.rt.now_s.set(1_700_000_000 + (TTL / 1000) as i64);
    assert_eq!(w.anchor(OPERATOR, 10_003, 1), Err(8));
    // a refresh revives it, keeping next_seq
    w.register(OPERATOR).unwrap();
    assert_eq!(w.anchor(OPERATOR, 10_003, 1), Ok(()));
    assert_eq!(w.st().anchor_count, 4);
}
