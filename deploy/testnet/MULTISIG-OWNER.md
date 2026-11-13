# Moving the registry owner from one key to a 2-of-3 council

Today one account, `pe-owner-erhan.testnet`, owns the registry `vpnreg.pe-owner-erhan.testnet`. Whoever holds that
one key decides which exit builds are allowed. This page shows how to hand that role to an account that only acts
when two of three people agree, and proves the whole path on a throwaway copy of the registry.

**Status: done on 2026-11-13.** The registry's owner is the 2-of-3 council `pe-owners.sputnikv2.testnet`, with members
`pe-council1-erhan.testnet`, `pe-council2-erhan.testnet` and `pe-council3-erhan.testnet`. All three seats are held by
the author for now; giving two of them to other people is one DAO policy proposal and does not touch the registry.

| step | transaction |
|---|---|
| DAO created (3 members, threshold 2, no access keys, code hash `AA4nA45v…`) | [`3ywCUrJW…`](https://testnet.nearblocks.io/txns/3ywCUrJWrLMRsSPe3bRP8rURxHzqf7T9rkmb9PtKW2n4) |
| factory auto-update turned off (proposal 0, two approvals) | [`CMK9GzuD…`](https://testnet.nearblocks.io/txns/CMK9GzuDo8hnpY2sfgNHAsaABHPTSa8NpgRTko4zjGeW), [`BPWDHNp6…`](https://testnet.nearblocks.io/txns/BPWDHNp6S3oYPJhLBBRM9goThesGRB2Pe4supzhNNQAx), [`8DkW2KYg…`](https://testnet.nearblocks.io/txns/8DkW2KYgWgKtnobeCvgxjmHd2YdvoYeLAbYd6PyBVY9b) |
| `propose_owner(pe-owners.sputnikv2.testnet)` by the single owner | [`BLaRVAn1…`](https://testnet.nearblocks.io/txns/BLaRVAn19UAjboeJEJQ9Xqc5nN7f2Yn1N9AeqYV1ao3K) |
| proposal 1 `accept_owner`, first approval (owner unchanged), second approval (owner = DAO) | [`8w4hSwiy…`](https://testnet.nearblocks.io/txns/8w4hSwiybzMod8Jj8UU9MGJE1RN7PPNeMs3YV6w5AgWv), [`AG21wQyc…`](https://testnet.nearblocks.io/txns/AG21wQycaDwUC31kHHjP6Wm9SfvfE5evubKAKcBtwAi4), [`HzsVd6XC…`](https://testnet.nearblocks.io/txns/HzsVd6XCWaB3JCxKfhktTAvP7htxKtNESsqczxHfPgsq) |

The steps below are the throwaway rehearsal and the generic commands it was done with.

## What changes, and what does not

- The owner becomes a Sputnik DAO account (`<name>.sputnikv2.testnet`) with three council members. Every owner
  action (`allow_compose`, `revoke_compose`, `allow_os`, `revoke_os`, `set_root`, `approve_operator`,
  `revoke_operator`, `propose_owner`) becomes a DAO proposal that runs only after two members approve it.
- The DAO account has no access key. Nobody can sign as it directly; it only moves through approved proposals.
- The registry contract, its account, its code hash (`C1hvenbrzHKN1n1f2z63Duburr8YXLAKBescrEvarCGM`) and its
  allowlist stay exactly as they are. Clients, exits and the operator need no change. The status page reads
  `get_owner` live, so it shows the new owner by itself.
- `scripts/owner.sh` stops working for the old key (the registry answers `E_UNAUTHORIZED`). Council members use
  `scripts/owner-dao.sh` instead.

Why Sputnik DAO and not the NEAR multisig contract: the DAO factory `sputnikv2.testnet` is live (5 600+ DAOs) and
creates a keyless account with a known code hash in one transaction, with nothing to build or audit ourselves. The
multisig contract would have to be built from source and deployed by hand, and it confirms requests with access
keys on the multisig account itself, which is harder to explain and to check from outside.

(The factory account is `sputnikv2.testnet`, without a dash. `sputnik-v2.testnet` exists too but is not the
factory: it does not answer the factory's view methods.)

## The throwaway run (NEAR testnet, 2026-11-13)

Accounts, all created from the testnet faucet for this test:

| role | account |
|---|---|
| registry copy | `vpnreg.pe-msdemo-owner.testnet` (same wasm as the live registry: fetched with `view_code`, SHA-256 `a39ed48c…0d9e`, code hash `C1hvenbr…arCGM`) |
| single owner | `pe-msdemo-owner.testnet` |
| council | `pe-msdemo-c1.testnet`, `pe-msdemo-c2.testnet`, `pe-msdemo-c3.testnet` |
| 2-of-3 owner | `pe-msdemo.sputnikv2.testnet` (code hash `AA4nA45vauiac3jdVwJTzSdUP3oj2r1fDaPAb2mHdgcH`, the factory default, Sputnik DAO 2.3.1; no access keys) |

`ab…ab` below is the dummy compose hash `abab…abab` (32 bytes of `ab`).

| # | what happened | signed by | result | transaction |
|---|---|---|---|---|
| 1 | create the registry account | single owner | ok | [2oJXuqkJ…](https://testnet.nearblocks.io/txns/2oJXuqkJWXaiFnpqAA2DGUWD6Cjsv95byNFL7Py9GgdK) |
| 2 | deploy the wasm and `new(owner = single owner, INTEL root)` | registry account | ok, code hash equals the live one | [GNtDfdZU…](https://testnet.nearblocks.io/txns/GNtDfdZUkFN5sGA343E99XwYAYFjMKTAfC8jAURdZxfT) |
| 3 | `allow_compose(ab…ab)` the old way | single owner | allowed | [5eis51kd…](https://testnet.nearblocks.io/txns/5eis51kds2ED66vRg2Eon74nBeWYjgwKoLxbJiGXENUP) |
| 4 | create the DAO with a 2-of-3 council | c1 | ok | [4CNSopoW…](https://testnet.nearblocks.io/txns/4CNSopoWcihVNp6N78frdJg77uD48yQPuH1QFiCEJwW3) |
| 5 | `propose_owner(DAO)` | single owner | pending owner = DAO, owner unchanged | [Dtj7s1yD…](https://testnet.nearblocks.io/txns/Dtj7s1yDptVVLN5Y4TBe8V69kjsXRzodEV4Q1ovPYD4S) |
| 6 | DAO proposal 0: call `accept_owner` | c1 | proposal created | [3LFMKjon…](https://testnet.nearblocks.io/txns/3LFMKjon1WJ572KmG3vpn5j8qpNM3isMwj57ix2Fg51J) |
| 7 | first approval | c1 | **nothing runs**: proposal `InProgress`, owner still the single key | [Hnnzwnk9…](https://testnet.nearblocks.io/txns/Hnnzwnk9XT7CxasnzyWJtHkNKsBPYkYdp3eWqcKdP2b6) |
| 8 | second approval | c2 | `accept_owner` runs, **owner = DAO** | [HASJ9uKH…](https://testnet.nearblocks.io/txns/HASJ9uKHZFPmQzJd3taNCemFGHEJmnTXbx8R8jqWa9Ay) |
| 9 | `revoke_compose(ab…ab)` with the old key | single owner | **refused**: `E_UNAUTHORIZED: only the owner` | [4zqqWXVr…](https://testnet.nearblocks.io/txns/4zqqWXVrSueouFGKUq59u4yPa7m5NBvGR7vFkWmHixDT) |
| 10 | an account outside the council tries to add a DAO proposal | single owner | **refused**: `ERR_PERMISSION_DENIED` | [Ghfxy4GH…](https://testnet.nearblocks.io/txns/Ghfxy4GHteWEn5ELGdYTWumg4fJRhebY7vPyTRJmpkmE) |
| 11 | DAO proposal 1: call `revoke_compose(ab…ab)` | c1 | proposal created | [aPbBtfA5…](https://testnet.nearblocks.io/txns/aPbBtfA5o317CThjW86p6RifbeHwVtZMkXcJ66BaY6p) |
| 12 | first approval | c1 | **nothing runs**: hash still allowed | [xeHwVsg5…](https://testnet.nearblocks.io/txns/xeHwVsg5m6WP6MVUUt1Hov6GkdQP9JX6cdaLTPyJAst) |
| 13 | second approval | c3 | `revoke_compose` runs, **hash no longer allowed** | [3TNyhpLz…](https://testnet.nearblocks.io/txns/3TNyhpLzpxtMVT1iaRegkjY3dNHR22vuorcC65CyhGVs) |
| 14 | DAO proposal 2: turn off factory auto-update (see "What you still trust") | c2 | proposal created | [7HmXC2Gc…](https://testnet.nearblocks.io/txns/7HmXC2Gcnq6afjyJ3rW2AKdS9fKAYAu8A7dGpQ21SfZh) |
| 15 | approvals | c2, then c3 | `auto_update` is now `false` | [DBkMtJyA…](https://testnet.nearblocks.io/txns/DBkMtJyAPc89KtBykppfzsXML4AFxTCHzstmQ64F7GZx), [AkFoEZj7…](https://testnet.nearblocks.io/txns/AkFoEZj7Nvd35wQMUvEBojGVDoTVy9B4Jx91u82ZfTZd) |
| 16 | going back, DAO proposal 3: call `propose_owner(single owner)` | c3 | proposal created | [2ASvfB6y…](https://testnet.nearblocks.io/txns/2ASvfB6yhE9pJ1chtMYjgmYHKMuP6f2X2u3fhWucJT8F) |
| 17 | approvals | c3, then c1 | pending owner = single owner | [BaVksZRv…](https://testnet.nearblocks.io/txns/BaVksZRvqHSbfi1T2kGff1uSGhseFU3SjBKLuJo5mmgV), [E22xTpJM…](https://testnet.nearblocks.io/txns/E22xTpJMKu6AXG8g8qemURV4XfS7pP9CRYxgRrKa6u2A) |
| 18 | `accept_owner` | single owner | owner = single owner again | [AymRGGjp…](https://testnet.nearblocks.io/txns/AymRGGjpeJEovDKH66LpcarWbc3ips9PYeyavTRJhKqD) |
| 19 | handed over a second time (`propose_owner`, proposal 4, two approvals) | single owner, c1, c1, c2 | owner = DAO, the state it is left in | [AB7sow6f…](https://testnet.nearblocks.io/txns/AB7sow6fT6jLYihfCcAkLqq9FbXZwWAMg6U8j6jjnYSQ), [7sXJRRcY…](https://testnet.nearblocks.io/txns/7sXJRRcYqrP7d3KnLncCN4M8VnN6BX6kViwukFHYKxo9), [DakBhy9S…](https://testnet.nearblocks.io/txns/DakBhy9SfNX7GwgwR5D9zpACVgmM2SVbbLbTAkdrPzhW), [sPTApy8o…](https://testnet.nearblocks.io/txns/sPTApy8ocSW1uoRiVkWqdymNU2q9NSzLh6GYU4UThVB) |

Rows 14 to 19 were sent with `scripts/owner-dao.sh`, so the helper is tested too. Rows 6 to 13 used the same
calls written out by hand.

Values that worked:

| call | gas | deposit |
|---|---|---|
| `sputnikv2.testnet` `create` | 150 Tgas | 6 NEAR (5.4 NEAR stays locked as the DAO's storage; fee 0.015 NEAR) |
| DAO `add_proposal` | 100 Tgas | 0.1 NEAR bond (set in the policy; returned to the proposer when the proposal is approved) |
| DAO `act_proposal` (`VoteApprove`) | 200 Tgas | 0 (fee about 0.0003 NEAR, about 0.0008 NEAR for the vote that executes) |
| the registry call inside the proposal | `"gas":"30000000000000"` (30 Tgas) | `"deposit":"0"` |

The registry arguments go into the proposal as base64 of the JSON: `{}` is `e30=`, and
`{"hash":"abab…abab"}` is `eyJoYXNoIjoiYWJhYmFi…YWJhYiJ9`. A full proposal body, as sent in row 11:

```json
{"proposal":{"description":"Revoke compose abab…abab","kind":{"FunctionCall":{
  "receiver_id":"vpnreg.pe-msdemo-owner.testnet",
  "actions":[{"method_name":"revoke_compose","args":"<base64 of {\"hash\":\"abab…abab\"}>","deposit":"0","gas":"30000000000000"}]}}}}
```

Not tested: a proposal whose registry call fails, a rejected proposal, an expired proposal (they expire after the
policy's 7 days), and changing the council members.

## Commands for the real registry

**Run on 2026-11-13 (see the top of this page).** Replace `COUNCIL_1`, `COUNCIL_2`, `COUNCIL_3` with three existing testnet accounts held by three
different people (do not reuse the operator account), and pick a DAO name (`pe-owners` below).
Each member needs about 1 NEAR for the bond and fees; whoever creates the DAO needs 6 NEAR more.

1. Any council member creates the DAO (one transaction):

```sh
cat > /tmp/dao-args.json <<'EOF'
{"config":{"name":"pe-owners","purpose":"Owner of the ProvenExit registry vpnreg.pe-owner-erhan.testnet","metadata":""},
 "policy":{"roles":[{"name":"council","kind":{"Group":["COUNCIL_1","COUNCIL_2","COUNCIL_3"]},
   "permissions":["*:AddProposal","*:VoteApprove","*:VoteReject","*:VoteRemove","*:Finalize"],"vote_policy":{}}],
  "default_vote_policy":{"weight_kind":"RoleWeight","quorum":"0","threshold":"2"},
  "proposal_bond":"100000000000000000000000","proposal_period":"604800000000000",
  "bounty_bond":"100000000000000000000000","bounty_forgiveness_period":"604800000000000"}}
EOF
near contract call-function as-transaction sputnikv2.testnet create \
  json-args "{\"name\":\"pe-owners\",\"args\":\"$(base64 < /tmp/dao-args.json | tr -d '\n')\"}" \
  prepaid-gas '150.0 Tgas' attached-deposit '6 NEAR' \
  sign-as COUNCIL_1 network-config testnet sign-with-legacy-keychain send
```

2. Everyone checks the DAO before it gets any power: three members, `"threshold":"2"`, no access keys, the
   expected code hash.

```sh
export DAO_ID=pe-owners.sputnikv2.testnet
scripts/owner-dao.sh show                                   # policy: the three accounts, threshold "2"
near account list-keys $DAO_ID network-config testnet now   # must be empty
curl -s https://rpc.testnet.fastnear.com -H 'content-type: application/json' -d '{"jsonrpc":"2.0","id":1,"method":"query",
  "params":{"request_type":"view_account","finality":"final","account_id":"'$DAO_ID'"}}'   # "code_hash":"AA4nA45vauiac3jdVwJTzSdUP3oj2r1fDaPAb2mHdgcH"
```

3. Turn off factory auto-update, so that only the council can ever change the DAO's code:

```sh
COUNCIL_ID=COUNCIL_1 scripts/owner-dao.sh raw "Turn off factory auto-update" \
  '{"FactoryInfoUpdate":{"factory_info":{"factory_id":"sputnikv2.testnet","auto_update":false}}}'   # prints the id, 0
COUNCIL_ID=COUNCIL_1 scripts/owner-dao.sh approve 0
COUNCIL_ID=COUNCIL_2 scripts/owner-dao.sh approve 0
near contract call-function as-read-only $DAO_ID get_factory_info json-args '{}' network-config testnet now   # auto_update: false
```

4. The current owner names the DAO as the next owner. This is the only step that uses the old owner key, and it
   changes nothing yet: until step 5 completes, the old owner stays owner and can name someone else instead.

```sh
scripts/owner.sh propose_owner '{"id":"pe-owners.sputnikv2.testnet"}'
```

5. The council accepts (two approvals):

```sh
COUNCIL_ID=COUNCIL_1 scripts/owner-dao.sh call accept_owner '{}'   # prints the id, 1
COUNCIL_ID=COUNCIL_1 scripts/owner-dao.sh approve 1
COUNCIL_ID=COUNCIL_2 scripts/owner-dao.sh approve 1
```

6. Check:

```sh
near contract call-function as-read-only vpnreg.pe-owner-erhan.testnet get_owner json-args '{}' network-config testnet now
# "pe-owners.sputnikv2.testnet"
```

Afterwards, write `DAO_ID` into `deploy/testnet/env.live` and replace the `scripts/owner.sh` lines in the deploy
notes and in `scripts/demo-live.sh` (it prints the owner command for the human to run) with the
`scripts/owner-dao.sh` form below.

## A revoke afterwards (the demo version)

```sh
export DAO_ID=pe-owners.sputnikv2.testnet
COUNCIL_ID=COUNCIL_1 scripts/owner-dao.sh call revoke_compose '{"hash":"<compose hash>"}'   # prints the proposal id N
COUNCIL_ID=COUNCIL_1 scripts/owner-dao.sh approve N      # one approval: the build is still allowed
scripts/owner-dao.sh show N                              # "status": "InProgress", one vote
COUNCIL_ID=COUNCIL_2 scripts/owner-dao.sh approve N      # second approval: the revoke runs in this transaction
```

Between the two approvals `plr vpn` still connects; after the second one the client refuses the exit, exactly as
after a single-key revoke. Allowing a build again is the same with `allow_compose`. To show that the old key is
out, run `scripts/owner.sh revoke_compose …` and read `E_UNAUTHORIZED: only the owner`.

**How long it takes.** Three transactions instead of one: propose, approve, approve. In the throwaway run, sent one
after another from one machine, they took 19 seconds in total. In real use the time is however long the second
person needs to see the request and run one command; the chain adds a few seconds per transaction. If no second
member answers, nothing is revoked. That is the price of the change: one person can no longer allow a bad build
alone, and one person can no longer pull a build alone either.

## What you still trust

- Any two of the three council members. Two of them can allow or revoke builds, replace council members, change
  the threshold, or hand ownership on. Losing two of the three keys locks the owner role for good.
- The Sputnik DAO contract (2.3.1, the factory's default code). By default a new DAO lets the factory's owner
  account replace its code (`auto_update: true`). Step 3 turns that off; skip it and the people behind
  `sputnikv2.testnet` could take over the owner role.
- Anyone can read every proposal and vote on chain (`get_proposal`, or the transactions of the DAO account), so
  who approved which build is public.

## Going back

The council hands ownership to a single account with the same two-step move, in the other direction (rows 16 to 18
of the throwaway run):

```sh
COUNCIL_ID=COUNCIL_1 scripts/owner-dao.sh call propose_owner '{"id":"pe-owner-erhan.testnet"}'   # prints N
COUNCIL_ID=COUNCIL_1 scripts/owner-dao.sh approve N
COUNCIL_ID=COUNCIL_2 scripts/owner-dao.sh approve N
scripts/owner.sh accept_owner '{}'
```

It needs two council members to agree. The old owner cannot take the role back alone.

## Left on testnet

The six throwaway accounts in the table above stay on testnet, with the registry copy owned by the DAO. Their keys
are in `~/.near-credentials/testnet/` (the files with `pe-msdemo` in the name) on the machine that ran the test. They hold only faucet
NEAR and control nothing real. Unlike the live registry, the registry copy still has an access key on its own
account; that does not matter for this test.
