# ProofSwap — Technical Specification

**Status:** Draft v0.5 · Research prototype
**Networks:** Monero **stagenet** · ICP mainnet canisters using **test tokens only** (ckTESTBTC, ckSepoliaUSDC)
**Out of scope:** Monero mainnet, real-value tokens, any hosted service

---

## 1. Summary

ProofSwap is a peer-to-peer exchange protocol between **Monero (XMR)** and **ICRC-1 chain-key tokens** on the Internet Computer (ICP). It needs no bridge, no wrapped XMR and no arbitrator.

The idea: ICP cannot custody XMR, because threshold signatures on ICP do not cover Monero's CLSAG ring signatures. It does not need to. A canister only:

1. holds the **ck-token leg** in escrow, and
2. **verifies cryptographically** that the XMR leg was paid, using a Monero **OutProof** (`get_tx_proof`) together with chain data fetched over HTTPS outcalls.

Escrow always sits on the ck side, so neither party can walk away with both legs.

**What the proof does and does not show.** An OutProof shows that a given transaction pays a given amount to a given address. It does not show that the transaction is valid (ring signatures, key images) or that it is in the chain. The canister does not check CLSAG signatures or key images. Validity and inclusion therefore rest on the t-of-k node agreement in §6.2 and §7. That is the central trust assumption of the design, see §10.

## 2. Goals and non-goals

### Goals
- G1: Trust-minimized XMR ⇄ ckToken swaps with no human arbitrator.
- G2: No XMR keys, no view keys and no wallet software inside the canister or the frontend.
- G3: Deterministic, auditable verification of XMR payments on-chain.
- G4: Griefing resistance through bonds.
- G5: A small codebase that is easy to audit (Rust canister, static frontend).

### Non-goals
- No wrapped XMR (`ckXMR`). Wrapping a privacy asset on a public ledger defeats its purpose.
- No price oracle. Makers quote fixed amounts on both legs.
- No order matching engine. The orderbook is a list and takers pick an offer.
- No mainnet deployment. See §12.

## 3. Roles and terminology

| Term | Meaning |
|---|---|
| **Maker** | Creates an offer. |
| **Taker** | Accepts an offer. |
| **ck-side** | The party that delivers the ck token. Its tokens are locked in escrow. |
| **xmr-side** | The party that delivers XMR. It must post a **bond** in the ck token and submit an OutProof. |
| **Payee** | The xmr-side's counterparty, who receives XMR at `payee_address`. |
| **Order** | One offer plus its lifecycle state. |
| **N_conf** | Number of Monero confirmations required (default 10, configurable per order, minimum 10). |

Two offer directions:

- `MakerBuysXmr`: the maker is ck-side, locks tokens when creating the offer and publishes its XMR receive address.
- `MakerSellsXmr`: the maker is xmr-side and posts a bond when creating the offer. The taker is ck-side, locks tokens when taking and supplies its XMR receive address.

## 4. Protocol flow

```
 ck-side                    ProofSwap canister                  xmr-side
    │                              │                               │
    │── lock ck amount (ICRC-2) ──▶│                               │
    │                              │◀──── lock bond (ICRC-2) ──────│
    │                              │   state = Locked, deadline T  │
    │                              │                               │
    │◀═══════════ XMR transfer on Monero (off-ICP) ════════════════│
    │                              │                               │
    │                              │◀─ submit_proof(txid, proof) ──│
    │                              │   verify proof (§6)           │
    │                              │   wait N_conf (§7)            │
    │                              │── release ck amount + bond ──▶│
    │                              │   state = Settled             │
```

On timeout with no valid proof: the ck-side gets its amount back plus the xmr-side's bond, and the state becomes `Expired`.

### 4.1 State machine

```
Open ──take──▶ Locked ──submit_proof(valid)──▶ Confirming ──N_conf reached──▶ Settled
 │               │                                  │
 cancel          deadline passed                     reorg / tx dropped
 ▼               ▼                                  ▼
Cancelled      Expired (ck refunded, bond slashed)  Locked (proof cleared, deadline unchanged)
```

| State | Allowed transitions | Trigger |
|---|---|---|
| `Open` | `Locked`, `Cancelled` | `take_order` / maker `cancel_order` |
| `Locked` | `Confirming`, `Expired` | valid proof / timer passes `deadline` |
| `Confirming` | `Settled`, `Locked` | timer sees N_conf / timer sees tx missing from the chain |
| `Settled`, `Expired`, `Cancelled` | none | final |

- `deadline = lock_time + pay_window` (default 2 h, between 30 min and 24 h).
- A proof that is submitted before the deadline extends the order by a `confirm_window` (default 2 h), so slow confirmations do not punish an honest payer.

## 5. Escrow (ICP side)

- Supported ledgers come from a fixed allowlist set at canister init: ckTESTBTC and ckSepoliaUSDC.
- Deposits go through ICRC-2 `icrc2_transfer_from`, so users approve the canister first.
- Each order has its own escrow **subaccount**: `sha256("proofswap/escrow" || order_id)`. That keeps balances reconcilable per order.
- `bond = max(bond_min, bond_bps × ck_amount)`, default 5 %. Ledger fees are deducted explicitly and documented in the UI.
- Payouts are **idempotent**. Each payout has a deterministic `created_at_time` and memo (`order_id || leg`), so the ledger's deduplication prevents a double payout after a retried call.

## 6. XMR payment verification

### 6.1 Input

The xmr-side calls `submit_proof(order_id, txid, proof_string)`. The proof comes from the user's own wallet:

```
monero-wallet-cli:  get_tx_proof <txid> <payee_address> <message>
wallet RPC:         get_tx_proof {txid, address, message}
GUI / Feather:      Advanced → Prove/Check → Generate
```

**The message is required and fixed:**

```
proofswap:v1:<canister_id>:<order_id>
```

Binding the proof to the canister and the order stops anyone from replaying it against another order or another deployment.

### 6.2 Fetching the transaction

The canister makes HTTPS outcalls to **k independent Monero stagenet nodes** (default k = 3, threshold t = 2):

- `POST /get_transactions` with `{"txs_hashes":[txid],"decode_as_json":false}`

A **transform function** reduces each response to the canonical tuple `(as_hex, block_height, in_pool)` and drops volatile fields (`credits`, `top_hash`, `untrusted`, `status` strings and so on). Every ICP replica must receive byte-identical bodies after the transform.

The canister **recomputes the txid from `as_hex`** and rejects any blob that does not hash to the claimed txid. So a node can withhold or delay data, but it cannot alter a transaction. It can, however, report a transaction blob that was never valid or never mined: the hash check binds the blob to the txid, not to the chain. Inclusion is only as good as the node agreement (§7, §10).

### 6.3 Proof verification (OutProof V2)

This is a port of `crypto::check_tx_proof` (src/crypto/crypto.cpp) and `wallet2::check_tx_proof` (src/wallet/wallet2.cpp). Only `OutProofV2` is accepted. V1 is rejected because it lacks domain separation.

1. Parse the transaction. Collect the tx public key `R` and any additional tx public keys `R_i` (these exist for subaddress outputs).
2. Decode `payee_address`, which gives `(A, B)` = (public view key, public spend key) and the subaddress flag.
3. Decode the proof: for each tx pubkey, a pair `(D, sig)` where `D = r·A`.
4. `prefix_hash = H_s(txid || message)`.
5. Verify each `sig` as a proof that the same `r` satisfies `R = r·G` (or `R = r·B` for subaddresses) and `D = r·A`, with domain separator `TXPROOF_V2`. As in Monero, the proof is valid if **at least one** `sig` verifies: in a transaction with additional tx public keys, the entries for outputs to other recipients do not verify for this address, which is normal. Requiring all of them would reject honest proofs.
6. For each output index `j`, using only the `D` of entries whose `sig` verified:
   - `derivation = 8·D` (first the main key's `D`, then `D_j` of additional key `j`)
   - `s = H_s(derivation || varint(j))`
   - Output belongs to the payee ⇔ `P_j == s·G + B`, and the view tag matches when present.
   - Decrypt the amount: `amount = ecdhAmount_j ⊕ H("amount" || s)[0..8]`, with `H` = Keccak-256 **without** reduction mod l (not `H_s`)
   - Check the commitment: `C_j == H_s("commitment_mask" || s)·G + amount·H`. An output whose commitment does not open contributes 0.
7. `received = Σ amount_j` over matching outputs.

**Acceptance rules (all must hold):**

| # | Rule |
|---|---|
| R1 | The proof verifies (steps 1–6). |
| R2 | `received ≥ order.xmr_amount` |
| R3 | `unlock_time == 0` |
| R4 | The tx was mined at a height after `order.lock_height`, the Monero height snapshotted when the order was locked. This blocks reuse of older payments to the same address. |
| R5 | `txid` has never been used by any other order (global set). |
| R6 | RCT type is supported (CLSAG/BP+ only). Pre-RCT transactions are rejected. |

**Test vectors:** generated with `monero-wallet-rpc` on stagenet and committed under `/test-vectors`. The CI must reproduce every vector, including negative ones (wrong message, wrong address, V1 proof, amount below the requirement, subaddress outputs).

## 7. Confirmation tracking

ICP replicas cannot agree on a moving chain tip, so the canister **never asks for the tip**. It asks questions whose answers are fixed:

- `get_block_header_by_height(h_tx)` must return a block whose hash, across t-of-k nodes, includes `txid`. The block blob is fetched and the tx hash list checked against it.
- `get_block_header_by_height(h_tx + N_conf − 1)` existing on t-of-k nodes means confirmations are satisfied.

A periodic timer re-checks (default every 2 min) while orders sit in `Confirming`.

- If the block at `h_tx` changes hash, or the tx disappears, the order **reorgs back** to `Locked`. The proof is cleared and the txid is freed again.
- RandomX PoW is **not** verified inside the canister (too expensive). Trust in the chain comes from agreement among independent nodes. That is stated openly in §10.

## 8. Canister interface (Candid sketch)

```candid
type Direction = variant { MakerBuysXmr; MakerSellsXmr };
type OrderState = variant { Open; Locked; Confirming; Settled; Expired; Cancelled };

type Order = record {
  id : nat64;
  direction : Direction;
  maker : principal;
  taker : opt principal;
  ledger : principal;           // ck token ledger
  ck_amount : nat;
  bond : nat;
  xmr_amount : nat64;           // piconero
  payee_address : opt text;     // stagenet address of the xmr receiver
  n_conf : nat32;
  pay_window_secs : nat32;
  lock_height : opt nat64;
  deadline : opt nat64;         // ns since epoch
  txid : opt text;
  state : OrderState;
};

type CreateArgs = record {
  direction : Direction; ledger : principal; ck_amount : nat; xmr_amount : nat64;
  payee_address : opt text; n_conf : opt nat32; pay_window_secs : opt nat32;
};

type ProofError = variant {
  BadState; NotXmrSide; DeadlinePassed; TxNotFound; TxidMismatch;
  InvalidProof; WrongMessage; InsufficientAmount : record { got : nat64; need : nat64 };
  UnlockTimeSet; TooOld; TxidReused; UnsupportedTx; RpcDisagreement;
};

service : {
  create_order : (CreateArgs) -> (variant { Ok : nat64; Err : text });
  take_order   : (nat64, opt text) -> (variant { Ok; Err : text });  // opt text = payee address
  cancel_order : (nat64) -> (variant { Ok; Err : text });
  submit_proof : (nat64, text, text) -> (variant { Ok; Err : ProofError });
  get_order    : (nat64) -> (opt Order) query;
  list_orders  : (opt OrderState, nat64, nat32) -> (vec Order) query;
  proof_message: (nat64) -> (text) query;  // returns the exact message to sign
}
```

## 9. Architecture

```
┌──────────────────────┐     ┌────────────────────────────────────────────┐
│ Static frontend      │     │ proofswap_backend (Rust canister)           │
│ (asset canister or   │────▶│  orderbook · escrow · proof verifier · timer│
│  any static host)    │     └──────┬──────────────────────┬──────────────┘
│ Internet Identity    │            │ ICRC-1/2             │ HTTPS outcalls
└──────────────────────┘            ▼                      ▼
                           ckTESTBTC / ckSepoliaUSDC   k × Monero stagenet nodes
```

**Crates:** `ic-cdk`, `ic-cdk-timers`, `icrc-ledger-types`, `candid`, `curve25519-dalek`, `sha3` (Keccak), `monero` (monero-rs) for transaction and address parsing. Proof verification lives in its own `no_std`-friendly crate, `proofswap-xmr-verify`, so it can be tested and audited separately.

**Storage:** `ic-stable-structures`, with orders in a `StableBTreeMap<u64, Order>` and used txids in a `StableBTreeSet`. Upgrades must not lose state.

**Cycles:** Outcalls are the main cost. Proof submissions are rate-limited per principal (default 5 per hour). The bond rule makes spam expensive. The showcase canister is topped up manually.

## 10. Security model

| Threat | Mitigation | Residual risk |
|---|---|---|
| xmr-side claims a payment that never happened | OutProof verification plus txid recomputation prove *what the tx pays*; t-of-k nodes attest *that it is mined* (§7) | an invalid or never-broadcast tx (forged inputs, double spend) is accepted if t of k nodes report it in a block: same as the node-majority row below |
| Proof replay across orders or deployments | Message binds `canister_id` and `order_id`; global txid set | none |
| Reusing an older payment to the same address | R4 (`lock_height`) | none |
| ck-side refuses to pay | Not possible: ck funds are locked before XMR moves | none |
| Taker locks an order and never pays (griefing) | Bond is slashed to the counterparty | maker's capital is idle until the deadline |
| Dishonest or colluding Monero RPC nodes | t-of-k agreement; the tx blob is bound to its txid | a colluding majority could fake inclusion, confirmations or block existence (no in-canister PoW, CLSAG or key-image check). Node independence is hard to verify: several public nodes can belong to one operator |
| Chain reorg | N_conf ≥ 10; reorg detection drops the order back to `Locked` | deep reorgs beyond N_conf |
| ICP subnet compromise | Out of scope; inherited from ICP | ck escrow is only as safe as the subnet |
| Canister upgrade by a malicious controller | Showcase: single controller, documented. Future: blackhole or SNS | **the controller can steal escrow**, so the showcase must stay test-only |

## 11. Privacy

Be explicit with users about what this reveals:

- The OutProof and the order record are **public on ICP**. For that one transaction, anyone can link `txid ↔ payee_address ↔ amount ↔ ICP principals`.
- The rest of the payee's wallet history stays private.
- Recommendations shown in the UI: use a **fresh subaddress per order** and pay from a wallet that has nothing else linked to your identity.
- The canister never holds a view key or spend key.

## 12. Deployment policy

This repository is a **research prototype**:

- Hard-coded to Monero **stagenet** address prefixes. Mainnet addresses are rejected by the parser.
- The ledger allowlist contains only **test tokens**.
- No fees and no revenue.
- No hosted service is operated. The showcase page explains the protocol and links to stagenet test instructions.

Any mainnet use would need an independent audit, a blackholed or DAO-controlled canister, and a legal assessment in the operator's jurisdiction.

## 13. Milestones

| M | Deliverable | Done when |
|---|---|---|
| M1 | `proofswap-xmr-verify` crate | all stagenet test vectors pass, including the negative ones |
| M2 | Outcall layer and transform | deterministic responses on a local replica plus mainnet canister against stagenet |
| M3 | Orderbook, escrow and state machine | PocketIC integration tests for all transitions, including timeouts |
| M4 | Confirmation timer and reorg handling | a simulated reorg sends the order back to `Locked` |
| M5 | Frontend | full stagenet swap end-to-end with Internet Identity |
| M6 | Security review and write-up | threat model checked against the code; findings published |

## 14. Open questions

- Q1: Is in-canister verification of block-header PoW feasible within the instruction limits (RandomX light mode)? Probably not, but it should be measured.
- Q2: Should the payee confirm receipt themselves (InProof with a view key, run client-side) as an optional fast path?
- Q3: How should partial fills work for large offers?
- Q4: Would ICP's planned confidential-compute (SEV-SNP) subnets allow optional view-key-based verification without revealing data?
- Q5: Can the canister check inclusion more cheaply than full PoW, e.g. verifying that the block's tx hash list commits to `txid` via the header's Merkle root, so a node must at least forge a header? (Narrows the trust gap, does not close it.)
- Q6: How are the k nodes chosen and rotated, and who can change the list (controller vs. governance)?

## 15. Related work

ProofSwap is not the only project working on non-custodial Monero trading, and it should not be. This section shows where each approach fits. Status as of November 2026.

| Project | Mechanism | Who holds XMR during a trade | Pairs | Status |
|---|---|---|---|---|
| [eigenwallet](https://github.com/eigenwallet/core) (formerly UnstoppableSwap) | Atomic swap: adaptor signatures on BTC, shared spend key on XMR | Nobody (2-of-2 key split) | BTC → XMR | Live |
| [BasicSwap](https://github.com/basicswap/basicswap) | Atomic swaps (HTLCs on scriptable coins, adaptor signatures for XMR) | Nobody | XMR ⇄ BTC, LTC, DASH, FIRO, PIVX, DCR | Live |
| [Bisq](https://bisq.network) (XMR auto-confirm) | BTC leg in 2-of-2 multisig; the XMR receiver's client checks txid + tx key against explorers | Nobody (paid directly) | XMR ⇄ BTC | Live |
| [Haveno](https://github.com/haveno-dex/haveno) (e.g. RetoSwap) | P2P trades, 2-of-3 Monero multisig escrow, human arbitrators | Multisig (traders + arbitrator) | XMR ⇄ crypto and fiat | Live |
| [THORChain](https://thorchain.org) | Liquidity pools; validators hold assets in threshold-signature vaults | Validator vault | XMR ⇄ BTC, ETH, stablecoins, … | Code released, activation pending |
| [Serai](https://github.com/serai-dex/serai) | Liquidity pools; economically secured threshold multisig | Validator multisig | BTC, ETH, XMR | Mainnet not launched |
| [DCRDEX](https://github.com/decred/dcrdex) | Order book, atomic swaps | Nobody | XMR ⇄ BTC in progress | XMR wallet merged, swap PR open |
| **ProofSwap** | Escrow on the ck-token leg only; XMR leg checked via OutProof + t-of-k nodes | **Nobody (paid directly)** | XMR ⇄ ICRC tokens (ckBTC, ckUSDC, …) | Spec stage, stagenet only |

### 15.1 What ProofSwap does differently

- **No pooled or shared XMR.** XMR goes straight from payer to payee. No protocol, multisig or validator set ever controls it, so there is no XMR honeypot. Only the ck leg and the bond sit in escrow.
- **Stablecoins, not just BTC.** XMR ⇄ ckUSDC is a first-class pair. Merchants and people paid in XMR often want dollars, not another volatile asset.
- **No arbitrator.** An order ends by a valid proof or by a timeout, not by a person's decision.
- **Little interaction.** The ck-side locks once and can go offline. The xmr-side makes one payment and submits one proof inside the pay window (§4.1). There is no multi-round protocol in which both sides must stay online.
- **The check runs in the contract, not in a client.** Compared with Bisq auto-confirm, release does not depend on the receiver's software being online and opted in, and the proof is bound to the order (§6.1) instead of revealing the tx key.

### 15.2 What ProofSwap does worse

- **Liquidity.** It is P2P: without a counterparty there is no trade. Pool designs (THORChain, Serai) win on instant execution.
- **Per-trade privacy leak.** The OutProof and order record publicly link one txid, the payee address, the amount and both ICP principals (§11). Atomic swaps reveal less.
- **Trust in RPC nodes.** Validity and inclusion of the XMR payment rest on t-of-k node agreement. The canister checks no ring signatures, key images or PoW (§7, §10). Atomic swaps do not have this assumption.
- **Trust in ICP.** The escrow is only as safe as the ICP subnet and the canister controller (§10).
- **It does not exist yet.** Everything here is a specification.

### 15.3 Why not just …

- **… use eigenwallet?** For BTC → XMR, you should. ProofSwap targets pairs atomic swaps do not cover well: stablecoins and other ICRC tokens.
- **… use Haveno?** Haveno works and supports fiat. ProofSwap replaces the human arbitrator with a proof check plus node agreement, for crypto-only trades.
- **… use Bisq auto-confirm?** It is the closest prior art (see References). ProofSwap moves the same idea from an opt-in client feature into the escrow contract.
- **… wait for THORChain?** Pools beat order books on liquidity. But pooled XMR in a validator vault is a different trust model: a key-management bug or validator collusion puts the whole pool at risk, not one trade.
- **… build ckXMR?** That would need threshold CLSAG signing in the ICP protocol itself. Serai shows threshold Monero signing is possible, but adding it to ICP is DFINITY's decision, and wrapping a privacy asset on a public ledger defeats the point (§2).

## Changelog

- v0.5 (2026-11-27): §6.3 corrected against Monero's `check_tx_proof` while porting it: a proof needs at least one valid entry, not all (step 5); only verified entries give derivations (step 6); the amount pad is plain Keccak `H`, not `H_s` (step 6).
- v0.4 (2026-11-27): added §15 Related work.

- v0.3 (2026-11-27): Bisq XMR auto-confirm added as closest prior art.
- v0.2 (2026-11-27): spelled out that the OutProof does not prove validity or inclusion; corrected the §10 residual risk for fake payments (was "none"); added Q5, Q6.
- v0.1 (2026-11-26): first draft.

## References

- Monero source: `src/crypto/crypto.cpp` (`generate_tx_proof`, `check_tx_proof`), `src/wallet/wallet2.cpp`
- Monero daemon RPC: `get_transactions`, `get_block_header_by_height`, `get_block`
- ICP docs: HTTPS outcalls, ICRC-1/ICRC-2, Chain Fusion, chain-key tokens
- Prior art: **Bisq XMR auto-confirm** (2020): the XMR sender supplies txid and tx key, the receiver's client checks it against Monero explorer instances (hosted by Bisq or self-run) and, if enabled, confirms receipt so the BTC leg is released from the 2-of-2 multisig. ProofSwap moves that check from a client into the escrow contract and uses a message-bound OutProof instead of revealing the tx key. Haveno (multisig and arbitrators), XMR⇄BTC atomic swaps (adaptor signatures, COMIT/eigenwallet)
