# ProofSwap

**Peer-to-peer XMR ⇄ ckToken swaps on the Internet Computer. No bridge, no wrapped Monero, no arbitrator.**

ICP can't custody Monero. It doesn't need to. A canister holds the ck-token leg in escrow and releases it only after it has verified a Monero payment proof (`get_tx_proof`) against transaction data fetched from several independent Monero nodes via HTTPS outcalls.

```
ck-side locks tokens → xmr-side pays XMR → submits OutProof → canister verifies + waits 10 conf → release
                                         └─ no valid proof before deadline → refund + bond slashed
```

> **Status: specification stage. There is no code yet.** Everything below describes the design in [`SPEC.md`](./SPEC.md), not a working system.
>
> ⚠️ **Research prototype.** Monero stagenet and ICP test tokens only. Not a service. Not audited. Don't put real funds anywhere near it.

## Why this design

| Approach | Problem |
|---|---|
| `ckXMR` (wrapped Monero) | No threshold CLSAG on ICP, and wrapping kills the privacy anyway |
| Multisig and an arbitrator (Haveno) | A human in the loop |
| Bisq XMR auto-confirm | Closest prior art: BTC leg in 2-of-2 multisig, XMR leg checked with the tx key against an explorer. But the check runs in the receiver's own client (opt-in), release depends on that client, disputes go to mediation, and it covers BTC only |
| Adaptor-signature atomic swaps (xmr-btc-swap) | Needs Bitcoin script on the other side; ICP threshold signing can't produce adaptor signatures |
| **ProofSwap** | Same idea, enforced by a contract: escrow only on the side ICP *can* control, verify the other side on-chain, release without anyone's cooperation. Works with any ICRC token |

No new cryptography: the verifier is a port of Monero's own `check_tx_proof`.

## Known weak spot

The OutProof proves *what a transaction pays*. It does not prove that the transaction is valid or mined. The canister does not check ring signatures, key images or proof of work, so inclusion and confirmations rest on agreement among t of k Monero nodes. A colluding node majority could get a forged payment accepted. See [`SPEC.md` §10](./SPEC.md#10-security-model) and open questions Q1, Q5, Q6.

Criticism of this, or of anything else in the spec, is welcome: open an issue.

## Docs

- [`SPEC.md`](./SPEC.md): protocol, verification algorithm, state machine, threat model, open questions

## Planned layout

```
crates/proofswap-xmr-verify/   # OutProof V2 + output scanning (pure Rust, tested against stagenet vectors)
canisters/backend/             # orderbook, ICRC escrow, outcalls, timers
site/                          # static showcase / frontend
test-vectors/                  # proofs generated with monero-wallet-rpc on stagenet
```

## License

MIT
