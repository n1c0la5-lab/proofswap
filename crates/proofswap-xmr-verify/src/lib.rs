//! # proofswap-xmr-verify
//!
//! Verifies a Monero **OutProofV2** (`get_tx_proof`) against a transaction blob, for
//! **stagenet only**. This is the payment check of the ProofSwap canister
//! (SPEC §6). It is a port of Monero's `check_tx_proof`, see `LICENSE-MONERO`.
//!
//! ## What this crate checks
//! - The payee address is a stagenet standard address or subaddress. Mainnet,
//!   testnet and integrated addresses are rejected (SPEC §12).
//! - The proof string is `OutProofV2`; `OutProofV1` is rejected.
//! - The transaction is version 2 with RingCT type 6 (CLSAG + Bulletproofs+), and
//!   the whole blob parses (R6).
//! - The blob hashes to the claimed txid (SPEC §6.2).
//! - `unlock_time == 0` (R3).
//! - At least one proof signature verifies over `H(txid || message)` with the
//!   `TXPROOF_V2` domain separator; matching outputs are found with the derivation
//!   `8·D`, view tags are checked, amounts are decrypted and checked against their
//!   Pedersen commitments (R1, SPEC §6.3 steps 1–7).
//! - The proven amount is at least the order amount (R2).
//!
//! ## What it does **not** check
//! - That the transaction is valid: no CLSAG ring signature, key image, range proof
//!   or balance check. The prunable part is only parsed for its structure.
//! - That the transaction is mined, at which height, or with how many confirmations.
//!   That rests on t-of-k node agreement in the canister (SPEC §7, §10).
//! - R4 (mined after `lock_height`) and R5 (txid not used before) need canister
//!   state. [`rules`] has the comparisons; the canister must supply true inputs.
//! - That the message belongs to the order. The canister must build it with
//!   [`proof_message`] and never take it from the caller.

#![no_std]
#![forbid(unsafe_code)]
#![deny(missing_debug_implementations)]

extern crate alloc;

pub mod address;
pub mod base58;
pub mod crypto;
pub mod error;
pub mod hash;
pub mod message;
pub mod proof;
pub mod rules;
pub mod tx;
pub mod varint;
pub mod verify;

pub use address::{parse_stagenet_address, AddressKind, StagenetAddress};
pub use error::{AddressError, ProofErrorKind, Unsupported, VerifyError};
pub use message::proof_message;
pub use proof::{parse_out_proof, OutProofV2, ProofEntry};
pub use rules::{check_r4_mined_after_lock, check_r5_txid_unused, UsedTxids};
pub use tx::{compute_txid, parse_transaction, ParsedTx, TxOutput};
pub use verify::{
    check_out_proof, verify_payment, MatchedOutput, PaymentClaim, ProofCheck, VerifiedPayment,
};

use alloc::vec::Vec;

/// Decodes a hex string (as in `as_hex` or a txid). Upper and lower case accepted.
pub fn decode_hex(s: &str) -> Result<Vec<u8>, VerifyError> {
    let b = s.as_bytes();
    if b.len() % 2 != 0 {
        return Err(VerifyError::Hex);
    }
    fn nib(c: u8) -> Result<u8, VerifyError> {
        match c {
            b'0'..=b'9' => Ok(c - b'0'),
            b'a'..=b'f' => Ok(c - b'a' + 10),
            b'A'..=b'F' => Ok(c - b'A' + 10),
            _ => Err(VerifyError::Hex),
        }
    }
    b.chunks(2)
        .map(|p| Ok((nib(p[0])? << 4) | nib(p[1])?))
        .collect()
}

/// Decodes a 64-character hex txid.
pub fn decode_txid(s: &str) -> Result<[u8; 32], VerifyError> {
    let v = decode_hex(s)?;
    v.try_into().map_err(|_| VerifyError::Hex)
}
