//! OutProofV2 verification (SPEC §6.3 steps 1–7) and the rules R1, R2, R3, R6.
//!
//! [`check_out_proof`] is a port of `wallet2::check_tx_proof` (out-proof branch) and
//! `wallet2::check_tx_key_helper` / `wallet2::is_out_to_acc` / `decodeRct` from
//! Monero v0.18.5.4 `src/wallet/wallet2.cpp`, plus `decodeRctSimple` from
//! `src/ringct/rctSigs.cpp`.
//! Copyright (c) 2014-2022, The Monero Project. BSD-3-Clause, see `LICENSE-MONERO`.
//!
//! Deliberate differences from Monero, all of them stricter:
//! - Only `OutProofV2`, only RingCT type 6, full blob consumed, canonical points.
//! - An entry whose signature fails contributes no derivation. Monero uses an
//!   all-zero derivation there and skips it in `is_out_to_acc`; same result.
//! - A matching output whose commitment does not open contributes 0 (Monero logs and
//!   adds 0 too) and is not listed in [`ProofCheck::outputs`].

use crate::address::{parse_stagenet_address, StagenetAddress};
use crate::crypto::{
    check_tx_proof_v2, commit, commitment_mask, decrypt_amount, derivation_from_shared_secret,
    derivation_to_scalar, derive_public_key, derive_view_tag,
};
use crate::error::VerifyError;
use crate::hash::keccak256_parts;
use crate::proof::{parse_out_proof, OutProofV2};
use crate::tx::{parse_extra, parse_transaction, ExtraField, ParsedTx};
use alloc::vec::Vec;

/// An output the proof shows to belong to the payee.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MatchedOutput {
    /// Output index `j` in the transaction.
    pub index: usize,
    /// Decrypted amount in piconero, checked against the commitment.
    pub amount: u64,
}

/// Result of [`check_out_proof`]: what the transaction pays the address.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProofCheck {
    pub txid: [u8; 32],
    /// `Σ amount_j` over matching outputs (step 7).
    pub received: u64,
    pub outputs: Vec<MatchedOutput>,
}

/// Steps 1–7 of SPEC §6.3 on an already parsed transaction (rule R1).
///
/// `message` is the exact message the proof was made for. The signature check is
/// over `H(txid || message)` with `txid` recomputed from the blob.
///
/// Like Monero, the proof is accepted if **at least one** entry verifies: in a tx
/// with additional tx public keys the entries for outputs of other recipients do
/// not verify for this address, and that is normal. Only verified entries yield
/// derivations for output scanning.
pub fn check_out_proof(
    tx: &ParsedTx,
    address: &StagenetAddress,
    message: &[u8],
    proof: &OutProofV2,
) -> Result<ProofCheck, VerifyError> {
    // Step 1: tx public keys from extra.
    let fields = parse_extra(&tx.extra);
    let additional: &[[u8; 32]] = fields
        .iter()
        .find_map(|f| match f {
            ExtraField::AdditionalPubKeys(k) => Some(k.as_slice()),
            _ => None,
        })
        .unwrap_or(&[]);
    if additional.len() + 1 != proof.entries.len() {
        return Err(VerifyError::ProofEntryCount {
            proof: proof.entries.len(),
            tx_keys: additional.len() + 1,
        });
    }

    // Step 4: prefix_hash = H(txid || message).
    let prefix_hash = keccak256_parts(&[&tx.txid, message]);

    // Steps 2, 3, 5.
    let a = &address.view_public_key;
    let b = if address.is_subaddress() {
        Some(&address.spend_public_key)
    } else {
        None
    };
    let e0 = &proof.entries[0];
    let mut good0 = false;
    let mut has_tx_pub_key = false;
    for f in &fields {
        let ExtraField::PubKey(r_pub) = f else {
            continue;
        };
        if *r_pub == [0u8; 32] {
            continue;
        }
        has_tx_pub_key = true;
        if check_tx_proof_v2(&prefix_hash, r_pub, a, b, &e0.shared_secret, &e0.c, &e0.r) {
            good0 = true;
            break;
        }
    }
    if !has_tx_pub_key {
        return Err(VerifyError::NoTxPubKey);
    }
    let mut good_additional = Vec::with_capacity(additional.len());
    for (i, r_pub) in additional.iter().enumerate() {
        let e = &proof.entries[i + 1];
        good_additional.push(check_tx_proof_v2(
            &prefix_hash,
            r_pub,
            a,
            b,
            &e.shared_secret,
            &e.c,
            &e.r,
        ));
    }
    if !good0 && !good_additional.iter().any(|&g| g) {
        return Err(VerifyError::InvalidProof);
    }

    // derivation = 8·D for every verified entry.
    let derivation0 = if good0 {
        Some(derivation_from_shared_secret(&e0.shared_secret).ok_or(VerifyError::InvalidProof)?)
    } else {
        None
    };
    let mut additional_derivations = Vec::with_capacity(additional.len());
    for (i, &g) in good_additional.iter().enumerate() {
        additional_derivations.push(if g {
            Some(
                derivation_from_shared_secret(&proof.entries[i + 1].shared_secret)
                    .ok_or(VerifyError::InvalidProof)?,
            )
        } else {
            None
        });
    }

    // Step 6: scan outputs.
    let spend = &address.spend_public_key;
    let mut received: u64 = 0;
    let mut outputs = Vec::new();
    for (j, out) in tx.outputs.iter().enumerate() {
        let idx = j as u64;
        let owns = |d: &[u8; 32]| {
            if let Some(tag) = out.view_tag {
                if derive_view_tag(d, idx) != tag {
                    return false;
                }
            }
            derive_public_key(d, idx, spend) == Some(out.key)
        };
        let found = match derivation0 {
            Some(ref d) if owns(d) => Some(*d),
            _ => match additional_derivations.get(j) {
                Some(Some(d)) if owns(d) => Some(*d),
                _ => None,
            },
        };
        let Some(d) = found else { continue };
        let s = derivation_to_scalar(&d, idx);
        let amount = decrypt_amount(&out.encrypted_amount, &s);
        if commit(&commitment_mask(&s), amount) != out.commitment {
            continue;
        }
        received = received
            .checked_add(amount)
            .ok_or(VerifyError::InvalidProof)?;
        outputs.push(MatchedOutput { index: j, amount });
    }

    // Step 7.
    Ok(ProofCheck {
        txid: tx.txid,
        received,
        outputs,
    })
}

/// Everything the canister has at `submit_proof` time.
#[derive(Debug, Clone, Copy)]
pub struct PaymentClaim<'a> {
    /// txid claimed by the xmr-side.
    pub txid: [u8; 32],
    /// Full transaction blob (`as_hex` from `get_transactions`, hex-decoded).
    pub tx_blob: &'a [u8],
    /// The order's `payee_address`.
    pub payee_address: &'a str,
    /// The expected message, built with [`crate::proof_message`].
    pub message: &'a str,
    /// The proof string from `get_tx_proof`.
    pub proof: &'a str,
    /// `order.xmr_amount` in piconero.
    pub min_amount: u64,
}

/// A payment that passed R1, R2, R3 and R6. R4 and R5 are still the canister's job
/// (see [`crate::rules`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedPayment {
    pub txid: [u8; 32],
    pub received: u64,
    pub outputs: Vec<MatchedOutput>,
}

/// Full check of a payment claim: address (stagenet only), proof string (V2 only),
/// transaction (R6), txid recomputation, R3, R1 (steps 1–7) and R2.
pub fn verify_payment(claim: &PaymentClaim<'_>) -> Result<VerifiedPayment, VerifyError> {
    let address = parse_stagenet_address(claim.payee_address)?;
    let proof = parse_out_proof(claim.proof)?;
    let tx = parse_transaction(claim.tx_blob)?; // R6
    if tx.txid != claim.txid {
        return Err(VerifyError::TxidMismatch { computed: tx.txid });
    }
    if tx.unlock_time != 0 {
        // R3
        return Err(VerifyError::UnlockTimeSet {
            unlock_time: tx.unlock_time,
        });
    }
    let check = check_out_proof(&tx, &address, claim.message.as_bytes(), &proof)?; // R1
    if check.outputs.is_empty() || check.received < claim.min_amount {
        // R2
        return Err(VerifyError::InsufficientAmount {
            got: check.received,
            need: claim.min_amount,
        });
    }
    Ok(VerifiedPayment {
        txid: check.txid,
        received: check.received,
        outputs: check.outputs,
    })
}
