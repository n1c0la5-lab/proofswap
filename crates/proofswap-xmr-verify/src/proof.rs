//! Parser for the `OutProofV2` string (SPEC §6.3 step 3).
//!
//! Format from Monero v0.18.5.4 `src/wallet/wallet2.cpp` (`get_tx_proof`,
//! `check_tx_proof`): the header `OutProofV2`, then per tx public key
//! `base58(D)` (44 chars) followed by `base58(c || r)` (88 chars).
//! Copyright (c) 2014-2022, The Monero Project. BSD-3-Clause, see `LICENSE-MONERO`.

use crate::base58;
use crate::error::VerifyError;
use alloc::vec::Vec;

const HEADER_V2: &str = "OutProofV2";
const HEADER_V1: &str = "OutProofV1";
const PK_LEN: usize = 44;
const SIG_LEN: usize = 88;
/// 1 main tx key plus at most 16 additional keys (one per output, max 16 outputs).
pub const MAX_PROOF_ENTRIES: usize = 17;

/// One `(D, sig)` pair: `D = r·A` and the Schnorr signature `(c, r)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProofEntry {
    pub shared_secret: [u8; 32],
    pub c: [u8; 32],
    pub r: [u8; 32],
}

/// A parsed OutProofV2. Entry 0 belongs to the main tx public key, entry `i + 1`
/// to additional tx public key `i`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutProofV2 {
    pub entries: Vec<ProofEntry>,
}

/// Parses an `OutProofV2…` string. `OutProofV1…` fails with [`VerifyError::ProofV1`];
/// anything else (including `InProof…`) with [`VerifyError::ProofFormat`].
pub fn parse_out_proof(s: &str) -> Result<OutProofV2, VerifyError> {
    if s.starts_with(HEADER_V1) {
        return Err(VerifyError::ProofV1);
    }
    let body = s.strip_prefix(HEADER_V2).ok_or(VerifyError::ProofFormat)?;
    let unit = PK_LEN + SIG_LEN;
    if body.is_empty() || body.len() % unit != 0 || !body.is_ascii() {
        return Err(VerifyError::ProofFormat);
    }
    let n = body.len() / unit;
    if n > MAX_PROOF_ENTRIES {
        return Err(VerifyError::ProofFormat);
    }
    let mut entries = Vec::with_capacity(n);
    for i in 0..n {
        let off = i * unit;
        let pk = base58::decode(&body[off..off + PK_LEN]).ok_or(VerifyError::ProofFormat)?;
        let sig =
            base58::decode(&body[off + PK_LEN..off + unit]).ok_or(VerifyError::ProofFormat)?;
        if pk.len() != 32 || sig.len() != 64 {
            return Err(VerifyError::ProofFormat);
        }
        let mut e = ProofEntry {
            shared_secret: [0; 32],
            c: [0; 32],
            r: [0; 32],
        };
        e.shared_secret.copy_from_slice(&pk);
        e.c.copy_from_slice(&sig[..32]);
        e.r.copy_from_slice(&sig[32..]);
        entries.push(e);
    }
    Ok(OutProofV2 { entries })
}
