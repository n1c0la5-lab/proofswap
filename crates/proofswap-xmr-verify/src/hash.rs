//! Keccak-256 (`cn_fast_hash`) and hash-to-scalar (`hash_to_scalar`).
//!
//! Ported from Monero v0.18.5.4 `src/crypto/hash.c` / `src/crypto/crypto.cpp`.
//! Copyright (c) 2014-2022, The Monero Project. BSD-3-Clause, see `LICENSE-MONERO`.

use curve25519_dalek::scalar::Scalar;
use sha3::{Digest, Keccak256};

/// Monero's `cn_fast_hash`: original Keccak-256 (not NIST SHA3-256).
pub fn keccak256(data: &[u8]) -> [u8; 32] {
    keccak256_parts(&[data])
}

/// Keccak-256 over the concatenation of `parts`.
pub fn keccak256_parts(parts: &[&[u8]]) -> [u8; 32] {
    let mut hasher = Keccak256::new();
    for part in parts {
        hasher.update(part);
    }
    let digest = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(digest.as_slice());
    out
}

/// Monero's `hash_to_scalar` (`H_s`): Keccak-256, then reduced mod l (`sc_reduce32`).
pub fn hash_to_scalar(parts: &[&[u8]]) -> Scalar {
    Scalar::from_bytes_mod_order(keccak256_parts(parts))
}
