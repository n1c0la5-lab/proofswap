//! Curve operations used by the OutProof check.
//!
//! Ported from Monero v0.18.5.4:
//! - `src/crypto/crypto.cpp`: `check_tx_proof` (V2 branch), `generate_key_derivation`,
//!   `derivation_to_scalar`, `derive_public_key`, `derive_view_tag`
//! - `src/ringct/rctOps.cpp`: `ecdhHash`, `genCommitmentMask`, `ecdhDecode` (v2), `addKeys2`
//! - `src/ringct/rctTypes.h`: the generator `H`
//!
//! Copyright (c) 2014-2022, The Monero Project. BSD-3-Clause, see `LICENSE-MONERO`.
//! Parts originally copyright (c) 2012-2013 The Cryptonote developers.

use crate::hash::{hash_to_scalar, keccak256, keccak256_parts};
use crate::varint::write_varint;
use alloc::vec::Vec;
use curve25519_dalek::edwards::{CompressedEdwardsY, EdwardsPoint};
use curve25519_dalek::scalar::Scalar;

/// Domain separator of OutProofV2/InProofV2 (`config::HASH_KEY_TXPROOF_V2`).
pub const HASH_KEY_TXPROOF_V2: &[u8] = b"TXPROOF_V2";

/// RingCT amount generator `H` (`rct::H`).
pub const H_BYTES: [u8; 32] = [
    0x8b, 0x65, 0x59, 0x70, 0x15, 0x37, 0x99, 0xaf, 0x2a, 0xea, 0xdc, 0x9f, 0xf1, 0xad, 0xd0, 0xea,
    0x6c, 0x72, 0x51, 0xd5, 0x41, 0x54, 0xcf, 0xa9, 0x2c, 0x17, 0x3a, 0x0d, 0xd3, 0x9c, 0x1f, 0x94,
];

/// Decodes a point and rejects non-canonical encodings.
///
/// Monero's `ge_frombytes_vartime` rejects `y >= p`; this additionally requires that
/// re-encoding gives back the same 32 bytes, which also rejects `x = 0` with the
/// sign bit set. Stricter than Monero only for encodings no wallet produces.
pub fn decode_point(bytes: &[u8; 32]) -> Option<EdwardsPoint> {
    let point = CompressedEdwardsY(*bytes).decompress()?;
    if point.compress().to_bytes() == *bytes {
        Some(point)
    } else {
        None
    }
}

/// Decodes a scalar and requires it to be fully reduced (Monero `sc_check`).
pub fn decode_scalar(bytes: &[u8; 32]) -> Option<Scalar> {
    Option::from(Scalar::from_canonical_bytes(*bytes))
}

fn h_point() -> EdwardsPoint {
    // H is a fixed, valid curve point (checked in `tests::h_is_a_valid_point`).
    CompressedEdwardsY(H_BYTES).decompress().unwrap_or_default()
}

/// Port of `crypto::check_tx_proof(..., version = 2)` for an OutProof.
///
/// Checks a Schnorr-type proof that one secret `r` satisfies `R = r·G` (standard
/// address, `b = None`) or `R = r·B` (subaddress, `b = Some(B)`) and `D = r·A`.
/// The challenge is `H_s(msg || D || X || Y || H(sep) || R || A || B_or_zero)`.
pub fn check_tx_proof_v2(
    prefix_hash: &[u8; 32],
    r_pub: &[u8; 32],
    a_pub: &[u8; 32],
    b_pub: Option<&[u8; 32]>,
    d_pub: &[u8; 32],
    sig_c: &[u8; 32],
    sig_r: &[u8; 32],
) -> bool {
    let (Some(r_p), Some(a_p), Some(d_p)) = (
        decode_point(r_pub),
        decode_point(a_pub),
        decode_point(d_pub),
    ) else {
        return false;
    };
    let b_p = match b_pub {
        Some(b) => match decode_point(b) {
            Some(p) => Some(p),
            None => return false,
        },
        None => None,
    };
    let (Some(c), Some(r)) = (decode_scalar(sig_c), decode_scalar(sig_r)) else {
        return false;
    };

    // X = c·R + r·B  (subaddress)  or  X = c·R + r·G  (standard address)
    let x = match b_p {
        Some(b) => c * r_p + r * b,
        None => EdwardsPoint::vartime_double_scalar_mul_basepoint(&c, &r_p, &r),
    };
    // Y = c·D + r·A
    let y = c * d_p + r * a_p;

    let sep = keccak256(HASH_KEY_TXPROOF_V2);
    let zero = [0u8; 32];
    let b_bytes: &[u8; 32] = b_pub.unwrap_or(&zero);
    let x_bytes = x.compress().to_bytes();
    let y_bytes = y.compress().to_bytes();
    let c2 = hash_to_scalar(&[
        prefix_hash,
        d_pub,
        &x_bytes,
        &y_bytes,
        &sep,
        r_pub,
        a_pub,
        b_bytes,
    ]);
    c2 == c
}

/// Port of `generate_key_derivation(pub, sec)`: `8·(sec·pub)`.
///
/// Returns `None` if `pub_key` is not a valid point or `sec` is not reduced.
pub fn generate_key_derivation(pub_key: &[u8; 32], sec: &[u8; 32]) -> Option<[u8; 32]> {
    let p = decode_point(pub_key)?;
    let s = decode_scalar(sec)?;
    Some((s * p).mul_by_cofactor().compress().to_bytes())
}

/// The derivation an OutProof gives the verifier: `8·D`, i.e. Monero's
/// `generate_key_derivation(D, I)` with the scalar 1.
pub fn derivation_from_shared_secret(d_pub: &[u8; 32]) -> Option<[u8; 32]> {
    Some(decode_point(d_pub)?.mul_by_cofactor().compress().to_bytes())
}

fn derivation_with_index(derivation: &[u8; 32], output_index: u64) -> Vec<u8> {
    let mut buf = Vec::with_capacity(42);
    buf.extend_from_slice(derivation);
    write_varint(&mut buf, output_index);
    buf
}

/// Port of `derivation_to_scalar`: `H_s(derivation || varint(index))`.
pub fn derivation_to_scalar(derivation: &[u8; 32], output_index: u64) -> Scalar {
    hash_to_scalar(&[&derivation_with_index(derivation, output_index)])
}

/// Port of `derive_public_key`: `H_s(derivation || varint(index))·G + base`.
pub fn derive_public_key(
    derivation: &[u8; 32],
    output_index: u64,
    base: &[u8; 32],
) -> Option<[u8; 32]> {
    let b = decode_point(base)?;
    let s = derivation_to_scalar(derivation, output_index);
    Some((EdwardsPoint::mul_base(&s) + b).compress().to_bytes())
}

/// Port of `derive_view_tag`: first byte of `H("view_tag" || derivation || varint(index))`.
pub fn derive_view_tag(derivation: &[u8; 32], output_index: u64) -> u8 {
    keccak256_parts(&[
        b"view_tag",
        &derivation_with_index(derivation, output_index),
    ])[0]
}

/// Port of `ecdhDecode` (v2, compact amounts): decrypts the 8-byte amount with
/// `H("amount" || s)[0..8]` (plain Keccak, not reduced) and returns it as `u64`.
pub fn decrypt_amount(encrypted: &[u8; 8], shared_scalar: &Scalar) -> u64 {
    let pad = keccak256_parts(&[b"amount", shared_scalar.as_bytes()]);
    let mut out = [0u8; 8];
    for ((o, e), p) in out.iter_mut().zip(encrypted).zip(&pad) {
        *o = e ^ p;
    }
    u64::from_le_bytes(out)
}

/// Port of `genCommitmentMask`: `H_s("commitment_mask" || s)`.
pub fn commitment_mask(shared_scalar: &Scalar) -> Scalar {
    hash_to_scalar(&[b"commitment_mask", shared_scalar.as_bytes()])
}

/// Pedersen commitment `mask·G + amount·H` (Monero `addKeys2(C, mask, amount, H)`).
pub fn commit(mask: &Scalar, amount: u64) -> [u8; 32] {
    let a = Scalar::from(amount);
    EdwardsPoint::vartime_double_scalar_mul_basepoint(&a, &h_point(), mask)
        .compress()
        .to_bytes()
}

/// Public key of a secret scalar, `sec·G` (Monero `secret_key_to_public_key`).
pub fn secret_key_to_public_key(sec: &[u8; 32]) -> Option<[u8; 32]> {
    let s = decode_scalar(sec)?;
    Some(EdwardsPoint::mul_base(&s).compress().to_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn h_is_a_valid_point() {
        let h = decode_point(&H_BYTES).expect("H decodes");
        assert_ne!(h, EdwardsPoint::default());
        assert!(!h.is_small_order());
    }
}
