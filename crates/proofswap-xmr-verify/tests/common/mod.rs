//! Synthetic test-vector generator.
//!
//! **Circular by construction:** this builds transactions and OutProofs following
//! our reading of Monero's `construct_tx_with_tx_key` / `generate_output_ephemeral_keys`
//! (src/cryptonote_core/cryptonote_tx_utils.cpp), `wallet2::get_tx_proof` and
//! `crypto::generate_tx_proof` (v0.18.5.4), and the crate then checks them. A shared
//! misreading of Monero would pass here. These vectors carry structure, negative
//! cases and sabotage probes only. The real confirmation is the stagenet vectors
//! from `monero-wallet-rpc` (milestone M1b, `scripts/gen-test-vectors.py`).
//!
//! The generator deliberately does not call the crate's crypto or parser code: it
//! uses `curve25519-dalek` and `sha3` directly, serializes the blob itself and
//! computes the txid from its own byte offsets. Only Base58 comes from the crate
//! (checked against Monero's own Base58 vectors).

#![allow(dead_code)]

use curve25519_dalek::edwards::{CompressedEdwardsY, EdwardsPoint};
use curve25519_dalek::scalar::Scalar;
use proofswap_xmr_verify::base58;
use sha3::{Digest, Keccak256};

pub const STAGENET_STD: u64 = 24;
pub const STAGENET_SUB: u64 = 36;
pub const STAGENET_INTEGRATED: u64 = 25;
pub const MAINNET_STD: u64 = 18;
pub const TESTNET_STD: u64 = 53;

pub fn keccak(parts: &[&[u8]]) -> [u8; 32] {
    let mut h = Keccak256::new();
    for p in parts {
        h.update(p);
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(h.finalize().as_slice());
    out
}

pub fn hs(parts: &[&[u8]]) -> Scalar {
    Scalar::from_bytes_mod_order(keccak(parts))
}

pub fn varint(mut v: u64, out: &mut Vec<u8>) {
    while v >= 0x80 {
        out.push((v as u8 & 0x7f) | 0x80);
        v >>= 7;
    }
    out.push(v as u8);
}

pub fn scalar(label: &str) -> Scalar {
    hs(&[b"proofswap-test", label.as_bytes()])
}

pub fn pt(p: &EdwardsPoint) -> [u8; 32] {
    p.compress().to_bytes()
}

pub fn dec(b: &[u8; 32]) -> EdwardsPoint {
    CompressedEdwardsY(*b).decompress().expect("valid point")
}

fn h_gen() -> EdwardsPoint {
    // rct::H from src/ringct/rctTypes.h
    dec(&[
        0x8b, 0x65, 0x59, 0x70, 0x15, 0x37, 0x99, 0xaf, 0x2a, 0xea, 0xdc, 0x9f, 0xf1, 0xad, 0xd0,
        0xea, 0x6c, 0x72, 0x51, 0xd5, 0x41, 0x54, 0xcf, 0xa9, 0x2c, 0x17, 0x3a, 0x0d, 0xd3, 0x9c,
        0x1f, 0x94,
    ])
}

/// A recipient: public keys plus (for scanning tests) the view secret.
#[derive(Clone, Debug)]
pub struct Recipient {
    pub spend_pub: EdwardsPoint,
    pub view_pub: EdwardsPoint,
    pub is_sub: bool,
}

impl Recipient {
    pub fn standard(label: &str) -> Self {
        let a = scalar(&format!("{label}/view"));
        let b = scalar(&format!("{label}/spend"));
        Recipient {
            spend_pub: EdwardsPoint::mul_base(&b),
            view_pub: EdwardsPoint::mul_base(&a),
            is_sub: false,
        }
    }

    /// A subaddress-shaped recipient: `D` arbitrary, `C = a·D`. (Not Monero's
    /// `get_subaddress` derivation, which the verifier never needs.)
    pub fn subaddress(label: &str) -> Self {
        let a = scalar(&format!("{label}/view"));
        let d = EdwardsPoint::mul_base(&scalar(&format!("{label}/subspend")));
        Recipient {
            spend_pub: d,
            view_pub: a * d,
            is_sub: true,
        }
    }

    pub fn address(&self) -> String {
        let prefix = if self.is_sub {
            STAGENET_SUB
        } else {
            STAGENET_STD
        };
        self.address_with_prefix(prefix)
    }

    pub fn address_with_prefix(&self, prefix: u64) -> String {
        let mut data = Vec::new();
        data.extend_from_slice(&pt(&self.spend_pub));
        data.extend_from_slice(&pt(&self.view_pub));
        base58::encode_addr(prefix, &data)
    }

    /// Same keys, claimed as the other address type.
    pub fn with_flipped_kind(&self) -> Self {
        Recipient {
            is_sub: !self.is_sub,
            ..self.clone()
        }
    }
}

#[derive(Clone, Debug)]
pub struct Dest {
    pub to: Recipient,
    pub amount: u64,
}

#[derive(Clone, Debug)]
pub struct TxSpec {
    pub label: String,
    pub version: u64,
    pub unlock_time: u64,
    pub rct_type: u8,
    pub dests: Vec<Dest>,
    /// Use per-output additional tx keys (Monero does when a tx pays a subaddress
    /// and anything else apart from change).
    pub additional_keys: bool,
    pub view_tags: bool,
    /// Coinbase input instead of `txin_to_key`.
    pub coinbase: bool,
    /// Attack helper: output `j` is built from the derivation `8·D0` for the given
    /// point `D0` instead of from a real tx key.
    pub forced_derivation: Vec<(usize, EdwardsPoint)>,
}

impl TxSpec {
    pub fn new(label: &str, dests: Vec<Dest>) -> Self {
        TxSpec {
            label: label.into(),
            version: 2,
            unlock_time: 0,
            rct_type: 6,
            dests,
            additional_keys: false,
            view_tags: true,
            coinbase: false,
            forced_derivation: Vec::new(),
        }
    }
}

pub struct BuiltTx {
    pub blob: Vec<u8>,
    pub txid: [u8; 32],
    pub r: Scalar,
    pub additional_r: Vec<Scalar>,
    /// Offsets: end of prefix, end of rct base.
    pub prefix_end: usize,
    pub base_end: usize,
    /// Offset of output j's encrypted amount and view tag inside the blob.
    pub ecdh_offset: Vec<usize>,
    pub view_tag_offset: Vec<Option<usize>>,
}

pub fn build_tx(spec: &TxSpec) -> BuiltTx {
    let r = scalar(&format!("{}/r", spec.label));
    let n = spec.dests.len();
    let additional_r: Vec<Scalar> = if spec.additional_keys {
        (0..n)
            .map(|j| scalar(&format!("{}/r{j}", spec.label)))
            .collect()
    } else {
        Vec::new()
    };

    // Main tx public key: r·D if the only destination is a subaddress and no
    // additional keys are used, else r·G (generate_output_ephemeral_keys).
    let main_r_pub = if !spec.additional_keys && n == 1 && spec.dests[0].to.is_sub {
        r * spec.dests[0].to.spend_pub
    } else {
        EdwardsPoint::mul_base(&r)
    };

    let mut out_keys = Vec::new();
    let mut tags = Vec::new();
    let mut enc_amounts = Vec::new();
    let mut commitments = Vec::new();
    let mut additional_pubs = Vec::new();
    for (j, d) in spec.dests.iter().enumerate() {
        let secret = if spec.additional_keys && d.to.is_sub {
            additional_r[j]
        } else {
            r
        };
        let derivation = match spec.forced_derivation.iter().find(|(k, _)| *k == j) {
            Some((_, d0)) => pt(&d0.mul_by_cofactor()),
            None => pt(&(secret * d.to.view_pub).mul_by_cofactor()),
        };
        let mut buf = derivation.to_vec();
        varint(j as u64, &mut buf);
        let s = hs(&[&buf]);
        out_keys.push(pt(&(EdwardsPoint::mul_base(&s) + d.to.spend_pub)));
        tags.push(keccak(&[b"view_tag", &buf])[0]);
        let pad = keccak(&[b"amount", s.as_bytes()]);
        let mut enc = d.amount.to_le_bytes();
        for (e, p) in enc.iter_mut().zip(pad.iter()) {
            *e ^= p;
        }
        enc_amounts.push(enc);
        let mask = hs(&[b"commitment_mask", s.as_bytes()]);
        commitments.push(pt(
            &(EdwardsPoint::mul_base(&mask) + Scalar::from(d.amount) * h_gen())
        ));
        if spec.additional_keys {
            let base = if d.to.is_sub {
                d.to.spend_pub
            } else {
                EdwardsPoint::mul_base(&Scalar::ONE)
            };
            additional_pubs.push(pt(&(additional_r[j] * base)));
        }
    }

    let mut extra = vec![0x01];
    extra.extend_from_slice(&pt(&main_r_pub));
    if spec.additional_keys {
        extra.push(0x04);
        varint(additional_pubs.len() as u64, &mut extra);
        for k in &additional_pubs {
            extra.extend_from_slice(k);
        }
    }

    let filler = |i: usize| keccak(&[spec.label.as_bytes(), b"/filler", &(i as u64).to_le_bytes()]);
    let mut blob = Vec::new();
    varint(spec.version, &mut blob);
    varint(spec.unlock_time, &mut blob);
    varint(1, &mut blob);
    let ring = 16usize;
    if spec.coinbase {
        blob.push(0xff);
        varint(1234, &mut blob);
    } else {
        blob.push(0x02);
        varint(0, &mut blob);
        varint(ring as u64, &mut blob);
        for i in 0..ring {
            varint(1000 + i as u64, &mut blob);
        }
        blob.extend_from_slice(&filler(0));
    }
    varint(n as u64, &mut blob);
    let mut view_tag_offset = Vec::new();
    for (j, k) in out_keys.iter().enumerate() {
        varint(0, &mut blob);
        if spec.view_tags {
            blob.push(0x03);
            blob.extend_from_slice(k);
            view_tag_offset.push(Some(blob.len()));
            blob.push(tags[j]);
        } else {
            blob.push(0x02);
            blob.extend_from_slice(k);
            view_tag_offset.push(None);
        }
    }
    varint(extra.len() as u64, &mut blob);
    blob.extend_from_slice(&extra);
    let prefix_end = blob.len();

    blob.push(spec.rct_type);
    varint(30_000_000, &mut blob);
    let mut ecdh_offset = Vec::new();
    for e in &enc_amounts {
        ecdh_offset.push(blob.len());
        blob.extend_from_slice(e);
    }
    for c in &commitments {
        blob.extend_from_slice(c);
    }
    let base_end = blob.len();

    // Prunable: one BP+ (A, A1, B, r1, s1, d1, L, R), one CLSAG, one pseudoOut.
    // Contents are filler; the verifier does not check them.
    varint(1, &mut blob);
    for i in 0..6 {
        blob.extend_from_slice(&filler(10 + i));
    }
    let l = 6 + (usize::BITS - (n.max(1) - 1).leading_zeros()) as usize;
    for side in 0..2 {
        varint(l as u64, &mut blob);
        for i in 0..l {
            blob.extend_from_slice(&filler(100 * (side + 1) + i));
        }
    }
    for i in 0..ring + 2 {
        blob.extend_from_slice(&filler(500 + i));
    }
    blob.extend_from_slice(&filler(999));

    let txid = keccak(&[
        &keccak(&[&blob[..prefix_end]]),
        &keccak(&[&blob[prefix_end..base_end]]),
        &keccak(&[&blob[base_end..]]),
    ]);
    BuiltTx {
        blob,
        txid,
        r,
        additional_r,
        prefix_end,
        base_end,
        ecdh_offset,
        view_tag_offset,
    }
}

/// `crypto::generate_tx_proof` (version 2) or the V1 hash (`version = 1`).
#[allow(clippy::too_many_arguments)]
pub fn generate_tx_proof(
    prefix_hash: &[u8; 32],
    r_pub: &EdwardsPoint,
    a: &EdwardsPoint,
    b: Option<&EdwardsPoint>,
    d: &EdwardsPoint,
    r: &Scalar,
    nonce_label: &str,
    version: u8,
) -> ([u8; 32], [u8; 32]) {
    let k = scalar(nonce_label);
    let x = match b {
        Some(b) => k * b,
        None => EdwardsPoint::mul_base(&k),
    };
    let y = k * a;
    let sep = keccak(&[b"TXPROOF_V2"]);
    let zero = [0u8; 32];
    let b_bytes = b.map(pt).unwrap_or(zero);
    let c = if version == 1 {
        hs(&[prefix_hash, &pt(d), &pt(&x), &pt(&y)])
    } else {
        hs(&[
            prefix_hash,
            &pt(d),
            &pt(&x),
            &pt(&y),
            &sep,
            &pt(r_pub),
            &pt(a),
            &b_bytes,
        ])
    };
    let sig_r = k - c * r;
    (c.to_bytes(), sig_r.to_bytes())
}

/// `wallet2::get_tx_proof` (out-proof branch) for `to`, over `message`.
pub fn get_tx_proof(tx: &BuiltTx, to: &Recipient, message: &str, version: u8) -> String {
    let prefix_hash = keccak(&[&tx.txid, message.as_bytes()]);
    let b = if to.is_sub { Some(&to.spend_pub) } else { None };
    let mut secrets = vec![tx.r];
    secrets.extend_from_slice(&tx.additional_r);
    let mut s = String::from(if version == 1 {
        "OutProofV1"
    } else {
        "OutProofV2"
    });
    for (i, sec) in secrets.iter().enumerate() {
        let d = sec * to.view_pub;
        let r_pub = match b {
            Some(b) => sec * b,
            None => EdwardsPoint::mul_base(sec),
        };
        let (c, r) = generate_tx_proof(
            &prefix_hash,
            &r_pub,
            &to.view_pub,
            b,
            &d,
            sec,
            &format!("nonce/{i}/{message}"),
            version,
        );
        s.push_str(&base58::encode(&pt(&d)));
        let mut sig = c.to_vec();
        sig.extend_from_slice(&r);
        s.push_str(&base58::encode(&sig));
    }
    s
}
