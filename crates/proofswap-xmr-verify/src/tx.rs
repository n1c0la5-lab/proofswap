//! Transaction parser for `as_hex` blobs and txid recomputation (SPEC §6.2, R6).
//!
//! Only version-2 transactions with RingCT type 6 (`RCTTypeBulletproofPlus`:
//! CLSAG ring signatures + Bulletproofs+) are accepted, the only type valid on the
//! network since hard fork 15. Everything else is [`VerifyError::UnsupportedTx`].
//! The whole blob must be consumed, so the txid binds exactly the bytes parsed.
//!
//! Serialization layout ported from Monero v0.18.5.4
//! `src/cryptonote_basic/cryptonote_basic.h` (`transaction_prefix`, `transaction`),
//! `src/ringct/rctTypes.h` (`serialize_rctsig_base`, `serialize_rctsig_prunable`),
//! `src/ringct/rctTypes.cpp` (`n_bulletproof_plus_max_amounts`) and
//! `src/cryptonote_basic/cryptonote_format_utils.cpp` (`calculate_transaction_hash`,
//! `parse_tx_extra`); `tx_extra` field tags from `tx_extra.h`.
//! Copyright (c) 2014-2022, The Monero Project. BSD-3-Clause, see `LICENSE-MONERO`.
//! Parts originally copyright (c) 2012-2013 The Cryptonote developers.

use crate::error::{Unsupported, VerifyError};
use crate::hash::{keccak256, keccak256_parts};
use crate::varint::read_varint;
use alloc::vec::Vec;

/// `RCTTypeBulletproofPlus`.
pub const RCT_TYPE_BULLETPROOF_PLUS: u8 = 6;
/// Monero's `CRYPTONOTE_MAX_TX_SIZE`.
pub const MAX_TX_SIZE: usize = 1_000_000;
/// `BULLETPROOF_PLUS_MAX_OUTPUTS`.
pub const MAX_OUTPUTS: usize = 16;

/// One transaction output.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TxOutput {
    /// One-time output public key `P`.
    pub key: [u8; 32],
    /// View tag (`txout_to_tagged_key`), `None` for `txout_to_key`.
    pub view_tag: Option<u8>,
    /// Encrypted amount, `ecdhInfo[i].amount` (8 bytes).
    pub encrypted_amount: [u8; 8],
    /// Amount commitment `C`, `outPk[i].mask`.
    pub commitment: [u8; 32],
}

/// The parts of a transaction the verifier needs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedTx {
    /// Recomputed transaction hash.
    pub txid: [u8; 32],
    pub version: u64,
    pub unlock_time: u64,
    pub input_count: usize,
    /// Ring size of the first input (CLSAG `s` vector length for every input).
    pub ring_size: usize,
    pub outputs: Vec<TxOutput>,
    /// Raw `extra` field.
    pub extra: Vec<u8>,
    pub rct_type: u8,
    pub fee: u64,
}

struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn varint(&mut self, what: &'static str) -> Result<u64, VerifyError> {
        read_varint(self.buf, &mut self.pos).ok_or(VerifyError::TxMalformed(what))
    }

    fn byte(&mut self, what: &'static str) -> Result<u8, VerifyError> {
        let b = *self
            .buf
            .get(self.pos)
            .ok_or(VerifyError::TxMalformed(what))?;
        self.pos += 1;
        Ok(b)
    }

    fn bytes(&mut self, n: usize, what: &'static str) -> Result<&'a [u8], VerifyError> {
        let end = self
            .pos
            .checked_add(n)
            .ok_or(VerifyError::TxMalformed(what))?;
        let s = self
            .buf
            .get(self.pos..end)
            .ok_or(VerifyError::TxMalformed(what))?;
        self.pos = end;
        Ok(s)
    }

    fn key(&mut self, what: &'static str) -> Result<[u8; 32], VerifyError> {
        let mut k = [0u8; 32];
        k.copy_from_slice(self.bytes(32, what)?);
        Ok(k)
    }

    /// Skips `count` items of `size` bytes, refusing counts the blob cannot hold.
    fn skip(&mut self, count: u64, size: usize, what: &'static str) -> Result<(), VerifyError> {
        let n = usize::try_from(count)
            .ok()
            .and_then(|c| c.checked_mul(size))
            .ok_or(VerifyError::TxMalformed(what))?;
        self.bytes(n, what).map(|_| ())
    }

    /// A count that must fit in the remaining bytes at `min_item` bytes per item.
    fn count(&mut self, min_item: usize, what: &'static str) -> Result<usize, VerifyError> {
        let c = self.varint(what)?;
        let c = usize::try_from(c).map_err(|_| VerifyError::TxMalformed(what))?;
        let remaining = self.buf.len() - self.pos;
        if c.checked_mul(min_item).is_none_or(|n| n > remaining) {
            return Err(VerifyError::TxMalformed(what));
        }
        Ok(c)
    }
}

/// Parses a full (unpruned) transaction blob and recomputes its txid.
pub fn parse_transaction(blob: &[u8]) -> Result<ParsedTx, VerifyError> {
    if blob.len() > MAX_TX_SIZE {
        return Err(VerifyError::TxMalformed(
            "blob larger than CRYPTONOTE_MAX_TX_SIZE",
        ));
    }
    let mut r = Reader { buf: blob, pos: 0 };

    // --- prefix ---
    let version = r.varint("version")?;
    if version != 2 {
        return Err(VerifyError::UnsupportedTx(Unsupported::Version(version)));
    }
    let unlock_time = r.varint("unlock_time")?;

    let input_count = r.count(1, "vin count")?;
    if input_count == 0 {
        return Err(VerifyError::TxMalformed("no inputs"));
    }
    let mut ring_size = 0usize;
    for i in 0..input_count {
        match r.byte("vin tag")? {
            0x02 => {
                r.varint("vin amount")?;
                let n = r.count(1, "key_offsets count")?;
                if n == 0 {
                    return Err(VerifyError::TxMalformed("empty ring"));
                }
                for _ in 0..n {
                    r.varint("key offset")?;
                }
                r.key("key image")?;
                if i == 0 {
                    ring_size = n;
                }
            }
            0xff => return Err(VerifyError::UnsupportedTx(Unsupported::Coinbase)),
            t => return Err(VerifyError::UnsupportedTx(Unsupported::InputType(t))),
        }
    }

    let output_count = r.count(33, "vout count")?;
    if output_count == 0 || output_count > MAX_OUTPUTS {
        return Err(VerifyError::TxMalformed("output count out of range"));
    }
    let mut out_keys = Vec::with_capacity(output_count);
    for _ in 0..output_count {
        r.varint("vout amount")?;
        match r.byte("vout tag")? {
            0x02 => out_keys.push((r.key("output key")?, None)),
            0x03 => {
                let k = r.key("output key")?;
                let tag = r.byte("view tag")?;
                out_keys.push((k, Some(tag)));
            }
            t => return Err(VerifyError::UnsupportedTx(Unsupported::OutputType(t))),
        }
    }

    let extra_len = r.count(1, "extra length")?;
    let extra = r.bytes(extra_len, "extra")?.to_vec();
    let prefix_end = r.pos;

    // --- rct base ---
    let rct_type = r.byte("rct type")?;
    if rct_type != RCT_TYPE_BULLETPROOF_PLUS {
        return Err(VerifyError::UnsupportedTx(Unsupported::RctType(rct_type)));
    }
    let fee = r.varint("txnFee")?;
    let mut amounts = Vec::with_capacity(output_count);
    for _ in 0..output_count {
        let mut a = [0u8; 8];
        a.copy_from_slice(r.bytes(8, "ecdhInfo")?);
        amounts.push(a);
    }
    let mut commitments = Vec::with_capacity(output_count);
    for _ in 0..output_count {
        commitments.push(r.key("outPk")?);
    }
    let base_end = r.pos;

    // --- rct prunable (BP+ / CLSAG) ---
    let nbp = r.count(6 * 32, "bpp count")?;
    if nbp == 0 || nbp > output_count {
        return Err(VerifyError::TxMalformed("bulletproof+ count"));
    }
    let mut max_amounts = 0usize;
    for _ in 0..nbp {
        r.skip(6, 32, "bpp A..d1")?;
        let l = r.count(32, "bpp L")?;
        r.skip(l as u64, 32, "bpp L")?;
        let rr = r.count(32, "bpp R")?;
        r.skip(rr as u64, 32, "bpp R")?;
        // n_bulletproof_max_amounts_base: 6 <= |L| == |R| <= 10
        if l < 6 || l != rr || l > 10 {
            return Err(VerifyError::TxMalformed("bulletproof+ L/R size"));
        }
        max_amounts += 1usize << (l - 6);
    }
    if max_amounts < output_count {
        return Err(VerifyError::TxMalformed(
            "bulletproof+ covers too few outputs",
        ));
    }
    for _ in 0..input_count {
        r.skip(ring_size as u64, 32, "CLSAG s")?;
        r.skip(2, 32, "CLSAG c1, D")?;
    }
    r.skip(input_count as u64, 32, "pseudoOuts")?;
    if r.pos != blob.len() {
        return Err(VerifyError::TxMalformed("trailing bytes"));
    }

    let txid = keccak256_parts(&[
        &keccak256(&blob[..prefix_end]),
        &keccak256(&blob[prefix_end..base_end]),
        &keccak256(&blob[base_end..]),
    ]);

    let outputs = out_keys
        .into_iter()
        .zip(amounts)
        .zip(commitments)
        .map(
            |(((key, view_tag), encrypted_amount), commitment)| TxOutput {
                key,
                view_tag,
                encrypted_amount,
                commitment,
            },
        )
        .collect();

    Ok(ParsedTx {
        txid,
        version,
        unlock_time,
        input_count,
        ring_size,
        outputs,
        extra,
        rct_type,
        fee,
    })
}

/// Recomputes the txid from a full transaction blob (SPEC §6.2):
/// `H(H(prefix) || H(rct_base) || H(rct_prunable))`.
///
/// Only supported transactions (see module docs) can be hashed.
pub fn compute_txid(blob: &[u8]) -> Result<[u8; 32], VerifyError> {
    parse_transaction(blob).map(|tx| tx.txid)
}

/// One field of `tx_extra`, as far as the verifier cares.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExtraField {
    Padding,
    PubKey([u8; 32]),
    Nonce,
    MergeMining,
    AdditionalPubKeys(Vec<[u8; 32]>),
    MysteriousMinergate,
}

/// Port of `parse_tx_extra`: parses fields until the first malformed one.
///
/// Like Monero (whose `check_tx_proof` ignores the return value of
/// `parse_tx_extra`), the fields parsed before an error are kept and used.
pub fn parse_extra(extra: &[u8]) -> Vec<ExtraField> {
    let mut fields = Vec::new();
    let mut r = Reader { buf: extra, pos: 0 };
    while r.pos < extra.len() {
        match parse_extra_field(&mut r) {
            Some(f) => fields.push(f),
            None => break,
        }
    }
    fields
}

fn parse_extra_field(r: &mut Reader<'_>) -> Option<ExtraField> {
    match r.byte("extra tag").ok()? {
        0x00 => {
            // tx_extra_padding: up to 254 further zero bytes, then end of extra.
            let mut size = 1usize;
            while r.pos < r.buf.len() {
                if size >= 255 || r.byte("padding").ok()? != 0 {
                    return None;
                }
                size += 1;
            }
            Some(ExtraField::Padding)
        }
        0x01 => Some(ExtraField::PubKey(r.key("extra pubkey").ok()?)),
        0x02 => {
            let n = r.count(1, "nonce").ok()?;
            if n > 255 {
                return None;
            }
            r.bytes(n, "nonce").ok()?;
            Some(ExtraField::Nonce)
        }
        0x03 => {
            let n = r.count(1, "merge mining").ok()?;
            let inner = r.bytes(n, "merge mining").ok()?;
            let mut ir = Reader { buf: inner, pos: 0 };
            ir.varint("mm depth").ok()?;
            ir.key("mm merkle root").ok()?;
            Some(ExtraField::MergeMining)
        }
        0x04 => {
            let n = r.count(32, "additional pubkeys").ok()?;
            let mut keys = Vec::with_capacity(n);
            for _ in 0..n {
                keys.push(r.key("additional pubkey").ok()?);
            }
            Some(ExtraField::AdditionalPubKeys(keys))
        }
        0xde => {
            let n = r.count(1, "minergate").ok()?;
            r.bytes(n, "minergate").ok()?;
            Some(ExtraField::MysteriousMinergate)
        }
        _ => None,
    }
}
