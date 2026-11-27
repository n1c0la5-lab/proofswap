//! Monero's block-wise Base58 (8-byte blocks, 11 characters per full block).
//!
//! Ported from Monero v0.18.5.4 `src/common/base58.cpp`.
//! Copyright (c) 2014-2022, The Monero Project. BSD-3-Clause, see `LICENSE-MONERO`.

use crate::hash::keccak256;
use crate::varint::{read_varint, write_varint};
use alloc::string::String;
use alloc::vec::Vec;

const ALPHABET: &[u8; 58] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
const ENCODED_BLOCK_SIZES: [usize; 9] = [0, 2, 3, 5, 6, 7, 9, 10, 11];
const FULL_BLOCK_SIZE: usize = 8;
const FULL_ENCODED_BLOCK_SIZE: usize = 11;
const ADDR_CHECKSUM_SIZE: usize = 4;

fn decoded_block_size(encoded: usize) -> Option<usize> {
    ENCODED_BLOCK_SIZES.iter().position(|&s| s == encoded)
}

fn digit(c: u8) -> Option<u64> {
    ALPHABET.iter().position(|&a| a == c).map(|d| d as u64)
}

fn encode_block(block: &[u8], out: &mut [u8]) {
    let mut num: u64 = 0;
    for &b in block {
        num = (num << 8) | u64::from(b);
    }
    let mut i = ENCODED_BLOCK_SIZES[block.len()];
    for slot in out.iter_mut() {
        *slot = ALPHABET[0];
    }
    while num > 0 {
        i -= 1;
        out[i] = ALPHABET[(num % 58) as usize];
        num /= 58;
    }
}

fn decode_block(block: &[u8], out: &mut Vec<u8>) -> Option<()> {
    let res_size = decoded_block_size(block.len())?;
    if res_size == 0 {
        return None;
    }
    let mut res_num: u64 = 0;
    let mut order: u64 = 1;
    for &c in block.iter().rev() {
        let d = digit(c)?;
        let product = u128::from(order) * u128::from(d);
        if product > u128::from(u64::MAX) {
            return None;
        }
        res_num = res_num.checked_add(product as u64)?;
        // 58^10 < 2^64, so this only wraps after the last digit of a full block.
        order = order.wrapping_mul(58);
    }
    if res_size < FULL_BLOCK_SIZE && (1u64 << (8 * res_size)) <= res_num {
        return None;
    }
    let bytes = res_num.to_be_bytes();
    out.extend_from_slice(&bytes[8 - res_size..]);
    Some(())
}

/// Encodes `data` in Monero Base58.
pub fn encode(data: &[u8]) -> String {
    let full = data.len() / FULL_BLOCK_SIZE;
    let last = data.len() % FULL_BLOCK_SIZE;
    let mut out = alloc::vec![0u8; full * FULL_ENCODED_BLOCK_SIZE + ENCODED_BLOCK_SIZES[last]];
    for i in 0..full {
        encode_block(
            &data[i * FULL_BLOCK_SIZE..(i + 1) * FULL_BLOCK_SIZE],
            &mut out[i * FULL_ENCODED_BLOCK_SIZE..(i + 1) * FULL_ENCODED_BLOCK_SIZE],
        );
    }
    if last > 0 {
        encode_block(
            &data[full * FULL_BLOCK_SIZE..],
            &mut out[full * FULL_ENCODED_BLOCK_SIZE..],
        );
    }
    // Every byte comes from ALPHABET, which is ASCII.
    out.into_iter().map(char::from).collect()
}

/// Decodes Monero Base58. Returns `None` for invalid characters, lengths or overflow.
pub fn decode(enc: &str) -> Option<Vec<u8>> {
    let enc = enc.as_bytes();
    let full = enc.len() / FULL_ENCODED_BLOCK_SIZE;
    let last = enc.len() % FULL_ENCODED_BLOCK_SIZE;
    decoded_block_size(last)?;
    let mut out = Vec::with_capacity(full * FULL_BLOCK_SIZE + FULL_BLOCK_SIZE);
    for i in 0..full {
        decode_block(
            &enc[i * FULL_ENCODED_BLOCK_SIZE..(i + 1) * FULL_ENCODED_BLOCK_SIZE],
            &mut out,
        )?;
    }
    if last > 0 {
        decode_block(&enc[full * FULL_ENCODED_BLOCK_SIZE..], &mut out)?;
    }
    Some(out)
}

/// Encodes an address: `varint(tag) || data || keccak(...)[0..4]`, then Base58.
pub fn encode_addr(tag: u64, data: &[u8]) -> String {
    let mut buf = Vec::new();
    write_varint(&mut buf, tag);
    buf.extend_from_slice(data);
    let checksum = keccak256(&buf);
    buf.extend_from_slice(&checksum[..ADDR_CHECKSUM_SIZE]);
    encode(&buf)
}

/// Error from [`decode_addr`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddrDecodeError {
    /// Not valid Monero Base58.
    Base58,
    /// The 4-byte Keccak checksum does not match.
    Checksum,
    /// The network tag varint is malformed.
    Tag,
}

/// Decodes an address into `(tag, data)` after checking the checksum.
pub fn decode_addr(addr: &str) -> Result<(u64, Vec<u8>), AddrDecodeError> {
    let mut raw = decode(addr).ok_or(AddrDecodeError::Base58)?;
    if raw.len() <= ADDR_CHECKSUM_SIZE {
        return Err(AddrDecodeError::Base58);
    }
    let body_len = raw.len() - ADDR_CHECKSUM_SIZE;
    let expected = keccak256(&raw[..body_len]);
    if expected[..ADDR_CHECKSUM_SIZE] != raw[body_len..] {
        return Err(AddrDecodeError::Checksum);
    }
    raw.truncate(body_len);
    let mut pos = 0;
    let tag = read_varint(&raw, &mut pos).ok_or(AddrDecodeError::Tag)?;
    Ok((tag, raw[pos..].to_vec()))
}

#[cfg(test)]
mod tests {
    //! Vectors from Monero v0.18.5.4 `tests/unit_tests/base58.cpp`.
    use super::*;

    #[test]
    fn monero_encode_vectors() {
        let cases: &[(&[u8], &str)] = &[
            (b"\x00", "11"),
            (b"\x39", "1z"),
            (b"\xFF", "5Q"),
            (b"\x00\x39", "11z"),
            (b"\x01\x00", "15R"),
            (b"\xFF\xFF", "LUv"),
            (b"\x01\x00\x00", "11LUw"),
            (b"\xFF\xFF\xFF", "2UzHL"),
            (b"\xFF\xFF\xFF\xFF", "7YXq9G"),
            (b"\xFF\xFF\xFF\xFF\xFF", "VtB5VXc"),
            (b"\xFF\xFF\xFF\xFF\xFF\xFF", "3CUsUpv9t"),
            (b"\xFF\xFF\xFF\xFF\xFF\xFF\xFF", "Ahg1opVcGW"),
            (b"\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF", "jpXCZedGfVQ"),
            (b"\x00\x00\x00\x00\x00\x00\x00\x3A", "11111111121"),
            (b"\x06\x15\x60\x13\x76\x28\x79\xF7", "22222222222"),
            (b"\x05\xE0\x22\xBA\x37\x4B\x2A\x00", "1z111111111"),
            (
                b"\x06\x15\x60\x13\x76\x28\x79\xF7\xFF\xFF\xFF\xFF\xFF",
                "22222222222VtB5VXc",
            ),
        ];
        for (data, enc) in cases {
            assert_eq!(encode(data), *enc);
            assert_eq!(decode(enc).as_deref(), Some(*data));
        }
    }

    #[test]
    fn monero_addr_vectors() {
        let (tag, data) = decode_addr(
            "PuT7GAdgbA83qvSEivPLYo11111111111111111111111111111111111111111111111111111111111111111111111111111169tWrH",
        )
        .unwrap();
        assert_eq!(tag, 0x1122_3344_5566_7788);
        assert_eq!(data, [0u8; 64]);
        let (tag, data) = decode_addr("PuT7GAdgbA81efAfdCjPg").unwrap();
        assert_eq!(tag, 0x1122_3344_5566_7788);
        assert_eq!(data, b"\x22\x22");
        assert_eq!(
            encode_addr(6, &[0xff; 64]),
            "2Aui6ejTFscjpXCZedGfVQjpXCZedGfVQjpXCZedGfVQjpXCZedGfVQjpXCZedGfVQjpXCZedGfVQjpXCZedGfVQVqegMoV"
        );
    }

    #[test]
    fn rejects_overflow_and_bad_symbols() {
        // 2^64 does not fit a full block ("jpXCZedGfVR" = 0xFF..FF + 1).
        assert_eq!(decode("jpXCZedGfVR"), None);
        // "5R" = 256 does not fit a 1-byte block.
        assert_eq!(decode("5R"), None);
        assert_eq!(decode("0O"), None);
        // invalid length (1 or 4 characters cannot occur)
        assert_eq!(decode("1"), None);
        assert_eq!(decode("1111"), None);
    }
}
