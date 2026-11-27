//! Monero varints (LEB128, little-endian base-128).
//!
//! Ported from Monero v0.18.5.4 `src/common/varint.h`, including its rejection of
//! non-canonical encodings and overflow.
//! Copyright (c) 2014-2022, The Monero Project. BSD-3-Clause, see `LICENSE-MONERO`.

use alloc::vec::Vec;

/// Reads a varint from `buf` at `*pos` and advances `*pos`.
///
/// Returns `None` on truncation, overflow beyond 64 bits, or a non-canonical
/// encoding (a trailing zero byte after the first one), like Monero's
/// `EVARINT_OVERFLOW` / `EVARINT_REPRESENT`.
pub fn read_varint(buf: &[u8], pos: &mut usize) -> Option<u64> {
    let mut value: u64 = 0;
    let mut shift: u32 = 0;
    loop {
        let byte = *buf.get(*pos)?;
        *pos += 1;
        if shift == 63 && byte > 1 {
            return None;
        }
        if byte == 0 && shift != 0 {
            return None;
        }
        value |= u64::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            return Some(value);
        }
        shift += 7;
        if shift > 63 {
            return None;
        }
    }
}

/// Appends the varint encoding of `value` to `out`.
pub fn write_varint(out: &mut Vec<u8>, mut value: u64) {
    while value >= 0x80 {
        out.push((value as u8 & 0x7f) | 0x80);
        value >>= 7;
    }
    out.push(value as u8);
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    #[test]
    fn roundtrip() {
        for v in [0u64, 1, 127, 128, 300, 1 << 35, u64::MAX] {
            let mut buf = Vec::new();
            write_varint(&mut buf, v);
            let mut pos = 0;
            assert_eq!(read_varint(&buf, &mut pos), Some(v));
            assert_eq!(pos, buf.len());
        }
    }

    #[test]
    fn rejects_non_canonical_and_overflow() {
        let mut pos = 0;
        assert_eq!(read_varint(&[0x80, 0x00], &mut pos), None);
        let mut pos = 0;
        assert_eq!(read_varint(&[0xff; 10], &mut pos), None);
        let mut pos = 0;
        assert_eq!(read_varint(&[0x80], &mut pos), None);
        let mut buf = vec![0xffu8; 9];
        buf.push(0x01);
        let mut pos = 0;
        assert_eq!(read_varint(&buf, &mut pos), Some(u64::MAX));
    }
}
