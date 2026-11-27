//! Stagenet address parsing (SPEC §6.3 step 2, §12).
//!
//! Network prefixes and the key layout (spend key, then view key) follow Monero
//! v0.18.5.4 `src/cryptonote_config.h` and `cryptonote_basic_impl.cpp`
//! (`get_account_address_from_str`).
//! Copyright (c) 2014-2022, The Monero Project. BSD-3-Clause, see `LICENSE-MONERO`.

use crate::base58::{decode_addr, AddrDecodeError};
use crate::crypto::decode_point;
use crate::error::AddressError;

/// Stagenet standard address prefix.
pub const STAGENET_ADDRESS_PREFIX: u64 = 24;
/// Stagenet integrated address prefix (rejected).
pub const STAGENET_INTEGRATED_PREFIX: u64 = 25;
/// Stagenet subaddress prefix.
pub const STAGENET_SUBADDRESS_PREFIX: u64 = 36;

const MAINNET_PREFIXES: [u64; 3] = [18, 19, 42];
const TESTNET_PREFIXES: [u64; 3] = [53, 54, 63];

/// Standard address or subaddress.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddressKind {
    Standard,
    Subaddress,
}

/// A decoded stagenet address: `(A, B)` = (public view key, public spend key).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StagenetAddress {
    pub spend_public_key: [u8; 32],
    pub view_public_key: [u8; 32],
    pub kind: AddressKind,
}

impl StagenetAddress {
    pub fn is_subaddress(&self) -> bool {
        self.kind == AddressKind::Subaddress
    }
}

/// Parses a stagenet standard address or subaddress.
///
/// Mainnet and testnet addresses are rejected with their own error, integrated
/// addresses too. Both keys must be valid, canonically encoded points.
pub fn parse_stagenet_address(s: &str) -> Result<StagenetAddress, AddressError> {
    let (tag, data) = decode_addr(s).map_err(|e| match e {
        AddrDecodeError::Checksum => AddressError::Checksum,
        AddrDecodeError::Base58 | AddrDecodeError::Tag => AddressError::Base58,
    })?;
    let kind = match tag {
        STAGENET_ADDRESS_PREFIX => AddressKind::Standard,
        STAGENET_SUBADDRESS_PREFIX => AddressKind::Subaddress,
        STAGENET_INTEGRATED_PREFIX => return Err(AddressError::Integrated),
        t if MAINNET_PREFIXES.contains(&t) => return Err(AddressError::Mainnet),
        t if TESTNET_PREFIXES.contains(&t) => return Err(AddressError::Testnet),
        t => return Err(AddressError::UnknownPrefix(t)),
    };
    if data.len() != 64 {
        return Err(AddressError::Length);
    }
    let mut spend_public_key = [0u8; 32];
    let mut view_public_key = [0u8; 32];
    spend_public_key.copy_from_slice(&data[..32]);
    view_public_key.copy_from_slice(&data[32..]);
    if decode_point(&spend_public_key).is_none() || decode_point(&view_public_key).is_none() {
        return Err(AddressError::InvalidKey);
    }
    Ok(StagenetAddress {
        spend_public_key,
        view_public_key,
        kind,
    })
}
