//! Error types and their mapping onto the canister's `ProofError` (SPEC §8).

use core::fmt;

/// Why an address was rejected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddressError {
    /// Not valid Monero Base58 or too short.
    Base58,
    /// The checksum does not match.
    Checksum,
    /// Mainnet address (prefix 18, 19 or 42). Rejected by policy (SPEC §12).
    Mainnet,
    /// Testnet address (prefix 53, 54 or 63).
    Testnet,
    /// Stagenet integrated address (prefix 25). Not supported: use a subaddress.
    Integrated,
    /// Any other network prefix.
    UnknownPrefix(u64),
    /// The key data is not exactly 64 bytes.
    Length,
    /// A key is not a valid, canonically encoded curve point.
    InvalidKey,
}

/// Why a transaction is outside what this verifier supports (rule R6).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Unsupported {
    /// Transaction version other than 2 (version 1 is pre-RingCT).
    Version(u64),
    /// RingCT type other than 6 (`RCTTypeBulletproofPlus`, CLSAG + BP+).
    RctType(u8),
    /// A coinbase (`txin_gen`) input.
    Coinbase,
    /// An input other than `txin_to_key`.
    InputType(u8),
    /// An output other than `txout_to_key` / `txout_to_tagged_key`.
    OutputType(u8),
}

/// Every reason [`crate::verify_payment`] and the parsers can fail.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerifyError {
    /// Hex input (txid or transaction blob) is malformed.
    Hex,
    /// The payee address is not an acceptable stagenet address.
    Address(AddressError),
    /// The proof is an `OutProofV1` (no domain separation). Only V2 is accepted.
    ProofV1,
    /// The proof string is not a well-formed `OutProofV2…` string.
    ProofFormat,
    /// The proof has a different number of entries than the tx has tx public keys.
    ProofEntryCount { proof: usize, tx_keys: usize },
    /// The transaction blob does not parse.
    TxMalformed(&'static str),
    /// The transaction parses but is not supported (R6).
    UnsupportedTx(Unsupported),
    /// The blob does not hash to the claimed txid (SPEC §6.2).
    TxidMismatch { computed: [u8; 32] },
    /// The transaction has no usable tx public key in `extra`.
    NoTxPubKey,
    /// No proof signature verifies (R1).
    InvalidProof,
    /// `unlock_time != 0` (R3).
    UnlockTimeSet { unlock_time: u64 },
    /// The proven amount is below the order amount (R2).
    InsufficientAmount { got: u64, need: u64 },
    /// The tx was not mined after the order's lock height (R4, canister data).
    TooOld { lock_height: u64, mined_height: u64 },
    /// The txid was already used by another order (R5, canister data).
    TxidReused,
    /// The canister id or order id cannot form a proof message.
    InvalidMessageInput,
}

/// Mirror of `ProofError` in SPEC §8, so the canister can map errors one to one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProofErrorKind {
    TxidMismatch,
    InvalidProof,
    WrongMessage,
    InsufficientAmount { got: u64, need: u64 },
    UnlockTimeSet,
    TooOld,
    TxidReused,
    UnsupportedTx,
}

impl VerifyError {
    /// Maps onto SPEC §8 `ProofError`.
    ///
    /// Notes:
    /// - `WrongMessage` is never produced. A proof signed over a different message is
    ///   indistinguishable from a forged one, so it fails as `InvalidProof`. The
    ///   canister builds the message itself with [`crate::proof_message`].
    /// - Address errors map to `InvalidProof`. The canister should reject bad
    ///   addresses earlier, at `create_order` / `take_order`, with
    ///   [`crate::parse_stagenet_address`].
    /// - A malformed tx blob or tx hex maps to `UnsupportedTx`.
    pub fn proof_error(&self) -> ProofErrorKind {
        match self {
            VerifyError::Address(_)
            | VerifyError::ProofV1
            | VerifyError::ProofFormat
            | VerifyError::ProofEntryCount { .. }
            | VerifyError::NoTxPubKey
            | VerifyError::InvalidProof
            | VerifyError::InvalidMessageInput => ProofErrorKind::InvalidProof,
            VerifyError::Hex | VerifyError::TxMalformed(_) | VerifyError::UnsupportedTx(_) => {
                ProofErrorKind::UnsupportedTx
            }
            VerifyError::TxidMismatch { .. } => ProofErrorKind::TxidMismatch,
            VerifyError::UnlockTimeSet { .. } => ProofErrorKind::UnlockTimeSet,
            VerifyError::InsufficientAmount { got, need } => ProofErrorKind::InsufficientAmount {
                got: *got,
                need: *need,
            },
            VerifyError::TooOld { .. } => ProofErrorKind::TooOld,
            VerifyError::TxidReused => ProofErrorKind::TxidReused,
        }
    }
}

impl From<AddressError> for VerifyError {
    fn from(e: AddressError) -> Self {
        VerifyError::Address(e)
    }
}

impl fmt::Display for AddressError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AddressError::Base58 => f.write_str("address is not valid base58"),
            AddressError::Checksum => f.write_str("address checksum mismatch"),
            AddressError::Mainnet => f.write_str("mainnet addresses are rejected (stagenet only)"),
            AddressError::Testnet => f.write_str("testnet addresses are rejected (stagenet only)"),
            AddressError::Integrated => f.write_str("integrated addresses are not supported"),
            AddressError::UnknownPrefix(p) => write!(f, "unknown address prefix {p}"),
            AddressError::Length => f.write_str("address key data has the wrong length"),
            AddressError::InvalidKey => f.write_str("address key is not a valid point"),
        }
    }
}

impl fmt::Display for VerifyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            VerifyError::Hex => f.write_str("malformed hex"),
            VerifyError::Address(e) => write!(f, "address: {e}"),
            VerifyError::ProofV1 => f.write_str("OutProofV1 is not accepted, use OutProofV2"),
            VerifyError::ProofFormat => f.write_str("malformed OutProofV2 string"),
            VerifyError::ProofEntryCount { proof, tx_keys } => {
                write!(
                    f,
                    "proof has {proof} entries, tx has {tx_keys} tx public keys"
                )
            }
            VerifyError::TxMalformed(what) => write!(f, "malformed transaction: {what}"),
            VerifyError::UnsupportedTx(u) => write!(f, "unsupported transaction: {u:?}"),
            VerifyError::TxidMismatch { .. } => {
                f.write_str("blob does not hash to the claimed txid")
            }
            VerifyError::NoTxPubKey => f.write_str("transaction has no tx public key"),
            VerifyError::InvalidProof => f.write_str("proof does not verify"),
            VerifyError::UnlockTimeSet { unlock_time } => {
                write!(f, "unlock_time is {unlock_time}, must be 0")
            }
            VerifyError::InsufficientAmount { got, need } => {
                write!(f, "proven amount {got} is below {need} piconero")
            }
            VerifyError::TooOld {
                lock_height,
                mined_height,
            } => {
                write!(
                    f,
                    "mined at {mined_height}, not after lock height {lock_height}"
                )
            }
            VerifyError::TxidReused => f.write_str("txid already used by another order"),
            VerifyError::InvalidMessageInput => {
                f.write_str("invalid canister id for the proof message")
            }
        }
    }
}
