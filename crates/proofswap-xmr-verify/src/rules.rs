//! Acceptance rules R4 and R5 (SPEC §6.3), which need canister state.
//!
//! This crate cannot know when a transaction was mined or which txids other orders
//! used. The canister supplies those values. These functions only do the
//! comparison, so that the rule is written down once and tested. **They prove
//! nothing about the values themselves**: `mined_height` is only as good as the
//! t-of-k node agreement (SPEC §7, §10), and the used-txid set is only as good as
//! the canister's stable storage.

use crate::error::VerifyError;
use alloc::collections::BTreeSet;

/// R4: the tx must be mined at a height strictly after `lock_height`, the Monero
/// height snapshotted when the order was locked.
pub fn check_r4_mined_after_lock(lock_height: u64, mined_height: u64) -> Result<(), VerifyError> {
    if mined_height > lock_height {
        Ok(())
    } else {
        Err(VerifyError::TooOld {
            lock_height,
            mined_height,
        })
    }
}

/// Set of txids already bound to an order (backed by a `StableBTreeSet` in the canister).
pub trait UsedTxids {
    fn contains_txid(&self, txid: &[u8; 32]) -> bool;
}

impl UsedTxids for BTreeSet<[u8; 32]> {
    fn contains_txid(&self, txid: &[u8; 32]) -> bool {
        self.contains(txid)
    }
}

/// R5: the txid must not have been used by any other order.
pub fn check_r5_txid_unused<S: UsedTxids + ?Sized>(
    txid: &[u8; 32],
    used: &S,
) -> Result<(), VerifyError> {
    if used.contains_txid(txid) {
        Err(VerifyError::TxidReused)
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn r4_requires_strictly_later_height() {
        assert!(check_r4_mined_after_lock(100, 101).is_ok());
        assert_eq!(
            check_r4_mined_after_lock(100, 100),
            Err(VerifyError::TooOld {
                lock_height: 100,
                mined_height: 100
            })
        );
        assert!(check_r4_mined_after_lock(100, 99).is_err());
    }

    #[test]
    fn r5_rejects_known_txid() {
        let mut used = BTreeSet::new();
        used.insert([7u8; 32]);
        assert_eq!(
            check_r5_txid_unused(&[7u8; 32], &used),
            Err(VerifyError::TxidReused)
        );
        assert!(check_r5_txid_unused(&[8u8; 32], &used).is_ok());
    }
}
