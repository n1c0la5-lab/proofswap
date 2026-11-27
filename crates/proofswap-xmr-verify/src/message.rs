//! The fixed proof message `proofswap:v1:<canister_id>:<order_id>` (SPEC §6.1).

use crate::error::VerifyError;
use alloc::format;
use alloc::string::String;

/// Builds the message the xmr-side must pass to `get_tx_proof`.
///
/// `canister_id` must be the textual principal (lowercase base32 groups separated
/// by `-`). Anything else, in particular `:`, is rejected so the message cannot be
/// made ambiguous.
pub fn proof_message(canister_id: &str, order_id: u64) -> Result<String, VerifyError> {
    let ok = !canister_id.is_empty()
        && canister_id.len() <= 63
        && !canister_id.starts_with('-')
        && !canister_id.ends_with('-')
        && canister_id
            .bytes()
            .all(|b| b.is_ascii_lowercase() || (b'2'..=b'7').contains(&b) || b == b'-');
    if !ok {
        return Err(VerifyError::InvalidMessageInput);
    }
    Ok(format!("proofswap:v1:{canister_id}:{order_id}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_spec_format() {
        assert_eq!(
            proof_message("ryjl3-tyaaa-aaaaa-aaaba-cai", 42).unwrap(),
            "proofswap:v1:ryjl3-tyaaa-aaaaa-aaaba-cai:42"
        );
    }

    #[test]
    fn rejects_separator_and_garbage() {
        for bad in ["", "a:b", "ABC-def", "x y", "-abc", "abc-", "abc1"] {
            assert_eq!(
                proof_message(bad, 1),
                Err(VerifyError::InvalidMessageInput),
                "{bad}"
            );
        }
    }
}
