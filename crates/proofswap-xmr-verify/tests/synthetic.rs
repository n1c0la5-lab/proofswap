//! End-to-end tests on synthetic vectors. See `common/mod.rs` for why these are
//! circular and what they can and cannot show.

mod common;

use common::*;
use proofswap_xmr_verify::{
    compute_txid, parse_out_proof, proof_message, verify_payment, AddressError, PaymentClaim,
    ProofErrorKind, Unsupported, VerifyError,
};

const CANISTER: &str = "ryjl3-tyaaa-aaaaa-aaaba-cai";
const XMR: u64 = 1_000_000_000_000;

fn msg(order: u64) -> String {
    proof_message(CANISTER, order).unwrap()
}

fn verify(
    tx: &BuiltTx,
    address: &str,
    message: &str,
    proof: &str,
    min: u64,
) -> Result<u64, VerifyError> {
    verify_payment(&PaymentClaim {
        txid: tx.txid,
        tx_blob: &tx.blob,
        payee_address: address,
        message,
        proof,
        min_amount: min,
    })
    .map(|v| v.received)
}

/// Standard payee, 1.5 XMR to the payee plus change to the payer.
fn standard_case(label: &str) -> (BuiltTx, Recipient, Recipient) {
    let payee = Recipient::standard(&format!("{label}/payee"));
    let payer = Recipient::standard(&format!("{label}/payer"));
    let tx = build_tx(&TxSpec::new(
        label,
        vec![
            Dest {
                to: payer.clone(),
                amount: 7 * XMR,
            },
            Dest {
                to: payee.clone(),
                amount: 3 * XMR / 2,
            },
        ],
    ));
    (tx, payee, payer)
}

// ---------------------------------------------------------------- positive

#[test]
fn standard_address_accepts_and_reports_amount_and_index() {
    let (tx, payee, _) = standard_case("std");
    let m = msg(1);
    let proof = get_tx_proof(&tx, &payee, &m, 2);
    let v = verify_payment(&PaymentClaim {
        txid: tx.txid,
        tx_blob: &tx.blob,
        payee_address: &payee.address(),
        message: &m,
        proof: &proof,
        min_amount: 3 * XMR / 2,
    })
    .unwrap();
    assert_eq!(v.received, 3 * XMR / 2);
    assert_eq!(v.outputs.len(), 1);
    assert_eq!(v.outputs[0].index, 1);
}

#[test]
fn txid_is_recomputed_from_blob() {
    let (tx, _, _) = standard_case("txid");
    assert_eq!(compute_txid(&tx.blob).unwrap(), tx.txid);
}

#[test]
fn subaddress_single_destination_accepts() {
    // One subaddress destination, no additional keys: R = r·D.
    let payee = Recipient::subaddress("sub1/payee");
    let tx = build_tx(&TxSpec::new(
        "sub1",
        vec![Dest {
            to: payee.clone(),
            amount: 2 * XMR,
        }],
    ));
    let m = msg(2);
    let proof = get_tx_proof(&tx, &payee, &m, 2);
    assert_eq!(
        verify(&tx, &payee.address(), &m, &proof, 2 * XMR),
        Ok(2 * XMR)
    );
}

#[test]
fn subaddress_with_additional_keys_accepts_although_other_entries_fail() {
    // Subaddress payee + standard change: Monero uses additional tx keys. The proof
    // entry for the main key and for the change output do not verify for this
    // address; acceptance needs only one valid entry (as in wallet2).
    let payee = Recipient::subaddress("sub2/payee");
    let other = Recipient::subaddress("sub2/other");
    let change = Recipient::standard("sub2/change");
    let mut spec = TxSpec::new(
        "sub2",
        vec![
            Dest {
                to: change,
                amount: XMR,
            },
            Dest {
                to: other,
                amount: 5 * XMR,
            },
            Dest {
                to: payee.clone(),
                amount: 4 * XMR,
            },
        ],
    );
    spec.additional_keys = true;
    let tx = build_tx(&spec);
    let m = msg(3);
    let proof = get_tx_proof(&tx, &payee, &m, 2);
    assert_eq!(parse_out_proof(&proof).unwrap().entries.len(), 4);
    assert_eq!(
        verify(&tx, &payee.address(), &m, &proof, 4 * XMR),
        Ok(4 * XMR)
    );
}

#[test]
fn standard_address_in_tx_with_additional_keys_accepts() {
    let payee = Recipient::standard("mix/payee");
    let sub = Recipient::subaddress("mix/sub");
    let mut spec = TxSpec::new(
        "mix",
        vec![
            Dest {
                to: sub,
                amount: XMR,
            },
            Dest {
                to: payee.clone(),
                amount: 2 * XMR,
            },
        ],
    );
    spec.additional_keys = true;
    let tx = build_tx(&spec);
    let m = msg(4);
    let proof = get_tx_proof(&tx, &payee, &m, 2);
    assert_eq!(
        verify(&tx, &payee.address(), &m, &proof, 2 * XMR),
        Ok(2 * XMR)
    );
}

#[test]
fn two_outputs_to_payee_are_summed() {
    let payee = Recipient::standard("sum/payee");
    let tx = build_tx(&TxSpec::new(
        "sum",
        vec![
            Dest {
                to: payee.clone(),
                amount: XMR,
            },
            Dest {
                to: Recipient::standard("sum/x"),
                amount: XMR,
            },
            Dest {
                to: payee.clone(),
                amount: 2 * XMR,
            },
        ],
    ));
    let m = msg(5);
    let proof = get_tx_proof(&tx, &payee, &m, 2);
    assert_eq!(
        verify(&tx, &payee.address(), &m, &proof, 3 * XMR),
        Ok(3 * XMR)
    );
}

#[test]
fn outputs_without_view_tag_accepted() {
    let payee = Recipient::standard("notag/payee");
    let mut spec = TxSpec::new(
        "notag",
        vec![Dest {
            to: payee.clone(),
            amount: XMR,
        }],
    );
    spec.view_tags = false;
    let tx = build_tx(&spec);
    let m = msg(6);
    let proof = get_tx_proof(&tx, &payee, &m, 2);
    assert_eq!(verify(&tx, &payee.address(), &m, &proof, XMR), Ok(XMR));
}

// ---------------------------------------------------------------- negative: proof / message / address

#[test]
fn wrong_message_rejected() {
    let (tx, payee, _) = standard_case("wm");
    let proof = get_tx_proof(&tx, &payee, &msg(7), 2);
    let r = verify(&tx, &payee.address(), &msg(8), &proof, 1);
    assert_eq!(r, Err(VerifyError::InvalidProof));
    // another canister, same order id
    let other = proof_message("aaaaa-aa", 7).unwrap();
    assert_eq!(
        verify(&tx, &payee.address(), &other, &proof, 1),
        Err(VerifyError::InvalidProof)
    );
}

#[test]
fn wrong_address_rejected() {
    let (tx, payee, payer) = standard_case("wa");
    let m = msg(9);
    let proof = get_tx_proof(&tx, &payee, &m, 2);
    let stranger = Recipient::standard("wa/stranger");
    assert_eq!(
        verify(&tx, &stranger.address(), &m, &proof, 1),
        Err(VerifyError::InvalidProof)
    );
    // The payer's address also receives an output (change), but this proof was made
    // for the payee, so it must not verify for the payer.
    assert_eq!(
        verify(&tx, &payer.address(), &m, &proof, 1),
        Err(VerifyError::InvalidProof)
    );
}

#[test]
fn proof_for_other_address_cannot_claim_payee_outputs() {
    // A valid proof for the payer's change, presented against the payee address.
    let (tx, payee, payer) = standard_case("swap");
    let m = msg(10);
    let proof_payer = get_tx_proof(&tx, &payer, &m, 2);
    assert_eq!(
        verify(&tx, &payer.address(), &m, &proof_payer, 7 * XMR),
        Ok(7 * XMR)
    );
    assert_eq!(
        verify(&tx, &payee.address(), &m, &proof_payer, 1),
        Err(VerifyError::InvalidProof)
    );
}

#[test]
fn v1_proof_rejected_with_own_error() {
    let (tx, payee, _) = standard_case("v1");
    let m = msg(11);
    let proof = get_tx_proof(&tx, &payee, &m, 1);
    assert!(proof.starts_with("OutProofV1"));
    assert_eq!(
        verify(&tx, &payee.address(), &m, &proof, 1),
        Err(VerifyError::ProofV1)
    );
}

#[test]
fn v1_signature_under_v2_header_rejected() {
    // Domain separation: a V1 challenge relabelled as V2 must not verify.
    let (tx, payee, _) = standard_case("v1as2");
    let m = msg(12);
    let proof = get_tx_proof(&tx, &payee, &m, 1).replacen("OutProofV1", "OutProofV2", 1);
    assert_eq!(
        verify(&tx, &payee.address(), &m, &proof, 1),
        Err(VerifyError::InvalidProof)
    );
}

#[test]
fn inproof_and_garbage_rejected() {
    let (tx, payee, _) = standard_case("garbage");
    let m = msg(13);
    let proof = get_tx_proof(&tx, &payee, &m, 2);
    for bad in [
        proof.replacen("OutProofV2", "InProofV2", 1),
        proof.replacen("OutProofV2", "OutProofV3", 1),
        proof[..proof.len() - 1].to_string(),
        "OutProofV2".to_string(),
    ] {
        assert_eq!(
            verify(&tx, &payee.address(), &m, &bad, 1),
            Err(VerifyError::ProofFormat),
            "{bad}"
        );
    }
}

#[test]
fn tampered_signature_rejected() {
    let (tx, payee, _) = standard_case("tsig");
    let m = msg(14);
    let proof = get_tx_proof(&tx, &payee, &m, 2);
    let mut p = parse_out_proof(&proof).unwrap();
    // flip a bit of r (keeps it a canonical scalar)
    p.entries[0].r[0] ^= 1;
    let mut s = String::from("OutProofV2");
    for e in &p.entries {
        s.push_str(&proofswap_xmr_verify::base58::encode(&e.shared_secret));
        let mut sig = e.c.to_vec();
        sig.extend_from_slice(&e.r);
        s.push_str(&proofswap_xmr_verify::base58::encode(&sig));
    }
    assert_eq!(
        verify(&tx, &payee.address(), &m, &s, 1),
        Err(VerifyError::InvalidProof)
    );
}

#[test]
fn proof_entry_count_must_match_tx_keys() {
    let (tx, payee, _) = standard_case("count");
    let m = msg(15);
    let proof = get_tx_proof(&tx, &payee, &m, 2);
    let doubled = format!("{proof}{}", &proof["OutProofV2".len()..]);
    assert_eq!(
        verify(&tx, &payee.address(), &m, &doubled, 1),
        Err(VerifyError::ProofEntryCount {
            proof: 2,
            tx_keys: 1
        })
    );
}

#[test]
fn subaddress_proof_against_standard_key_type_rejected() {
    let payee = Recipient::subaddress("kt1/payee");
    let tx = build_tx(&TxSpec::new(
        "kt1",
        vec![Dest {
            to: payee.clone(),
            amount: XMR,
        }],
    ));
    let m = msg(16);
    let proof = get_tx_proof(&tx, &payee, &m, 2);
    assert_eq!(verify(&tx, &payee.address(), &m, &proof, XMR), Ok(XMR));
    // same keys, encoded with the standard prefix (24) instead of 36
    let as_standard = payee.with_flipped_kind().address();
    assert_eq!(
        verify(&tx, &as_standard, &m, &proof, 1),
        Err(VerifyError::InvalidProof)
    );
}

#[test]
fn standard_proof_against_subaddress_key_type_rejected() {
    let (tx, payee, _) = standard_case("kt2");
    let m = msg(17);
    let proof = get_tx_proof(&tx, &payee, &m, 2);
    let as_sub = payee.with_flipped_kind().address();
    assert_eq!(
        verify(&tx, &as_sub, &m, &proof, 1),
        Err(VerifyError::InvalidProof)
    );
}

#[test]
fn mainnet_testnet_integrated_addresses_rejected() {
    let (tx, payee, _) = standard_case("net");
    let m = msg(18);
    let proof = get_tx_proof(&tx, &payee, &m, 2);
    for (prefix, err) in [
        (MAINNET_STD, AddressError::Mainnet),
        (42, AddressError::Mainnet),
        (TESTNET_STD, AddressError::Testnet),
        (STAGENET_INTEGRATED, AddressError::Integrated),
        (99, AddressError::UnknownPrefix(99)),
    ] {
        let addr = payee.address_with_prefix(prefix);
        assert_eq!(
            verify(&tx, &addr, &m, &proof, 1),
            Err(VerifyError::Address(err)),
            "prefix {prefix}"
        );
    }
}

#[test]
fn unverified_proof_entry_yields_no_derivation() {
    // Attack: the tx creator adds an output built from an arbitrary point D0
    // (derivation 8·D0, spend key of the payee) and puts D0 into proof entry 0,
    // whose signature cannot verify. Entry 3 (the real subaddress output) verifies,
    // so the proof passes the "at least one entry" rule. The forged output must
    // not count: only verified entries may yield derivations (wallet2 uses a null
    // derivation for them).
    let payee = Recipient::subaddress("unv/payee");
    let d0 = curve25519_dalek::edwards::EdwardsPoint::mul_base(&scalar("unv/d0"));
    let mut spec = TxSpec::new(
        "unv",
        vec![
            Dest {
                to: Recipient::standard("unv/change"),
                amount: XMR,
            },
            Dest {
                to: payee.clone(),
                amount: 9 * XMR,
            },
            Dest {
                to: payee.clone(),
                amount: XMR,
            },
        ],
    );
    spec.additional_keys = true;
    spec.forced_derivation = vec![(1, d0)];
    let tx = build_tx(&spec);
    let m = msg(30);
    let honest = get_tx_proof(&tx, &payee, &m, 2);
    let mut p = parse_out_proof(&honest).unwrap();
    p.entries[0].shared_secret = pt(&d0);
    let mut forged = String::from("OutProofV2");
    for e in &p.entries {
        forged.push_str(&proofswap_xmr_verify::base58::encode(&e.shared_secret));
        let mut sig = e.c.to_vec();
        sig.extend_from_slice(&e.r);
        forged.push_str(&proofswap_xmr_verify::base58::encode(&sig));
    }
    // only output 2 (1 XMR) is proven, not the forged 9 XMR at index 1
    assert_eq!(verify(&tx, &payee.address(), &m, &forged, 1), Ok(XMR));
    assert_eq!(
        verify(&tx, &payee.address(), &m, &forged, 9 * XMR),
        Err(VerifyError::InsufficientAmount {
            got: XMR,
            need: 9 * XMR
        })
    );
}

// ---------------------------------------------------------------- negative: amount / tx

#[test]
fn amount_below_order_rejected() {
    let (tx, payee, _) = standard_case("amt");
    let m = msg(19);
    let proof = get_tx_proof(&tx, &payee, &m, 2);
    assert_eq!(
        verify(&tx, &payee.address(), &m, &proof, 3 * XMR / 2 + 1),
        Err(VerifyError::InsufficientAmount {
            got: 3 * XMR / 2,
            need: 3 * XMR / 2 + 1
        })
    );
    assert!(
        VerifyError::InsufficientAmount { got: 1, need: 2 }.proof_error()
            == ProofErrorKind::InsufficientAmount { got: 1, need: 2 }
    );
}

#[test]
fn tampered_encrypted_amount_fails_commitment() {
    // Raise the decrypted amount by flipping a high bit of the encrypted amount.
    // The commitment no longer opens, so the output counts 0.
    let (mut tx, payee, _) = standard_case("ecdh");
    tx.blob[tx.ecdh_offset[1] + 5] ^= 0x01;
    tx.txid = compute_txid(&tx.blob).unwrap();
    let m = msg(20);
    let proof = get_tx_proof(&tx, &payee, &m, 2);
    assert_eq!(
        verify(&tx, &payee.address(), &m, &proof, 1),
        Err(VerifyError::InsufficientAmount { got: 0, need: 1 })
    );
}

#[test]
fn wrong_view_tag_skips_output() {
    let (mut tx, payee, _) = standard_case("vtag");
    let off = tx.view_tag_offset[1].unwrap();
    tx.blob[off] ^= 0xff;
    tx.txid = compute_txid(&tx.blob).unwrap();
    let m = msg(21);
    let proof = get_tx_proof(&tx, &payee, &m, 2);
    assert_eq!(
        verify(&tx, &payee.address(), &m, &proof, 1),
        Err(VerifyError::InsufficientAmount { got: 0, need: 1 })
    );
}

#[test]
fn unlock_time_rejected() {
    let payee = Recipient::standard("lock/payee");
    let mut spec = TxSpec::new(
        "lock",
        vec![Dest {
            to: payee.clone(),
            amount: XMR,
        }],
    );
    spec.unlock_time = 2_000_000;
    let tx = build_tx(&spec);
    let m = msg(22);
    let proof = get_tx_proof(&tx, &payee, &m, 2);
    assert_eq!(
        verify(&tx, &payee.address(), &m, &proof, 1),
        Err(VerifyError::UnlockTimeSet {
            unlock_time: 2_000_000
        })
    );
}

#[test]
fn unsupported_tx_types_rejected() {
    let payee = Recipient::standard("types/payee");
    let m = msg(23);
    for (rct, version, coinbase, want) in [
        (5u8, 2u64, false, Unsupported::RctType(5)),
        (0, 2, false, Unsupported::RctType(0)),
        (4, 2, false, Unsupported::RctType(4)),
        (6, 1, false, Unsupported::Version(1)),
        (6, 2, true, Unsupported::Coinbase),
    ] {
        let mut spec = TxSpec::new(
            "types",
            vec![Dest {
                to: payee.clone(),
                amount: XMR,
            }],
        );
        spec.rct_type = rct;
        spec.version = version;
        spec.coinbase = coinbase;
        let tx = build_tx(&spec);
        let proof = get_tx_proof(&tx, &payee, &m, 2);
        assert_eq!(
            verify(&tx, &payee.address(), &m, &proof, 1),
            Err(VerifyError::UnsupportedTx(want)),
            "rct {rct} v{version} coinbase {coinbase}"
        );
    }
}

#[test]
fn txid_not_matching_blob_rejected() {
    let (tx, payee, _) = standard_case("tm");
    let m = msg(24);
    let proof = get_tx_proof(&tx, &payee, &m, 2);
    // 1) claimed txid of a different transaction
    let (other, _, _) = standard_case("tm-other");
    let r = verify_payment(&PaymentClaim {
        txid: other.txid,
        tx_blob: &tx.blob,
        payee_address: &payee.address(),
        message: &m,
        proof: &proof,
        min_amount: 1,
    });
    assert_eq!(r, Err(VerifyError::TxidMismatch { computed: tx.txid }));
    // 2) node alters a byte in the prunable part, claimed txid stays the real one
    let mut forged = tx.blob.clone();
    let last = forged.len() - 1;
    forged[last] ^= 1;
    let r = verify_payment(&PaymentClaim {
        txid: tx.txid,
        tx_blob: &forged,
        payee_address: &payee.address(),
        message: &m,
        proof: &proof,
        min_amount: 1,
    });
    assert!(matches!(r, Err(VerifyError::TxidMismatch { .. })), "{r:?}");
}

#[test]
fn trailing_or_truncated_blob_rejected() {
    let (tx, _, _) = standard_case("trail");
    let mut longer = tx.blob.clone();
    longer.push(0);
    assert_eq!(
        compute_txid(&longer),
        Err(VerifyError::TxMalformed("trailing bytes"))
    );
    for cut in [
        1,
        10,
        tx.blob.len() - tx.base_end,
        tx.blob.len() - tx.prefix_end + 1,
    ] {
        assert!(
            compute_txid(&tx.blob[..tx.blob.len() - cut]).is_err(),
            "cut {cut}"
        );
    }
}
