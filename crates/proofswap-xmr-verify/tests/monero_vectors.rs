//! Tests against data produced by Monero itself (not circular).
//!
//! - `data/monero-crypto-tests.txt`: excerpt of `tests/crypto/tests.txt`, Monero
//!   v0.18.5.4 (BSD-3-Clause, see `LICENSE-MONERO`).
//! - `data/monero-bulletproof-txs.txt`: transaction blobs from
//!   `tests/unit_tests/bulletproofs.cpp`, same tag.
//! - Addresses with known network and type from
//!   `tests/functional_tests/validate_address.py`, same tag.

use proofswap_xmr_verify::crypto::{
    decode_point, decode_scalar, derive_public_key, derive_view_tag, generate_key_derivation,
    secret_key_to_public_key,
};
use proofswap_xmr_verify::hash::hash_to_scalar;
use proofswap_xmr_verify::{
    decode_hex, parse_stagenet_address, parse_transaction, AddressError, AddressKind, Unsupported,
    VerifyError,
};

const CRYPTO_TESTS: &str = include_str!("data/monero-crypto-tests.txt");
const BP_TXS: &str = include_str!("data/monero-bulletproof-txs.txt");

fn h32(s: &str) -> [u8; 32] {
    decode_hex(s).unwrap().try_into().unwrap()
}

fn lines(cmd: &str) -> Vec<Vec<&'static str>> {
    let v: Vec<Vec<&str>> = CRYPTO_TESTS
        .lines()
        .map(|l| l.split(' ').collect::<Vec<_>>())
        .filter(|f| f[0] == cmd)
        .collect();
    assert!(!v.is_empty(), "no vectors for {cmd}");
    v
}

#[test]
fn generate_key_derivation_matches_monero() {
    let v = lines("generate_key_derivation");
    for f in &v {
        let got = generate_key_derivation(&h32(f[1]), &h32(f[2]));
        match f[3] {
            "true" => assert_eq!(got, Some(h32(f[4])), "{f:?}"),
            _ => assert_eq!(got, None, "{f:?}"),
        }
    }
    assert_eq!(v.len(), 272);
}

#[test]
fn derive_public_key_matches_monero() {
    let v = lines("derive_public_key");
    for f in &v {
        let got = derive_public_key(&h32(f[1]), f[2].parse().unwrap(), &h32(f[3]));
        match f[4] {
            "true" => assert_eq!(got, Some(h32(f[5])), "{f:?}"),
            _ => assert_eq!(got, None, "{f:?}"),
        }
    }
    assert_eq!(v.len(), 272);
}

#[test]
fn derive_view_tag_matches_monero() {
    let v = lines("derive_view_tag");
    for f in &v {
        let tag = decode_hex(f[3]).unwrap();
        assert_eq!(
            derive_view_tag(&h32(f[1]), f[2].parse().unwrap()),
            tag[0],
            "{f:?}"
        );
    }
    assert_eq!(v.len(), 70);
}

#[test]
fn hash_to_scalar_matches_monero() {
    let v = lines("hash_to_scalar");
    for f in &v {
        // "x" encodes empty input (tests/io.h)
        let data = if f[1] == "x" {
            Vec::new()
        } else {
            decode_hex(f[1]).unwrap()
        };
        assert_eq!(hash_to_scalar(&[&data]).to_bytes(), h32(f[2]), "{f:?}");
    }
    assert_eq!(v.len(), 256);
}

#[test]
fn secret_key_to_public_key_matches_monero() {
    let v = lines("secret_key_to_public_key");
    for f in &v {
        let got = secret_key_to_public_key(&h32(f[1]));
        match f[2] {
            "true" => assert_eq!(got, Some(h32(f[3])), "{f:?}"),
            _ => assert_eq!(got, None, "{f:?}"),
        }
    }
    assert_eq!(v.len(), 272);
}

#[test]
fn check_key_matches_monero() {
    let v = lines("check_key");
    for f in &v {
        assert_eq!(decode_point(&h32(f[1])).is_some(), f[2] == "true", "{f:?}");
    }
    assert_eq!(v.len(), 372);
}

#[test]
fn check_scalar_matches_monero() {
    let v = lines("check_scalar");
    for f in &v {
        assert_eq!(decode_scalar(&h32(f[1])).is_some(), f[2] == "true", "{f:?}");
    }
    assert_eq!(v.len(), 337);
}

#[test]
fn real_bulletproof_txs_parse_until_rct_type_and_are_rejected() {
    let blobs: Vec<&str> = BP_TXS.lines().filter(|l| !l.starts_with('#')).collect();
    assert_eq!(blobs.len(), 8);
    for b in blobs {
        let blob = decode_hex(b).unwrap();
        // The prefix (inputs, outputs, extra) parses; the type is BP (3) or BP2 (4).
        match parse_transaction(&blob) {
            Err(VerifyError::UnsupportedTx(Unsupported::RctType(t))) => {
                assert!(t == 3 || t == 4, "type {t}")
            }
            other => panic!("expected UnsupportedTx(RctType), got {other:?}"),
        }
    }
}

const ADDRS: &[(&str, &str, &str)] = &[
    ("mainnet", "", "42ey1afDFnn4886T7196doS9GPMzexD9gXpsZJDwVjeRVdFCSoHnv7KPbBeGpzJBzHRCAs9UxqeoyFQMYbqSWYTfJJQAWDm"),
    ("mainnet", "", "44Kbx4sJ7JDRDV5aAhLJzQCjDz2ViLRduE3ijDZu3osWKBjMGkV1XPk4pfDUMqt1Aiezvephdqm6YD19GKFD9ZcXVUTp6BW"),
    ("testnet", "", "9ujeXrjzf7bfeK3KZdCqnYaMwZVFuXemPU8Ubw335rj2FN1CdMiWNyFV3ksEfMFvRp9L9qum5UxkP5rN9aLcPxbH1au4WAB"),
    ("stagenet", "", "53teqCAESLxeJ1REzGMAat1ZeHvuajvDiXqboEocPaDRRmqWoVPzy46GLo866qRFjbNhfkNckyhST3WEvBviDwpUDd7DSzB"),
    ("mainnet", "i", "4BxSHvcgTwu25WooY4BVmgdcKwZu5EksVZSZkDd6ooxSVVqQ4ubxXkhLF6hEqtw96i9cf3cVfLw8UWe95bdDKfRQeYtPwLm1Jiw7AKt2LY"),
    ("mainnet", "s", "8AsN91rznfkBGTY8psSNkJBg9SZgxxGGRUhGwRptBhgr5XSQ1XzmA9m8QAnoxydecSh5aLJXdrgXwTDMMZ1AuXsN1EX5Mtm"),
    ("mainnet", "s", "86kKnBKFqzCLxtK1Jmx2BkNBDBSMDEVaRYMMyVbeURYDWs8uNGDZURKCA5yRcyMxHzPcmCf1q2fSdhQVcaKsFrtGRsdGfNk"),
    ("testnet", "i", "AApMA1VuhiCaHzr5X2KXi2Zc9oJ3VaGjkfChxxpRpxkyKf1NetvbRbQTbFMrGkr85DjnEH7JsBaoUFsgKwZnmtnVWnoB8MDotCsLb7eWwz"),
    ("testnet", "s", "BdKg9udkvckC5T58a8Nmtb6BNsgRAxs7uA2D49sWNNX5HPW5Us6Wxu8QMXrnSx3xPBQQ2iu9kwEcRGAoiz6EPmcZKbF62GS"),
    ("testnet", "s", "BcFvPa3fT4gVt5QyRDe5Vv7VtUFao9ci8NFEy3r254KF7R1N2cNB5FYhGvrHbMStv4D6VDzZ5xtxeKV8vgEPMnDcNFuwZb9"),
    ("stagenet", "i", "5K8mwfjumVseCcQEjNbf59Um6R9NfVUNkHTLhhPCmNvgDLVS88YW5tScnm83rw9mfgYtchtDDTW5jEfMhygi27j1QYphX38hg6m4VMtN29"),
    ("stagenet", "s", "73LhUiix4DVFMcKhsPRG51QmCsv8dYYbL6GcQoLwEEFvPvkVvc7BhebfA4pnEFF9Lq66hwvLqBvpHjTcqvpJMHmmNjPPBqa"),
    ("stagenet", "s", "7A1Hr63MfgUa8pkWxueD5xBqhQczkusYiCMYMnJGcGmuQxa7aDBxN1G7iCuLCNB3VPeb2TW7U9FdxB27xKkWKfJ8VhUZthF"),
    ("mainnet", "s", "888tNkZrPN6JsEgekjMnABU4TBzc2Dt29EPAvkRxbANsAnjyPbb3iQ1YBRk1UXcdRsiKc9dhwMVgN5S9cQUiyoogDavup3H"),
];

#[test]
fn monero_addresses_are_classified_by_network() {
    for (net, kind, addr) in ADDRS {
        let got = parse_stagenet_address(addr);
        match (*net, *kind) {
            ("mainnet", _) => assert_eq!(got, Err(AddressError::Mainnet), "{addr}"),
            ("testnet", _) => assert_eq!(got, Err(AddressError::Testnet), "{addr}"),
            ("stagenet", "i") => assert_eq!(got, Err(AddressError::Integrated), "{addr}"),
            ("stagenet", "s") => assert_eq!(got.unwrap().kind, AddressKind::Subaddress, "{addr}"),
            ("stagenet", "") => assert_eq!(got.unwrap().kind, AddressKind::Standard, "{addr}"),
            _ => unreachable!(),
        }
    }
}

#[test]
fn monero_bad_addresses_are_rejected() {
    // from validate_address.py: last character changed -> checksum mismatch
    assert_eq!(
        parse_stagenet_address(
            "42ey1afDFnn4886T7196doS9GPMzexD9gXpsZJDwVjeRVdFCSoHnv7KPbBeGpzJBzHRCAs9UxqeoyFQMYbqSWYTfJJQAWD9"
        ),
        Err(AddressError::Checksum)
    );
    for bad in ["", "a", " ", "@", "42ey"] {
        assert!(parse_stagenet_address(bad).is_err(), "{bad:?}");
    }
}
