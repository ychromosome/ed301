use crate::{
    PublicKey, SecretKey, SharedSecret, X301Error, X301KeyGenError, keygen, public_from_secret,
    shared_secret, validate_public_encoding,
    x301::{BASE_U_BYTES, zero_scalar_ladder_for_test},
};
use serde_json::Value;
use std::{cell::Cell, vec::Vec};
use zeroize::{Zeroize, ZeroizeOnDrop};

std::thread_local! {
    static ROUNDS: Cell<usize> = const { Cell::new(0) };
    static STATE_DROPS: Cell<usize> = const { Cell::new(0) };
    static PANIC_AFTER_STATE: Cell<bool> = const { Cell::new(false) };
}

pub(crate) fn count_round() {
    ROUNDS.with(|x| x.set(x.get() + 1));
}
pub(crate) fn count_state_zeroization() {
    STATE_DROPS.with(|x| x.set(x.get() + 1));
}
pub(crate) fn state_failpoint() {
    PANIC_AFTER_STATE.with(|x| {
        assert!(!x.replace(false), "controlled X301 state unwind");
    });
}
fn reset_rounds() {
    ROUNDS.with(|x| x.set(0));
}
fn rounds() -> usize {
    ROUNDS.with(Cell::get)
}
fn corpus() -> Value {
    serde_json::from_str(include_str!("../../../../vectors/x301-v2.json")).unwrap()
}
fn hex(value: &str) -> Vec<u8> {
    assert!(value.len().is_multiple_of(2));
    (0..value.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&value[i..i + 2], 16).unwrap())
        .collect()
}
fn fixed(value: &str) -> [u8; 38] {
    crate::test_support::decode_hex_array(value.as_bytes())
}
fn key_case<'a>(v: &'a Value, id: &str) -> &'a Value {
    v["keys"]
        .as_array()
        .unwrap()
        .iter()
        .find(|x| x["id"] == id)
        .unwrap()
}
fn text<'a>(v: &'a Value, name: &str) -> &'a str {
    v[name].as_str().unwrap()
}

#[test]
fn shared_cross_language_error_precedence() {
    let v: Value = serde_json::from_str(include_str!(
        "../../../../vectors/x301-error-precedence.json"
    ))
    .unwrap();
    let mut count = 0;
    for secret in v["secrets"].as_array().unwrap() {
        for peer in v["peers"].as_array().unwrap() {
            let Some(expected) = secret["error"].as_str().or(peer["error"].as_str()) else {
                continue;
            };
            reset_rounds();
            let error = shared_secret(&hex(text(secret, "hex")), &hex(text(peer, "hex")))
                .err()
                .expect("input must fail");
            assert_eq!(std::format!("{error:?}"), expected);
            assert_eq!(rounds(), 0);
            count += 1;
        }
    }
    assert_eq!(count, 39);
}

#[test]
fn all_gate_b_keys_preserve_raw_import_and_exact_clamp() {
    let v = corpus();
    assert_eq!(v["keys"].as_array().unwrap().len(), 7);
    for case in v["keys"].as_array().unwrap() {
        let raw = fixed(text(case, "secret_hex"));
        let key = SecretKey::from_bytes(&raw).unwrap();
        assert_eq!(key.as_bytes(), &raw);
        assert_eq!(key.clamped_for_test(), &fixed(text(case, "clamped_hex")));
        reset_rounds();
        let public = key.public_key().unwrap();
        assert_eq!(rounds(), 0, "public derivation uses the fixed table");
        let ladder = key
            .shared_secret(&PublicKey::from_bytes(&BASE_U_BYTES).unwrap())
            .unwrap();
        assert_eq!(rounds(), 301, "the ladder oracle still consumes every bit");
        assert_eq!(public.as_bytes(), ladder.as_bytes());
        assert_eq!(public.as_bytes(), &fixed(text(case, "public_hex")));
        assert_eq!(public_from_secret(&raw).unwrap(), public.to_bytes());
        assert_eq!(
            PublicKey::from_bytes(public.as_bytes()).unwrap().to_bytes(),
            public.to_bytes()
        );
    }
}

#[test]
fn all_gate_b_curve_and_twist_evaluations_match() {
    let v = corpus();
    let cases = v["evaluations"].as_array().unwrap();
    assert_eq!(cases.len(), 24);
    assert_eq!(
        cases
            .iter()
            .filter(|c| c["classification"] == "twist")
            .count(),
        8
    );
    for case in cases {
        let key = key_case(&v, text(case, "key"));
        let secret = fixed(text(key, "secret_hex"));
        let public = fixed(text(case, "u_hex"));
        reset_rounds();
        let result = shared_secret(&secret, &public).unwrap();
        assert_eq!(rounds(), 301, "{}", case["id"]);
        assert_eq!(
            result.as_bytes(),
            crate::x301::canonical_shared_for_test(&secret, &public)
                .unwrap()
                .as_bytes()
        );
        assert_eq!(
            result.as_bytes(),
            &fixed(text(case, "result_hex")),
            "{}",
            case["id"]
        );
        assert_eq!(result.as_bytes()[37] & 0xe0, 0);
        assert!(result.as_bytes().iter().any(|b| *b != 0));
    }
}

#[test]
fn fixed_base_matches_full_ladder_for_ten_thousand_raw_secrets() {
    let mut state = 0x4531_5833_3031_5055_u64;
    let base = PublicKey::from_bytes(&BASE_U_BYTES).unwrap();
    for _ in 0..10_000 {
        let mut raw = [0_u8; 38];
        for chunk in raw.chunks_mut(8) {
            let word = crate::test_support::splitmix64(&mut state).to_le_bytes();
            chunk.copy_from_slice(&word[..chunk.len()]);
        }
        let key = SecretKey::from_bytes(&raw).unwrap();
        reset_rounds();
        let fixed = key.public_key().unwrap();
        assert_eq!(rounds(), 0);
        let ladder = key.shared_secret(&base).unwrap();
        assert_eq!(rounds(), 301);
        assert_eq!(fixed.as_bytes(), ladder.as_bytes());
    }
    crate::x301::zero_scalar_fixed_base_for_test();
}

#[test]
fn lazy_ladder_matches_canonical_oracle_for_ten_thousand_random_peers() {
    let mut state = 0x4532_5833_3031_4c41_u64;
    for index in 0..10_000 {
        let mut raw = [0_u8; 38];
        let mut peer = [0_u8; 38];
        for bytes in [&mut raw, &mut peer] {
            for chunk in bytes.chunks_mut(8) {
                let word = crate::test_support::splitmix64(&mut state).to_le_bytes();
                chunk.copy_from_slice(&word[..chunk.len()]);
            }
        }
        // Generate canonical public inputs, without changing the import path.
        peer[37] &= 0x1f;
        if index < 3 {
            peer.fill(0);
            peer[0] = index as u8;
        }
        let public = PublicKey::from_bytes(&peer).unwrap();
        let key = SecretKey::from_bytes(&raw).unwrap();
        reset_rounds();
        let actual = key.shared_secret(&public);
        assert_eq!(rounds(), 301);
        reset_rounds();
        let expected = crate::x301::canonical_shared_for_test(&raw, &peer);
        assert_eq!(rounds(), 301);
        assert_eq!(
            actual.map(|value| *value.as_bytes()),
            expected.map(|value| *value.as_bytes()),
            "sample {index}"
        );
    }
}

#[test]
fn all_gate_b_dh_pairs_match_both_directions_and_prepared_objects() {
    let v = corpus();
    assert_eq!(v["dh"].as_array().unwrap().len(), 4);
    for pair in v["dh"].as_array().unwrap() {
        let a = key_case(&v, text(pair, "a"));
        let b = key_case(&v, text(pair, "b"));
        let a_key = SecretKey::from_bytes(&fixed(text(a, "secret_hex"))).unwrap();
        let b_key = SecretKey::from_bytes(&fixed(text(b, "secret_hex"))).unwrap();
        let a_public = PublicKey::from_bytes(&fixed(text(a, "public_hex"))).unwrap();
        let b_public = PublicKey::from_bytes(&fixed(text(b, "public_hex"))).unwrap();
        let expected = fixed(text(pair, "shared_hex"));
        assert_eq!(
            a_key.shared_secret(&b_public).unwrap().as_bytes(),
            &expected
        );
        assert_eq!(
            b_key.shared_secret(&a_public).unwrap().as_bytes(),
            &expected
        );
    }
}

#[test]
fn all_thirty_three_gate_b_errors_have_the_correct_stage_and_no_output() {
    let v = corpus();
    let cases = v["errors"].as_array().unwrap();
    assert_eq!(cases.len(), 33);
    for case in cases {
        let secret = hex(text(case, "secret_hex"));
        let public = hex(text(case, "u_hex"));
        let expected = match text(case, "stage") {
            "decode-secret" => X301Error::InvalidSecretLength,
            "decode-u" if public.len() != 38 => X301Error::InvalidPublicLength,
            "decode-u" => X301Error::NonCanonicalPublic,
            "result" => X301Error::AllZeroSharedSecret,
            _ => panic!("unexpected vector stage"),
        };
        reset_rounds();
        assert_eq!(
            shared_secret(&secret, &public).err(),
            Some(expected),
            "{}",
            case["id"]
        );
        assert_eq!(
            rounds(),
            if expected == X301Error::AllZeroSharedSecret {
                301
            } else {
                0
            }
        );
        assert_eq!(
            crate::x301::canonical_shared_for_test(&secret, &public).err(),
            Some(expected)
        );
    }
}

#[test]
fn all_sixty_four_weak_aliases_fail_before_u_decoding_or_ladder() {
    let v = corpus();
    let cases = v["weak_secrets"].as_array().unwrap();
    assert_eq!(cases.len(), 64);
    for case in cases {
        let raw = fixed(text(case, "secret_hex"));
        reset_rounds();
        assert_eq!(
            SecretKey::from_bytes(&raw).err(),
            Some(X301Error::WeakSecret)
        );
        assert_eq!(public_from_secret(&raw).err(), Some(X301Error::WeakSecret));
        assert_eq!(
            shared_secret(&raw, &BASE_U_BYTES).err(),
            Some(X301Error::WeakSecret)
        );
        assert_eq!(shared_secret(&raw, &[]).err(), Some(X301Error::WeakSecret));
        assert_eq!(
            shared_secret(&raw, &[0xff; 38]).err(),
            Some(X301Error::WeakSecret)
        );
        assert_eq!(rounds(), 0);
    }
    assert_eq!(
        shared_secret(&[], &[]).err(),
        Some(X301Error::InvalidSecretLength)
    );
}

#[test]
fn keygen_retries_every_weak_alias_but_not_random_source_errors() {
    let v = corpus();
    let weak = v["weak_secrets"].as_array().unwrap();
    let valid = fixed(text(key_case(&v, "ascending"), "secret_hex"));
    let mut calls = 0;
    reset_rounds();
    let generated = keygen(|out| {
        *out = if calls < weak.len() {
            fixed(text(&weak[calls], "secret_hex"))
        } else {
            valid
        };
        calls += 1;
        Ok::<(), ()>(())
    })
    .unwrap();
    assert_eq!(calls, 65);
    assert_eq!(
        rounds(),
        0,
        "key generation uses the fixed-base public path"
    );
    assert_eq!(generated.0.as_bytes(), &valid);
    assert_eq!(
        generated.1.to_bytes(),
        fixed(text(key_case(&v, "ascending"), "public_hex"))
    );
    let mut failed_calls = 0;
    let failed = keygen(|_| {
        failed_calls += 1;
        Err::<(), _>("RNG failed")
    });
    assert_eq!(failed.err(), Some(X301KeyGenError::Random("RNG failed")));
    assert_eq!(failed_calls, 1);
}

#[test]
fn normative_iteration_chain_matches_every_checkpoint_through_1000() {
    let v = corpus();
    let checkpoints = v["iteration"]["checkpoints"].as_array().unwrap();
    let mut k = BASE_U_BYTES;
    let mut u = BASE_U_BYTES;
    for i in 1..=1000 {
        let old = k;
        k = *shared_secret(&k, &u).unwrap().as_bytes();
        u = old;
        if let Some(point) = checkpoints.iter().find(|p| p["count"].as_u64() == Some(i)) {
            assert_eq!(k, fixed(text(point, "k_hex")));
            assert_eq!(u, fixed(text(point, "u_hex")));
        }
    }
}

#[test]
fn leading_zero_scalar_still_visits_all_301_rounds_in_internal_ladder() {
    reset_rounds();
    zero_scalar_ladder_for_test();
    assert_eq!(rounds(), 301);
}

#[test]
fn public_import_is_encoding_only_and_never_normalizes() {
    let zero = [0_u8; 38];
    let mut one = zero;
    one[0] = 1;
    let mut two = zero;
    two[0] = 2;
    for input in [zero, one, two, BASE_U_BYTES] {
        reset_rounds();
        assert_eq!(validate_public_encoding(&input), Ok(()));
        assert_eq!(crate::canonicalize_public_encoding(&input).unwrap(), input);
        assert_eq!(rounds(), 0);
    }
    for mask in [0x20, 0x40, 0x80, 0xe0] {
        let mut invalid = BASE_U_BYTES;
        invalid[37] |= mask;
        assert_eq!(
            crate::canonicalize_public_encoding(&invalid),
            Err(X301Error::NonCanonicalPublic)
        );
    }
}

#[test]
fn secret_owners_zeroize_and_real_ladder_scope_unwinds_safely() {
    fn owner<T: ZeroizeOnDrop>() {}
    owner::<SecretKey>();
    owner::<SharedSecret>();
    assert!(core::mem::needs_drop::<SecretKey>());
    assert!(core::mem::needs_drop::<SharedSecret>());
    let raw = [7_u8; 38];
    let mut key = SecretKey::from_bytes(&raw).unwrap();
    key.zeroize();
    assert_eq!(key.as_bytes(), &[0_u8; 38]);
    assert_eq!(key.clamped_for_test(), &[0_u8; 38]);
    STATE_DROPS.with(|x| x.set(0));
    PANIC_AFTER_STATE.with(|x| x.set(true));
    let outcome = std::panic::catch_unwind(|| shared_secret(&raw, &BASE_U_BYTES));
    assert!(outcome.is_err());
    assert_eq!(STATE_DROPS.with(Cell::get), 1);
    assert!(public_from_secret(&raw).is_ok());
    let mut shared = shared_secret(&raw, &BASE_U_BYTES).unwrap();
    shared.zeroize();
    assert_eq!(shared.as_bytes(), &[0_u8; 38]);
}
