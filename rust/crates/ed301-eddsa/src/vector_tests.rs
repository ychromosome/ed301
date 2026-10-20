// SPDX-License-Identifier: Apache-2.0
// Adapted v1 test intentions; all parameter-dependent expected bytes come from Gate B.
extern crate std;

use std::{string::String, vec::Vec};

use super::{
    edwards::EdwardsPoint,
    parameters::{HASH_BYTES, PUBLIC_KEY_BYTES, SEED_BYTES, SIGNATURE_BYTES, SIGNATURE_DOMAIN},
    scalar::Scalar,
    signature::{
        Signature, SigningKey, VerifyingKey,
        test_support::{trace, trace_with_context},
    },
    signature_hash::{Domain, challenge_hash, hash_to_scalar},
    validate_public_key, verify, verify_with_context,
};

fn decode_hex(value: &str) -> Vec<u8> {
    assert_eq!(value.len() % 2, 0);
    value
        .as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| (nibble(pair[0]) << 4) | nibble(pair[1]))
        .collect()
}

fn nibble(value: u8) -> u8 {
    match value {
        b'0'..=b'9' => value - b'0',
        b'a'..=b'f' => value - b'a' + 10,
        _ => panic!("invalid fixture hex"),
    }
}

fn array<const N: usize>(value: &str) -> [u8; N] {
    decode_hex(value).try_into().expect("fixture length")
}

fn fixture() -> serde_json::Value {
    serde_json::from_str(include_str!("../../../../vectors/ed301-eddsa-v2.json"))
        .expect("Gate-B vectors parse")
}

fn by_id<'a>(items: &'a [serde_json::Value], id: &str) -> &'a serde_json::Value {
    items
        .iter()
        .find(|item| item["id"] == id)
        .unwrap_or_else(|| panic!("missing fixture id {id}"))
}

#[test]
fn all_positive_vectors_and_intermediates_match() {
    let document = fixture();
    assert_eq!(document["schema"], "Ed301-EdDSA-v2-reference-vectors-1");
    let cases = document["signing"].as_array().expect("signing");
    assert_eq!(cases.len(), 9);
    assert_eq!(
        (SEED_BYTES, PUBLIC_KEY_BYTES, SIGNATURE_BYTES, HASH_BYTES),
        (38, 38, 76, 76)
    );
    for case in cases {
        let seed = array::<38>(case["seed_hex"].as_str().expect("seed"));
        let message = decode_hex(case["message_hex"].as_str().expect("message"));
        let context = decode_hex(case["context_hex"].as_str().expect("context"));
        let expected = &case["trace"];
        let string = |name: &str| expected[name].as_str().expect("trace");
        let actual = trace_with_context(&seed, &message, &context);
        let mut domain = Vec::from(SIGNATURE_DOMAIN.as_slice());
        domain.extend_from_slice(&[0, context.len() as u8]);
        domain.extend_from_slice(&context);
        assert_eq!(domain, decode_hex(string("domain")));
        assert_eq!(actual.expanded_hash, array::<76>(string("expanded_hash")));
        assert_eq!(
            actual.pruned_scalar,
            array::<38>(string("pruned_secret_scalar"))
        );
        assert_eq!(actual.prefix, array::<38>(string("prefix")));
        assert_eq!(actual.public_key, array::<38>(string("public_key")));
        assert_eq!(actual.nonce_hash, array::<76>(string("nonce_hash")));
        assert_eq!(actual.nonce_scalar, array::<38>(string("nonce_scalar")));
        assert_eq!(actual.commitment, array::<38>(string("commitment")));
        assert_eq!(actual.challenge_hash, array::<76>(string("challenge_hash")));
        assert_eq!(
            actual.challenge_scalar,
            array::<38>(string("challenge_scalar"))
        );
        assert_eq!(actual.response, array::<38>(string("response")));
        assert_eq!(actual.signature, array::<76>(string("signature")));
        let key = SigningKey::from_seed(&seed).expect("seed");
        assert_eq!(
            key.verifying_key().expect("public").to_bytes(),
            actual.public_key
        );
        assert_eq!(
            key.sign_with_context(&message, &context)
                .expect("sign")
                .to_bytes(),
            actual.signature
        );
        assert_eq!(
            key.sign_with_context(&message, &context)
                .expect("repeat")
                .to_bytes(),
            actual.signature
        );
        assert!(verify_with_context(
            &actual.public_key,
            &message,
            &context,
            &actual.signature
        ));
    }
}

#[test]
fn frozen_v1_fixture_keys_and_signatures_are_separated_from_v2() {
    let old: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../tests/fixtures/v1/ed301-eddsa-v1.json"
    ))
    .expect("frozen v1");
    let mut count = 0;
    for case in old["cases"]
        .as_array()
        .expect("cases")
        .iter()
        .chain(old["context_cases"].as_array().expect("contexts"))
    {
        let seed = array::<38>(case["seed_hex"].as_str().expect("seed"));
        let message = decode_hex(case["message_hex"].as_str().expect("message"));
        let context = decode_hex(case["context_hex"].as_str().expect("context"));
        let old_public = array::<38>(case["public_key_hex"].as_str().expect("public"));
        let old_signature = array::<76>(case["signature_hex"].as_str().expect("signature"));
        assert!(!verify_with_context(
            &old_public,
            &message,
            &context,
            &old_signature
        ));
        let key = SigningKey::from_seed(&seed).expect("seed");
        let new_public = key.verifying_key().expect("public").to_bytes();
        assert_ne!(new_public, old_public);
        assert!(!verify_with_context(
            &new_public,
            &message,
            &context,
            &old_signature
        ));
        count += 1;
    }
    assert_eq!(count, 7);
}

#[test]
fn native_context_vectors_and_boundaries_match() {
    let seed = [0x42_u8; 38];
    let key = SigningKey::from_seed(&seed).expect("seed");
    let public = key.verifying_key().expect("public").to_bytes();
    for context in [b"".as_slice(), b"a\0b\xff".as_slice(), &[0x5a; 255]] {
        let signature = key
            .sign_with_context(b"message", context)
            .expect("sign")
            .to_bytes();
        assert!(verify_with_context(
            &public, b"message", context, &signature
        ));
        let mut different = context.to_vec();
        different.push(0);
        assert!(!verify_with_context(
            &public, b"message", &different, &signature
        ));
    }
    assert!(key.sign_with_context(b"message", &[0x5a; 256]).is_err());
    let signature = key.sign(b"message").expect("sign").to_bytes();
    assert!(!verify_with_context(
        &public,
        b"message",
        &[0x5a; 256],
        &signature
    ));
}

#[test]
fn complete_point_and_scalar_acceptance_matrices_match() {
    let document = fixture();
    assert_eq!(
        document["point_decoding"].as_array().expect("points").len(),
        15
    );
    for case in document["point_decoding"].as_array().expect("points") {
        let encoded = decode_hex(case["encoded_hex"].as_str().expect("encoding"));
        let exact: Option<&[u8; 38]> = encoded.as_slice().try_into().ok();
        let decoded = exact.is_some_and(|bytes| EdwardsPoint::decode(bytes).is_ok());
        assert_eq!(
            decoded,
            case["accepted"].as_bool().expect("decision"),
            "{}",
            case["id"]
        );
        assert_eq!(
            validate_public_key(&encoded),
            case["id"] == "base",
            "{}",
            case["id"]
        );
        let old = exact.is_some_and(|bytes| {
            EdwardsPoint::decode(bytes).is_ok_and(|point| {
                let table = point.prepare_vartime_table();
                point
                    .is_identity()
                    .not()
                    .and(point.is_prime_subgroup_with_table(&table))
                    .to_bool()
            })
        });
        assert_eq!(
            validate_public_key(&encoded),
            old,
            "old [q] import oracle: {}",
            case["id"]
        );
    }
    for case in document["scalar_decoding"].as_array().expect("scalars") {
        let encoded = array::<38>(case["encoded_hex"].as_str().expect("encoding"));
        assert_eq!(
            Scalar::from_canonical_bytes(&encoded).is_some().to_bool(),
            case["accepted"].as_bool().expect("decision"),
            "{}",
            case["id"]
        );
    }
}

#[test]
fn all_sixty_one_verification_cases_match() {
    let document = fixture();
    let cases = document["verification"].as_array().expect("verification");
    assert_eq!(cases.len(), 61);
    for case in cases {
        let public = decode_hex(case["public_key_hex"].as_str().expect("public"));
        let message = decode_hex(case["message_hex"].as_str().expect("message"));
        let context = decode_hex(case["context_hex"].as_str().expect("context"));
        let signature = decode_hex(case["signature_hex"].as_str().expect("signature"));
        assert_eq!(
            verify_with_context(&public, &message, &context, &signature),
            case["accepted"].as_bool().expect("decision"),
            "{}",
            case["id"]
        );
    }
}

#[test]
fn signing_error_corpus_is_rejected() {
    let document = fixture();
    for case in document["signing_errors"].as_array().expect("errors") {
        let seed = decode_hex(case["seed_hex"].as_str().expect("seed"));
        let message = decode_hex(case["message_hex"].as_str().expect("message"));
        let context = decode_hex(case["context_hex"].as_str().expect("context"));
        assert!(
            super::sign_with_context(&seed, &message, &context).is_err(),
            "{}",
            case["id"]
        );
    }
}

#[test]
fn adding_the_group_order_to_s_is_rejected_as_noncanonical() {
    let document = fixture();
    let order = crate::generated_parameters::PRIME_ORDER_ENCODING;
    for case in document["signing"].as_array().expect("signing") {
        let mut signature = decode_hex(case["trace"]["signature"].as_str().expect("signature"));
        let mut carry = 0_u16;
        for index in 0..38 {
            let sum = signature[38 + index] as u16 + order[index] as u16 + carry;
            signature[38 + index] = sum as u8;
            carry = sum >> 8;
        }
        assert_eq!(carry, 0);
        assert!(Signature::from_bytes(&signature).is_err());
        assert!(!verify_with_context(
            &decode_hex(case["trace"]["public_key"].as_str().expect("public")),
            &decode_hex(case["message_hex"].as_str().expect("message")),
            &decode_hex(case["context_hex"].as_str().expect("context")),
            &signature
        ));
    }
}

#[test]
fn parsers_fail_closed_for_adjacent_lengths() {
    let document = fixture();
    let positive = &document["signing"][0]["trace"];
    let public_key = decode_hex(positive["public_key"].as_str().expect("public"));
    let signature = decode_hex(positive["signature"].as_str().expect("signature"));
    for length in [0_usize, 1, 37, 39, 75, 77, 512] {
        let bytes = std::vec![0_u8; length];
        assert!(VerifyingKey::from_bytes(&bytes).is_err());
        assert!(Signature::from_bytes(&bytes).is_err());
        assert!(!verify(&bytes, b"", &signature));
        assert!(!verify(&public_key, b"", &bytes));
    }
}

#[test]
fn fixture_ids_are_the_expected_stable_set() {
    let document = fixture();
    let ids: Vec<String> = document["signing"]
        .as_array()
        .expect("signing")
        .iter()
        .map(|case| case["id"].as_str().expect("id").into())
        .collect();
    assert_eq!(
        ids,
        [
            "empty",
            "short-ascii",
            "binary",
            "long-binary-4096",
            "context-ascii",
            "context-binary",
            "context-max-255",
            "zero-seed",
            "ones-seed"
        ]
    );
}

fn cofactor_equation(
    public_key: &[u8; 38],
    message: &[u8],
    signature: &[u8; 76],
    doublings: usize,
) -> bool {
    let public = EdwardsPoint::decode_strict_subgroup(public_key).expect("valid test key");
    let commitment_encoding: &[u8; 38] = signature[..38].try_into().expect("R");
    let response_encoding: &[u8; 38] = signature[38..].try_into().expect("S");
    let commitment = EdwardsPoint::decode(commitment_encoding).expect("valid test R");
    let response = Scalar::from_canonical_bytes(response_encoding).expect_copied("valid test S");
    let digest = challenge_hash(Domain::EMPTY, commitment_encoding, public_key, message);
    let challenge = hash_to_scalar(digest);
    let mut left = EdwardsPoint::BASEPOINT.scalar_mul(&response);
    let mut right = commitment.add(public.scalar_mul(&challenge));
    for _ in 0..doublings {
        left = left.double();
        right = right.double();
    }
    left.ct_eq(&right).to_bool()
}

#[test]
fn pure_torsion_commitments_are_accepted_only_by_the_factor_four_language() {
    let seed =
        array::<38>("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425");
    let public_trace = trace(&seed, b"");
    let secret = Scalar::reduce_pruned_le(&public_trace.pruned_scalar);
    let order_two = crate::generated_parameters::ORDER_TWO_ENCODING;
    let order_four = crate::generated_parameters::ORDER_FOUR_ENCODING;
    let mut minus_order_four = order_four;
    minus_order_four[37] ^= 0x80;

    for (label, commitment, factor_one, factor_two) in [
        ("order-two", order_two, false, true),
        ("order-four", order_four, false, false),
        ("minus-order-four", minus_order_four, false, false),
    ] {
        let message = label.as_bytes();
        let digest = challenge_hash(
            Domain::EMPTY,
            &commitment,
            &public_trace.public_key,
            message,
        );
        let challenge = hash_to_scalar(digest);
        let response = challenge.mul(&secret).canonical_bytes();
        let mut signature = [0_u8; 76];
        signature[..38].copy_from_slice(&commitment);
        signature[38..].copy_from_slice(&response[..]);
        assert!(Signature::from_bytes(&signature).is_ok(), "{label} syntax");
        assert_eq!(
            cofactor_equation(&public_trace.public_key, message, &signature, 0),
            factor_one,
            "{label} factor one"
        );
        assert_eq!(
            cofactor_equation(&public_trace.public_key, message, &signature, 1),
            factor_two,
            "{label} factor two"
        );
        assert!(
            cofactor_equation(&public_trace.public_key, message, &signature, 2),
            "{label} factor four"
        );
        assert!(
            verify(&public_trace.public_key, message, &signature),
            "{label}"
        );
    }
}

#[test]
fn mixed_torsion_matrix_distinguishes_factors_one_two_and_four() {
    let seed =
        array::<38>("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425");
    let base = trace(&seed, b"torsion-matrix");
    let secret = Scalar::reduce_pruned_le(&base.pruned_scalar);
    let nonce = Scalar::from_canonical_bytes(&base.nonce_scalar).expect_copied("nonce");
    let prime_commitment = EdwardsPoint::decode(&base.commitment).expect("prime R");
    let identity = EdwardsPoint::IDENTITY;
    let order_two =
        EdwardsPoint::decode(&crate::generated_parameters::ORDER_TWO_ENCODING).expect("T2");
    let order_four =
        EdwardsPoint::decode(&crate::generated_parameters::ORDER_FOUR_ENCODING).expect("T4");
    let minus_order_four = order_four.negate();

    for (label, torsion, expected) in [
        ("identity", identity, [true, true, true]),
        ("order-two", order_two, [false, true, true]),
        ("order-four", order_four, [false, false, true]),
        ("minus-order-four", minus_order_four, [false, false, true]),
    ] {
        let commitment = prime_commitment
            .add(torsion)
            .encode()
            .expect("mixed commitment encoding");
        let digest = challenge_hash(
            Domain::EMPTY,
            &commitment,
            &base.public_key,
            b"torsion-matrix",
        );
        let challenge = hash_to_scalar(digest);
        let secret_response_term = challenge.mul(&secret);
        let response = nonce.add(&secret_response_term).canonical_bytes();
        let mut signature = [0_u8; 76];
        signature[..38].copy_from_slice(&commitment);
        signature[38..].copy_from_slice(&response[..]);
        for (doublings, expected_result) in expected.into_iter().enumerate() {
            assert_eq!(
                cofactor_equation(&base.public_key, b"torsion-matrix", &signature, doublings),
                expected_result,
                "{label} factor {}",
                1 << doublings
            );
        }
        assert!(verify(&base.public_key, b"torsion-matrix", &signature));
    }
}

#[test]
fn point_sign_and_reserved_bit_boundaries_are_explicit() {
    let mut negative_base = crate::generated_parameters::BASE_ENCODING;
    negative_base[37] ^= 0x80;
    assert!(EdwardsPoint::decode_strict_subgroup(&negative_base).is_ok());
    assert!(validate_public_key(&negative_base));

    let order_four_positive = [0_u8; 38];
    let mut order_four_negative = order_four_positive;
    order_four_negative[37] = 0x80;
    assert!(EdwardsPoint::decode(&order_four_positive).is_ok());
    assert!(EdwardsPoint::decode(&order_four_negative).is_ok());

    let mut negative_zero_at_minus_one = crate::generated_parameters::ORDER_TWO_ENCODING;
    negative_zero_at_minus_one[37] |= 0x80;
    assert!(EdwardsPoint::decode(&negative_zero_at_minus_one).is_err());

    for sign in [0_u8, 0x80] {
        let document = fixture();
        let case = by_id(
            document["point_decoding"].as_array().expect("point cases"),
            "nonsquare-x",
        );
        let mut nonsquare = array::<38>(case["encoded_hex"].as_str().expect("point bytes"));
        nonsquare[37] = sign;
        assert!(EdwardsPoint::decode(&nonsquare).is_err());
    }
    for reserved in [0x20_u8, 0x40, 0x60] {
        let mut encoded = [0_u8; 38];
        encoded[0] = 1;
        encoded[37] = reserved;
        assert!(EdwardsPoint::decode(&encoded).is_err());
    }
}

#[test]
fn deterministic_single_bit_mutations_fail_closed() {
    let document = fixture();
    let case = by_id(
        document["signing"].as_array().expect("cases"),
        "short-ascii",
    );
    let public_key = decode_hex(case["trace"]["public_key"].as_str().expect("public key"));
    let message = decode_hex(case["message_hex"].as_str().expect("message"));
    let signature = decode_hex(case["trace"]["signature"].as_str().expect("signature"));

    for index in 0..public_key.len() * 8 {
        let mut changed = public_key.clone();
        changed[index >> 3] ^= 1 << (index & 7);
        assert!(
            !verify(&changed, &message, &signature),
            "public bit {index}"
        );
    }
    for index in 0..signature.len() * 8 {
        let mut changed = signature.clone();
        changed[index >> 3] ^= 1 << (index & 7);
        assert!(
            !verify(&public_key, &message, &changed),
            "signature bit {index}"
        );
    }
    for index in 0..message.len() * 8 {
        let mut changed = message.clone();
        changed[index >> 3] ^= 1 << (index & 7);
        assert!(
            !verify(&public_key, &changed, &signature),
            "message bit {index}"
        );
    }
}

fn add_le(target: &mut [u8], addend: &[u8]) {
    let mut carry = 0_u16;
    for (byte, add) in target.iter_mut().zip(addend) {
        let sum = u16::from(*byte) + u16::from(*add) + carry;
        *byte = sum as u8;
        carry = sum >> 8;
    }
    assert_eq!(carry, 0);
}

// libsodium test/default/sign.c: per-case and trailing checks; the overlap case has
// no safe-Rust equivalent because shared and mutable slices cannot alias.
#[test]
fn libsodium_pattern_sign_kat() {
    let document: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../vectors/ed301-eddsa-v2-sign-kat.json"
    ))
    .expect("sign KAT parses");
    let q = decode_hex(
        by_id(
            fixture()["scalar_decoding"].as_array().expect("scalars"),
            "scalar-q",
        )["encoded_hex"]
            .as_str()
            .expect("q"),
    );
    let cases = document["cases"].as_array().expect("cases");
    assert_eq!(cases.len(), 1024);
    for (i, case) in cases.iter().enumerate() {
        let seed = array::<38>(case["seed"].as_str().expect("seed"));
        let public_key = array::<38>(case["pk"].as_str().expect("pk"));
        let expected = array::<76>(case["sig"].as_str().expect("sig"));
        let message = decode_hex(case["m"].as_str().expect("m"));
        assert_eq!(message.len(), i);
        let key = SigningKey::from_seed(&seed).expect("seed");
        assert_eq!(key.verifying_key().expect("public").to_bytes(), public_key);
        let signature = key.sign(&message).expect("sign").to_bytes();
        assert_eq!(signature, expected, "signature {i}");
        assert!(verify(&public_key, &message, &signature), "verify {i}");

        let mut malleated = signature;
        add_le(&mut malleated[38..], &q);
        assert!(!verify(&public_key, &message, &malleated), "malleable {i}");

        let mut signed = Vec::from(signature.as_slice());
        signed.extend_from_slice(&message);
        signed[i + SIGNATURE_BYTES - 1] = signed[i + SIGNATURE_BYTES - 1].wrapping_add(1);
        assert!(
            !verify(
                &public_key,
                &signed[SIGNATURE_BYTES..],
                &signed[..SIGNATURE_BYTES]
            ),
            "forged {i}"
        );
        assert!(
            !verify(&public_key, &message, &signature[..i % SIGNATURE_BYTES]),
            "short {i}"
        );
    }

    let last = &cases[1023];
    let message = decode_hex(last["m"].as_str().expect("m"));
    let public_key = array::<38>(last["pk"].as_str().expect("pk"));
    let mut signature = array::<76>(last["sig"].as_str().expect("sig"));
    // Bits 300..303 of S lie above every canonical scalar, like bits 253..255 for Ed25519.
    for j in 1_u8..16 {
        signature[75] ^= j << 4;
        assert!(
            !verify(&public_key, &message, &signature),
            "high S bits {j}"
        );
        signature[75] ^= j << 4;
    }
    let mut non_canonical = decode_hex(
        by_id(
            fixture()["point_decoding"].as_array().expect("points"),
            "y-p",
        )["encoded_hex"]
            .as_str()
            .expect("p"),
    );
    add_le(&mut non_canonical, &[9]);
    assert!(!verify(&non_canonical, &message, &signature));
    let mut public = [0_u8; 38];
    assert!(!verify(&public, &message, &signature));
    let mut invalid_r = signature;
    invalid_r[..38].fill(0xff);
    invalid_r[0] = 0xdb;
    assert!(!verify(&public, &message, &invalid_r));
    assert!(!verify(&public_key, &message, &invalid_r));
    for y in [2_u8, 5] {
        public[0] = y;
        assert!(!verify(&public, &message, &signature), "public y={y}");
    }
}

#[test]
fn wycheproof_pattern_verification_cases() {
    let document: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../vectors/ed301-eddsa-v2-wycheproof.json"
    ))
    .expect("Wycheproof-pattern vectors parse");
    let group = &document["testGroups"][0];
    let public_key = decode_hex(group["publicKey"]["pk"].as_str().expect("pk"));
    let tests = group["tests"].as_array().expect("tests");
    assert_eq!(
        tests.len() as u64,
        document["numberOfTests"].as_u64().expect("count")
    );
    for case in tests {
        let message = decode_hex(case["msg"].as_str().expect("msg"));
        let signature = decode_hex(case["sig"].as_str().expect("sig"));
        let valid = match case["result"].as_str().expect("result") {
            "valid" => true,
            "invalid" => false,
            _ => panic!("unexpected vector result"),
        };
        assert_eq!(
            verify(&public_key, &message, &signature),
            valid,
            "tcId {}",
            case["tcId"]
        );
    }
}
