//! Context-bound, one-shot `Ed301-EdDSA-v2` signatures.

#[cfg(test)]
extern crate std;

use crate::{
    edwards::{EdwardsPoint, VartimePointTable},
    parameters::{FIELD_BYTES, PUBLIC_KEY_BYTES, SEED_BYTES, SIGNATURE_BYTES},
    scalar::Scalar,
    secret::{Secret, secret},
    secret_taint::declassify,
    signature_hash::{Domain, challenge_hash, expand_seed, hash_to_scalar, nonce_hash},
};

/// A deterministic key, parse or signing failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SignatureError {
    /// The seed was not exactly 38 bytes.
    InvalidSeedLength,
    /// The public key was not a canonical, nonidentity prime-subgroup point.
    InvalidPublicKey,
    /// The signature length, commitment point or scalar was noncanonical.
    InvalidSignature,
    /// The native context exceeded the RFC 8032 one-octet length bound.
    InvalidContextLength,
    /// A secret-derived invariant or signing self-check failed.
    InternalFailure,
}

/// Owning 38-byte signing seed.
///
/// The owner is deliberately neither `Copy` nor `Clone` and zeroizes its seed
/// on drop. Seed generation remains the caller's CSPRNG responsibility.
pub struct SigningKey {
    seed: Secret<[u8; SEED_BYTES]>,
}

impl SigningKey {
    /// Import an exact 38-byte seed.
    pub fn from_seed(seed: &[u8]) -> Result<Self, SignatureError> {
        let seed: &[u8; SEED_BYTES] = seed
            .try_into()
            .map_err(|_| SignatureError::InvalidSeedLength)?;
        let mut owned = secret([0_u8; SEED_BYTES]);
        owned.copy_from_slice(seed);
        Ok(Self { seed: owned })
    }

    /// Derive the public verification key.
    pub fn verifying_key(&self) -> Result<VerifyingKey, SignatureError> {
        Ok(self.expand()?.verifying_key())
    }

    /// Expand this seed into a reusable, zeroizing signing key.
    ///
    /// Reuse this object when signing more than once.  Expansion hashes the
    /// seed and derives the canonical public point once. Hostile external
    /// public-key input continues to use the strict parser and subgroup test.
    pub fn expand(&self) -> Result<ExpandedSigningKey, SignatureError> {
        ExpandedSigningKey::derive(&self.seed)
    }

    /// Sign one opaque message with the empty native context.
    pub fn sign(&self, message: &[u8]) -> Result<Signature, SignatureError> {
        self.sign_with_context(message, b"")
    }

    /// Sign one opaque message with a native context of at most 255 bytes.
    pub fn sign_with_context(
        &self,
        message: &[u8],
        context: &[u8],
    ) -> Result<Signature, SignatureError> {
        self.expand()?.sign_with_context(message, context)
    }
}

/// Fully validated public key without a verification table.
///
/// Validation is eager; only preparation for repeated verification is deferred.
/// This value contains public state only and does not retain a signing key.
#[derive(Clone)]
pub struct ValidatedPublicKey {
    encoded: [u8; PUBLIC_KEY_BYTES],
    point: EdwardsPoint,
}

impl ValidatedPublicKey {
    /// Parse and fully validate a 38-byte public key without preparing a table.
    ///
    /// The input must be public: running time may depend on its bytes. Secret
    /// derivation and signing use their internally constructed public state
    /// instead of this parser.
    #[inline(never)] // Preserve the public-input boundary for linked-code call-site audits.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, SignatureError> {
        let encoded: &[u8; PUBLIC_KEY_BYTES] = bytes
            .try_into()
            .map_err(|_| SignatureError::InvalidPublicKey)?;
        #[cfg(any(test, feature = "secret-taint-instrumentation"))]
        audit_public_import(encoded);
        // Same acceptance set as `decode_strict_subgroup`: canonical decode,
        // nonidentity, then membership in 4E = E[q]. Both symbols are evaluated.
        let point = EdwardsPoint::decode(encoded).map_err(|_| SignatureError::InvalidPublicKey)?;
        if point.is_identity().to_bool() || !point.is_prime_subgroup_decoded().to_bool() {
            return Err(SignatureError::InvalidPublicKey);
        }
        Ok(Self {
            encoded: *encoded,
            point,
        })
    }

    /// Borrow the canonical public-key bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; PUBLIC_KEY_BYTES] {
        &self.encoded
    }

    /// Build the table used by repeated public verification.
    #[must_use]
    pub fn prepare(&self) -> VerifyingKey {
        VerifyingKey::from_validated_point(self.encoded, self.point)
    }
}

/// Fully validated public verification key with its prepared table.
#[derive(Clone)]
pub struct VerifyingKey {
    encoded: [u8; PUBLIC_KEY_BYTES],
    odd_multiples: VartimePointTable,
}

impl VerifyingKey {
    /// Parse and fully validate a 38-byte public key with public-dependent time.
    /// The input must not contain confidential data.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, SignatureError> {
        Ok(ValidatedPublicKey::from_bytes(bytes)?.prepare())
    }

    /// Return the canonical public-key bytes.
    #[must_use]
    pub const fn to_bytes(&self) -> [u8; PUBLIC_KEY_BYTES] {
        self.encoded
    }

    /// Borrow the canonical public-key bytes without copying prepared state.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; PUBLIC_KEY_BYTES] {
        &self.encoded
    }

    /// Verify a parsed signature over one opaque message.
    #[must_use]
    pub fn verify(&self, message: &[u8], signature: &Signature) -> bool {
        self.verify_with_context(message, b"", signature)
    }

    /// Verify a parsed signature with a native context of at most 255 bytes.
    #[must_use]
    pub fn verify_with_context(
        &self,
        message: &[u8],
        context: &[u8],
        signature: &Signature,
    ) -> bool {
        self.verify_bytes_with_context(message, context, signature.as_bytes())
    }

    /// Parse and verify an exact 76-byte signature over one opaque message.
    ///
    /// This is the preferred boundary for integrations that receive wire
    /// bytes. It parses the commitment and response exactly once without
    /// retaining either arithmetic representation in the public `Signature`.
    #[must_use]
    pub fn verify_bytes(&self, message: &[u8], signature: &[u8]) -> bool {
        self.verify_bytes_with_context(message, b"", signature)
    }

    /// Parse and verify wire bytes with a native context of at most 255 bytes.
    #[must_use]
    pub fn verify_bytes_with_context(
        &self,
        message: &[u8],
        context: &[u8],
        signature: &[u8],
    ) -> bool {
        let Some(domain) = Domain::new(context) else {
            return false;
        };
        let Ok(signature) = ParsedSignature::from_bytes(signature) else {
            return false;
        };
        let digest = challenge_hash(
            domain,
            &signature.commitment_encoding,
            &self.encoded,
            message,
        );
        let challenge = hash_to_scalar(digest);
        let equation = EdwardsPoint::vartime_double_scalar_mul_basepoint(
            &signature.response,
            &challenge,
            &self.odd_multiples,
        )
        .add(signature.commitment.negate())
        .multiply_by_cofactor();
        equation.is_identity().to_bool()
    }

    fn from_validated_point(encoded: [u8; PUBLIC_KEY_BYTES], point: EdwardsPoint) -> Self {
        Self {
            encoded,
            odd_multiples: point.prepare_vartime_table(),
        }
    }
}

#[cfg(test)]
std::thread_local! {
    static PUBLIC_IMPORT_CALLS: core::cell::Cell<usize> = const { core::cell::Cell::new(0) };
}

#[cfg(feature = "secret-taint-instrumentation")]
static DIAGNOSTIC_PUBLIC_IMPORT_CALLS: core::sync::atomic::AtomicUsize =
    core::sync::atomic::AtomicUsize::new(0);

/// Process-wide import-entry counter for single-threaded instrumented tests.
/// This diagnostic is absent from ordinary builds and is not an application API.
#[cfg(feature = "secret-taint-instrumentation")]
#[must_use]
pub fn public_import_count_for_diagnostics() -> usize {
    DIAGNOSTIC_PUBLIC_IMPORT_CALLS.load(core::sync::atomic::Ordering::Relaxed)
}

#[cfg(any(test, feature = "secret-taint-instrumentation"))]
fn audit_public_import(encoded: &[u8; PUBLIC_KEY_BYTES]) {
    #[cfg(test)]
    PUBLIC_IMPORT_CALLS.with(|count| count.set(count.get() + 1));
    #[cfg(feature = "secret-taint-instrumentation")]
    {
        DIAGNOSTIC_PUBLIC_IMPORT_CALLS.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
        if ed301_valgrind_client::running_on_valgrind() != 0 {
            // Inspect only shadow metadata; never declassify the supplied key.
            let mut vbits = [0_u8; PUBLIC_KEY_BYTES];
            let status = ed301_valgrind_client::get_vbits(encoded, &mut vbits);
            ed301_valgrind_client::make_defined(&mut vbits);
            assert_eq!(status, 1, "public-key import V-bit observation failed");
            assert!(
                vbits.iter().all(|byte| *byte == 0),
                "public-key import received secret-tainted input"
            );
        }
    }
    #[cfg(not(feature = "secret-taint-instrumentation"))]
    let _ = encoded;
}

struct ParsedSignature {
    commitment_encoding: [u8; FIELD_BYTES],
    commitment: EdwardsPoint,
    response: Scalar,
}

impl ParsedSignature {
    fn from_bytes(bytes: &[u8]) -> Result<Self, SignatureError> {
        let encoded: &[u8; SIGNATURE_BYTES] = bytes
            .try_into()
            .map_err(|_| SignatureError::InvalidSignature)?;
        let commitment_encoding: &[u8; FIELD_BYTES] = encoded[..FIELD_BYTES]
            .try_into()
            .map_err(|_| SignatureError::InvalidSignature)?;
        let response_encoding: &[u8; FIELD_BYTES] = encoded[FIELD_BYTES..]
            .try_into()
            .map_err(|_| SignatureError::InvalidSignature)?;
        let commitment = EdwardsPoint::decode(commitment_encoding)
            .map_err(|_| SignatureError::InvalidSignature)?;
        let response = Scalar::from_canonical_bytes(response_encoding)
            .into_option_copied()
            .ok_or(SignatureError::InvalidSignature)?;
        Ok(Self {
            commitment_encoding: *commitment_encoding,
            commitment,
            response,
        })
    }
}

/// Validated canonical 76-byte wire signature.
///
/// The public value contains no retained field, scalar or projective-point
/// representation. In particular, signing cannot carry nonce-correlated
/// projective state across the public-output boundary.
#[repr(transparent)]
#[derive(Clone, Copy)]
pub struct Signature {
    encoded: [u8; SIGNATURE_BYTES],
}

const _: () = assert!(core::mem::size_of::<Signature>() == SIGNATURE_BYTES);

impl Signature {
    /// Parse the exact 76-byte signature syntax.
    ///
    /// `R` must be a canonical curve point, but identity, pure torsion and
    /// mixed-torsion points are intentionally not rejected here. `S` must be
    /// the canonical 38-byte integer in `0 <= S < L`.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, SignatureError> {
        let encoded: &[u8; SIGNATURE_BYTES] = bytes
            .try_into()
            .map_err(|_| SignatureError::InvalidSignature)?;
        ParsedSignature::from_bytes(encoded)?;
        Ok(Self { encoded: *encoded })
    }

    /// Borrow the complete canonical wire representation.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; SIGNATURE_BYTES] {
        &self.encoded
    }

    /// Return the canonical wire representation.
    #[must_use]
    pub const fn to_bytes(self) -> [u8; SIGNATURE_BYTES] {
        self.encoded
    }
}

/// Sign one opaque message from an exact seed.
pub fn sign(seed: &[u8], message: &[u8]) -> Result<[u8; SIGNATURE_BYTES], SignatureError> {
    let key = SigningKey::from_seed(seed)?;
    Ok(key.sign(message)?.to_bytes())
}

/// Sign one opaque message with a native context of at most 255 bytes.
pub fn sign_with_context(
    seed: &[u8],
    message: &[u8],
    context: &[u8],
) -> Result<[u8; SIGNATURE_BYTES], SignatureError> {
    let key = SigningKey::from_seed(seed)?;
    Ok(key.sign_with_context(message, context)?.to_bytes())
}

/// Apply the full profile public-key validation rule.
#[must_use]
pub fn validate_public_key(public_key: &[u8]) -> bool {
    ValidatedPublicKey::from_bytes(public_key).is_ok()
}

/// Parse and verify a signature, returning one fail-closed boolean.
#[must_use]
pub fn verify(public_key: &[u8], message: &[u8], signature: &[u8]) -> bool {
    verify_with_context(public_key, message, b"", signature)
}

/// Parse and verify with a native context of at most 255 bytes.
#[must_use]
pub fn verify_with_context(
    public_key: &[u8],
    message: &[u8],
    context: &[u8],
    signature: &[u8],
) -> bool {
    let public_key = match VerifyingKey::from_bytes(public_key) {
        Ok(public_key) => public_key,
        Err(_) => return false,
    };
    public_key.verify_bytes_with_context(message, context, signature)
}

fn sign_expanded(
    expanded: &ExpandedSigningKey,
    message: &[u8],
    context: &[u8],
) -> Result<Signature, SignatureError> {
    let domain = Domain::new(context).ok_or(SignatureError::InvalidContextLength)?;
    let nonce_digest = nonce_hash(domain, &expanded.prefix, message);
    let nonce = hash_to_scalar(nonce_digest);
    let commitment_point = secret(EdwardsPoint::scalar_mul_base(&nonce));
    #[cfg(test)]
    hit_secret_failpoint(SecretFailpoint::CommitmentPoint);

    let mut commitment = match commitment_point.encode_public_artifact() {
        Ok(commitment) => commitment,
        Err(_) => return Err(SignatureError::InternalFailure),
    };
    declassify(&mut commitment);

    let challenge_digest = challenge_hash(domain, &commitment, &expanded.public_key, message);
    let challenge = hash_to_scalar(challenge_digest);
    let secret_response_term = challenge.mul(&expanded.reduced_scalar);
    let response = nonce.add(&secret_response_term);

    let mut encoded = secret([0_u8; SIGNATURE_BYTES]);
    encoded[..FIELD_BYTES].copy_from_slice(&commitment);
    let mut response_bytes = secret([0_u8; FIELD_BYTES]);
    response.write_canonical_bytes(&mut response_bytes);
    encoded[FIELD_BYTES..].copy_from_slice(&response_bytes[..]);
    #[cfg(test)]
    hit_secret_failpoint(SecretFailpoint::SignIntermediates);
    declassify(&mut encoded);

    let signature = Signature { encoded: *encoded };
    #[cfg(feature = "sign-self-verify")]
    if !expanded
        .verifying_key()
        .verify_bytes_with_context(message, context, signature.as_bytes())
    {
        return Err(SignatureError::InternalFailure);
    }
    Ok(signature)
}

/// Reusable signing state derived from one seed.
///
/// The reduced secret scalar and nonce prefix remain in zeroizing owners.
/// Cloning deliberately creates another zeroizing owner; callers should
/// prefer borrowing unless an API lifecycle requires an immutable snapshot.
pub struct ExpandedSigningKey {
    reduced_scalar: Secret<Scalar>,
    prefix: Secret<[u8; FIELD_BYTES]>,
    public_key: [u8; PUBLIC_KEY_BYTES],
    public_point: EdwardsPoint,
}

impl Clone for ExpandedSigningKey {
    fn clone(&self) -> Self {
        Self {
            reduced_scalar: secret(*self.reduced_scalar),
            prefix: secret(*self.prefix),
            public_key: self.public_key,
            public_point: self.public_point,
        }
    }
}

impl ExpandedSigningKey {
    /// Construct a prepared verifier from the internally validated public
    /// point.
    ///
    /// The expanded signing state deliberately does not retain the roughly
    /// 10-KiB verification table. Integrations that verify repeatedly should
    /// call this once and retain the returned value.
    #[must_use]
    pub fn verifying_key(&self) -> VerifyingKey {
        self.validated_public_key().prepare()
    }

    /// Return only the validated public state, without a verification table
    /// or any reference to the secret signing state.
    #[must_use]
    pub fn validated_public_key(&self) -> ValidatedPublicKey {
        ValidatedPublicKey {
            encoded: self.public_key,
            point: self.public_point,
        }
    }

    /// Borrow the canonical public-key bytes without cloning the prepared
    /// verification table.
    #[must_use]
    pub const fn verifying_key_bytes(&self) -> &[u8; PUBLIC_KEY_BYTES] {
        &self.public_key
    }

    /// Sign one opaque message without re-expanding the seed.
    pub fn sign(&self, message: &[u8]) -> Result<Signature, SignatureError> {
        self.sign_with_context(message, b"")
    }

    /// Sign without repeating key expansion, using at most 255 context bytes.
    pub fn sign_with_context(
        &self,
        message: &[u8],
        context: &[u8],
    ) -> Result<Signature, SignatureError> {
        sign_expanded(self, message, context)
    }

    fn derive(seed: &[u8; SEED_BYTES]) -> Result<Self, SignatureError> {
        let expanded_hash = expand_seed(seed);
        let mut pruned_scalar = secret([0_u8; FIELD_BYTES]);
        pruned_scalar.copy_from_slice(&expanded_hash[..FIELD_BYTES]);
        pruned_scalar[0] &= 0xfc;
        pruned_scalar[FIELD_BYTES - 1] = (pruned_scalar[FIELD_BYTES - 1] & 0x0f) | 0x10;
        let mut prefix = secret([0_u8; FIELD_BYTES]);
        prefix.copy_from_slice(&expanded_hash[FIELD_BYTES..]);

        let reduced_scalar = Scalar::reduce_pruned_le(&pruned_scalar);
        #[cfg(test)]
        hit_secret_failpoint(SecretFailpoint::ExpandedSecret);
        let public_point = secret(EdwardsPoint::scalar_mul_base_pruned(&pruned_scalar));
        #[cfg(test)]
        hit_secret_failpoint(SecretFailpoint::ExpandedPoint);

        // Identity is mathematically impossible for the pruned scalar below,
        // so this cheap declassified predicate is an internal fault check, not
        // attacker-controlled public-key validation.
        let mut public_is_identity = public_point.is_identity();
        declassify(&mut public_is_identity);
        if public_is_identity.to_bool() {
            return Err(SignatureError::InternalFailure);
        }

        /*
         * `public_point` is constructed as `[s]B`, so it is in the subgroup
         * generated by the exact-order base point.  The pruned scalar lies in
         * `2^300 <= s < 2^301` and is divisible by four.  The only multiples
         * of the odd, 300-bit order in that interval are 2L and 3L, neither
         * divisible by four; therefore the point cannot be the identity. The
         * cheap identity fault check above is retained, while re-running a
         * generic `[L]P` check here would only repeat work on an internally
         * constructed value. The optional fault-detection build retains that
         * explicit subgroup invariant check.
         */
        #[cfg(feature = "sign-self-verify")]
        {
            let mut public_is_valid = public_point.is_prime_subgroup_nonidentity();
            declassify(&mut public_is_valid);
            if !public_is_valid.to_bool() {
                return Err(SignatureError::InternalFailure);
            }
        }

        let (public_key, public_point) = match public_point.canonical_public_artifact() {
            Ok(artifact) => artifact,
            Err(_) => return Err(SignatureError::InternalFailure),
        };

        Ok(Self {
            reduced_scalar,
            prefix,
            public_key,
            public_point,
        })
    }
}

#[cfg(test)]
#[derive(Clone, Copy, Eq, PartialEq)]
enum SecretFailpoint {
    ExpandedSecret,
    ExpandedPoint,
    CommitmentPoint,
    SignIntermediates,
}

#[cfg(test)]
std::thread_local! {
    static SECRET_FAILPOINT: core::cell::Cell<Option<SecretFailpoint>> = const {
        core::cell::Cell::new(None)
    };
}

#[cfg(test)]
fn arm_secret_failpoint(point: SecretFailpoint) {
    SECRET_FAILPOINT.with(|slot| slot.set(Some(point)));
}

#[cfg(test)]
fn hit_secret_failpoint(point: SecretFailpoint) {
    SECRET_FAILPOINT.with(|slot| {
        if slot.get() == Some(point) {
            slot.set(None);
            panic!("controlled panic with live secret owners");
        }
    });
}

#[cfg(test)]
pub(crate) mod test_support {
    use super::*;

    pub(crate) struct Trace {
        pub(crate) expanded_hash: [u8; 76],
        pub(crate) pruned_scalar: [u8; 38],
        pub(crate) prefix: [u8; 38],
        pub(crate) public_key: [u8; 38],
        pub(crate) nonce_hash: [u8; 76],
        pub(crate) nonce_scalar: [u8; 38],
        pub(crate) commitment: [u8; 38],
        pub(crate) challenge_hash: [u8; 76],
        pub(crate) challenge_scalar: [u8; 38],
        pub(crate) response: [u8; 38],
        pub(crate) signature: [u8; 76],
    }

    pub(crate) fn trace(seed: &[u8; 38], message: &[u8]) -> Trace {
        trace_with_context(seed, message, b"")
    }

    pub(crate) fn trace_with_context(seed: &[u8; 38], message: &[u8], context: &[u8]) -> Trace {
        let expanded_hash = expand_seed(seed);
        let mut pruned_scalar = secret([0_u8; 38]);
        pruned_scalar.copy_from_slice(&expanded_hash[..38]);
        pruned_scalar[0] &= 0xfc;
        pruned_scalar[37] = (pruned_scalar[37] & 0x0f) | 0x10;
        let mut prefix = secret([0_u8; 38]);
        prefix.copy_from_slice(&expanded_hash[38..]);
        let reduced_secret = Scalar::reduce_pruned_le(&pruned_scalar);
        let public_key = EdwardsPoint::BASEPOINT
            .scalar_mul_pruned(&pruned_scalar)
            .encode()
            .expect("test-derived public key");
        let domain = Domain::new(context).expect("test context length");
        let nonce_digest = nonce_hash(domain, &prefix, message);
        let nonce_hash = *nonce_digest;
        let nonce = hash_to_scalar(nonce_digest);
        let nonce_scalar = nonce.canonical_bytes();
        let commitment = EdwardsPoint::BASEPOINT
            .scalar_mul(&nonce)
            .encode()
            .expect("test-derived commitment");
        let challenge_digest = challenge_hash(domain, &commitment, &public_key, message);
        let challenge_hash = *challenge_digest;
        let challenge = hash_to_scalar(challenge_digest);
        let challenge_scalar = challenge.canonical_bytes();
        let secret_response_term = challenge.mul(&reduced_secret);
        let response_scalar = nonce.add(&secret_response_term);
        let response = response_scalar.canonical_bytes();
        let mut signature = [0_u8; 76];
        signature[..38].copy_from_slice(&commitment);
        signature[38..].copy_from_slice(&response[..]);
        Trace {
            expanded_hash: *expanded_hash,
            pruned_scalar: *pruned_scalar,
            prefix: *prefix,
            public_key,
            nonce_hash,
            nonce_scalar,
            commitment,
            challenge_hash,
            challenge_scalar,
            response,
            signature,
        }
    }

    #[cfg(panic = "unwind")]
    #[test]
    fn actual_secret_scopes_unwind_and_subsequent_signing_recovers() {
        use std::panic::{AssertUnwindSafe, catch_unwind};

        let seed = [0x5a_u8; 38];
        let key = SigningKey::from_seed(&seed).expect("fixed seed length");
        let expected = key.sign(b"after-unwind").expect("baseline signature");

        for point in [
            SecretFailpoint::ExpandedSecret,
            SecretFailpoint::ExpandedPoint,
            SecretFailpoint::CommitmentPoint,
            SecretFailpoint::SignIntermediates,
        ] {
            arm_secret_failpoint(point);
            let outcome = catch_unwind(AssertUnwindSafe(|| key.sign(b"after-unwind")));
            assert!(outcome.is_err());
            assert_eq!(
                key.sign(b"after-unwind")
                    .expect("signing after controlled unwind")
                    .to_bytes(),
                expected.to_bytes()
            );
        }

        assert!(core::mem::needs_drop::<ExpandedSigningKey>());
    }

    #[cfg(panic = "unwind")]
    #[test]
    fn returned_fixed_base_points_zeroize_on_return_and_unwind() {
        use std::panic::{AssertUnwindSafe, catch_unwind};

        let key = SigningKey::from_seed(&[0x5a; SEED_BYTES]).expect("fixed seed");
        let before = EdwardsPoint::zeroization_count_for_test();
        let expanded = key.expand().expect("seed expansion");
        // The internal accumulator and the returned projective point are
        // distinct owners; the retained canonical affine point is public.
        assert_eq!(EdwardsPoint::zeroization_count_for_test(), before + 2);
        let expected = expanded.sign(b"returned point owners").expect("signing");
        assert_eq!(EdwardsPoint::zeroization_count_for_test(), before + 4);

        arm_secret_failpoint(SecretFailpoint::ExpandedPoint);
        assert!(catch_unwind(AssertUnwindSafe(|| key.expand())).is_err());
        assert_eq!(EdwardsPoint::zeroization_count_for_test(), before + 6);

        arm_secret_failpoint(SecretFailpoint::CommitmentPoint);
        assert!(
            catch_unwind(AssertUnwindSafe(|| expanded.sign(b"returned point owners"))).is_err()
        );
        assert_eq!(EdwardsPoint::zeroization_count_for_test(), before + 8);
        assert_eq!(
            expanded
                .sign(b"returned point owners")
                .expect("recovery")
                .to_bytes(),
            expected.to_bytes()
        );
        assert_eq!(EdwardsPoint::zeroization_count_for_test(), before + 10);
    }

    #[test]
    fn signing_and_key_derivation_never_enter_public_import_checks() {
        let before = PUBLIC_IMPORT_CALLS.with(core::cell::Cell::get);
        let key = SigningKey::from_seed(&[0x54; SEED_BYTES]).expect("fixed seed");
        let expanded = key.expand().expect("seed expansion");
        let public = key.verifying_key().expect("public derivation");
        let signature = key.sign(b"import boundary").expect("one-shot signature");
        let prepared_signature = expanded
            .sign(b"import boundary")
            .expect("prepared signature");
        assert_eq!(signature.to_bytes(), prepared_signature.to_bytes());
        assert!(public.verify(b"import boundary", &signature));
        assert_eq!(PUBLIC_IMPORT_CALLS.with(core::cell::Cell::get), before);

        // Prove that the observer reaches the real parser, not a dead hook.
        let imported = VerifyingKey::from_bytes(public.as_bytes()).expect("external public import");
        assert_eq!(PUBLIC_IMPORT_CALLS.with(core::cell::Cell::get), before + 1);
        assert!(imported.verify(b"import boundary", &signature));
    }

    #[test]
    fn internally_derived_public_keys_match_strict_external_validation() {
        let mut state = 0x6a09_e667_f3bc_c909_u64;

        for case_index in 0..2_048_u64 {
            let mut seed = [0_u8; SEED_BYTES];
            for byte in &mut seed {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                *byte = state as u8;
            }

            let expanded = SigningKey::from_seed(&seed)
                .expect("fixed-size seed")
                .expand()
                .expect("internal public derivation");
            let derived = expanded.verifying_key();
            let encoded = derived.to_bytes();
            let lightweight = expanded.validated_public_key();
            let parsed_lightweight = ValidatedPublicKey::from_bytes(&encoded)
                .expect("the lightweight representation has the same strict policy");
            assert_eq!(lightweight.as_bytes(), &encoded);
            assert_eq!(parsed_lightweight.as_bytes(), &encoded);
            let reparsed = VerifyingKey::from_bytes(&encoded)
                .expect("every internally derived key must pass the external policy");
            assert_eq!(encoded, *expanded.verifying_key_bytes());

            if case_index % 64 == 0 {
                let message = case_index.to_le_bytes();
                let signature = expanded.sign(&message).expect("deterministic signature");
                assert!(derived.verify(&message, &signature));
                assert!(reparsed.verify(&message, &signature));
                assert!(lightweight.prepare().verify(&message, &signature));
                assert!(parsed_lightweight.prepare().verify(&message, &signature));
            }
        }
    }

    #[test]
    fn public_signature_storage_is_exactly_the_wire_value() {
        let seed = [0x42_u8; SEED_BYTES];
        let signature = SigningKey::from_seed(&seed)
            .expect("fixed-size seed")
            .sign(b"wire-only signature")
            .expect("deterministic signature");

        assert_eq!(core::mem::size_of::<Signature>(), SIGNATURE_BYTES);
        assert_eq!(core::mem::size_of_val(&signature), SIGNATURE_BYTES);
        assert_eq!(signature.as_bytes(), &signature.to_bytes());
        assert!(core::mem::size_of::<ValidatedPublicKey>() < 1024);
        assert!(core::mem::size_of::<VerifyingKey>() > 10 * 1024);
    }
}
