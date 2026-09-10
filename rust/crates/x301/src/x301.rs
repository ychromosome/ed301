//! Raw X301-v2 operations with strict encodings and zeroizing secret owners.

use crypto_bigint::{Choice, CtEq};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::{
    edwards::EdwardsPoint,
    field_5x64::{Fe301, Fe301Lazy},
    parameters::{FIELD_BYTES, LADDER_BITS, PUBLIC_BYTES, SECRET_BYTES, SHARED_BYTES},
    secret_taint::declassify,
    x_generated_parameters::{A24_MINUS_WORDS, TWIST_ORDER_BYTES},
};

/// Raw X301 input/output byte length.
pub const X301_BYTES: usize = FIELD_BYTES;
/// Canonical Montgomery coordinate of the approved v2 base point.
pub const BASE_U_BYTES: [u8; FIELD_BYTES] = crate::x_generated_parameters::BASE_U_BYTES;
const A24_MINUS: Fe301 = Fe301::from_canonical_words(A24_MINUS_WORDS);
const A24_MINUS_LAZY: Fe301Lazy = Fe301Lazy::from_fe301(A24_MINUS);
#[cfg(test)]
const BASE_U: Fe301 = Fe301::from_canonical_words(crate::x_generated_parameters::BASE_U_WORDS);

/// Failure without a partial output value.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum X301Error {
    /// The raw secret has a length other than 38 bytes.
    InvalidSecretLength,
    /// The clamped scalar is the excluded full twist order.
    WeakSecret,
    /// The public-coordinate input has a length other than 38 bytes.
    InvalidPublicLength,
    /// The public coordinate is at least p or has a reserved high bit set.
    NonCanonicalPublic,
    /// The complete ladder/finalization produced infinity or a zero coordinate.
    AllZeroSharedSecret,
}

/// Key-generation failures; only the specified weak clamp is resampled.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum X301KeyGenError<E> {
    /// The caller's random source failed.
    Random(E),
    /// A validated scalar unexpectedly failed public derivation.
    Internal,
}

/// Reusable, non-Copy owner of the original raw secret and its validated clamp.
pub struct SecretKey {
    raw: Zeroizing<[u8; SECRET_BYTES]>,
    clamped: Zeroizing<[u8; SECRET_BYTES]>,
}

impl SecretKey {
    /// Import exact raw bytes. Secret validation precedes any peer-u processing.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, X301Error> {
        let raw: &[u8; SECRET_BYTES] = bytes
            .try_into()
            .map_err(|_| X301Error::InvalidSecretLength)?;
        let mut clamped = Zeroizing::new(*raw);
        clamped[0] &= 0xfc;
        clamped[SECRET_BYTES - 1] = (clamped[SECRET_BYTES - 1] & 0x0f) | 0x10;
        let mut valid = clamped.ct_eq(&TWIST_ORDER_BYTES).not();
        // This one-bit membership result is the specified early rejection boundary.
        declassify(&mut valid);
        if !valid.to_bool() {
            return Err(X301Error::WeakSecret);
        }
        Ok(Self {
            raw: Zeroizing::new(*raw),
            clamped,
        })
    }

    /// Borrow the original serialized bytes. The caller owns any copies it makes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; SECRET_BYTES] {
        &self.raw
    }

    /// Derive a public key with the shared constant-time Edwards fixed-base table.
    /// The validated X301 clamp is used unchanged, followed by u=(Z+Y)/(Z-Y).
    pub fn public_key(&self) -> Result<PublicKey, X301Error> {
        let output = fixed_base_public(&self.clamped)?;
        let mut public = *output.as_bytes();
        declassify(&mut public);
        PublicKey::from_bytes(&public)
    }

    /// Derive raw key material with a previously validated canonical peer.
    pub fn shared_secret(&self, peer: &PublicKey) -> Result<SharedSecret, X301Error> {
        multiply(&self.clamped, peer.coordinate)
    }
}

impl Zeroize for SecretKey {
    fn zeroize(&mut self) {
        self.raw.zeroize();
        self.clamped.zeroize();
    }
}
impl ZeroizeOnDrop for SecretKey {}

/// Reusable canonical public coordinate, without curve/twist classification.
#[derive(Clone)]
pub struct PublicKey {
    bytes: [u8; PUBLIC_BYTES],
    coordinate: Fe301,
}

impl PublicKey {
    /// Validate the exact canonical encoding; low-order values are not filtered here.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, X301Error> {
        let bytes: &[u8; PUBLIC_BYTES] = bytes
            .try_into()
            .map_err(|_| X301Error::InvalidPublicLength)?;
        let coordinate = Fe301::from_canonical_bytes(bytes)
            .into_option_copied()
            .ok_or(X301Error::NonCanonicalPublic)?;
        Ok(Self {
            bytes: *bytes,
            coordinate,
        })
    }

    /// Return the unchanged canonical public bytes.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; PUBLIC_BYTES] {
        self.bytes
    }

    /// Borrow the canonical public bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; PUBLIC_BYTES] {
        &self.bytes
    }
}

/// Non-Copy, zeroizing owner of successful raw shared key material.
pub struct SharedSecret(Zeroizing<[u8; SHARED_BYTES]>);
impl SharedSecret {
    /// Borrow raw key material. No KDF, authentication or implicit public copy is applied.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; SHARED_BYTES] {
        &self.0
    }
}
impl Zeroize for SharedSecret {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}
impl ZeroizeOnDrop for SharedSecret {}

/// Strict raw X301-v2. Invalid secret status takes precedence over invalid peer-u.
pub fn x301(secret: &[u8], peer: &[u8]) -> Result<SharedSecret, X301Error> {
    let secret = SecretKey::from_bytes(secret)?;
    let peer = PublicKey::from_bytes(peer)?;
    secret.shared_secret(&peer)
}

/// Derive the canonical public coordinate from a raw secret.
pub fn public_from_secret(secret: &[u8]) -> Result<[u8; PUBLIC_BYTES], X301Error> {
    SecretKey::from_bytes(secret)?
        .public_key()
        .map(|public| public.to_bytes())
}

/// Derive secret raw bytes, returning an owner only on success.
pub fn shared_secret(secret: &[u8], peer: &[u8]) -> Result<SharedSecret, X301Error> {
    x301(secret, peer)
}

/// Validate only the public encoding; no mask, reduction, ladder or subgroup test.
pub fn validate_public_encoding(public: &[u8]) -> Result<(), X301Error> {
    PublicKey::from_bytes(public).map(|_| ())
}

/// Return the original canonical input or reject it; this never normalizes an alias.
pub fn canonicalize_public_encoding(public: &[u8]) -> Result<[u8; PUBLIC_BYTES], X301Error> {
    PublicKey::from_bytes(public).map(|key| key.to_bytes())
}

/// Generate a secret owner and public key using a fallible, caller-supplied random source.
///
/// The callback must fill all 38 bytes independently and uniformly. Only the
/// excluded clamped scalar is retried; random-source and internal errors are final.
pub fn keygen<E, F>(mut fill_random: F) -> Result<(SecretKey, PublicKey), X301KeyGenError<E>>
where
    F: FnMut(&mut [u8; SECRET_BYTES]) -> Result<(), E>,
{
    loop {
        let mut bytes = Zeroizing::new([0_u8; SECRET_BYTES]);
        fill_random(&mut bytes).map_err(X301KeyGenError::Random)?;
        let secret = match SecretKey::from_bytes(&*bytes) {
            Ok(secret) => secret,
            Err(X301Error::WeakSecret) => continue,
            Err(_) => return Err(X301KeyGenError::Internal),
        };
        let public = secret.public_key().map_err(|_| X301KeyGenError::Internal)?;
        return Ok((secret, public));
    }
}

struct LadderState {
    x1: Fe301Lazy,
    x2: Fe301Lazy,
    z2: Fe301Lazy,
    x3: Fe301Lazy,
    z3: Fe301Lazy,
}
impl Zeroize for LadderState {
    fn zeroize(&mut self) {
        self.x1.zeroize();
        self.x2.zeroize();
        self.z2.zeroize();
        self.x3.zeroize();
        self.z3.zeroize();
        #[cfg(test)]
        {
            assert!(
                self.x1.is_zero_representation_for_test()
                    && self.x2.is_zero_representation_for_test()
                    && self.z2.is_zero_representation_for_test()
                    && self.x3.is_zero_representation_for_test()
                    && self.z3.is_zero_representation_for_test()
            );
            crate::tests::count_state_zeroization();
        }
    }
}
struct ProjectiveOutput {
    x: Fe301,
    z: Fe301,
}
impl Zeroize for ProjectiveOutput {
    fn zeroize(&mut self) {
        self.x.zeroize();
        self.z.zeroize();
    }
}

#[inline(always)]
fn swap(left: &mut Fe301Lazy, right: &mut Fe301Lazy, choice: Choice) {
    let original = *left;
    *left = Fe301Lazy::conditional_select(*left, *right, choice);
    *right = Fe301Lazy::conditional_select(*right, original, choice);
}

#[inline(never)]
fn ladder301(scalar: &[u8; SECRET_BYTES], u: Fe301) -> Zeroizing<ProjectiveOutput> {
    let mut state = Zeroizing::new(LadderState {
        x1: Fe301Lazy::from_fe301(u),
        x2: Fe301Lazy::from_fe301(Fe301::ONE),
        z2: Fe301Lazy::from_fe301(Fe301::ZERO),
        x3: Fe301Lazy::from_fe301(u),
        z3: Fe301Lazy::from_fe301(Fe301::ONE),
    });
    let mut previous = Choice::FALSE;
    #[cfg(test)]
    crate::tests::state_failpoint();
    for bit_index in (0..LADDER_BITS).rev() {
        #[cfg(test)]
        crate::tests::count_round();
        let bit = Choice::from_u8_lsb(scalar[bit_index >> 3] >> (bit_index & 7));
        let s = &mut *state;
        swap(&mut s.x2, &mut s.x3, previous.xor(bit));
        swap(&mut s.z2, &mut s.z3, previous.xor(bit));
        previous = bit;
        let a = s.x2.add_loose(s.z2);
        let aa = a.square();
        let b = s.x2.sub_loose(s.z2);
        let bb = b.square();
        let e = aa.sub_loose(bb);
        let c = s.x3.add_loose(s.z3);
        let d = s.x3.sub_loose(s.z3);
        let da = d.mul(a);
        let cb = c.mul(b);
        s.x3 = da.add_loose(cb).square();
        s.z3 = s.x1.mul(da.sub_loose(cb).square());
        s.x2 = aa.mul(bb);
        // A24 remains a full field multiplication. Both final factors are
        // below 4p; no extra tightening is required by the wide reducer.
        s.z2 = e.mul(aa.add_loose(e.mul_tight(A24_MINUS_LAZY)));
        #[cfg(test)]
        for coordinate in [s.x1, s.x2, s.z2, s.x3, s.z3] {
            coordinate.assert_lazy_bound_for_test();
        }
    }
    let s = &mut *state;
    swap(&mut s.x2, &mut s.x3, previous);
    swap(&mut s.z2, &mut s.z3, previous);
    Zeroizing::new(ProjectiveOutput {
        x: s.x2.canonical(),
        z: s.z2.canonical(),
    })
}

// The pre-E2 canonical ladder is retained as the differential test oracle.
#[cfg(test)]
struct CanonicalLadderState {
    x1: Fe301,
    x2: Fe301,
    z2: Fe301,
    x3: Fe301,
    z3: Fe301,
}
#[cfg(test)]
impl Zeroize for CanonicalLadderState {
    fn zeroize(&mut self) {
        self.x1.zeroize();
        self.x2.zeroize();
        self.z2.zeroize();
        self.x3.zeroize();
        self.z3.zeroize();
        #[cfg(test)]
        {
            assert!(
                self.x1.is_zero().to_bool()
                    && self.x2.is_zero().to_bool()
                    && self.z2.is_zero().to_bool()
                    && self.x3.is_zero().to_bool()
                    && self.z3.is_zero().to_bool()
            );
            crate::tests::count_state_zeroization();
        }
    }
}

#[cfg(test)]
#[inline(always)]
fn canonical_swap(left: &mut Fe301, right: &mut Fe301, choice: Choice) {
    let original = *left;
    *left = Fe301::conditional_select(*left, *right, choice);
    *right = Fe301::conditional_select(*right, original, choice);
}

#[cfg(test)]
#[inline(never)]
fn canonical_ladder301(scalar: &[u8; SECRET_BYTES], u: Fe301) -> Zeroizing<ProjectiveOutput> {
    let mut state = Zeroizing::new(CanonicalLadderState {
        x1: u,
        x2: Fe301::ONE,
        z2: Fe301::ZERO,
        x3: u,
        z3: Fe301::ONE,
    });
    let mut previous = Choice::FALSE;
    #[cfg(test)]
    crate::tests::state_failpoint();
    for bit_index in (0..LADDER_BITS).rev() {
        #[cfg(test)]
        crate::tests::count_round();
        let bit = Choice::from_u8_lsb(scalar[bit_index >> 3] >> (bit_index & 7));
        let s = &mut *state;
        canonical_swap(&mut s.x2, &mut s.x3, previous.xor(bit));
        canonical_swap(&mut s.z2, &mut s.z3, previous.xor(bit));
        previous = bit;
        let a = s.x2.add(s.z2);
        let aa = a.square();
        let b = s.x2.sub(s.z2);
        let bb = b.square();
        let e = aa.sub(bb);
        let c = s.x3.add(s.z3);
        let d = s.x3.sub(s.z3);
        let da = d.mul(a);
        let cb = c.mul(b);
        s.x3 = da.add(cb).square();
        s.z3 = s.x1.mul(da.sub(cb).square());
        s.x2 = aa.mul(bb);
        s.z2 = e.mul(aa.add(A24_MINUS.mul(e)));
    }
    let s = &mut *state;
    canonical_swap(&mut s.x2, &mut s.x3, previous);
    canonical_swap(&mut s.z2, &mut s.z3, previous);
    Zeroizing::new(ProjectiveOutput { x: s.x2, z: s.z2 })
}

#[cfg(test)]
pub(crate) fn canonical_shared_for_test(
    secret: &[u8],
    peer: &[u8],
) -> Result<SharedSecret, X301Error> {
    let secret = SecretKey::from_bytes(secret)?;
    let peer = PublicKey::from_bytes(peer)?;
    finalize_projective(canonical_ladder301(&secret.clamped, peer.coordinate))
}

fn multiply(scalar: &[u8; SECRET_BYTES], u: Fe301) -> Result<SharedSecret, X301Error> {
    finalize_projective(ladder301(scalar, u))
}

fn fixed_base_public(scalar: &[u8; SECRET_BYTES]) -> Result<SharedSecret, X301Error> {
    // The shared routine consumes all 301 encoded bits. No EdDSA seed expansion,
    // pruning, reduction modulo q or X301 fixed-bit ladder shortcut is applied.
    let point = Zeroizing::new(EdwardsPoint::scalar_mul_base_pruned(scalar));
    let coordinates = Zeroizing::new(point.montgomery_projective());
    finalize_projective(Zeroizing::new(ProjectiveOutput {
        x: coordinates[0],
        z: coordinates[1],
    }))
}

fn finalize_projective(projective: Zeroizing<ProjectiveOutput>) -> Result<SharedSecret, X301Error> {
    let inverse = Zeroizing::new(projective.z.invert().to_inner_unchecked());
    let affine = Zeroizing::new(projective.x.mul(*inverse));
    let output = Zeroizing::new(affine.to_canonical_bytes());
    let mut valid = projective.z.is_zero().not().and(affine.is_zero().not());
    declassify(&mut valid);
    if !valid.to_bool() {
        return Err(X301Error::AllZeroSharedSecret);
    }
    Ok(SharedSecret(output))
}

#[cfg(test)]
pub(crate) fn zero_scalar_ladder_for_test() {
    let output = ladder301(&[0_u8; SECRET_BYTES], BASE_U);
    assert!(output.z.is_zero().to_bool());
}

#[cfg(test)]
pub(crate) fn zero_scalar_fixed_base_for_test() {
    assert!(matches!(
        fixed_base_public(&[0; SECRET_BYTES]),
        Err(X301Error::AllZeroSharedSecret)
    ));
}

#[cfg(test)]
impl SecretKey {
    pub(crate) fn clamped_for_test(&self) -> &[u8; SECRET_BYTES] {
        &self.clamped
    }
}
