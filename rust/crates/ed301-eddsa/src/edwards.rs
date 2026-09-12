//! Internal extended-coordinate arithmetic for the ED301-v2 Edwards group.
//!
//! The formulas are complete for a twisted-Edwards curve with square `a` and
//! nonsquare `d`. Secret fixed-base multiplication uses a signed-radix-16
//! comb. Public verification uses variable-time wNAF/Straus arithmetic; the
//! 301-round ladder remains a test reference.

use crypto_bigint::Choice;

use crate::{
    field_5x64::{Fe301 as FieldElement, Fe301Lazy as Lazy},
    parameters::{FIELD_BITS, FIELD_BYTES},
    scalar::Scalar,
    secret::secret,
    secret_taint::declassify,
};

#[cfg(any(test, feature = "sign-self-verify"))]
use crate::generated_parameters::PRIME_ORDER_SET_BITS_DESC;
#[cfg(test)]
use crate::generated_parameters::PRIME_ORDER_WNAF8_DESC;
use crate::generated_parameters::{EDWARDS_A, EDWARDS_D_MAGNITUDE};
const _: () = assert!(crate::generated_parameters::HALVING_P_MOD_4 == 3);
const _: () = assert!(crate::generated_parameters::HALVING_CHI_B == -1);
const _: () = assert!(crate::generated_parameters::HALVING_CHI_D_A_MINUS_D == 1);
const BASEPOINT_TABLE_ROWS: usize = FIELD_BYTES;
const BASEPOINT_TABLE_WIDTH: usize = 8;
const BASEPOINT_TABLE_SIZE: usize = BASEPOINT_TABLE_ROWS * BASEPOINT_TABLE_WIDTH;
const RADIX16_DIGITS: usize = FIELD_BYTES * 2;
const BASEPOINT_WNAF_WIDTH: u32 = 8;
const POINT_WNAF_WIDTH: u32 = 8;
const BASEPOINT_ODD_MULTIPLES: usize = 1 << (BASEPOINT_WNAF_WIDTH - 2);
const POINT_ODD_MULTIPLES: usize = 1 << (POINT_WNAF_WIDTH - 2);

pub(crate) type VartimePointTable = [AffineNielsPoint; POINT_ODD_MULTIPLES];

#[cfg(test)]
pub(crate) const BASEPOINT_ENCODING: [u8; FIELD_BYTES] = crate::generated_parameters::BASE_ENCODING;
#[cfg(test)]
const PRIME_ORDER_BYTES: [u8; FIELD_BYTES] = crate::generated_parameters::PRIME_ORDER_ENCODING;

/// Generic failure from strict Edwards point decoding or encoding.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct EdwardsPointError;

/// ED301-v2 point in extended coordinates `(X:Y:Z:T)` with `XY = ZT`.
#[derive(Clone, Copy)]
pub(crate) struct EdwardsPoint {
    x: FieldElement,
    y: FieldElement,
    z: FieldElement,
    t: FieldElement,
}

impl zeroize::Zeroize for EdwardsPoint {
    fn zeroize(&mut self) {
        self.x.zeroize();
        self.y.zeroize();
        self.z.zeroize();
        self.t.zeroize();
        #[cfg(test)]
        {
            assert!(
                self.x
                    .is_zero()
                    .and(self.y.is_zero())
                    .and(self.z.is_zero())
                    .and(self.t.is_zero())
                    .to_bool()
            );
            tests::record_point_zeroization();
        }
    }
}

// A distinct non-Copy payload keeps the encoder's normalization inverse in a
// logical zeroizing owner, including a failed presence check or unwinding.
struct EncodingInverse(FieldElement);

impl zeroize::Zeroize for EncodingInverse {
    fn zeroize(&mut self) {
        self.0.zeroize();
        #[cfg(test)]
        {
            assert!(self.0.is_zero().to_bool());
            tests::record_inverse_zeroization();
        }
    }
}

/// Affine cached point for the mixed-addition formulas used by fixed-base and
/// public verification tables. `xy = x + y` and `dt_abs = |d|*x*y` remove one
/// field multiplication and the small-constant multiply from every table add.
#[derive(Clone, Copy)]
pub(crate) struct AffineNielsPoint {
    x: FieldElement,
    y: FieldElement,
    xy: FieldElement,
    dt_abs: FieldElement,
}

impl AffineNielsPoint {
    const IDENTITY: Self = Self {
        x: FieldElement::ZERO,
        y: FieldElement::ONE,
        xy: FieldElement::ONE,
        dt_abs: FieldElement::ZERO,
    };

    fn from_projective(point: EdwardsPoint, inverse_z: FieldElement) -> Self {
        let x = point.x.mul(inverse_z);
        let y = point.y.mul(inverse_z);
        Self {
            x,
            y,
            xy: x.add(y),
            dt_abs: x.mul(y).mul_small(EDWARDS_D_MAGNITUDE),
        }
    }

    const fn from_projective_const(point: EdwardsPoint, inverse_z: FieldElement) -> Self {
        let x = point.x.mul_const(inverse_z);
        let y = point.y.mul_const(inverse_z);
        Self {
            x,
            y,
            xy: x.add_const(y),
            dt_abs: x.mul_const(y).mul_small_const(EDWARDS_D_MAGNITUDE),
        }
    }

    fn negate(self) -> Self {
        let x = self.x.neg();
        Self {
            x,
            y: self.y,
            xy: x.add(self.y),
            dt_abs: self.dt_abs.neg(),
        }
    }

    fn conditional_select(when_false: Self, when_true: Self, choice: Choice) -> Self {
        Self {
            x: FieldElement::conditional_select(when_false.x, when_true.x, choice),
            y: FieldElement::conditional_select(when_false.y, when_true.y, choice),
            xy: FieldElement::conditional_select(when_false.xy, when_true.xy, choice),
            dt_abs: FieldElement::conditional_select(when_false.dt_abs, when_true.dt_abs, choice),
        }
    }
}

impl EdwardsPoint {
    #[cfg(test)]
    pub(crate) fn zeroization_count_for_test() -> usize {
        tests::point_zeroizations()
    }

    /// Edwards identity `(0, 1)`.
    pub(crate) const IDENTITY: Self = Self {
        x: FieldElement::ZERO,
        y: FieldElement::ONE,
        z: FieldElement::ONE,
        t: FieldElement::ZERO,
    };

    /// Deterministically derived ED301-v2 base point of exact order `q`.
    pub(crate) const BASEPOINT: Self = Self {
        x: FieldElement::from_canonical_words(crate::generated_parameters::BASE_X_WORDS),
        y: FieldElement::from_canonical_words(crate::generated_parameters::BASE_Y_WORDS),
        z: FieldElement::ONE,
        t: FieldElement::from_canonical_words(crate::generated_parameters::BASE_T_WORDS),
    };

    fn from_affine(x: FieldElement, y: FieldElement) -> Self {
        Self {
            x,
            y,
            z: FieldElement::ONE,
            t: x.mul(y),
        }
    }

    /// Add two valid extended points with the complete twisted-Edwards formula.
    ///
    /// Intermediate products stay lazily reduced below `2p` and sums or
    /// differences below `4p` (`Fe301Lazy`, `Fe301LazyLinear`); only the four
    /// returned coordinates are canonicalised. The negative sign of `d` is
    /// folded into the sum/difference pair; `add_const` retains the original
    /// canonical formula as the independent test oracle.
    pub(crate) fn add(self, rhs: Self) -> Self {
        let (x, y, z, t) = (
            Lazy::from_fe301(self.x),
            Lazy::from_fe301(self.y),
            Lazy::from_fe301(self.z),
            Lazy::from_fe301(self.t),
        );
        let (rx, ry, rz, rt) = (
            Lazy::from_fe301(rhs.x),
            Lazy::from_fe301(rhs.y),
            Lazy::from_fe301(rhs.z),
            Lazy::from_fe301(rhs.t),
        );
        let xx = x.mul(rx);
        let yy = y.mul(ry);
        let dt_abs = t.mul_small(EDWARDS_D_MAGNITUDE).mul(rt);
        let zz = z.mul(rz);
        let cross = x
            .add_loose(y)
            .mul(rx.add_loose(ry))
            .sub_loose(xx.add_loose(yy).tighten());
        let difference = zz.add_loose(dt_abs);
        let sum = zz.sub_loose(dt_abs);
        let twisted = yy.sub_loose(xx.mul_small(EDWARDS_A));

        Self {
            x: cross.mul(difference).canonical(),
            y: sum.mul(twisted).canonical(),
            z: difference.mul(sum).canonical(),
            t: cross.mul(twisted).canonical(),
        }
    }

    /// Add an affine precomputed point using the complete mixed formula.
    pub(crate) fn add_affine(self, rhs: AffineNielsPoint) -> Self {
        let (x, y, z, t) = (
            Lazy::from_fe301(self.x),
            Lazy::from_fe301(self.y),
            Lazy::from_fe301(self.z),
            Lazy::from_fe301(self.t),
        );
        let xx = x.mul(Lazy::from_fe301(rhs.x));
        let yy = y.mul(Lazy::from_fe301(rhs.y));
        let dt_abs = t.mul(Lazy::from_fe301(rhs.dt_abs));
        let cross = x
            .add_loose(y)
            .mul_tight(Lazy::from_fe301(rhs.xy))
            .sub_loose(xx.add_loose(yy).tighten());
        let difference = z.add_loose(dt_abs);
        let sum = z.sub_loose(dt_abs);
        let twisted = yy.sub_loose(xx.mul_small(EDWARDS_A));

        Self {
            x: cross.mul(difference).canonical(),
            y: sum.mul(twisted).canonical(),
            z: difference.mul(sum).canonical(),
            t: cross.mul(twisted).canonical(),
        }
    }

    /// Double a valid extended point with the complete dedicated formula.
    pub(crate) fn double(self) -> Self {
        let (x, y, z) = (
            Lazy::from_fe301(self.x),
            Lazy::from_fe301(self.y),
            Lazy::from_fe301(self.z),
        );
        let xx = x.square();
        let yy = y.square();
        let zz = z.square();
        let two_zz = zz.add_loose(zz).tighten();
        let twisted_xx = xx.mul_small(EDWARDS_A);
        let cross = x
            .add_loose(y)
            .square()
            .sub_loose(xx.add_loose(yy).tighten());
        let sum = twisted_xx.add_loose(yy);
        let difference = sum.tighten().sub_loose(two_zz);
        let twisted_difference = twisted_xx.sub_loose(yy);

        Self {
            x: cross.mul(difference).canonical(),
            y: sum.mul(twisted_difference).canonical(),
            z: difference.mul(sum).canonical(),
            t: cross.mul(twisted_difference).canonical(),
        }
    }

    const fn add_const(self, rhs: Self) -> Self {
        let xx = self.x.mul_const(rhs.x);
        let yy = self.y.mul_const(rhs.y);
        let dt = self
            .t
            .mul_small_const(EDWARDS_D_MAGNITUDE)
            .neg_const()
            .mul_const(rhs.t);
        let zz = self.z.mul_const(rhs.z);
        let cross = self
            .x
            .add_const(self.y)
            .mul_const(rhs.x.add_const(rhs.y))
            .sub_const(xx)
            .sub_const(yy);
        let difference = zz.sub_const(dt);
        let sum = zz.add_const(dt);
        let twisted = yy.sub_const(xx.mul_small_const(EDWARDS_A));

        Self {
            x: cross.mul_const(difference),
            y: sum.mul_const(twisted),
            z: difference.mul_const(sum),
            t: cross.mul_const(twisted),
        }
    }

    const fn double_const(self) -> Self {
        let xx = self.x.square_const();
        let yy = self.y.square_const();
        let zz = self.z.square_const();
        let two_zz = zz.add_const(zz);
        let twisted_xx = xx.mul_small_const(EDWARDS_A);
        let cross = self
            .x
            .add_const(self.y)
            .square_const()
            .sub_const(xx)
            .sub_const(yy);
        let sum = twisted_xx.add_const(yy);
        let difference = sum.sub_const(two_zz);
        let twisted_difference = twisted_xx.sub_const(yy);

        Self {
            x: cross.mul_const(difference),
            y: sum.mul_const(twisted_difference),
            z: difference.mul_const(sum),
            t: cross.mul_const(twisted_difference),
        }
    }

    /// Return the Edwards inverse `(-x, y)`.
    pub(crate) fn negate(self) -> Self {
        Self {
            x: self.x.neg(),
            y: self.y,
            z: self.z,
            t: self.t.neg(),
        }
    }

    /// Multiply by a canonical scalar in exactly 301 rounds.
    #[cfg(test)]
    pub(crate) fn scalar_mul(self, scalar: &Scalar) -> Self {
        self.scalar_mul_with(|bit_index| scalar.bit(bit_index))
    }

    #[cfg(test)]
    fn scalar_mul_encoded(self, scalar: &[u8; FIELD_BYTES]) -> Self {
        self.scalar_mul_with(|bit_index| {
            Choice::from_u8_lsb(scalar[bit_index >> 3] >> (bit_index & 7))
        })
    }

    /// Multiply by the exact pruned 301-bit secret encoding.
    ///
    /// Unlike [`Self::scalar_mul`], this path intentionally does not require
    /// the input to be canonical modulo `L`; the profile's pruned secret lies in
    /// `2^300 <= s < 2^301` and is consumed in exactly 301 rounds.
    #[cfg(test)]
    pub(crate) fn scalar_mul_pruned(self, scalar: &[u8; FIELD_BYTES]) -> Self {
        self.scalar_mul_encoded(scalar)
    }

    /// Multiply the fixed base point by a canonical secret scalar.
    ///
    /// This is the standard EdDSA signed-radix-16 shape: 38 rows contain
    /// `[1..8] * [256^i]B`; odd digits are accumulated, shifted by four
    /// doublings, and followed by the even digits.  Every secret digit scans
    /// all eight entries and uses conditional selection.
    pub(crate) fn scalar_mul_base(scalar: &Scalar) -> Self {
        let mut encoded = crate::secret::secret([0_u8; FIELD_BYTES]);
        scalar.write_canonical_bytes(&mut encoded);
        Self::scalar_mul_base_encoded(&encoded)
    }

    /// Multiply the fixed base point by the exact pruned secret encoding.
    pub(crate) fn scalar_mul_base_pruned(scalar: &[u8; FIELD_BYTES]) -> Self {
        Self::scalar_mul_base_encoded(scalar)
    }

    /// Numerator and denominator of u=(Z+Y)/(Z-Y), without normalization.
    /// X301 owns these secret intermediates and handles the zero denominator.
    #[allow(
        dead_code,
        reason = "shared Edwards module also serves X301 fixed-base derivation"
    )]
    pub(crate) fn montgomery_projective(&self) -> [FieldElement; 2] {
        [self.z.add(self.y), self.z.sub(self.y)]
    }

    fn scalar_mul_base_encoded(scalar: &[u8; FIELD_BYTES]) -> Self {
        let digits = signed_radix16(scalar);
        let mut result = crate::secret::secret(Self::IDENTITY);
        #[cfg(test)]
        tests::fixed_base_state_failpoint();
        let mut digit_index = 1;

        while digit_index < RADIX16_DIGITS {
            *result = result.add_affine(select_basepoint(digit_index >> 1, digits[digit_index]));
            digit_index += 2;
        }

        *result = result.double().double().double().double();
        digit_index = 0;
        while digit_index < RADIX16_DIGITS {
            *result = result.add_affine(select_basepoint(digit_index >> 1, digits[digit_index]));
            digit_index += 2;
        }
        *result
    }

    #[cfg(test)]
    fn scalar_mul_with(self, mut scalar_bit: impl FnMut(usize) -> Choice) -> Self {
        let mut accumulator = Self::IDENTITY;
        let mut bit_index = FIELD_BITS;

        while bit_index != 0 {
            bit_index -= 1;
            let doubled = accumulator.double();
            let added = doubled.add(self);
            let bit = scalar_bit(bit_index);
            accumulator = Self::conditional_select(doubled, added, bit);
        }

        accumulator
    }

    /// Return whether `[L]P` is the identity using the fixed public wNAF
    /// schedule and the caller-supplied odd-multiples table of this point.
    ///
    /// The digit positions, digit values, loop counts and table indices come
    /// only from [`PRIME_ORDER_WNAF8_DESC`], a public constant, so the
    /// control flow is input-independent even though the point additions use
    /// the variable-time mixed-addition path. Callers must pass the table
    /// built from this same point.
    #[cfg(test)]
    pub(crate) fn is_prime_subgroup_with_table(&self, table: &VartimePointTable) -> Choice {
        let (leading_position, leading_digit) = PRIME_ORDER_WNAF8_DESC[0];
        debug_assert_eq!(leading_digit, 1);
        let mut accumulator = *self;
        let mut current_bit = leading_position as usize;
        let mut digit_index = 1;

        while digit_index < PRIME_ORDER_WNAF8_DESC.len() {
            let (position, digit) = PRIME_ORDER_WNAF8_DESC[digit_index];
            while current_bit > position as usize {
                accumulator = accumulator.double();
                current_bit -= 1;
            }
            accumulator = vartime_add_signed(accumulator, digit, table, false);
            digit_index += 1;
        }
        accumulator.is_identity()
    }

    /// Require nonidentity membership in `4E = E[q]` after canonical decoding.
    /// The caller must supply an affine point returned by `decode` (`Z = 1`).
    /// This is a public-input-only path, not a constant-time secret-point test.
    /// Both symbols and the square-root validity mask are always computed;
    /// no division or selection of a rational halving root is needed.
    pub(crate) fn is_prime_subgroup_decoded(&self) -> Choice {
        let (w, _, _, second, root_valid) = self.halving_terms();
        let first_symbol = w.is_nonzero_square();
        let second_symbol = second.is_nonzero_square();
        first_symbol
            .and(second_symbol)
            .and(root_valid)
            .and(self.y.ct_eq(&FieldElement::ONE.neg()).not())
            .and(self.is_identity().not())
    }

    // Public-input-only halving terms; never use on secret projective state.
    // Expose the actual production intermediates to the child test module.
    // Return fields: w, delta, sqrt candidate, second symbol input, root valid.
    fn halving_terms(
        &self,
    ) -> (
        FieldElement,
        FieldElement,
        FieldElement,
        FieldElement,
        Choice,
    ) {
        debug_assert!(self.z.ct_eq(&FieldElement::ONE).to_bool());
        let b = FieldElement::from_canonical_words(crate::generated_parameters::MONTGOMERY_B_WORDS);
        let a_minus_d = FieldElement::from_u64(EDWARDS_A + EDWARDS_D_MAGNITUDE);
        let yy = self.y.square();
        let w = b.mul(FieldElement::ONE.sub(yy));
        let delta =
            a_minus_d.mul(FieldElement::from_u64(EDWARDS_A).add(yy.mul_small(EDWARDS_D_MAGNITUDE)));
        let root = delta.sqrt_fixed();
        let root_valid = root.is_some();
        let candidate = root.to_inner_unchecked();
        let second = b
            .mul_small(EDWARDS_D_MAGNITUDE)
            .neg()
            .mul(self.y.add(FieldElement::ONE))
            .mul(a_minus_d.neg().sub(candidate));
        (w, delta, candidate, second, root_valid)
    }

    /// Multiply by the fixed public prime order using its sparse bit pattern.
    ///
    /// The loop counts and additions depend only on
    /// [`PRIME_ORDER_SET_BITS_DESC`], never on point data. This is used for
    /// strict public-key subgroup validation and remains safe when the point
    /// was derived from a secret scalar because its control flow is entirely
    /// input-independent.
    #[cfg(any(test, feature = "sign-self-verify"))]
    fn scalar_mul_prime_order_sparse(self) -> Self {
        let mut accumulator = self;
        let mut current_bit = PRIME_ORDER_SET_BITS_DESC[0] as usize;
        let mut set_bit_index = 1;

        while set_bit_index < PRIME_ORDER_SET_BITS_DESC.len() {
            let set_bit = PRIME_ORDER_SET_BITS_DESC[set_bit_index] as usize;
            while current_bit > set_bit {
                accumulator = accumulator.double();
                current_bit -= 1;
            }
            accumulator = accumulator.add(self);
            set_bit_index += 1;
        }
        accumulator
    }

    /// Compute `[base_scalar]B - [point_scalar]point` for public verification.
    ///
    /// Both scalar recodings, branches and table indices are variable-time.
    /// Signature responses, challenges and verification keys are public, so
    /// this follows the same separation used by Ed25519/Ed448 implementations:
    /// secret signing stays on the constant-time fixed-base path while public
    /// verification uses a Straus/wNAF multiscalar multiplication.
    pub(crate) fn vartime_double_scalar_mul_basepoint(
        base_scalar: &Scalar,
        point_scalar: &Scalar,
        point_table: &VartimePointTable,
    ) -> Self {
        let base_digits = base_scalar.vartime_wnaf(BASEPOINT_WNAF_WIDTH);
        let point_digits = point_scalar.vartime_wnaf(POINT_WNAF_WIDTH);
        let mut top = FIELD_BITS;

        while top != 0 && base_digits[top] == 0 && point_digits[top] == 0 {
            top -= 1;
        }

        let mut result = Self::IDENTITY;
        loop {
            result = result.double();
            result = vartime_add_signed(result, base_digits[top], &BASEPOINT_ODD_TABLE, false);
            result = vartime_add_signed(result, point_digits[top], point_table, true);
            if top == 0 {
                break;
            }
            top -= 1;
        }
        result
    }

    /// Precompute public odd multiples for repeated verification.
    ///
    /// This table contains no secret material and its construction is
    /// deliberately variable-time.  A validated public key owns it so the
    /// per-signature path follows OpenSSL's prepared-key pattern.
    pub(crate) fn prepare_vartime_table(self) -> VartimePointTable {
        build_vartime_odd_point_table(self)
    }

    /// Encode a valid point as the canonical 38-byte compressed representation.
    #[cfg(test)]
    pub(crate) fn encode(&self) -> Result<[u8; FIELD_BYTES], EdwardsPointError> {
        self.encode_inner(false)
    }

    /// Encode a secret-derived point whose completed bytes are a public wire
    /// artifact, declassifying only impossible invariant-fault predicates in
    /// the Valgrind instrumentation build.
    pub(crate) fn encode_public_artifact(&self) -> Result<[u8; FIELD_BYTES], EdwardsPointError> {
        self.encode_inner(true)
    }

    /// Canonicalize a secret-derived public point without decoding its wire
    /// encoding again.
    ///
    /// Only affine coordinates that are uniquely determined by the completed
    /// public encoding cross the declassification boundary. The secret-tainted
    /// projective `Z` coordinate is deliberately discarded rather than being
    /// treated as public.
    pub(crate) fn canonical_public_artifact(
        &self,
    ) -> Result<([u8; FIELD_BYTES], Self), EdwardsPointError> {
        let (mut encoded, affine_x, affine_y) = self.encode_components(true)?;
        let mut canonical_point = Self::from_affine(affine_x, affine_y);
        declassify(&mut encoded);
        declassify(&mut canonical_point);
        Ok((encoded, canonical_point))
    }

    #[inline(always)]
    fn encode_inner(
        &self,
        declassify_fault_predicates: bool,
    ) -> Result<[u8; FIELD_BYTES], EdwardsPointError> {
        let (encoded, _, _) = self.encode_components(declassify_fault_predicates)?;
        Ok(encoded)
    }

    fn encode_components(
        &self,
        declassify_fault_predicates: bool,
    ) -> Result<([u8; FIELD_BYTES], FieldElement, FieldElement), EdwardsPointError> {
        let mut point_is_valid = self.is_valid();
        if declassify_fault_predicates {
            declassify(&mut point_is_valid);
        }
        if !point_is_valid.to_bool() {
            return Err(EdwardsPointError);
        }
        let inverse = self.z.invert().map(|value| secret(EncodingInverse(value)));
        #[cfg(test)]
        tests::encoding_inverse_failpoint();
        let mut inverse_is_present = inverse.is_some();
        if declassify_fault_predicates {
            declassify(&mut inverse_is_present);
        }
        if !inverse_is_present.to_bool() {
            return Err(EdwardsPointError);
        }
        let inverse_value = &inverse.as_inner_unchecked().0;
        let affine_x = self.x.mul(*inverse_value);
        let affine_y = self.y.mul(*inverse_value);
        let mut encoded = affine_y.to_canonical_bytes();
        encoded[FIELD_BYTES - 1] |= affine_x.is_odd().to_u8() << 7;
        Ok((encoded, affine_x, affine_y))
    }

    /// Decode a canonical compressed ED301-v2 point.
    ///
    /// Identity, torsion and mixed-order points are accepted here. Protocols
    /// requiring a nonidentity prime-subgroup point must use
    /// [`Self::decode_strict_subgroup`].
    pub(crate) fn decode(encoded: &[u8; FIELD_BYTES]) -> Result<Self, EdwardsPointError> {
        if encoded[FIELD_BYTES - 1] & 0x60 != 0 {
            return Err(EdwardsPointError);
        }

        let sign = Choice::from((encoded[FIELD_BYTES - 1] >> 7) & 1);
        let mut y_bytes = *encoded;
        y_bytes[FIELD_BYTES - 1] &= 0x1f;
        let y = FieldElement::from_canonical_bytes(&y_bytes)
            .into_option_copied()
            .ok_or(EdwardsPointError)?;
        let yy = y.square();
        let numerator = FieldElement::ONE.sub(yy);
        let denominator =
            FieldElement::from_u64(EDWARDS_A).sub(yy.mul_small(EDWARDS_D_MAGNITUDE).neg());
        let root = FieldElement::sqrt_ratio(numerator, denominator)
            .into_option_copied()
            .ok_or(EdwardsPointError)?;

        if root.is_zero().and(sign).to_bool() {
            return Err(EdwardsPointError);
        }
        let negate = root.is_odd().xor(sign);
        let x = FieldElement::conditional_select(root, root.neg(), negate);
        let point = Self::from_affine(x, y);
        if !point.is_valid().to_bool() {
            return Err(EdwardsPointError);
        }
        Ok(point)
    }

    /// Decode and require a nonidentity point of exact prime order `q`.
    #[cfg(test)]
    pub(crate) fn decode_strict_subgroup(
        encoded: &[u8; FIELD_BYTES],
    ) -> Result<Self, EdwardsPointError> {
        let point = Self::decode(encoded)?;
        if !point.is_prime_subgroup_nonidentity().to_bool() {
            return Err(EdwardsPointError);
        }
        Ok(point)
    }

    /// Return whether the point is the Edwards identity.
    pub(crate) fn is_identity(&self) -> Choice {
        self.x.is_zero().and(self.y.ct_eq(&self.z))
    }

    /// Return whether the point is nonidentity and satisfies `[q]P = I`.
    #[cfg(any(test, feature = "sign-self-verify"))]
    pub(crate) fn is_prime_subgroup_nonidentity(&self) -> Choice {
        self.is_identity().not().and(self.is_prime_subgroup())
    }

    /// Return whether `[L]P` is the identity, allowing the identity itself.
    #[cfg(any(test, feature = "sign-self-verify"))]
    pub(crate) fn is_prime_subgroup(&self) -> Choice {
        self.scalar_mul_prime_order_sparse().is_identity()
    }

    /// Multiply by the public cofactor four using two complete doublings.
    pub(crate) fn multiply_by_cofactor(self) -> Self {
        self.double().double()
    }

    /// Compare two valid projective points without affine inversion.
    #[cfg(test)]
    pub(crate) fn ct_eq(&self, rhs: &Self) -> Choice {
        self.x
            .mul(rhs.z)
            .ct_eq(&rhs.x.mul(self.z))
            .and(self.y.mul(rhs.z).ct_eq(&rhs.y.mul(self.z)))
    }

    fn is_valid(&self) -> Choice {
        let xx = self.x.square();
        let yy = self.y.square();
        let zz = self.z.square();
        let extended_relation = self.x.mul(self.y).ct_eq(&self.z.mul(self.t));
        let left = xx.mul_small(EDWARDS_A).mul(zz).add(yy.mul(zz));
        let right = zz.square().sub(xx.mul_small(EDWARDS_D_MAGNITUDE).mul(yy));

        self.z
            .is_zero()
            .not()
            .and(extended_relation)
            .and(left.ct_eq(&right))
    }

    #[cfg(test)]
    fn conditional_select(when_false: Self, when_true: Self, choice: Choice) -> Self {
        Self {
            x: FieldElement::conditional_select(when_false.x, when_true.x, choice),
            y: FieldElement::conditional_select(when_false.y, when_true.y, choice),
            z: FieldElement::conditional_select(when_false.z, when_true.z, choice),
            t: FieldElement::conditional_select(when_false.t, when_true.t, choice),
        }
    }
}

const fn build_basepoint_table() -> [AffineNielsPoint; BASEPOINT_TABLE_SIZE] {
    let mut projective = [EdwardsPoint::IDENTITY; BASEPOINT_TABLE_SIZE];
    let mut row_base = EdwardsPoint::BASEPOINT;
    let mut row = 0;

    while row < BASEPOINT_TABLE_ROWS {
        projective[row * BASEPOINT_TABLE_WIDTH] = row_base;
        let mut entry = 1;
        while entry < BASEPOINT_TABLE_WIDTH {
            projective[row * BASEPOINT_TABLE_WIDTH + entry] =
                projective[row * BASEPOINT_TABLE_WIDTH + entry - 1].add_const(row_base);
            entry += 1;
        }
        let mut doubling = 0;
        while doubling < 8 {
            row_base = row_base.double_const();
            doubling += 1;
        }
        row += 1;
    }
    batch_normalize_const(projective)
}

static BASEPOINT_TABLE: [AffineNielsPoint; BASEPOINT_TABLE_SIZE] = build_basepoint_table();

const fn build_basepoint_odd_table() -> [AffineNielsPoint; BASEPOINT_ODD_MULTIPLES] {
    let mut projective = [EdwardsPoint::IDENTITY; BASEPOINT_ODD_MULTIPLES];
    let step = EdwardsPoint::BASEPOINT.double_const();
    projective[0] = EdwardsPoint::BASEPOINT;
    let mut index = 1;
    while index < BASEPOINT_ODD_MULTIPLES {
        projective[index] = projective[index - 1].add_const(step);
        index += 1;
    }
    batch_normalize_const(projective)
}

static BASEPOINT_ODD_TABLE: [AffineNielsPoint; BASEPOINT_ODD_MULTIPLES] =
    build_basepoint_odd_table();

fn build_vartime_odd_point_table(point: EdwardsPoint) -> VartimePointTable {
    let mut projective = [EdwardsPoint::IDENTITY; POINT_ODD_MULTIPLES];
    let step = point.double();
    projective[0] = point;
    let mut index = 1;
    while index < POINT_ODD_MULTIPLES {
        projective[index] = projective[index - 1].add(step);
        index += 1;
    }
    batch_normalize(projective)
}

const fn batch_normalize_const<const N: usize>(points: [EdwardsPoint; N]) -> [AffineNielsPoint; N] {
    let mut prefixes = [FieldElement::ONE; N];
    let mut product = FieldElement::ONE;
    let mut index = 0;
    while index < N {
        prefixes[index] = product;
        product = product.mul_const(points[index].z);
        index += 1;
    }
    let mut inverse = product.invert_const_nonzero();
    let mut output = [AffineNielsPoint::IDENTITY; N];
    index = N;
    while index != 0 {
        index -= 1;
        let inverse_z = inverse.mul_const(prefixes[index]);
        inverse = inverse.mul_const(points[index].z);
        output[index] = AffineNielsPoint::from_projective_const(points[index], inverse_z);
    }
    output
}

fn batch_normalize<const N: usize>(points: [EdwardsPoint; N]) -> [AffineNielsPoint; N] {
    let mut prefixes = [FieldElement::ONE; N];
    let mut product = FieldElement::ONE;
    let mut index = 0;
    while index < N {
        prefixes[index] = product;
        product = product.mul(points[index].z);
        index += 1;
    }
    let mut inverse = product.invert().to_inner_unchecked();
    let mut output = [AffineNielsPoint::IDENTITY; N];
    index = N;
    while index != 0 {
        index -= 1;
        let inverse_z = inverse.mul(prefixes[index]);
        inverse = inverse.mul(points[index].z);
        output[index] = AffineNielsPoint::from_projective(points[index], inverse_z);
    }
    output
}

fn vartime_add_signed<const N: usize>(
    accumulator: EdwardsPoint,
    digit: i8,
    table: &[AffineNielsPoint; N],
    negate_scalar: bool,
) -> EdwardsPoint {
    if digit == 0 {
        return accumulator;
    }
    let magnitude = digit.unsigned_abs() as usize;
    let mut addend = table[magnitude >> 1];
    if (digit < 0) ^ negate_scalar {
        addend = addend.negate();
    }
    accumulator.add_affine(addend)
}

fn signed_radix16(scalar: &[u8; FIELD_BYTES]) -> crate::secret::Secret<[i8; RADIX16_DIGITS]> {
    let mut digits = crate::secret::secret([0_i8; RADIX16_DIGITS]);
    let mut index = 0;
    while index < RADIX16_DIGITS {
        digits[index] = ((scalar[index >> 1] >> ((index & 1) << 2)) & 0x0f) as i8;
        index += 1;
    }

    index = 0;
    while index + 1 < RADIX16_DIGITS {
        let carry = digits[index].wrapping_add(8) >> 4;
        digits[index] = digits[index].wrapping_sub(carry.wrapping_shl(4));
        digits[index + 1] = digits[index + 1].wrapping_add(carry);
        index += 1;
    }
    digits
}

fn select_basepoint(row: usize, digit: i8) -> AffineNielsPoint {
    let signed = digit as i16;
    let sign_mask = signed >> 15;
    let magnitude = (signed ^ sign_mask).wrapping_sub(sign_mask) as u8;
    let negative = Choice::from_u8_lsb((digit as u8) >> 7);
    let mut selected = AffineNielsPoint::IDENTITY;
    let mut entry = 0;

    while entry < BASEPOINT_TABLE_WIDTH {
        selected = AffineNielsPoint::conditional_select(
            selected,
            BASEPOINT_TABLE[row * BASEPOINT_TABLE_WIDTH + entry],
            Choice::from_u8_eq(magnitude, (entry + 1) as u8),
        );
        entry += 1;
    }
    AffineNielsPoint::conditional_select(selected, selected.negate(), negative)
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::test_support::{decode_hex_array, splitmix64};

    std::thread_local! {
        static FIXED_BASE_FAIL: core::cell::Cell<bool> = const { core::cell::Cell::new(false) };
        static POINT_DROPS: core::cell::Cell<usize> = const { core::cell::Cell::new(0) };
        static INVERSE_FAIL: core::cell::Cell<bool> = const { core::cell::Cell::new(false) };
        static INVERSE_DROPS: core::cell::Cell<usize> = const { core::cell::Cell::new(0) };
    }

    pub(super) fn point_zeroizations() -> usize {
        POINT_DROPS.with(core::cell::Cell::get)
    }

    pub(super) fn record_inverse_zeroization() {
        INVERSE_DROPS.with(|count| count.set(count.get() + 1));
    }

    pub(super) fn encoding_inverse_failpoint() {
        INVERSE_FAIL
            .with(|fail| assert!(!fail.replace(false), "controlled encoding-inverse unwind"));
    }

    pub(super) fn record_point_zeroization() {
        POINT_DROPS.with(|count| count.set(count.get() + 1));
    }

    pub(super) fn fixed_base_state_failpoint() {
        FIXED_BASE_FAIL
            .with(|fail| assert!(!fail.replace(false), "controlled fixed-base state unwind"));
    }

    #[test]
    fn fixed_base_secret_accumulator_zeroizes_during_unwind() {
        POINT_DROPS.with(|count| count.set(0));
        FIXED_BASE_FAIL.with(|fail| fail.set(true));
        let outcome =
            std::panic::catch_unwind(|| EdwardsPoint::scalar_mul_base_pruned(&TEST_PRUNED_SECRET));
        assert!(outcome.is_err());
        assert_eq!(POINT_DROPS.with(core::cell::Cell::get), 1);
        let point = EdwardsPoint::scalar_mul_base_pruned(&TEST_PRUNED_SECRET);
        assert_eq!(point.encode(), Ok(TEST_PUBLIC_ENCODING));
    }

    #[test]
    fn encoding_inverse_owner_zeroizes_on_return_and_unwind() {
        let before = INVERSE_DROPS.with(core::cell::Cell::get);
        assert_eq!(EdwardsPoint::BASEPOINT.encode(), Ok(BASEPOINT_ENCODING));
        assert_eq!(INVERSE_DROPS.with(core::cell::Cell::get), before + 1);

        INVERSE_FAIL.with(|fail| fail.set(true));
        let outcome = std::panic::catch_unwind(|| EdwardsPoint::BASEPOINT.encode());
        assert!(outcome.is_err());
        assert_eq!(INVERSE_DROPS.with(core::cell::Cell::get), before + 2);

        assert_eq!(EdwardsPoint::BASEPOINT.encode(), Ok(BASEPOINT_ENCODING));
        assert_eq!(INVERSE_DROPS.with(core::cell::Cell::get), before + 3);
    }

    const SCALAR_12345: [u8; FIELD_BYTES] = decode_hex_array(
        b"3930000000000000000000000000000000000000000000000000000000000000000000000000",
    );
    const MULTIPLE_12345_ENCODING: [u8; FIELD_BYTES] =
        crate::generated_parameters::MULTIPLE_12345_ENCODING;
    const TEST_PRUNED_SECRET: [u8; FIELD_BYTES] = crate::generated_parameters::TEST_PRUNED_SECRET;
    const TEST_PUBLIC_ENCODING: [u8; FIELD_BYTES] =
        crate::generated_parameters::TEST_PUBLIC_ENCODING;
    const TEST_NONCE_SCALAR: [u8; FIELD_BYTES] = crate::generated_parameters::TEST_NONCE_SCALAR;
    const TEST_COMMITMENT_ENCODING: [u8; FIELD_BYTES] =
        crate::generated_parameters::TEST_COMMITMENT_ENCODING;
    const FIELD_MODULUS_ENCODING: [u8; FIELD_BYTES] =
        crate::generated_parameters::FIELD_MODULUS_ENCODING;
    const ORDER_TWO_ENCODING: [u8; FIELD_BYTES] = crate::generated_parameters::ORDER_TWO_ENCODING;
    const ORDER_FOUR_ENCODING: [u8; FIELD_BYTES] = crate::generated_parameters::ORDER_FOUR_ENCODING;
    const MIXED_ORDER_TWO_ENCODING: [u8; FIELD_BYTES] =
        crate::generated_parameters::MIXED_ORDER_TWO_ENCODING;
    const MIXED_ORDER_FOUR_ENCODING: [u8; FIELD_BYTES] =
        crate::generated_parameters::MIXED_ORDER_FOUR_ENCODING;

    fn scalar(bytes: &[u8; FIELD_BYTES]) -> Scalar {
        Scalar::from_canonical_bytes(bytes)
            .expect_copied("test scalar must be canonically encoded below q")
    }

    /// The lazily reduced runtime formulas must agree with the canonical
    /// compile-time formulas on random prime-order points, on the small-order
    /// points, on the identity and on inverse pairs, including the cases that
    /// drive coordinates to zero or to `p - 1`.
    #[test]
    fn lazy_formulas_match_the_canonical_constant_formulas() {
        const RANDOM_POINTS: usize = 5_000;
        const FIXED_POINTS: usize = 7;

        fn affine_niels(point: EdwardsPoint) -> (AffineNielsPoint, EdwardsPoint) {
            let inverse_z = point
                .z
                .invert()
                .expect_copied("test points have a nonzero Z coordinate");
            let niels = AffineNielsPoint::from_projective(point, inverse_z);
            let affine = EdwardsPoint::from_affine(point.x.mul(inverse_z), point.y.mul(inverse_z));
            (niels, affine)
        }
        fn assert_same(index: usize, operation: &str, lazy: EdwardsPoint, canonical: EdwardsPoint) {
            assert!(
                lazy.is_valid().to_bool(),
                "point {index} {operation}: lazy result invalid"
            );
            assert!(
                lazy.ct_eq(&canonical).to_bool(),
                "point {index} {operation}: lazy and canonical differ"
            );
            for coordinate in [lazy.x, lazy.y, lazy.z, lazy.t] {
                assert!(
                    FieldElement::from_canonical_bytes(&coordinate.to_canonical_bytes())
                        .is_some()
                        .to_bool(),
                    "point {index} {operation}: lazy result coordinate is not canonical"
                );
            }
        }

        let mut points = [EdwardsPoint::IDENTITY; FIXED_POINTS + RANDOM_POINTS];
        points[1] = EdwardsPoint::BASEPOINT;
        points[2] = EdwardsPoint::BASEPOINT.negate();
        points[3] = EdwardsPoint::decode(&ORDER_TWO_ENCODING).expect("order-two point decodes");
        points[4] = EdwardsPoint::decode(&ORDER_FOUR_ENCODING).expect("order-four point decodes");
        points[5] = EdwardsPoint::decode(&MIXED_ORDER_TWO_ENCODING).expect("mixed point decodes");
        points[6] = EdwardsPoint::decode(&MIXED_ORDER_FOUR_ENCODING).expect("mixed point decodes");
        let mut state: u64 = 0x4c41_5a59_4544_5753;
        for point in points.iter_mut().skip(FIXED_POINTS) {
            let mut bytes = [0_u8; FIELD_BYTES];
            for byte in bytes.iter_mut() {
                *byte = splitmix64(&mut state) as u8;
            }
            bytes[FIELD_BYTES - 1] &= 0x1f;
            *point = EdwardsPoint::BASEPOINT.scalar_mul_encoded(&bytes);
        }

        let mut previous = EdwardsPoint::BASEPOINT;
        for (index, point) in points.iter().copied().enumerate() {
            assert_same(index, "double", point.double(), point.double_const());
            assert_same(index, "add", point.add(previous), point.add_const(previous));
            assert_same(
                index,
                "add negation",
                point.add(point.negate()),
                point.add_const(point.negate()),
            );
            assert!(point.add(point.negate()).is_identity().to_bool());
            let (niels, affine) = affine_niels(previous);
            assert_same(
                index,
                "add_affine",
                point.add_affine(niels),
                point.add_const(affine),
            );
            assert_same(
                index,
                "add_affine negated",
                point.add_affine(niels.negate()),
                point.add_const(affine.negate()),
            );
            let (self_niels, self_affine) = affine_niels(point);
            assert_same(
                index,
                "add_affine self",
                point.add_affine(self_niels),
                point.add_const(self_affine),
            );
            previous = point;
        }
    }

    #[test]
    fn folded_d_tables_and_negation_match_original_addition() {
        fn check(cached: AffineNielsPoint) {
            let affine = EdwardsPoint::from_affine(cached.x, cached.y);
            assert!(affine.is_valid().to_bool());
            assert!(cached.xy.ct_eq(&cached.x.add(cached.y)).to_bool());
            assert!(
                cached
                    .dt_abs
                    .ct_eq(&cached.x.mul(cached.y).mul_small(EDWARDS_D_MAGNITUDE))
                    .to_bool()
            );
            let constant = AffineNielsPoint::from_projective_const(affine, FieldElement::ONE);
            let runtime = AffineNielsPoint::from_projective(affine, FieldElement::ONE);
            assert!(constant.dt_abs.ct_eq(&cached.dt_abs).to_bool());
            assert!(runtime.dt_abs.ct_eq(&cached.dt_abs).to_bool());
            for point in [EdwardsPoint::IDENTITY, EdwardsPoint::BASEPOINT, affine] {
                assert!(
                    point
                        .add_affine(cached)
                        .ct_eq(&point.add_const(affine))
                        .to_bool()
                );
                assert!(
                    point
                        .add_affine(cached.negate())
                        .ct_eq(&point.add_const(affine.negate()))
                        .to_bool()
                );
            }
        }
        // Check every compile-time fixed-base entry, not just a regenerated
        // runtime table, so a mixed old/new dt convention cannot pass.
        for cached in BASEPOINT_TABLE {
            check(cached);
        }
        check(AffineNielsPoint::IDENTITY);
        for encoded in [
            ORDER_TWO_ENCODING,
            ORDER_FOUR_ENCODING,
            MIXED_ORDER_FOUR_ENCODING,
        ] {
            let point = EdwardsPoint::decode(&encoded).expect("directed point decodes");
            check(AffineNielsPoint::from_projective(point, FieldElement::ONE));
        }
    }

    #[test]
    fn basepoint_constant_roundtrips_and_has_exact_prime_order() {
        assert!(EdwardsPoint::BASEPOINT.is_valid().to_bool());
        assert_eq!(EdwardsPoint::BASEPOINT.encode(), Ok(BASEPOINT_ENCODING));

        let decoded = EdwardsPoint::decode_strict_subgroup(&BASEPOINT_ENCODING)
            .expect("the basepoint encoding must be a strict subgroup point");
        assert!(decoded.ct_eq(&EdwardsPoint::BASEPOINT).to_bool());
        assert!(
            EdwardsPoint::BASEPOINT
                .scalar_mul_encoded(&PRIME_ORDER_BYTES)
                .is_identity()
                .to_bool()
        );
    }

    #[test]
    fn fixed_base_radix16_matches_the_generic_constant_time_ladder() {
        for scalar_bytes in [[0_u8; FIELD_BYTES], SCALAR_12345, TEST_NONCE_SCALAR] {
            let scalar = scalar(&scalar_bytes);
            let expected = EdwardsPoint::BASEPOINT.scalar_mul(&scalar);
            let actual = EdwardsPoint::scalar_mul_base(&scalar);
            assert!(actual.ct_eq(&expected).to_bool());
        }

        let expected = EdwardsPoint::BASEPOINT.scalar_mul_pruned(&TEST_PRUNED_SECRET);
        let actual = EdwardsPoint::scalar_mul_base_pruned(&TEST_PRUNED_SECRET);
        assert!(actual.ct_eq(&expected).to_bool());
        assert_eq!(
            actual.encode(),
            Ok(TEST_PUBLIC_ENCODING),
            "the fixed-base path must match the Gate-B reference bytes"
        );
    }

    #[test]
    fn public_straus_and_affine_tables_match_complete_group_arithmetic() {
        let public = EdwardsPoint::decode_strict_subgroup(&TEST_PUBLIC_ENCODING)
            .expect("the reference public key is a strict subgroup point");
        let table = public.prepare_vartime_table();
        let mut near_order = PRIME_ORDER_BYTES;
        near_order[0] -= 1;
        let scalars = [
            Scalar::ZERO,
            Scalar::ONE,
            scalar(&SCALAR_12345),
            scalar(&TEST_NONCE_SCALAR),
            scalar(&near_order),
        ];

        for base_scalar in &scalars {
            for point_scalar in &scalars {
                let expected = EdwardsPoint::BASEPOINT
                    .scalar_mul(base_scalar)
                    .add(public.scalar_mul(point_scalar).negate());
                let actual = EdwardsPoint::vartime_double_scalar_mul_basepoint(
                    base_scalar,
                    point_scalar,
                    &table,
                );
                assert!(
                    actual.ct_eq(&expected).to_bool(),
                    "public wNAF/Straus arithmetic must retain the complete-formula result"
                );
            }
        }

        let mut odd_multiple = public;
        let step = public.double();
        for affine in table {
            let accumulator = EdwardsPoint::BASEPOINT.add(odd_multiple);
            assert!(
                EdwardsPoint::BASEPOINT
                    .add_affine(affine)
                    .ct_eq(&accumulator)
                    .to_bool(),
                "batch-normalized affine entries must retain their odd multiple"
            );
            odd_multiple = odd_multiple.add(step);
        }
    }

    #[test]
    fn complete_group_formulas_cover_identity_negation_and_doubling() {
        let base = EdwardsPoint::BASEPOINT;
        assert!(base.add(EdwardsPoint::IDENTITY).ct_eq(&base).to_bool());
        assert!(EdwardsPoint::IDENTITY.add(base).ct_eq(&base).to_bool());
        assert!(base.add(base.negate()).is_identity().to_bool());
        assert!(base.double().ct_eq(&base.add(base)).to_bool());
        assert!(base.scalar_mul(&Scalar::ZERO).is_identity().to_bool());
        assert!(base.scalar_mul(&Scalar::ONE).ct_eq(&base).to_bool());

        let mut two = [0_u8; FIELD_BYTES];
        two[0] = 2;
        assert!(
            base.scalar_mul(&scalar(&two))
                .ct_eq(&base.double())
                .to_bool()
        );
    }

    #[test]
    fn scalar_multiplication_calls_exactly_301_fixed_rounds() {
        let mut rounds = 0_usize;
        let result = EdwardsPoint::BASEPOINT.scalar_mul_with(|_| {
            rounds += 1;
            Choice::FALSE
        });

        assert_eq!(rounds, 301);
        assert!(result.is_identity().to_bool());
    }

    #[test]
    fn halving_matches_old_order_test_on_one_hundred_thousand_balanced_points() {
        let order_four = EdwardsPoint::decode(&ORDER_FOUR_ENCODING).expect("order four");
        let order_two = EdwardsPoint::decode(&ORDER_TWO_ENCODING).expect("order two");
        let torsion = [
            EdwardsPoint::IDENTITY,
            order_two,
            order_four,
            order_four.negate(),
        ];
        let mut state = 0x4533_4841_4c56_494e_u64;
        let mut counts = [[0_usize; 4]; 4];
        for index in 0..100_000 {
            let mut scalar_bytes = [0; FIELD_BYTES];
            for byte in &mut scalar_bytes {
                *byte = splitmix64(&mut state) as u8;
            }
            // k < 2^298 < q; keep k mod 4 and the torsion class independent
            // and exactly balanced, with 6,250 cases in every joint class.
            scalar_bytes[FIELD_BYTES - 1] &= 0x03;
            scalar_bytes[0] = (scalar_bytes[0] & !3) | (index & 3) as u8;
            let class = (index >> 2) & 3;
            counts[index & 3][class] += 1;
            let point = EdwardsPoint::scalar_mul_base_encoded(&scalar_bytes).add(torsion[class]);
            let encoded = point.encode().expect("random point encoding");
            let decoded = EdwardsPoint::decode(&encoded).expect("random point decoding");
            let table = decoded.prepare_vartime_table();
            let old = decoded
                .is_identity()
                .not()
                .and(decoded.is_prime_subgroup_with_table(&table));
            let new = decoded.is_prime_subgroup_decoded();
            assert_eq!(
                new.to_bool(),
                old.to_bool(),
                "random point {index}, torsion {class}"
            );
            assert_eq!(
                new.to_bool(),
                class == 0 && !decoded.is_identity().to_bool()
            );
        }
        assert_eq!(counts, [[6_250; 4]; 4]);
        for point in torsion.into_iter().chain([
            EdwardsPoint::BASEPOINT,
            EdwardsPoint::BASEPOINT.negate(),
            EdwardsPoint::BASEPOINT.add(order_two),
            EdwardsPoint::BASEPOINT.add(order_four),
            EdwardsPoint::BASEPOINT.add(order_four.negate()),
        ]) {
            let decoded = EdwardsPoint::decode(&point.encode().expect("directed encoding"))
                .expect("directed decoding");
            let table = decoded.prepare_vartime_table();
            let old = decoded
                .is_identity()
                .not()
                .and(decoded.is_prime_subgroup_with_table(&table));
            assert_eq!(decoded.is_prime_subgroup_decoded().to_bool(), old.to_bool());
        }
    }

    #[test]
    fn supplied_halving_vectors_match_every_production_intermediate() {
        fn decimal(value: &serde_json::Value) -> FieldElement {
            let integer =
                crypto_bigint::U320::from_str_radix_vartime(value.as_str().expect("decimal"), 10)
                    .expect("decimal field value");
            assert!(
                integer
                    < crypto_bigint::U320::from_words(crate::generated_parameters::MODULUS_WORDS)
            );
            FieldElement::from_canonical_words(integer.to_words())
        }
        fn same(actual: FieldElement, expected: FieldElement, label: &str) {
            assert_eq!(
                actual.to_canonical_bytes(),
                expected.to_canonical_bytes(),
                "{label}"
            );
        }
        let document: serde_json::Value = serde_json::from_str(include_str!(
            "../../../../vectors/ed301-v2-subgroup-halving.json"
        ))
        .expect("halving fixture");
        let b = FieldElement::from_canonical_words(crate::generated_parameters::MONTGOMERY_B_WORDS);
        same(b, decimal(&document["B_decimal"]), "B");
        assert_eq!(i8::from(b.legendre()), -1);
        let a = FieldElement::from_u64(EDWARDS_A);
        let d = FieldElement::from_u64(EDWARDS_D_MAGNITUDE).neg();
        assert_eq!(i8::from(d.mul(a.sub(d)).legendre()), 1);
        let cases = document["vectors"].as_array().expect("vector array");
        assert_eq!(cases.len(), 25);
        for case in cases {
            let label = case["label"].as_str().expect("label");
            let encoded = decode_hex_array::<FIELD_BYTES>(
                case["encoded_hex"].as_str().expect("encoded").as_bytes(),
            );
            let point = EdwardsPoint::decode(&encoded).expect("supplied point decodes");
            same(point.y, decimal(&case["y_decimal"]), label);
            let (w, delta, root, second, valid) = point.halving_terms();
            let in_two = point
                .is_identity()
                .or(point.y.ct_eq(&FieldElement::ONE.neg()))
                .or(w.legendre().is_one());
            assert_eq!(
                in_two.to_bool(),
                case["in_2E"].as_bool().expect("in 2E"),
                "{label}"
            );
            let new = point.is_prime_subgroup_decoded().to_bool();
            let old = point
                .is_prime_subgroup_with_table(&point.prepare_vartime_table())
                .to_bool();
            assert_eq!(new, case["in_4E"].as_bool().expect("in 4E"), "{label}");
            assert_eq!(
                old,
                case["in_4E_truth"].as_bool().expect("truth"),
                "{label}"
            );
            assert_eq!(new, old, "{label}");
            if case.get("w_decimal").is_some() {
                same(w, decimal(&case["w_decimal"]), label);
                assert_eq!(
                    i8::from(w.legendre()) as i64,
                    case["chi_w"].as_i64().expect("chi w"),
                    "{label}"
                );
            }
            if case.get("delta_decimal").is_some() {
                assert!(valid.to_bool(), "{label}");
                same(delta, decimal(&case["delta_decimal"]), label);
                same(root, decimal(&case["sqrt_delta_decimal"]), label);
                // These inversions and both roots exist only in the test.
                let inverse = d
                    .mul(point.y.add(FieldElement::ONE))
                    .invert()
                    .expect_copied("test denominator");
                let center = d.mul(point.y).add(a);
                for (index, numerator) in
                    [center.add(root), center.sub(root)].into_iter().enumerate()
                {
                    let t = numerator.mul(inverse);
                    same(t, decimal(&case["roots_decimal"][index]), label);
                    let expected = case["chi_B_1_minus_t_both_roots"][index]
                        .as_i64()
                        .expect("root symbol");
                    assert_eq!(
                        i8::from(b.mul(FieldElement::ONE.sub(t)).legendre()) as i64,
                        expected,
                        "{label}"
                    );
                    assert_eq!(
                        i8::from(second.legendre()) as i64,
                        expected,
                        "selection-free {label}"
                    );
                }
            }
        }
    }

    #[test]
    fn fixed_wnaf_subgroup_schedule_matches_the_sparse_reference() {
        // The hardcoded schedule must reconstruct the prime order exactly.
        let mut reconstructed = [0_i128; 5];
        for (position, digit) in PRIME_ORDER_WNAF8_DESC {
            let limb = position as usize / 64;
            let shift = position as usize % 64;
            reconstructed[limb] += (digit as i128) << shift;
        }
        let mut carried = [0_u64; 5];
        let mut carry = 0_i128;
        for (index, value) in reconstructed.into_iter().enumerate() {
            let total = value + carry;
            carried[index] = total as u64;
            carry = total >> 64;
        }
        assert_eq!(carry, 0);
        let mut expected = [0_u64; 5];
        for (index, byte) in PRIME_ORDER_BYTES.iter().enumerate() {
            expected[index / 8] |= (*byte as u64) << ((index % 8) * 8);
        }
        assert_eq!(carried, expected);

        // Torsion representatives with canonical encodings.
        let identity = {
            let mut encoding = [0_u8; FIELD_BYTES];
            encoding[0] = 1;
            EdwardsPoint::decode(&encoding).expect("identity decodes")
        };
        let order_two = EdwardsPoint::decode(&ORDER_TWO_ENCODING).expect("order-2 decodes");
        let order_four = EdwardsPoint::decode(&ORDER_FOUR_ENCODING).expect("order-4 decodes");
        let mixed_two =
            EdwardsPoint::decode(&MIXED_ORDER_TWO_ENCODING).expect("mixed order-2 decodes");
        let mixed_four =
            EdwardsPoint::decode(&MIXED_ORDER_FOUR_ENCODING).expect("mixed order-4 decodes");
        let torsion = [identity, order_two, order_four, order_four.negate()];

        let mut state: u64 = 0x574e_4146_3853_4348;
        let mut checked = 0_usize;
        let mut candidates = [EdwardsPoint::IDENTITY; 32];
        candidates[0] = identity;
        candidates[1] = order_two;
        candidates[2] = order_four;
        candidates[3] = order_four.negate();
        candidates[4] = mixed_two;
        candidates[5] = mixed_four;
        candidates[6] = EdwardsPoint::BASEPOINT;
        let mut index = 7;
        while index < candidates.len() {
            let mut scalar_bytes = [0_u8; FIELD_BYTES];
            for byte in scalar_bytes.iter_mut() {
                *byte = splitmix64(&mut state) as u8;
            }
            scalar_bytes[FIELD_BYTES - 1] &= 0x03;
            let multiple = EdwardsPoint::BASEPOINT.scalar_mul_encoded(&scalar_bytes);
            // Shift through the complete four-element torsion group.
            candidates[index] = multiple.add(torsion[index % torsion.len()]);
            index += 1;
        }

        for point in candidates {
            // Table construction must be total for every decodable point.
            let table = point.prepare_vartime_table();
            let fast = point.is_prime_subgroup_with_table(&table).to_bool();
            let reference = point.is_prime_subgroup().to_bool();
            assert_eq!(
                fast, reference,
                "fixed wNAF subgroup predicate diverged from the sparse reference"
            );
            checked += 1;
        }
        assert_eq!(checked, 32);
    }

    #[test]
    fn sparse_prime_order_schedule_matches_the_generic_ladder() {
        let mut reconstructed = [0_u8; FIELD_BYTES];
        for bit in PRIME_ORDER_SET_BITS_DESC {
            reconstructed[bit as usize >> 3] |= 1 << (bit as usize & 7);
        }
        assert_eq!(reconstructed, PRIME_ORDER_BYTES);

        let mut point = EdwardsPoint::IDENTITY;
        for _ in 0..2_048 {
            let sparse = point.scalar_mul_prime_order_sparse();
            let generic = point.scalar_mul_encoded(&PRIME_ORDER_BYTES);
            assert!(
                sparse.ct_eq(&generic).to_bool(),
                "the fixed sparse order schedule must match the generic ladder"
            );
            point = point.add(EdwardsPoint::BASEPOINT);
        }

        for encoded in [
            ORDER_TWO_ENCODING,
            ORDER_FOUR_ENCODING,
            MIXED_ORDER_TWO_ENCODING,
            MIXED_ORDER_FOUR_ENCODING,
        ] {
            let point = EdwardsPoint::decode(&encoded).expect("the torsion case must decode");
            assert!(
                point
                    .scalar_mul_prime_order_sparse()
                    .ct_eq(&point.scalar_mul_encoded(&PRIME_ORDER_BYTES))
                    .to_bool(),
                "the sparse schedule must retain torsion behavior"
            );
        }
    }

    #[test]
    fn canonical_public_artifact_matches_strict_decode() {
        let mut point = EdwardsPoint::BASEPOINT;
        for _ in 0..128 {
            let (encoded, canonical) = point
                .canonical_public_artifact()
                .expect("a valid point must canonicalize");
            let decoded = EdwardsPoint::decode(&encoded).expect("the artifact must decode");
            assert!(canonical.ct_eq(&decoded).to_bool());
            assert_eq!(canonical.encode(), Ok(encoded));
            point = point.add(EdwardsPoint::BASEPOINT);
        }
    }

    #[test]
    fn fixed_12345_multiple_matches_the_curve_reference() {
        let multiple = EdwardsPoint::BASEPOINT.scalar_mul(&scalar(&SCALAR_12345));
        assert_eq!(multiple.encode(), Ok(MULTIPLE_12345_ENCODING));
        assert!(multiple.is_prime_subgroup_nonidentity().to_bool());
    }

    #[test]
    fn gate_b_vector_points_match_scalar_multiplication() {
        let public = EdwardsPoint::BASEPOINT.scalar_mul_pruned(&TEST_PRUNED_SECRET);
        let commitment = EdwardsPoint::BASEPOINT.scalar_mul(&scalar(&TEST_NONCE_SCALAR));
        assert_eq!(public.encode(), Ok(TEST_PUBLIC_ENCODING));
        assert_eq!(commitment.encode(), Ok(TEST_COMMITMENT_ENCODING));

        for encoded in [TEST_PUBLIC_ENCODING, TEST_COMMITMENT_ENCODING] {
            let decoded = EdwardsPoint::decode_strict_subgroup(&encoded)
                .expect("Gate-B signer output must pass strict subgroup decoding");
            assert_eq!(decoded.encode(), Ok(encoded));
        }
    }

    #[test]
    fn strict_decoding_rejects_identity_torsion_and_mixed_order() {
        let mut identity_encoding = [0_u8; FIELD_BYTES];
        identity_encoding[0] = 1;
        let identity = EdwardsPoint::decode(&identity_encoding)
            .expect("the identity has a canonical general point encoding");
        assert!(identity.is_identity().to_bool());
        assert!(EdwardsPoint::decode_strict_subgroup(&identity_encoding).is_err());

        let order_two = EdwardsPoint::decode(&ORDER_TWO_ENCODING)
            .expect("the rational order-two point has a canonical encoding");
        assert!(EdwardsPoint::decode_strict_subgroup(&ORDER_TWO_ENCODING).is_err());

        let mixed = EdwardsPoint::BASEPOINT.add(order_two);
        let mixed_encoding = mixed.encode().expect("a mixed-order point must encode");
        assert!(EdwardsPoint::decode(&mixed_encoding).is_ok());
        assert!(EdwardsPoint::decode_strict_subgroup(&mixed_encoding).is_err());
    }

    #[test]
    fn decoding_rejects_noncanonical_and_nonpoint_encodings() {
        let mut reserved_301 = BASEPOINT_ENCODING;
        reserved_301[FIELD_BYTES - 1] |= 0x20;
        assert!(EdwardsPoint::decode(&reserved_301).is_err());

        let mut reserved_302 = BASEPOINT_ENCODING;
        reserved_302[FIELD_BYTES - 1] |= 0x40;
        assert!(EdwardsPoint::decode(&reserved_302).is_err());
        assert!(EdwardsPoint::decode(&FIELD_MODULUS_ENCODING).is_err());

        let nonpoint = crate::generated_parameters::NONPOINT_ENCODING;
        assert!(EdwardsPoint::decode(&nonpoint).is_err());

        let mut noncanonical_identity = [0_u8; FIELD_BYTES];
        noncanonical_identity[0] = 1;
        noncanonical_identity[FIELD_BYTES - 1] = 0x80;
        assert!(EdwardsPoint::decode(&noncanonical_identity).is_err());
    }
}
