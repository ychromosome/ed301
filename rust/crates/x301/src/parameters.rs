//! Public sizes and version identity of the X301-v2 raw XDH profile.

/// Public project/algorithm name; provider identities remain separately versioned.
pub const ALGORITHM_NAME: &str = "X301";
/// Versioned specification identifier, distinct from every historical X301-v1 profile.
pub const SPECIFICATION_VERSION: &str = "X301-v2";
/// Prime-field bit length from Gate A.
pub const FIELD_BITS: usize = crate::x_generated_parameters::FIELD_BITS;
/// Exact field-coordinate byte length.
pub const FIELD_BYTES: usize = crate::x_generated_parameters::FIELD_BYTES;
/// Exact raw private-input length.
pub const SECRET_BYTES: usize = FIELD_BYTES;
/// Exact canonical public-coordinate length.
pub const PUBLIC_BYTES: usize = FIELD_BYTES;
/// Exact successful raw shared-coordinate length.
pub const SHARED_BYTES: usize = FIELD_BYTES;
/// Fixed number of ladder rounds, including leading zero bits.
pub const LADDER_BITS: usize = FIELD_BITS;

const _: () = {
    assert!(FIELD_BITS == 301);
    assert!(FIELD_BYTES == 38);
};
