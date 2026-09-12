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

// Crate-private sizes needed by the shared Edwards/scalar module. They do not
// expose scalar reduction or EdDSA pruning as an X301 operation.
pub(crate) const SCALAR_BYTES: usize = FIELD_BYTES;
pub(crate) const HASH_BYTES: usize = 2 * FIELD_BYTES;

const _: () = {
    assert!(FIELD_BITS == 301);
    assert!(FIELD_BYTES == 38);
    // Keep the word form bound to the public bytes even though only the test
    // oracle needs it at runtime after fixed-base public derivation.
    let words = crate::x_generated_parameters::BASE_U_WORDS;
    let bytes = crate::x_generated_parameters::BASE_U_BYTES;
    assert!(words[4] >> 45 == 0);
    let mut index = 0;
    while index < FIELD_BYTES {
        assert!((words[index / 8] >> (8 * (index % 8))) as u8 == bytes[index]);
        index += 1;
    }
};
