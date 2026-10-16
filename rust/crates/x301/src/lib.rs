//! Strictly encoded X301-v2 raw Diffie-Hellman core.
//!
//! The output is secret raw key material, not a KDF, authentication protocol
//! or authenticated channel.

#![no_std]
#![forbid(unsafe_code)]
#![deny(missing_docs)]

#[cfg(not(panic = "unwind"))]
compile_error!("x301-core requires panic=unwind for named zeroizing owners");

#[path = "../../ed301-eddsa/src/field.rs"]
mod field;
#[allow(
    dead_code,
    reason = "shared reviewed field also provides EdDSA-only lazy/table helpers"
)]
#[path = "../../ed301-eddsa/src/field_5x64.rs"]
mod field_5x64;
#[allow(
    dead_code,
    reason = "the hash-bound shared constants include EdDSA test and table values"
)]
#[path = "../../ed301-eddsa/src/generated_parameters.rs"]
mod generated_parameters;
// Share the actual Edwards table/formulas, not a fork or a public EdDSA API.
// The scalar module satisfies the shared Edwards module's unused EdDSA entry
// points; X301 passes its exact clamp bytes directly, never through Scalar.
#[allow(
    dead_code,
    reason = "shared group also contains EdDSA verification helpers"
)]
#[path = "../../ed301-eddsa/src/edwards.rs"]
mod edwards;
#[allow(
    dead_code,
    reason = "shared group also contains canonical EdDSA scalar APIs"
)]
#[path = "../../ed301-eddsa/src/scalar.rs"]
mod scalar;
#[path = "../../ed301-eddsa/src/secret.rs"]
mod secret;
#[path = "../../ed301-eddsa/src/secret_taint.rs"]
mod secret_taint;
mod x_generated_parameters;

pub mod parameters;
pub mod x301;
pub use x301::{
    PublicKey, SecretKey, SharedSecret, X301Error, X301KeyGenError, canonicalize_public_encoding,
    keygen, public_from_secret, shared_secret, validate_public_encoding, x301,
};

#[cfg(test)]
extern crate std;
#[cfg(test)]
#[path = "../../ed301-eddsa/src/test_support.rs"]
mod test_support;
#[cfg(test)]
mod tests;
