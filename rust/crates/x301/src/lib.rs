//! Experimental strictly encoded X301-v2 raw Diffie-Hellman core.
//!
//! The output is secret raw key material, not a KDF, authentication protocol
//! or production-approved channel. Phase-D validation is required.

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
#[path = "../../ed301-eddsa/src/secret_taint.rs"]
mod secret_taint;
mod x_generated_parameters;

pub mod parameters;
pub mod x301;
pub use x301::{
    PublicKey, SecretKey, SharedSecret, X301Error, X301KeyGenError, canonicalize_public_encoding,
    keygen, public_from_secret, shared_secret, validate_public_encoding, x301,
};

// Fe301 is a Copy canonical five-word value and its reviewed Default is zero.
// zeroize supplies the volatile overwrite and optimization barrier.
impl zeroize::DefaultIsZeroes for field_5x64::Fe301 {}

#[cfg(test)]
extern crate std;
#[cfg(test)]
#[path = "../../ed301-eddsa/src/test_support.rs"]
mod test_support;
#[cfg(test)]
mod tests;
