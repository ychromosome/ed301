//! Ed301-EdDSA-v2 deterministic, one-shot signatures with native contexts.
//! Public-key import is variable-time and accepts only public data.

#![no_std]
#![forbid(unsafe_code)]
#![deny(missing_docs)]

#[cfg(not(panic = "unwind"))]
compile_error!("ed301-eddsa requires panic=unwind so named secret owners are dropped");

mod edwards;
mod field;
mod field_5x64;
mod generated_parameters;
pub mod parameters;
mod scalar;
mod secret;
mod secret_taint;
pub mod signature;
mod signature_hash;
#[cfg(test)]
mod test_support;

pub use signature::{
    ExpandedSigningKey, Signature, SignatureError, SigningKey, ValidatedPublicKey, VerifyingKey,
    sign, sign_with_context, validate_public_key, verify, verify_with_context,
};

#[cfg(test)]
mod vector_tests;
