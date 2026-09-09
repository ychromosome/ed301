// SPDX-License-Identifier: Apache-2.0
// Whole-process lifecycle high-water marks, not isolated per-call stack bounds.
#![forbid(unsafe_code)]
use ed301_eddsa::{ExpandedSigningKey, SigningKey, VerifyingKey};
use std::hint::black_box;

#[inline(never)]
fn expand(seed: &[u8; 38], count: u64) {
    for _ in 0..count {
        black_box(
            SigningKey::from_seed(black_box(seed))
                .unwrap()
                .expand()
                .unwrap(),
        );
    }
}

#[inline(never)]
fn cold_sign(seed: &[u8; 38], message: &[u8], context: &[u8], count: u64) {
    for _ in 0..count {
        black_box(
            SigningKey::from_seed(black_box(seed))
                .unwrap()
                .sign_with_context(black_box(message), black_box(context))
                .unwrap(),
        );
    }
}

#[inline(never)]
fn prepared_sign(seed: &[u8; 38], message: &[u8], context: &[u8], count: u64) {
    let expanded = SigningKey::from_seed(seed).unwrap().expand().unwrap();
    for _ in 0..count {
        black_box(
            expanded
                .sign_with_context(black_box(message), black_box(context))
                .unwrap(),
        );
    }
}

#[inline(never)]
fn public_bytes(seed: &[u8; 38]) -> [u8; 38] {
    *SigningKey::from_seed(seed)
        .unwrap()
        .expand()
        .unwrap()
        .verifying_key_bytes()
}

#[inline(never)]
fn public_import(seed: &[u8; 38], count: u64) {
    let public = public_bytes(seed);
    for _ in 0..count {
        black_box(VerifyingKey::from_bytes(black_box(&public)).unwrap());
    }
}

#[inline(never)]
fn prepare_verifier(seed: &[u8; 38], count: u64) {
    let expanded = SigningKey::from_seed(seed).unwrap().expand().unwrap();
    for _ in 0..count {
        black_box(expanded.verifying_key());
    }
}

#[inline(never)]
fn prepared_verify(seed: &[u8; 38], message: &[u8], context: &[u8], count: u64) {
    let expanded: ExpandedSigningKey = SigningKey::from_seed(seed).unwrap().expand().unwrap();
    let signature = expanded.sign_with_context(message, context).unwrap();
    let verifying = VerifyingKey::from_bytes(expanded.verifying_key_bytes()).unwrap();
    for _ in 0..count {
        assert!(black_box(verifying.verify_bytes_with_context(
            black_box(message),
            black_box(context),
            black_box(signature.as_bytes())
        )));
    }
}

#[inline(never)]
fn import_verify(seed: &[u8; 38], message: &[u8], context: &[u8], count: u64) {
    let expanded = SigningKey::from_seed(seed).unwrap().expand().unwrap();
    let public = *expanded.verifying_key_bytes();
    let signature = expanded.sign_with_context(message, context).unwrap();
    for _ in 0..count {
        let verifying = VerifyingKey::from_bytes(black_box(&public)).unwrap();
        assert!(black_box(verifying.verify_bytes_with_context(
            black_box(message),
            black_box(context),
            black_box(signature.as_bytes())
        )));
    }
}

#[inline(never)]
fn stack_control() {
    let mut buffer = [0_u8; 262144];
    for (i, byte) in buffer.iter_mut().enumerate() {
        *byte = (i * 17 + 3) as u8;
    }
    black_box(&mut buffer);
}

#[inline(never)]
fn rss_control() {
    let mut buffer = vec![0_u8; 8 * 1024 * 1024];
    for byte in buffer.iter_mut().step_by(4096) {
        *byte = 0xa5; // Fault in physical pages rather than only reserving address space.
    }
    black_box(&mut buffer);
}

fn main() -> Result<(), &'static str> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.len() != 4 {
        return Err("usage: operation message-length context-length count");
    }
    let m: usize = args[1].parse().map_err(|_| "message")?;
    let c: usize = args[2].parse().map_err(|_| "context")?;
    let count: u64 = args[3].parse().map_err(|_| "count")?;
    if m > 16384 || c > 255 || !(1..=10000).contains(&count) {
        return Err("outside resource-harness bounds");
    }
    let seed: [u8; 38] = std::array::from_fn(|i| i as u8);
    let message = vec![0x5a_u8; m];
    let context: Vec<u8> = (0..c).map(|i| (i * 17 + 3) as u8).collect();
    match args[0].as_str() {
        "empty" => {
            black_box((&message, &context, &seed, count));
        }
        "seed-expand" => expand(&seed, count),
        "cold-sign" => cold_sign(&seed, &message, &context, count),
        "prepared-sign" => prepared_sign(&seed, &message, &context, count),
        "public-import" => public_import(&seed, count),
        "prepare-verifier" => prepare_verifier(&seed, count),
        "prepared-verify" => prepared_verify(&seed, &message, &context, count),
        "import-verify" => import_verify(&seed, &message, &context, count),
        "stack-control" => stack_control(),
        "rss-control" => rss_control(),
        _ => return Err("unknown operation"),
    }
    println!(
        "RESOURCE_DONE operation={} message_bytes={m} context_bytes={c} count={count}",
        args[0]
    );
    Ok(())
}
