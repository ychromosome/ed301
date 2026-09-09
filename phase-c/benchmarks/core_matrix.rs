// SPDX-License-Identifier: Apache-2.0
// One identical public-API harness is built against each bound implementation.
use ed301_eddsa::{ExpandedSigningKey, Signature, SigningKey, VerifyingKey};
use std::hint::black_box;
use std::mem::size_of;
use std::time::Instant;

fn measure(mut operation: impl FnMut(), count: u64) -> f64 {
    let start = Instant::now();
    for _ in 0..count {
        operation();
    }
    start.elapsed().as_secs_f64() * 1e9 / count as f64
}

fn main() -> Result<(), &'static str> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.as_slice() == ["sizes"] {
        println!(
            "SIZES SigningKey={} ExpandedSigningKey={} VerifyingKey={} Signature={}",
            size_of::<SigningKey>(),
            size_of::<ExpandedSigningKey>(),
            size_of::<VerifyingKey>(),
            size_of::<Signature>()
        );
        return Ok(());
    }
    if args.len() != 4 {
        return Err("usage: operation message-length context-length count; or sizes");
    }
    let message_len: usize = args[1].parse().map_err(|_| "message length")?;
    let context_len: usize = args[2].parse().map_err(|_| "context length")?;
    let count: u64 = args[3].parse().map_err(|_| "count")?;
    if message_len > 16384 || context_len > 255 || !(1..=100000).contains(&count) {
        return Err("argument outside benchmark bounds");
    }
    let seed: [u8; 38] = std::array::from_fn(|i| i as u8);
    let message: Vec<u8> = (0..message_len).map(|i| (i * 29 + 7) as u8).collect();
    let context: Vec<u8> = (0..context_len).map(|i| (i * 17 + 3) as u8).collect();
    let expanded = SigningKey::from_seed(&seed)
        .map_err(|_| "seed")?
        .expand()
        .map_err(|_| "expand")?;
    let public = *expanded.verifying_key_bytes();
    let verifying = VerifyingKey::from_bytes(&public).map_err(|_| "public")?;
    let signature = expanded
        .sign_with_context(&message, &context)
        .map_err(|_| "signature")?;
    if !verifying.verify_with_context(&message, &context, &signature) {
        return Err("self-test");
    }
    let mean_ns = match args[0].as_str() {
        "cold-sign" => measure(
            || {
                let key = SigningKey::from_seed(black_box(&seed)).unwrap();
                black_box(
                    key.sign_with_context(black_box(&message), black_box(&context))
                        .unwrap(),
                );
            },
            count,
        ),
        "prepared-sign" => measure(
            || {
                black_box(
                    expanded
                        .sign_with_context(black_box(&message), black_box(&context))
                        .unwrap(),
                );
            },
            count,
        ),
        "prepared-verify" => measure(
            || {
                assert!(black_box(verifying.verify_bytes_with_context(
                    black_box(&message),
                    black_box(&context),
                    black_box(signature.as_bytes()),
                )));
            },
            count,
        ),
        "import-verify" => measure(
            || {
                let key = VerifyingKey::from_bytes(black_box(&public)).unwrap();
                assert!(black_box(key.verify_bytes_with_context(
                    black_box(&message),
                    black_box(&context),
                    black_box(signature.as_bytes()),
                )));
            },
            count,
        ),
        "prepare-verifier" => measure(
            || {
                black_box(expanded.verifying_key());
            },
            count,
        ),
        _ => return Err("unknown operation"),
    };
    println!(
        "RESULT operation={} message_bytes={message_len} context_bytes={context_len} count={count} mean_ns={mean_ns:.3}",
        args[0]
    );
    Ok(())
}
