// SPDX-License-Identifier: Apache-2.0
// Identical shared API harness for the bound integration-v1 and D1-v2 cores.
use std::{hint::black_box, time::Instant};
use x301_implementation::x301 as api;

fn measure<T>(mut operation: impl FnMut() -> T, count: u64) -> f64 {
    let start = Instant::now();
    for _ in 0..count {
        black_box(operation());
    }
    start.elapsed().as_secs_f64() * 1e9 / count as f64
}

fn main() -> Result<(), &'static str> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.len() != 2 {
        return Err("usage: operation count");
    }
    let count: u64 = args[1].parse().map_err(|_| "count")?;
    if !(1..=100_000_000).contains(&count) {
        return Err("count out of range");
    }
    let seed: [u8; 38] = std::array::from_fn(|i| i as u8);
    let other: [u8; 38] = std::array::from_fn(|i| (37 - i) as u8);
    let public = api::public_from_secret(&seed).map_err(|_| "public")?;
    let peer = api::public_from_secret(&other).map_err(|_| "peer")?;
    if api::shared_secret(&seed, &peer)
        .map_err(|_| "shared")?
        .as_bytes()
        != api::shared_secret(&other, &public)
            .map_err(|_| "other shared")?
            .as_bytes()
    {
        return Err("DH self-test");
    }
    #[cfg(feature = "v2")]
    let prepared =
        x301_implementation::SecretKey::from_bytes(&seed).map_err(|_| "prepared secret")?;
    #[cfg(feature = "v2")]
    let prepared_peer =
        x301_implementation::PublicKey::from_bytes(&peer).map_err(|_| "prepared peer")?;
    let mean = match args[0].as_str() {
        "public" => measure(|| api::public_from_secret(black_box(&seed)).unwrap(), count),
        "shared" => measure(
            || api::shared_secret(black_box(&seed), black_box(&peer)).unwrap(),
            count,
        ),
        "validate-public" => measure(
            || api::validate_public_encoding(black_box(&peer)).unwrap(),
            count,
        ),
        "canonical-public" => measure(
            || api::canonicalize_public_encoding(black_box(&peer)).unwrap(),
            count,
        ),
        #[cfg(feature = "v2")]
        "import-secret" => measure(
            || x301_implementation::SecretKey::from_bytes(black_box(&seed)).unwrap(),
            count,
        ),
        #[cfg(feature = "v2")]
        "import-public" => measure(
            || x301_implementation::PublicKey::from_bytes(black_box(&peer)).unwrap(),
            count,
        ),
        #[cfg(feature = "v2")]
        "prepared-shared" => measure(
            || prepared.shared_secret(black_box(&prepared_peer)).unwrap(),
            count,
        ),
        #[cfg(feature = "v2")]
        "prepared-public" => measure(|| prepared.public_key().unwrap(), count),
        _ => return Err("unknown operation or unavailable version-specific object API"),
    };
    println!(
        "RESULT operation={} count={count} mean_ns={mean:.3}",
        args[0]
    );
    #[cfg(feature = "v2")]
    println!(
        "OBJECT_BYTES SecretKey={} PublicKey={} SharedSecret={}",
        std::mem::size_of::<x301_implementation::SecretKey>(),
        std::mem::size_of::<x301_implementation::PublicKey>(),
        std::mem::size_of::<x301_implementation::SharedSecret>()
    );
    Ok(())
}
