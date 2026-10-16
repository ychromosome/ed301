use std::hint::black_box;
use std::time::Instant;
use x301_core::{PublicKey, SecretKey, x301};

fn parse_count(value: Option<String>) -> Result<u64, &'static str> {
    let count = value
        .ok_or("missing count")?
        .parse::<u64>()
        .map_err(|_| "invalid count")?;
    if count == 0 || count > 100_000_000 {
        return Err("count outside 1..=100000000");
    }
    Ok(count)
}

fn measure<T>(mut operation: impl FnMut() -> T, count: u64) -> f64 {
    let started = Instant::now();
    for _ in 0..count {
        black_box(operation());
    }
    started.elapsed().as_secs_f64() * 1_000_000_000.0 / count as f64
}

fn main() -> Result<(), &'static str> {
    let mut arguments = std::env::args().skip(1);
    let operation = arguments.next().ok_or("missing operation")?;
    let count = parse_count(arguments.next())?;
    if arguments.next().is_some() {
        return Err("too many arguments");
    }

    let seed: [u8; 38] = std::array::from_fn(|i| i as u8);
    let other: [u8; 38] = std::array::from_fn(|i| (37 - i) as u8);
    let public = x301::public_from_secret(&seed).map_err(|_| "public")?;
    let peer = x301::public_from_secret(&other).map_err(|_| "peer")?;
    let shared = x301::shared_secret(&seed, &peer).map_err(|_| "shared")?;
    let reverse = x301::shared_secret(&other, &public).map_err(|_| "reverse shared")?;
    if shared.as_bytes() != reverse.as_bytes() {
        return Err("self-test");
    }
    let secret = SecretKey::from_bytes(&seed).map_err(|_| "secret key")?;
    let peer_key = PublicKey::from_bytes(&peer).map_err(|_| "peer key")?;

    let mean_ns = match operation.as_str() {
        "public" => measure(
            || x301::public_from_secret(black_box(&seed)).unwrap(),
            count,
        ),
        "shared" => measure(
            || x301::shared_secret(black_box(&seed), black_box(&peer)).unwrap(),
            count,
        ),
        "import-secret" => measure(|| SecretKey::from_bytes(black_box(&seed)).unwrap(), count),
        "import-public" => measure(|| PublicKey::from_bytes(black_box(&peer)).unwrap(), count),
        "prepared-public" => measure(|| secret.public_key().unwrap(), count),
        "prepared-shared" => measure(
            || secret.shared_secret(black_box(&peer_key)).unwrap(),
            count,
        ),
        _ => {
            return Err(
                "operation must be public, shared, import-secret, import-public, \
                 prepared-public or prepared-shared",
            );
        }
    };
    println!("RESULT operation={operation} count={count} mean_ns={mean_ns:.3}");
    Ok(())
}
