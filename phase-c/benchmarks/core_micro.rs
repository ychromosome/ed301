// SPDX-License-Identifier: Apache-2.0
// Included by a test-only crate that compiles the original private modules.
// No product visibility, arithmetic source or safety check is changed.
use crate::field_5x64::{Fe301, Fe301Lazy};
use crate::scalar::Scalar;
use std::hint::black_box;
use std::time::Instant;

fn measure<T>(mut operation: impl FnMut(usize) -> T, count: u64) -> f64 {
    let start = Instant::now();
    for index in 0..count {
        // Includes the loop, operand selection, black_box and result drop.
        black_box(operation((index as usize) & 15));
    }
    start.elapsed().as_secs_f64() * 1e9 / count as f64
}

fn main() -> Result<(), &'static str> {
    let mut args = std::env::args().skip(1);
    let operation = args.next().ok_or("operation missing")?;
    let count = args
        .next()
        .ok_or("count missing")?
        .parse::<u64>()
        .map_err(|_| "invalid count")?;
    if args.next().is_some() || !(1..=100_000_000).contains(&count) {
        return Err("count outside benchmark bounds or extra arguments");
    }
    let bytes: [[u8; 38]; 16] = std::array::from_fn(|j| {
        let mut value = std::array::from_fn(|i| (i * 29 + j * 17 + 7) as u8);
        value[37] &= 0x03; // Less than either bound p or q; never zero.
        value
    });
    let fields: [Fe301; 16] = std::array::from_fn(|i| {
        Fe301::from_canonical_bytes(&bytes[i]).expect_copied("canonical field input")
    });
    let lazy: [Fe301Lazy; 16] = std::array::from_fn(|i| Fe301Lazy::from_fe301(fields[i]));
    let scalars: [Scalar; 16] = std::array::from_fn(|i| {
        Scalar::from_canonical_bytes(&bytes[i]).expect_copied("canonical scalar input")
    });
    let hashes: [[u8; 76]; 16] =
        std::array::from_fn(|j| std::array::from_fn(|i| (i * 31 + j * 19 + 11) as u8));
    let pruned: [[u8; 38]; 16] = std::array::from_fn(|j| {
        let mut value = bytes[j];
        value[0] &= 0xfc;
        value[37] = (value[37] & 0x0f) | 0x10;
        value
    });
    // Non-timed correctness controls exercise both field and scalar inputs.
    for value in fields {
        let inverse = value.invert().expect_copied("nonzero input");
        assert!(value.mul(inverse).ct_eq(&Fe301::ONE).to_bool());
    }
    for (input, value) in bytes.iter().zip(&scalars) {
        let mut encoded = [0_u8; 38];
        value.write_canonical_bytes(&mut encoded);
        assert_eq!(&encoded, input);
    }
    let ns = match operation.as_str() {
        "control-field-copy" => measure(|i| black_box(fields[i]), count),
        "field-add" => measure(
            |i| black_box(fields[i]).add(black_box(fields[(i + 7) & 15])),
            count,
        ),
        "field-sub" => measure(
            |i| black_box(fields[i]).sub(black_box(fields[(i + 7) & 15])),
            count,
        ),
        "field-mul" => measure(
            |i| black_box(fields[i]).mul(black_box(fields[(i + 7) & 15])),
            count,
        ),
        "field-square" => measure(|i| black_box(fields[i]).square(), count),
        "field-mul-301" => measure(|i| black_box(fields[i]).mul_small(301), count),
        "field-mul-a" => measure(
            |i| black_box(fields[i]).mul_small(parameters::EDWARDS_A),
            count,
        ),
        "field-mul-d" => measure(
            |i| {
                let value = black_box(fields[i]).mul_small(301);
                if cfg!(feature = "profile-v2") {
                    value.neg()
                } else {
                    value
                }
            },
            count,
        ),
        "field-invert" => measure(|i| black_box(fields[i]).invert(), count),
        "field-sqrt-ratio" => measure(
            |i| Fe301::sqrt_ratio(black_box(fields[i]), black_box(fields[(i + 7) & 15])),
            count,
        ),
        "lazy-mul" => measure(
            |i| black_box(lazy[i]).mul(black_box(lazy[(i + 7) & 15])),
            count,
        ),
        "lazy-square" => measure(|i| black_box(lazy[i]).square(), count),
        "lazy-mul-a" => measure(
            |i| black_box(lazy[i]).mul_small(parameters::EDWARDS_A),
            count,
        ),
        "lazy-loose-mul" => measure(
            |i| {
                black_box(lazy[i])
                    .add_loose(black_box(lazy[(i + 7) & 15]))
                    .mul(black_box(lazy[(i + 3) & 15]).sub_loose(black_box(lazy[(i + 11) & 15])))
            },
            count,
        ),
        "scalar-add" => measure(
            |i| black_box(&scalars[i]).add(black_box(&scalars[(i + 7) & 15])),
            count,
        ),
        "scalar-mul" => measure(
            |i| black_box(&scalars[i]).mul(black_box(&scalars[(i + 7) & 15])),
            count,
        ),
        "scalar-reduce-pruned" => {
            measure(|i| Scalar::reduce_pruned_le(black_box(&pruned[i])), count)
        }
        "scalar-reduce-hash" => measure(|i| Scalar::reduce_hash_le(black_box(&hashes[i])), count),
        "scalar-wnaf-public" => measure(|i| black_box(&scalars[i]).vartime_wnaf(8), count),
        _ => return Err("unknown operation"),
    };
    println!("RESULT operation={operation} count={count} mean_ns={ns:.3}");
    Ok(())
}
