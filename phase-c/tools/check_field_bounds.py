#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Recalculate the v2 five-limb reduction bounds with exact public integers."""

import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
raw = (ROOT / "provenance/phase-a/2026-09-09/parameter/ed301-v2.json").read_bytes()
expected = "13f0eaf541919a1447b9d3c58e6d57eb77ffab94ebe37539c70301d6fddcfaa0"
if hashlib.sha256(raw).hexdigest() != expected:
    raise SystemExit("FAIL: Gate-A parameter hash")
data = json.loads(raw)
p = int(data["field"]["p_decimal"])
a = int(data["edwards"]["a_decimal"])
d = int(data["edwards"]["d_signed"])
word = 1 << 64
split = 1 << 301
fold = split - p
small_max = (1 << a.bit_length()) - 1


def require(condition, name):
    if not condition:
        raise SystemExit("FAIL: " + name)


require(p == (1 << 301) - (1 << 89) + 907, "field family")
require(a.bit_length() == 36 and a <= small_max, "public multiplier range")
require(0 < fold < 1 << 89, "positive two-word fold constant")
require(fold == (word - 907) + ((1 << 25) - 1) * word, "fold limb decomposition")
require(4 * p < 1 << 303, "loose operand bound")

# A product of any two accepted loose operands is below 2^606.  Each fold
# uses low < 2^301 and the indicated inclusive maximum of the high part.
wide_max = (1 << 606) - 1
high0_max = wide_max >> 301
fold1_max = (split - 1) + high0_max * fold
high1_max = fold1_max >> 301
fold2_max = (split - 1) + high1_max * fold
require(high0_max < 1 << 305, "first high part fits five words")
require(fold1_max < (1 << 301) + (1 << 394) < 1 << 395, "first fold fits seven words")
require(high1_max < 1 << 94, "second high part fits two words")
require(fold2_max < (1 << 301) + (1 << 183) < 2 * p, "second fold needs one subtraction")
require(fold1_max < 1 << (7 * 64) and fold2_max < 1 << (5 * 64), "no discarded output carry")

small_product_max = (2 * p - 1) * small_max
small_high_max = small_product_max >> 301
penalty_max = small_high_max * 907
positive_max = (split - 1) + small_high_max * (1 << 89)
require(small_product_max < 1 << 338, "lazy small product fits six words")
require(small_high_max < 1 << 37, "small high fits one word")
require(penalty_max < 1 << 47 < word, "small penalty fits the subtracted low word")
require(positive_max < (1 << 301) + (1 << 126) < 2 * p, "small reduction bound")
require(positive_max < 1 << 320, "small positive sum cannot overflow five words")
require(penalty_max < p, "single-modulus correction dominates the full penalty")

# Every multiply-accumulate has one word product, an output word and carry.
require((word - 1) ** 2 + 2 * (word - 1) == (1 << 128) - 1, "u128 multiply-accumulate bound")
require((word - 1) * small_max + (small_max - 1) < 1 << 100, "small multiply-accumulate bound")
# A 5x5 square column has at most five products plus propagated carry.
require(5 * (word - 1) ** 2 + 5 * (word - 1) < 1 << 131 < 1 << 192, "square column accumulator bound")

# E4: exact maxima for the existing 5 diagonal + 10 doubled-cross schedule.
# Full-width words deliberately cover a superset of all field representations.
require((word - 1) ** 2 < 1 << 128, "single square product fits u128")
require(1 << 128 <= 2 * (word - 1) ** 2 < 1 << 129, "doubled cross needs the retained 129th bit")
require(2 * word - 2 < 1 << 128 and 2 * word - 1 < 1 << 128, "192-bit helper low and middle additions")
square_columns = []
carry = 0
for column, count in enumerate((1, 2, 3, 4, 5, 4, 3, 2, 1)):
    maximum = carry + count * (word - 1) ** 2
    require(carry <= 5 * (word - 1), f"square carry into column {column}")
    require(maximum < 1 << 131, f"square column {column} fits 131 bits")
    require(maximum >> 128 <= 4, f"square high-word additions cannot wrap in column {column}")
    square_columns.append({"column": column, "weighted_products": count,
                           "carry_in_max": str(carry), "accumulator_max": str(maximum),
                           "carry_out_max": str(maximum >> 64)})
    carry = maximum >> 64
require(carry < word, "last square carry fits output word nine")

# E7: row-wise cross products, a full-width shift, then diagonal additions.
# Local MAC bounds hold for arbitrary words, not just the all-max example.
row_steps = []
for i in range(4):
    # Earlier rows end at most at (i-1)+5; this row's carry slot is fresh.
    require(i == 0 or (i - 1) + 5 < i + 5, f"row {i} carry destination initially zero")
    for j in range(i + 1, 5):
        mac_max = (word - 1) ** 2 + 2 * (word - 1)
        require(mac_max < 1 << 128, f"row {i} product {j} MAC capacity")
        require(mac_max >> 64 <= word - 1, f"row {i} product {j} carry capacity")
        require(i + j < i + 5 < 10, f"row {i} product {j} output indices")
        row_steps.append({"row": i, "column": i + j, "j": j, "mac_max": str(mac_max)})
square_operand_max = word**5 - 1
cross_max = sum((word - 1) ** 2 * word ** (i + j) for i in range(5) for j in range(i + 1, 5))
diagonal_max = sum((word - 1) ** 2 * word ** (2 * i) for i in range(5))
require(len(row_steps) == 10, "row-wise square has exactly ten cross products")
require(2 * cross_max + diagonal_max == square_operand_max**2, "cross/diagonal decomposition")
require(square_operand_max**2 < word**10, "full-word square fits 640 bits")
require(cross_max < 1 << 639 and 2 * cross_max < 1 << 640, "cross doubling loses no high carry")
diagonal_low_max = 2 * (word - 1) + 1
diagonal_high_max = (word - 1) + (word - 2) + 1
require(diagonal_low_max < 1 << 65 and diagonal_low_max >> 64 <= 1, "diagonal low addition capacity")
require(diagonal_high_max < 1 << 65 and diagonal_high_max >> 64 <= 1, "diagonal high addition capacity")
# For arbitrary operands, every partial diagonal sum is nonnegative and at
# most x^2. This all-max monotone bound therefore also excludes a final carry.
require(2 * cross_max + diagonal_max < 1 << 640, "last diagonal carry is zero")

# E2/E7: each round restores the lazy state bound without extra tightening.
lazy_max = 2 * p - 1
loose_max = 4 * p - 1
sum_max = 2 * lazy_max
subtraction_max = lazy_max + 2 * p
require(sum_max == 4 * p - 2 < 1 << 320, "lazy sum has no word carry")
require(subtraction_max == loose_max < 1 << 320, "lazy augmented subtraction has no word carry")
require(2 * p - lazy_max == 1, "lazy augmented subtraction has no final borrow")
narrow_max = (1 << 32) - 1
narrow_product_max = loose_max * narrow_max
narrow_high_max = narrow_product_max >> 301
require(narrow_product_max < 1 << 335 < 1 << 338, "loose narrow small product domain")
require(narrow_product_max <= small_product_max, "loose narrow product within existing small-reducer proof")
require((word - 1) * narrow_max + (narrow_max - 1) < 1 << 96, "narrow MAC capacity")
require(narrow_high_max < 1 << 34, "narrow high word capacity")
require(907 * narrow_high_max < 1 << 44 < word, "narrow penalty capacity")
require((split - 1) + narrow_high_max * (1 << 89) < (1 << 301) + (1 << 123) < 2 * p,
        "narrow reducer restores lazy domain")
scale = a - d
a24 = int(data["montgomery"]["A24_minus_decimal"])
montgomery_a = int(data["montgomery"]["A_decimal"])
require(d == -301 and int(data["edwards"]["d_decimal"]) == p + d, "signed d agrees with canonical residue")
require(0 < scale <= small_max < p, "nonzero 36-bit projective scale")
require(abs(d) <= narrow_max, "scaled numerator fits narrow public bound")
require(montgomery_a * scale % p == 2 * (a + d) % p, "Montgomery/Edwards A identity")
require(4 * a24 % p == (montgomery_a - 2) % p, "minus A24 convention")
require(a24 * scale % p == d % p, "scaled A24 identity")
require(lazy_max * scale <= small_product_max, "scaled AA small reducer input")
require(loose_max * abs(d) <= narrow_product_max, "scaled E narrow reducer input")
ladder_products = {
    "aa_bb": loose_max ** 2,
    "da_cb": loose_max ** 2,
    "x3": sum_max ** 2,
    "difference_square": loose_max ** 2,
    "z3": lazy_max ** 2,
    "x2": lazy_max ** 2,
    "z2": loose_max ** 2,
}
for name, bound in ladder_products.items():
    require(bound <= loose_max ** 2 < 1 << 606, f"lazy ladder {name} reducer input")
    fold1 = (split - 1) + (bound >> 301) * fold
    fold2 = (split - 1) + (fold1 >> 301) * fold
    require(fold1 < 1 << (7 * 64), f"lazy ladder {name} first fold capacity")
    require(fold2 < 2 * p, f"lazy ladder {name} restores state bound")

print(json.dumps({
    "status": "PASS", "parameter_sha256": expected,
    "public_multiplier_bits": a.bit_length(), "public_multiplier_max": str(small_max),
    "wide_input_max": str(wide_max), "first_fold_upper_bound": str(fold1_max),
    "second_fold_upper_bound": str(fold2_max), "two_p": str(2 * p),
    "small_product_upper_bound": str(small_product_max),
    "small_high_upper_bound": str(small_high_max), "small_penalty_upper_bound": str(penalty_max),
    "square_diagonal_products": 5, "square_doubled_cross_products": 10,
    "square_schedule": "row-wise cross products, full-width shift, diagonals",
    "square_row_steps": row_steps,
    "square_cross_max": str(cross_max), "square_diagonal_max": str(diagonal_max),
    "square_full_output_max": str(square_operand_max**2),
    "square_diagonal_low_add_max": str(diagonal_low_max),
    "square_diagonal_high_add_max": str(diagonal_high_max),
    "historical_column_oracle_only": True,
    "square_columns": square_columns,
    "loose_narrow_multiplier_max": str(narrow_max),
    "loose_narrow_product_max": str(narrow_product_max),
    "loose_narrow_high_max": str(narrow_high_max),
    "a24_scale_denominator": str(scale), "a24_scale_numerator": str(d),
    "a24_scaled_aa_product_max": str(lazy_max * scale),
    "a24_scaled_e_product_max": str(loose_max * abs(d)),
    "ladder_rounds": 301,
    "ladder_lazy_max": str(lazy_max), "ladder_loose_max": str(loose_max),
    "ladder_product_maxima": {name: str(bound) for name, bound in ladder_products.items()},
    "runtime_constant_time_claim": False,
}, indent=2, sort_keys=True))
