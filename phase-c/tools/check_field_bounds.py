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

print(json.dumps({
    "status": "PASS", "parameter_sha256": expected,
    "public_multiplier_bits": a.bit_length(), "public_multiplier_max": str(small_max),
    "wide_input_max": str(wide_max), "first_fold_upper_bound": str(fold1_max),
    "second_fold_upper_bound": str(fold2_max), "two_p": str(2 * p),
    "small_product_upper_bound": str(small_product_max),
    "small_high_upper_bound": str(small_high_max), "small_penalty_upper_bound": str(penalty_max),
    "runtime_constant_time_claim": False,
}, indent=2, sort_keys=True))
