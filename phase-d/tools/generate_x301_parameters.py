#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Embed X301-specific constants from approved Gate-A/B bytes; no runtime JSON."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[2]
PARAMETERS = ROOT / "provenance/phase-a/2026-09-09/parameter/ed301-v2.json"
VECTORS = ROOT / "vectors/x301-v2.json"
CONTRACT = ROOT / "phase-b/inputs/X301-v2_EINGABEVERTRAG_2026-09-10.md"
EXPECTED = {
    PARAMETERS: "13f0eaf541919a1447b9d3c58e6d57eb77ffab94ebe37539c70301d6fddcfaa0",
    VECTORS: "b675f677f0d717a09f3c1cc55bf0c2ad97d17ca14a7890565a41916222cc80f0",
    CONTRACT: "b33d3fe0bf6b5b026192695902902f4b7592d4271ca98161f47920b47c6a1c2c",
    ROOT / "rust/crates/ed301-eddsa/src/generated_parameters.rs": "089321a9f25162712f02275ebafbf7f572f1e992e88c65a62544fc0d79e1b947",
}


def generate():
    for path, expected in EXPECTED.items():
        if hashlib.sha256(path.read_bytes()).hexdigest() != expected:
            raise RuntimeError(f"approved input changed: {path}")
    p = json.loads(PARAMETERS.read_text())
    modulus = int(p["field"]["p_decimal"])
    a24 = int(p["montgomery"]["A24_minus_decimal"])
    a = int(p["montgomery"]["A_decimal"])
    base = int(p["basepoint"]["G_montgomery_u_decimal"])
    nt = int(p["twist"]["order_decimal"])
    assert 0 < base < modulus and 0 < a24 < modulus
    assert p["montgomery"]["A24_convention"] == "minus"
    assert 4 * a24 % modulus == (a - 2) % modulus
    assert base.to_bytes(38, "little").hex() == p["basepoint"]["G_montgomery_u_little_endian_hex"]
    assert 2**300 <= nt < 2**301 and nt % 4 == 0
    assert nt.to_bytes(38, "little").hex() == "84ca911e62530d13b204a5718d1a9ada9621c5ffffffffffffffffffffffffffffffffffff1f"
    lines = ["// SPDX-License-Identifier: Apache-2.0",
             "// Generated from hash-bound Gate A/B; do not transcribe parameters.",
             f"// Gate-A SHA-256: {EXPECTED[PARAMETERS]}",
             f"// Gate-B X301 vectors SHA-256: {EXPECTED[VECTORS]}",
             f"pub(crate) const FIELD_BITS: usize = {p['field']['bit_length']};",
             f"pub(crate) const FIELD_BYTES: usize = {p['encoding']['field_bytes']};"]
    for name, value in (("A24_MINUS_WORDS", a24), ("BASE_U_WORDS", base)):
        words = [(value >> (64 * i)) & ((1 << 64) - 1) for i in range(5)]
        lines.append(f"pub(crate) const {name}: [u64; 5] = [" + ",".join(f"0x{w:016x}" for w in words) + "];")
    for name, value in (("BASE_U_BYTES", base), ("TWIST_ORDER_BYTES", nt)):
        lines.append(f"pub(crate) const {name}: [u8; 38] = [" + ",".join(f"0x{b:02x}" for b in value.to_bytes(38, "little")) + "];")
    return subprocess.run(["/usr/bin/rustfmt", "--edition=2024", "--emit=stdout"],
                          input="\n".join(lines) + "\n", capture_output=True, text=True, check=True).stdout


parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--check", type=Path)
args = parser.parse_args()
content = generate()
if args.check:
    if args.check.read_text() != content:
        raise SystemExit("FAIL: X301 embedded parameters differ")
    print("PASS: embedded X301 constants reproduce approved inputs")
else:
    print(content, end="")
