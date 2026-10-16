#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Measure the Rust cores and the OpenSSL EVP layer; print Markdown tables.

From the repository root, after building the provider modules (for example
with provider-tests/run.py, which leaves them in <workdir>/modules):

    python3 -I benchmarks/run.py --modules <workdir>/modules [--cpu 2] [--runs 9]

Each case runs --runs times on one pinned CPU. Each run uses an iteration
count calibrated to about 200 ms and reports its mean; the tables give the
median and minimum of those run means in microseconds. Ed25519, Ed448,
X25519 and X448 come from the same OpenSSL as reference points.
"""

import argparse
import os
from pathlib import Path
import re
import statistics
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
parser.add_argument("--modules", type=Path, required=True, help="directory with ed301_eddsa_v2.so and x301_v2.so")
parser.add_argument("--openssl-prefix", type=Path, default=Path("/usr"))
parser.add_argument("--cpu", default="2")
parser.add_argument("--runs", type=int, default=9)
parser.add_argument("--workdir", type=Path)
args = parser.parse_args()

prefix = args.openssl_prefix.resolve()
lib = next(prefix / d for d in ("lib64", "lib") if (prefix / d / "libcrypto.so").exists())
work = (args.workdir or Path(tempfile.mkdtemp(prefix="ed301-bench-"))).resolve()
work.mkdir(parents=True, exist_ok=True)
modules = args.modules.resolve()
env = dict(os.environ, OPENSSL_CONF="/dev/null", LD_LIBRARY_PATH=str(lib))


def build():
    for crate in ("ed301-bench", "x301-bench"):
        subprocess.run(["cargo", "build", "--release", "--locked", "--manifest-path",
                        ROOT / "rust/performance" / crate / "Cargo.toml"],
                       env=dict(env, CARGO_TARGET_DIR=str(work / "target")), check=True)
    for name in ("signature_bench", "x301_bench"):
        subprocess.run(["gcc", "-std=c11", "-D_GNU_SOURCE", "-O2", "-Wall", "-Wextra", "-Werror",
                        f"-I{prefix / 'include'}", ROOT / "benchmarks/evp" / f"{name}.c",
                        "-o", work / name, f"-L{lib}", f"-Wl,-rpath,{lib}", "-lcrypto"], check=True)


def mean_us(command):
    """Run one measurement and return its mean per operation in microseconds."""
    out = subprocess.run(["taskset", "-c", args.cpu, *map(str, command)], env=env,
                         capture_output=True, text=True, check=True).stdout
    if (m := re.search(r"mean_ns=([0-9.]+)", out)):
        return float(m[1]) / 1000
    m = re.search(r"count=([0-9]+) total_ns=([0-9]+)", out)
    return int(m[2]) / int(m[1]) / 1000


def measure(command_for):
    """command_for(count) builds the command; calibrate, then take run means."""
    per_op = mean_us(command_for(200))
    count = max(50, int(200_000 / per_op))
    means = [mean_us(command_for(count)) for _ in range(args.runs)]
    return statistics.median(means), min(means)


def table(title, header, rows):
    print(f"\n### {title}\n")
    print("| " + " | ".join(header) + " |")
    print("| --- |" + " ---: |" * (len(header) - 1))
    for row in rows:
        print("| " + " | ".join(row) + " |")


def cell(result):
    digits = 3 if result[0] < 1 else 1
    return f"{result[0]:.{digits}f} ({result[1]:.{digits}f})"


build()
ed, x = work / "target/release/ed301-benchmark", work / "target/release/x301-benchmark"
table("Rust core", ["Operation", "Median (min) µs"], [
    [label, cell(measure(lambda n, b=binary, o=op: [b, o, n]))]
    for label, binary, op in (
        ("Ed301 key expansion", ed, "expand"), ("Ed301 sign (prepared key)", ed, "sign"),
        ("Ed301 verify (prepared key)", ed, "verify"), ("Ed301 public-key import", ed, "import"),
        ("X301 public key from secret", x, "public"), ("X301 shared secret", x, "shared"),
        ("X301 public-key import", x, "import-public"))])

signatures = (("Ed25519", "ED25519", "-"), ("Ed301", "Ed301-EdDSA", "ed301_eddsa_v2"), ("Ed448", "ED448", "-"))
table("OpenSSL EVP signatures", ["Algorithm", "Keygen", "Sign", "Verify"], [
    [label] + [cell(measure(lambda n, op=op, a=alg, p=prov: [
        work / "signature_bench", op, a, "-", modules if p != "-" else "-", p, n]))
        for op in ("keygen", "sign", "verify")]
    for label, alg, prov in signatures])

exchanges = (("X25519", "X25519", "-", 32), ("X301", "X301", "x301_v2", 38), ("X448", "X448", "-", 56))
table("OpenSSL EVP key exchange", ["Algorithm", "Keygen", "Derive (steady state)"], [
    [label] + [cell(measure(lambda n, op=op, a=alg, p=prov, k=size: [
        work / "x301_bench", op, a, "-", modules if p != "-" else "-", p, k, n]))
        for op in ("keygen", "derive-steady")]
    for label, alg, prov, size in exchanges])
