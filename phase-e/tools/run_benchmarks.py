#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Paired core/EVP/codec/TLS measurements, rotated repeats and explicit legacy profiles."""

import argparse
import json
import math
import os
from pathlib import Path
import re
import shutil
import statistics
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "phase-d/d2/tools"))
from d2_common import ROOT, TOOLS, Receipt, canonical_build_source, digest, verify_receipt

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--source-sha", required=True)
parser.add_argument("--functional", type=Path, required=True)
parser.add_argument("--functional-sha", required=True)
parser.add_argument("--legacy", type=Path, required=True)
parser.add_argument("--legacy-sha", required=True)
parser.add_argument("--output", type=Path, required=True)
parser.add_argument("--cpu", type=int, default=2)
parser.add_argument("--repetitions", type=int, default=9)
parser.add_argument("--target-ms", type=int, default=200)
args = parser.parse_args()
if args.cpu not in os.sched_getaffinity(0) or args.repetitions < 9 or args.target_ms < 200:
    parser.error("available CPU, >=9 repeats and >=200 ms calibration required")
functional = args.functional.resolve(strict=True)
legacy = args.legacy.resolve(strict=True)
for path, expected in ((functional, args.functional_sha), (legacy, args.legacy_sha)):
    if digest(path / "SHA256SUMS") != expected:
        raise SystemExit("benchmark input receipt digest mismatch")
identity = verify_receipt(functional)
old_identity = verify_receipt(legacy)
if any(item["source_manifest_sha256"] != args.source_sha for item in (identity, old_identity)):
    raise SystemExit("benchmark controllers must use one Phase-E snapshot")
if identity["openssl_version"] != old_identity["openssl_version"]:
    raise SystemExit("benchmark ABI mismatch")
receipt = Receipt(args.output, args.source_sha, "same-layer-benchmarks")
out = receipt.output
build_root = canonical_build_source(receipt)
version = identity["openssl_version"]
prefix = functional / "openssl/inst" / version
modules = functional / "modules"
for name in ("bin", "targets", "markers", "generated"):
    (out / name).mkdir(mode=0o700)
runtime = dict(receipt.clean, OPENSSL_CONF="/dev/null", LD_LIBRARY_PATH=str(prefix / "lib"))
toolchain = receipt.run("toolchain", ["/usr/bin/rustc", "--version", "--verbose"])
receipt.identity.update(openssl_version=version, functional_receipt_sha256=args.functional_sha,
                        legacy_receipt_sha256=args.legacy_sha, cpu_affinity=args.cpu,
                        repetitions=args.repetitions, target_ms=args.target_ms,
                        x_v1_profile="original C O0 and crypto-bigint overflow-off; never silently normalized",
                        v2_profile="C O3; all Rust crates overflow-on; Phase E optimized E4 E1 E2 E3 E5",
                        tls_scope="real TLS engine, memory BIO, warm SSL_CTX, SSL/BIO allocation/free included, no resumption",
                        codec_scope="valid generated objects; context allocation/teardown included; strict file precheck separate",
                        unavailable=["X301-v1 persistent codecs", "X301-v1 raw TLS group"],
                        load_before=Path("/proc/loadavg").read_text().strip())
receipt.run("platform", ["/usr/bin/uname", "-a"])
receipt.run("cpu", ["/usr/bin/lscpu"])
for attribute in ("scaling_governor", "scaling_driver"):
    path = Path(f"/sys/devices/system/cpu/cpu{args.cpu}/cpufreq/{attribute}")
    receipt.identity[attribute] = path.read_text().strip() if path.exists() else "unavailable"
receipt.write_identity()

for name, source in (
    ("signature", ROOT / "phase-c/benchmarks/openssl_signature_bench.c"),
    ("xdh", ROOT / "phase-d/d2/benchmarks/x301_bench.c"),
    ("codec", ROOT / "phase-d/d2/benchmarks/codec_bench.c"),
    ("tls", ROOT / "phase-d/d2/benchmarks/tls_bench.c"),
):
    receipt.run("compile-" + name, ["/usr/bin/gcc", "-std=c11", "-D_GNU_SOURCE", "-O2", "-Wall", "-Wextra", "-Werror",
                "-I" + str(prefix / "include"), source, "-o", out / "bin" / name,
                "-L" + str(prefix / "lib"), "-Wl,-rpath," + str(prefix / "lib"), "-lssl", "-lcrypto"])
    receipt.run("ldd-" + name, ["/usr/bin/ldd", out / "bin" / name], runtime)
receipt.run("xdh-lifecycle-selftest", [out / "bin/xdh", "--self-test"], runtime)
if digest(legacy / "ed-source/performance/ed301-bench/src/main.rs") != digest(ROOT / "rust/performance/ed301-bench/src/main.rs"):
    raise SystemExit("Ed core benchmark harnesses are not identical")


def build_core(name, source, manifest, required, exceptions="", features=()):
    home = out / (name + "-cargo-home")
    home.mkdir(mode=0o700)
    marker = out / "markers" / name
    marker.mkdir(mode=0o700)
    (marker / "toolchain.txt").write_text(toolchain)
    receipt.run(name + "-cargo-config", ["/usr/bin/python3", "-I", "-B", ROOT / "rust/scripts/write-cargo-config.py",
                                        home / "config.toml", source / "vendor"])
    env = dict(receipt.clean, CARGO_HOME=str(home), CARGO_TARGET_DIR=str(out / "targets" / name),
               CARGO_NET_OFFLINE="true", CARGO_INCREMENTAL="0", CCACHE_DISABLE="1",
               ED301_PROFILE_MARKER_DIR=str(marker), RUSTC_WRAPPER=str(
                   source / "scripts/rustc-profile-guard.sh" if "v1" in name else build_root / "phase-d/d2/tools/rustc_profile_guard.sh"))
    if exceptions:
        env["ED301_PROFILE_EXCEPTIONS"] = exceptions
    if not manifest.with_name("Cargo.lock").exists():
        receipt.run(name + "-lock", ["/usr/bin/cargo", "generate-lockfile", "--manifest-path", manifest, "--offline"], env)
    command = ["/usr/bin/cargo", "build", "--manifest-path", manifest, "--release", "--locked", "--offline"]
    if features:
        command += ["--features", ",".join(features)]
    receipt.run(name + "-build", command, env)
    receipt.run(name + "-profile", ["/bin/sh", source / "scripts/check-profile-markers.sh", marker] + required)
    binary_name = "ed301-benchmark" if name.startswith("ed") else "x301-core-benchmark"
    binary = out / "bin" / name
    shutil.copy2(out / "targets" / name / "release" / binary_name, binary)
    return binary


cores = {}
for generation, source in (("v1", legacy / "ed-source"), ("v2", build_root / "rust")):
    cores["ed-" + generation] = build_core("ed-" + generation, source,
        source / "performance/ed301-bench/Cargo.toml", ["crypto_bigint=on", "ed301_eddsa=on", "ed301_benchmark=on"])
for generation, source, package, dependency in (
    ("v1", legacy / "x-source", "ed301-eddsa", legacy / "x-source/crates/ed301-eddsa"),
    ("v2", build_root / "rust", "x301-core", build_root / "rust/crates/x301"),
):
    directory = out / "generated" / ("x-" + generation)
    (directory / "src").mkdir(mode=0o700, parents=True)
    shutil.copy2(ROOT / "phase-d/benchmarks/x301_core_bench.rs", directory / "src/main.rs")
    dependency_features = ',features=["x301"]' if generation == "v1" else ""
    manifest = directory / "Cargo.toml"
    manifest.write_text('[workspace]\n[package]\nname="x301-core-benchmark"\nversion="0.0.0"\nedition="2024"\npublish=false\n'
        '[features]\nv2=[]\n[dependencies]\nx301-implementation={package=' + json.dumps(package) + ',path='
        + json.dumps(str(dependency)) + dependency_features + '}\n[profile.release]\nopt-level=3\nlto="thin"\n'
        'codegen-units=1\npanic="unwind"\noverflow-checks=true\n'
        + ('[profile.release.package."crypto-bigint:0.7.5"]\noverflow-checks=false\n' if generation == "v1" else ""))
    required = ["crypto_bigint=off", "ed301_eddsa=on"] if generation == "v1" else ["crypto_bigint=on", "x301_core=on"]
    cores["x-" + generation] = build_core("x-" + generation, source, manifest, required + ["x301_core_benchmark=on"],
        "crypto_bigint=off" if generation == "v1" else "", [] if generation == "v1" else ["v2"])

cases = []


def add(layer, algorithm, operation, command):
    cases.append({"layer": layer, "algorithm": algorithm, "operation": operation, "command": list(map(str, command))})


for operation in ("expand", "sign", "verify", "import"):
    for generation in ("v1", "v2"):
        add("Rust-Ed", "Ed301-" + generation, operation, [cores["ed-" + generation], operation])
for operation in ("public", "shared", "validate-public", "canonical-public"):
    for generation in ("v1", "v2"):
        add("Rust-X", "X301-" + generation, operation, [cores["x-" + generation], operation])
for operation in ("import-secret", "import-public", "prepared-public", "prepared-shared"):
    add("Rust-X", "X301-v2", operation, [cores["x-v2"], operation])
ed_implementations = (
    ("Ed25519", "ED25519", "provider=default", "-", "-"),
    ("Ed448", "ED448", "provider=default", "-", "-"),
    ("Ed301-v1", "Ed301-EdDSA-v1", "provider=ed301_eddsa_v1", legacy / "modules/ed-normal", "ed301_eddsa_v1"),
    ("Ed301-v2", "Ed301-EdDSA", "provider=ed301_eddsa_v2", modules, "ed301_eddsa_v2"),
)
for operation in ("keygen", "sign", "verify"):
    for label, algorithm, props, directory, provider in ed_implementations:
        add("EVP-signature", label, operation, [out / "bin/signature", operation, algorithm, props, directory, provider])
for operation in ("keygen", "derive-setup", "derive-first", "derive-second", "derive-steady"):
    for label, algorithm, props, directory, provider, size in (
        ("X25519", "X25519", "provider=default", "-", "-", 32),
        ("X448", "X448", "provider=default", "-", "-", 56),
        ("X301-v1", "X301", "provider=x301", legacy / "modules/x-normal", "x301", 38),
        ("X301-v2", "X301", "provider=x301_v2", modules, "x301_v2", 38),
    ):
        add("EVP-XDH", label, operation, [out / "bin/xdh", operation, algorithm, props, directory, provider, size])
for operation in ("kem-keygen", "encaps", "decaps"):
    for label, algorithm, props, directory, provider in (
        ("ML-KEM-1024", "ML-KEM-1024", "provider=default", "-", "-"),
        ("Hybrid-v1", "X301MLKEM1024", "provider=x301", legacy / "modules/x-tls", "x301"),
        ("Hybrid-v2", "X301MLKEM1024", "provider=x301_v2_tls", modules, "x301_v2_tls"),
    ):
        add("EVP-KEM", label, operation, [out / "bin/xdh", operation, algorithm, props, directory, provider, 0])
codec_implementations = (
    ("Ed25519", "ED25519", "provider=default", modules, "-"),
    ("Ed448", "ED448", "provider=default", modules, "-"),
    ("Ed301-v1", "Ed301-EdDSA-v1", "provider=ed301_eddsa_v1_tls_test", legacy / "modules/ed-tls", "ed301_eddsa_v1_tls_test"),
    ("Ed301-v2", "Ed301-EdDSA", "provider=ed301_eddsa_v2_tls", modules, "ed301_eddsa_v2_tls"),
    ("X25519", "X25519", "provider=default", modules, "-"),
    ("X448", "X448", "provider=default", modules, "-"),
    ("X301-v2", "X301", "provider=x301_v2_tls", modules, "x301_v2_tls"),
)
for selection, form in (("private", "DER"), ("public", "DER"), ("private", "PEM"), ("encrypted", "PEM")):
    for operation in ("encode", "decode"):
        for label, algorithm, props, directory, provider in codec_implementations:
            add("EVP-codec", label, operation + "-" + selection + "-" + form,
                [out / "bin/codec", operation, selection, form, algorithm, props, directory, provider])
for label, algorithm, props, ed_dir, ed_module, x_dir, x_module, group, wire in (
    ("Ed25519-X25519", "ED25519", "provider=default", "-", "-", "-", "-", "X25519", "0x001d"),
    ("Ed448-X25519", "ED448", "provider=default", "-", "-", "-", "-", "X25519", "0x001d"),
    ("Ed-v1-X25519", "Ed301-EdDSA-v1", "provider=ed301_eddsa_v1_tls_test", legacy / "modules/ed-tls", "ed301_eddsa_v1_tls_test", "-", "-", "X25519", "0x001d"),
    ("Ed-v2-X25519", "Ed301-EdDSA", "provider=ed301_eddsa_v2_tls", modules, "ed301_eddsa_v2_tls", "-", "-", "X25519", "0x001d"),
    ("Ed-v1-Hybrid-v1", "Ed301-EdDSA-v1", "provider=ed301_eddsa_v1_tls_test", legacy / "modules/ed-tls", "ed301_eddsa_v1_tls_test", legacy / "modules/x-tls", "x301", "X301MLKEM1024", "0xfe2e"),
    ("Ed-v2-Hybrid-v2", "Ed301-EdDSA", "provider=ed301_eddsa_v2_tls", modules, "ed301_eddsa_v2_tls", modules, "x301_v2_tls", "X301MLKEM1024", "0xfe2f"),
    ("Ed-v2-Raw-v2", "Ed301-EdDSA", "provider=ed301_eddsa_v2_tls", modules, "ed301_eddsa_v2_tls", modules, "x301_v2_tls", "X301", "0xfe30"),
    ("ECDSA-X25519", "EC", "provider=default", "-", "-", "-", "-", "X25519", "0x001d"),
    ("ECDSA-Hybrid-v1", "EC", "provider=default", "-", "-", legacy / "modules/x-tls", "x301", "X301MLKEM1024", "0xfe2e"),
    ("ECDSA-Hybrid-v2", "EC", "provider=default", "-", "-", modules, "x301_v2_tls", "X301MLKEM1024", "0xfe2f"),
    ("ECDSA-Raw-v2", "EC", "provider=default", "-", "-", modules, "x301_v2_tls", "X301", "0xfe30"),
):
    add("TLS-engine", label, "full-handshake-warm-context",
        [out / "bin/tls", algorithm, props, ed_dir, ed_module, x_dir, x_module, group, wire])
(out / "CASES.json").write_text(json.dumps(cases, indent=2) + "\n")


def measure(index, count, label):
    log = receipt.run(label + f"-{index:03d}", ["/usr/bin/taskset", "-c", args.cpu]
                      + cases[index]["command"] + [count], runtime)
    found = re.search(r"^RESULT .*mean_ns=([0-9.]+)$", log, re.M)
    if not found or not math.isfinite(float(found[1])) or float(found[1]) <= 0:
        raise SystemExit("invalid benchmark result")
    return float(found[1])


counts = [max(100, min(1000000, math.ceil(args.target_ms * 1e6 / measure(i, 100, "calibration"))))
          for i in range(len(cases))]
raw = out / "raw.tsv"
raw.write_text("repeat\tcase\tlayer\talgorithm\toperation\tcount\tmean_ns\n")
values = [[] for _ in cases]
for repeat in range(args.repetitions):
    order = list(range(len(cases)))
    if repeat % 2:
        order.reverse()
    shift = (2 * repeat) % len(order)
    order = order[shift:] + order[:shift]
    for index in order:
        value = measure(index, counts[index], f"repeat-{repeat + 1}")
        values[index].append(value)
        case = cases[index]
        with raw.open("a") as stream:
            stream.write("\t".join(map(str, [repeat + 1, index, case["layer"], case["algorithm"],
                                           case["operation"], counts[index], value])) + "\n")
summary = []
for case, timings in zip(cases, values):
    summary.append({key: case[key] for key in ("layer", "algorithm", "operation")} | {
        "repetitions": len(timings), "mean_ns": statistics.mean(timings), "median_ns": statistics.median(timings),
        "stdev_ns": statistics.stdev(timings), "min_ns": min(timings), "max_ns": max(timings)})
(out / "SUMMARY.json").write_text(json.dumps(summary, indent=2) + "\n")
for i, path in enumerate(sorted(modules.glob("*.so")) + sorted((legacy / "modules").glob("*/*.so"))):
    receipt.run(f"module-size-{i}", ["/usr/bin/size", "-A", path])
    receipt.run(f"module-sections-{i}", ["/usr/bin/readelf", "-SW", path])
for index, case in enumerate(cases):
    if (case["layer"] == "TLS-engine"
            or (case["layer"] == "EVP-signature" and case["operation"] == "sign")
            or (case["layer"] == "EVP-XDH" and case["operation"] == "derive-steady")
            or (case["layer"] == "EVP-codec" and case["operation"] == "decode-private-DER")):
        receipt.run(f"resources-{index:03d}", ["/usr/bin/time", "-v", "/usr/bin/taskset", "-c", args.cpu]
                    + case["command"] + [100], runtime)
receipt.identity.update(case_count=len(cases), load_after=Path("/proc/loadavg").read_text().strip())
verify_receipt(functional)
verify_receipt(legacy)
canonical_build_source(receipt)
receipt.seal()
