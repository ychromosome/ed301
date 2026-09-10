#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Native-C ASan/UBSan, whole-process Memcheck and input-to-DSO secret taint."""

import argparse
from pathlib import Path
import shutil
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from d2_common import ROOT, TOOLS, Receipt, canonical_build_source, digest, verify_receipt

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--source-sha", required=True)
parser.add_argument("--functional", type=Path, required=True)
parser.add_argument("--functional-sha", required=True)
parser.add_argument("--output", type=Path, required=True)
args = parser.parse_args()
functional = args.functional.resolve(strict=True)
if digest(functional / "SHA256SUMS") != args.functional_sha:
    raise SystemExit("functional receipt digest mismatch")
identity = verify_receipt(functional)
if identity["source_manifest_sha256"] != args.source_sha:
    raise SystemExit("memory and functional stages must use one source snapshot")
receipt = Receipt(args.output, args.source_sha, "memory-and-secret-taint")
out = receipt.output
build_root = canonical_build_source(receipt)
version = identity["openssl_version"]
prefix = functional / "openssl/inst" / version
lib = prefix / "lib"
generated = functional / "generated"
for name in ("cargo-home", "targets", "markers", "bin", "modules-asan", "modules-taint"):
    (out / name).mkdir(mode=0o700)
receipt.identity.update(openssl_version=version, functional_receipt_sha256=args.functional_sha,
                        asan_ubsan_scope="C harnesses and provider C shims; Rust/OpenSSL not compiler-instrumented",
                        memcheck_scope="complete native process including Rust, C and OpenSSL",
                        mlkem_taint_scope="delegated ML-KEM is not claimed independently constant-time here")
receipt.write_identity()
receipt.run("cargo-config", ["/usr/bin/python3", "-I", "-B", ROOT / "rust/scripts/write-cargo-config.py",
                            out / "cargo-home/config.toml", build_root / "rust/vendor"])
toolchain = receipt.run("toolchain", ["/usr/bin/rustc", "--version", "--verbose"])
receipt.run("valgrind-identity", ["/usr/bin/valgrind", "--version"])
runtime = dict(receipt.clean, OPENSSL_CONF="/dev/null", LD_LIBRARY_PATH=str(lib),
               OPENSSL_MODULES=str(functional / "modules"), ED301V2_EXPECT_OPENSSL_PREFIX=str(prefix),
               ED301V2_FRESH_COPY_DIR=str(functional / "fresh-modules"), RUST_BACKTRACE="0")
variants = [
    ("ed-normal", "ed301-eddsa-provider", "", "ed301_eddsa_v2", "ed301_eddsa_v2"),
    ("ed-pki", "ed301-eddsa-provider", "pki-experiment", "ed301_eddsa_v2", "ed301_eddsa_v2_pki_test"),
    ("ed-tls", "ed301-eddsa-provider", "tls-experiment", "ed301_eddsa_v2", "ed301_eddsa_v2_tls_test"),
    ("ed-collider", "ed301-eddsa-provider", "tls-collider", "ed301_eddsa_v2", "ed301_eddsa_v2_tls_collider"),
    ("ed-failpoint", "ed301-eddsa-provider", "test-failpoint", "ed301_eddsa_v2", "ed301_eddsa_v2_failpoint"),
    ("x-normal", "x301-provider", "", "x301_v2", "x301_v2"),
    ("x-pki", "x301-provider", "pki-experiment", "x301_v2", "x301_v2_pki_test"),
    ("x-tls", "x301-provider", "tls-x301-mlkem1024", "x301_v2", "x301_v2_tls_test"),
    ("x-failpoint", "x301-provider", "test-failpoint", "x301_v2", "x301_v2_failpoint"),
]


def build(variant, package, features, library, module, directory):
    marker = out / "markers" / variant
    marker.mkdir(mode=0o700)
    (marker / "toolchain.txt").write_text(toolchain)
    env = dict(runtime, CARGO_HOME=str(out / "cargo-home"), CARGO_TARGET_DIR=str(out / "targets" / variant),
               CARGO_NET_OFFLINE="true", CARGO_INCREMENTAL="0", CCACHE_DISABLE="1", CC="/usr/bin/gcc", AR="/usr/bin/ar",
               ED301_HERMETIC_PROVIDER_BUILD="1", X301_HERMETIC_PROVIDER_BUILD="1", ED301_HERMETIC_NATIVE_BUILD="1",
               OPENSSL_INCLUDE_DIR=str(prefix / "include"), OPENSSL_LIB_DIR=str(lib),
               ED301_PROFILE_MARKER_DIR=str(marker), RUSTC_WRAPPER=str(build_root / "phase-d/d2/tools/rustc_profile_guard.sh"))
    receipt.run("build-" + variant, ["/usr/bin/cargo", "build", "--manifest-path", build_root / "provider/Cargo.toml",
                "--release", "--locked", "--offline", "-vv", "-p", package, "--features", features], env)
    receipt.run("profile-" + variant, ["/bin/sh", ROOT / "rust/scripts/check-profile-markers.sh", marker,
                                      "crypto_bigint=on", library + "=on"])
    destination = out / directory / (module + ".so")
    shutil.copy2(out / "targets" / variant / "release" / ("lib" + library + ".so"), destination)
    destination.chmod(0o555)
    receipt.identity.setdefault("module_sha256", {})[str(destination.relative_to(out))] = digest(destination)


for variant, package, feature, library, module in variants:
    features = "test-sanitizer" + ("," + feature if feature else "")
    build("asan-" + variant, package, features, library, module, "modules-asan")
for index in (0, 1, 7):
    variant, package, feature, library, module = variants[index]
    features = "secret-taint-instrumentation" + ("," + feature if feature else "")
    build("taint-" + variant, package, features, library, module, "modules-taint")

ed_harnesses = ["provider_load", "provider_keymgmt", "provider_signature", "provider_serialization", "provider_pki",
                "provider_rand", "provider_lifecycle", "provider_tls", "provider_hardening",
                "provider_shim_unit", "val01_decoder_bio", "provider_context_contract", "provider_generation_policy", "provider_discovery_order", "provider_tls_lengths"]
x_harnesses = ["provider_x301_contract", "provider_x301_hybrid_contract", "provider_x301_nested_properties",
               "provider_x301_hybrid_kat"]


def compile_harness(name, source, extra=(), sanitizer=False):
    command = ["/usr/bin/gcc", "-std=c11", "-D_GNU_SOURCE", "-O2", "-g", "-Wall", "-Wextra", "-Werror",
               "-I" + str(prefix / "include"), "-I" + str(generated), "-I" + str(ROOT / "provider-tests")]
    if sanitizer:
        command += ["-fsanitize=address,undefined", "-fno-sanitize-recover=all", "-fno-omit-frame-pointer"]
    command += list(extra) + [source, "-o", out / "bin" / name, "-L" + str(lib), "-Wl,-rpath," + str(lib),
                              "-lssl", "-lcrypto", "-ldl", "-pthread"]
    receipt.run("compile-" + name, command)


for name in ed_harnesses:
    compile_harness("asan-" + name, ROOT / "provider-tests" / (name + ".c"), sanitizer=True)
for name in x_harnesses:
    compile_harness("asan-" + name, ROOT / "provider-tests/x301" / (name + ".c"), sanitizer=True)
for source, name in (("provider_serialization", "x301_serialization"), ("val01_decoder_bio", "x301_decoder")):
    compile_harness("asan-" + name, ROOT / "provider-tests" / (source + ".c"), ["-DX301_CODEC_TEST"], True)
compile_harness("provider_secret_taint", ROOT / "provider-tests/provider_secret_taint.c")
compile_harness("provider_x301_secret_taint", ROOT / "provider-tests/x301/provider_x301_secret_taint.c",
                [ROOT / "rust/secret-taint/valgrind-client/c/valgrind_client.c"])
compile_harness("provider_taint_control", ROOT / "provider-tests/provider_taint_control.c")
compile_harness("asan-x301_failpoint_contract", ROOT / "provider-tests/x301/provider_x301_contract.c",
                ['-DX301_PROVIDER="x301_v2_failpoint"'], True)
asan = dict(runtime, OPENSSL_MODULES=str(out / "modules-asan"),
            ASAN_OPTIONS="detect_leaks=0:halt_on_error=1", UBSAN_OPTIONS="halt_on_error=1:print_stacktrace=1")
for name in ed_harnesses + x_harnesses + ["x301_serialization", "x301_decoder"]:
    command = [out / "bin" / ("asan-" + name)]
    if name in x_harnesses and name != "provider_x301_hybrid_kat":
        command.append(out / "modules-asan")
    receipt.run("run-asan-" + name, command, asan)
receipt.run("run-asan-x301-failpoints", [out / "bin/asan-x301_failpoint_contract", out / "modules-asan"],
            dict(asan, X301_V2_PROVIDER_FAILPOINT_MODE="active"))
valgrind = ["/usr/bin/valgrind", "--tool=memcheck", "--vgdb=no", "--error-exitcode=99",
            "--leak-check=full", "--errors-for-leak-kinds=definite,indirect,possible", "--quiet"]
for name in ed_harnesses + x_harnesses + ["x301_serialization", "x301_decoder"]:
    command = valgrind + [functional / "bin" / name]
    if name in x_harnesses and name != "provider_x301_hybrid_kat":
        command.append(functional / "modules")
    # Full panic recovery is checked above with the sanitizer test and by the
    # non-sanitized functional run. This focused leak lane excludes panic-hook
    # symbolization, whose lifetime belongs to Rust's runtime machinery.
    env = dict(runtime, ED301V2_RUST_ALLOC_ONLY="1") if name == "provider_hardening" else runtime
    receipt.run("run-valgrind-" + name, command, env, timeout=1800)
receipt.run("run-valgrind-x301-failpoints", valgrind + [functional / "bin/x301_failpoint_contract", functional / "modules"],
            dict(runtime, X301_V2_PROVIDER_FAILPOINT_MODE="alloc-only"), timeout=1800)
taint = valgrind + ["--track-origins=yes", "--undef-value-errors=yes"]
positive = receipt.run("taint-positive-control", taint + [out / "bin/provider_taint_control"], runtime, expected=99)
if not any(marker in positive for marker in ("uninitialised", "uninitialized")):
    raise SystemExit("taint positive control did not report undefined data use")
taint_env = dict(runtime, OPENSSL_MODULES=str(out / "modules-taint"))
for mode in ("defined", "tainted"):
    receipt.run("ed-taint-" + mode, taint + [out / "bin/provider_secret_taint", mode], taint_env)
    for path in ("pki", "bridge"):
        receipt.run("ed-taint-" + path + "-" + mode,
                    taint + [out / "bin/provider_secret_taint", mode, path], taint_env)
    receipt.run("x-taint-" + mode, taint + [out / "bin/provider_x301_secret_taint", out / "modules-taint", mode], taint_env)
for path in ("pki", "bridge"):
    positive = receipt.run("ed-export-positive-control-" + path,
        taint + [out / "bin/provider_secret_taint", "tainted", path, "export-control"],
        taint_env, expected=99)
    if ("private_export_positive_control=triggered" not in positive
            or not any(marker in positive for marker in ("uninitialised", "uninitialized"))):
        raise SystemExit("private export positive control did not observe tainted DER")
for path, checksum in receipt.identity["module_sha256"].items():
    if digest(out / path) != checksum:
        raise SystemExit("instrumented module changed during memory tests")
verify_receipt(functional)
canonical_build_source(receipt)
receipt.seal()
