#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Focused E8 review follow-up: unchanged runtime, new private-export taint tests."""

import argparse
from pathlib import Path
import shutil
import sys

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "phase-d/d2/tools"))
from d2_common import Receipt, canonical_build_source, digest, verify_receipt
sys.path.insert(0, str(ROOT / "phase-e/e8_handoff"))
from handoff_common import check_members, check_source

parser = argparse.ArgumentParser(description=__doc__)
for name in ("functional", "benchmark", "base-evidence", "output"):
    parser.add_argument("--" + name, type=Path, required=True)
for name in ("source-sha", "functional-sha", "benchmark-sha", "base-source-sha"):
    parser.add_argument("--" + name, required=True)
args = parser.parse_args()
functional = args.functional.resolve(strict=True)
benchmark = args.benchmark.resolve(strict=True)
base = args.base_evidence.resolve(strict=True)
base_rows = check_source(base / "source", base / "SOURCE_SHA256SUMS", args.base_source_sha)
identities = []
for directory, checksum in ((functional, args.functional_sha), (benchmark, args.benchmark_sha)):
    check_members(directory, "SHA256SUMS", checksum)
    identity = verify_receipt(directory)
    if identity["source_manifest_sha256"] != args.base_source_sha:
        raise SystemExit("bound E8 inputs do not share the approved base source")
    identities.append(identity)
version = identities[0]["openssl_version"]
if (version not in ("3.5.8", "4.0.2") or identities[1]["openssl_version"] != version
        or identities[1]["functional_receipt_sha256"] != args.functional_sha):
    raise SystemExit("E8 input ABI or receipt linkage mismatch")

receipt = Receipt(args.output, args.source_sha, "e8-review-followup")
out = receipt.output
build_root = canonical_build_source(receipt)
if receipt.identity["build_source_sha256"] != identities[0]["build_source_sha256"]:
    raise SystemExit("runtime inputs changed: this is no longer a tooling/test-only follow-up")
# Compare the entire runtime tree as well as its content-derived build identity.
runtime_paths = sorted(path for part in ("rust", "provider", "vectors")
                       for path in (ROOT / part).rglob("*") if path.is_file())
for path in runtime_paths:
    name = path.relative_to(ROOT).as_posix()
    if digest(path) != base_rows.get(name):
        raise SystemExit("runtime differs from approved E8: " + name)
receipt.identity.update(openssl_version=version,
    base_source_manifest_sha256=args.base_source_sha,
    functional_receipt_sha256=args.functional_sha,
    benchmark_receipt_sha256=args.benchmark_sha,
    runtime_files_compared=len(runtime_paths), runtime_changes=False,
    scope="new defined/tainted raw/parameter export and PKCS8 DER direct/bridge tests; existing E8 codegen replay; not a full new Gate E",
    excluded="PEM/base64, password encryption, all allocator failures and universal CT proof")
receipt.write_identity()
for part in ("cargo-home", "targets", "markers", "bin", "modules-taint"):
    (out / part).mkdir(mode=0o700)
prefix = functional / "openssl/inst" / version
lib = prefix / "lib"
runtime = dict(receipt.clean, OPENSSL_CONF="/dev/null", LD_LIBRARY_PATH=str(lib),
    OPENSSL_MODULES=str(out / "modules-taint"), ED301V2_EXPECT_OPENSSL_PREFIX=str(prefix),
    RUST_BACKTRACE="0")
receipt.run("cargo-config", ["/usr/bin/python3", "-I", "-B",
    ROOT / "rust/scripts/write-cargo-config.py", out / "cargo-home/config.toml", build_root / "rust/vendor"])
toolchain = receipt.run("toolchain", ["/usr/bin/rustc", "--version", "--verbose"])
if "release: 1.98.0\n" not in toolchain or "LLVM version: 21.1.8\n" not in toolchain:
    raise SystemExit("follow-up requires the reviewed E8 compiler")
receipt.run("valgrind-version", ["/usr/bin/valgrind", "--version"])
receipt.run("gawk-version", ["/usr/bin/gawk", "--version"])
receipt.run("driver-syntax", ["/bin/sh", "-n", ROOT / "phase-e/tools/check_codegen.sh"])
receipt.run("dependency-controls", ["/usr/bin/python3", "-I", "-B",
    ROOT / "phase-e/tools/test_codegen_prerequisites.py"])

for variant, feature, module in (
    ("ed-normal", "secret-taint-instrumentation", "ed301_eddsa_v2"),
    ("ed-pki", "secret-taint-instrumentation,pki-experiment", "ed301_eddsa_v2_pki_test"),
):
    marker = out / "markers" / variant
    marker.mkdir(mode=0o700)
    (marker / "toolchain.txt").write_text(toolchain)
    env = dict(runtime, CARGO_HOME=str(out / "cargo-home"),
        CARGO_TARGET_DIR=str(out / "targets" / variant), CARGO_NET_OFFLINE="true",
        CARGO_INCREMENTAL="0", CCACHE_DISABLE="1", CC="/usr/bin/gcc", AR="/usr/bin/ar",
        ED301_HERMETIC_PROVIDER_BUILD="1", X301_HERMETIC_PROVIDER_BUILD="1",
        ED301_HERMETIC_NATIVE_BUILD="1", OPENSSL_INCLUDE_DIR=str(prefix / "include"),
        OPENSSL_LIB_DIR=str(lib), ED301_PROFILE_MARKER_DIR=str(marker),
        RUSTC_WRAPPER=str(build_root / "phase-d/d2/tools/rustc_profile_guard.sh"))
    receipt.run("build-" + variant, ["/usr/bin/cargo", "build", "--manifest-path",
        build_root / "provider/Cargo.toml", "--release", "--locked", "--offline", "-vv",
        "-p", "ed301-eddsa-provider", "--features", feature], env)
    receipt.run("profile-" + variant, ["/bin/sh", ROOT / "rust/scripts/check-profile-markers.sh",
        marker, "crypto_bigint=on", "ed301_eddsa_v2=on"])
    destination = out / "modules-taint" / (module + ".so")
    shutil.copy2(out / "targets" / variant / "release/libed301_eddsa_v2.so", destination)
    destination.chmod(0o555)
    receipt.identity.setdefault("module_sha256", {})[destination.relative_to(out).as_posix()] = digest(destination)
receipt.write_identity()

for name in ("provider_secret_taint", "provider_taint_control"):
    receipt.run("compile-" + name, ["/usr/bin/gcc", "-std=c11", "-D_GNU_SOURCE", "-O2", "-g",
        "-Wall", "-Wextra", "-Werror", "-I" + str(prefix / "include"),
        "-I" + str(functional / "generated"), "-I" + str(ROOT / "provider-tests"),
        ROOT / "provider-tests" / (name + ".c"), "-o", out / "bin" / name,
        "-L" + str(lib), "-Wl,-rpath," + str(lib), "-lssl", "-lcrypto", "-ldl", "-pthread"])
taint = ["/usr/bin/valgrind", "--tool=memcheck", "--vgdb=no", "--error-exitcode=99",
    "--leak-check=full", "--errors-for-leak-kinds=definite,indirect,possible", "--quiet",
    "--track-origins=yes", "--undef-value-errors=yes"]
positive = receipt.run("taint-positive-control", taint + [out / "bin/provider_taint_control"], runtime, expected=99)
if not any(marker in positive for marker in ("uninitialised", "uninitialized")):
    raise SystemExit("instrumentation positive control did not fire")
for path in ("normal", "pki", "bridge"):
    for mode in ("defined", "tainted"):
        output = receipt.run("private-export-" + path + "-" + mode,
            taint + [out / "bin/provider_secret_taint", mode, path], runtime)
        marker = f"mode={mode} path={path} private_export=1 pkcs8_der={int(path != 'normal')} pass=1"
        if marker not in output:
            raise SystemExit("private export run did not attest its complete path")
for path in ("pki", "bridge"):
    output = receipt.run("export-positive-control-" + path,
        taint + [out / "bin/provider_secret_taint", "tainted", path, "export-control"], runtime, expected=99)
    if (output.count("private_export_positive_control=triggered") != 4
            or not any(marker in output for marker in ("uninitialised", "uninitialized"))
            or "private_export=1 pkcs8_der=1 pass=1" not in output):
        raise SystemExit("export positive control did not observe the four actual encoded outputs")

# The six measured E8 ELF inputs are unchanged. This repeats their exact
# arithmetic checks with the new dependency preflight; it is not a new build.
checker = ROOT / "phase-e/tools/check_codegen.sh"
for profile, variant, module in (
    ("ed", "ed-normal", "ed301_eddsa_v2"), ("ed", "ed-tls", "ed301_eddsa_v2_tls_test"),
    ("x", "x-normal", "x301_v2"), ("x", "x-tls", "x301_v2_tls_test"),
):
    receipt.run("codegen-" + module, ["/bin/sh", checker, profile + "-provider",
        functional / "modules" / (module + ".so"), functional / "markers" / variant / "toolchain.txt",
        out / ("codegen-" + module)])
for profile in ("ed", "x"):
    receipt.run("codegen-" + profile + "-core", ["/bin/sh", checker, profile + "-core",
        benchmark / "bin" / (profile + "-v2"), benchmark / "markers" / (profile + "-v2") / "toolchain.txt",
        out / ("codegen-" + profile + "-core")])
for name, checksum in receipt.identity["module_sha256"].items():
    if digest(out / name) != checksum:
        raise SystemExit("new instrumented DSO changed during validation")
for directory, checksum in ((functional, args.functional_sha), (benchmark, args.benchmark_sha)):
    check_members(directory, "SHA256SUMS", checksum)
check_source(base / "source", base / "SOURCE_SHA256SUMS", args.base_source_sha)
canonical_build_source(receipt)
receipt.identity.update(regular_taint_runs=6, positive_control_runs=3, existing_elf_codegen_replays=6)
receipt.seal()
