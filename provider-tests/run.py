#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Build the OpenSSL provider variants and run the provider C test suite.

Runs against an installed OpenSSL (default prefix /usr). From the repository root:

    python3 -I provider-tests/run.py [--openssl-prefix /usr] [--workdir DIR]

Steps: provider profile-header and fixture checks, the build_support.rs
regression test (also runnable alone: python3 -I provider-tests/test_build_support.py),
provider Rust unit tests, nine provider builds copied to DIR/modules, the C
harnesses with their argument/environment variants, and two negative controls.
CARGO_HOME is taken from the environment if set. Cargo needs registry access.

Not run here: OpenSSL's native evp_test (ed301 EVP file and ML-KEM data), which
needs an OpenSSL source tree; the Ed301 EVP test file is still generated as
DIR/generated/openssl_evp_ed301.txt.
"""

import argparse
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
TESTS = ROOT / "provider-tests"
MANIFEST = ROOT / "provider/Cargo.toml"

parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
parser.add_argument("--openssl-prefix", type=Path, default=Path("/usr"))
parser.add_argument("--workdir", type=Path)
args = parser.parse_args()

prefix = args.openssl_prefix.resolve()
include = prefix / "include"
lib = next((prefix / d for d in ("lib64", "lib") if (prefix / d / "libcrypto.so").exists()), None)
if not (include / "openssl/opensslv.h").is_file() or lib is None:
    raise SystemExit(f"no OpenSSL headers and libcrypto.so under {prefix}")
work = (args.workdir or Path(tempfile.mkdtemp(prefix="provider-tests-"))).resolve()
for name in ("home", "logs", "target", "modules", "fresh-modules", "bin", "generated"):
    (work / name).mkdir(parents=True, exist_ok=True)
modules, bin_dir, generated = work / "modules", work / "bin", work / "generated"
print(f"workdir={work} openssl_include={include} openssl_lib={lib}", flush=True)

# The harnesses require libcrypto to come from exactly <ED301V2_EXPECT_OPENSSL_PREFIX>/lib.
# For a lib64 layout, point them at a small prefix whose lib links to the real directory.
expect_prefix = prefix
if (prefix / "lib").resolve() != lib.resolve():
    expect_prefix = work / "openssl-prefix"
    expect_prefix.mkdir(exist_ok=True)
    for link, target in (("lib", lib), ("include", include)):
        if not (expect_prefix / link).is_symlink():
            (expect_prefix / link).symlink_to(target)

# A clean environment: build scripts reject CFLAGS, CPPFLAGS, LDFLAGS and similar overrides.
clean = {"PATH": "/usr/bin:/bin", "HOME": str(work / "home"), "LC_ALL": "C",
         "CARGO_HOME": os.environ.get("CARGO_HOME", str(work / "cargo-home"))}
build_env = dict(clean, CARGO_TARGET_DIR=str(work / "target"), CARGO_INCREMENTAL="0", CCACHE_DISABLE="1",
                 CC="/usr/bin/gcc", AR="/usr/bin/ar", ED301_HERMETIC_PROVIDER_BUILD="1",
                 X301_HERMETIC_PROVIDER_BUILD="1", OPENSSL_INCLUDE_DIR=str(include),
                 OPENSSL_LIB_DIR=str(lib), OPENSSL_CONF="/dev/null", LD_LIBRARY_PATH=str(lib))
runtime = dict(clean, OPENSSL_CONF="/dev/null", LD_LIBRARY_PATH=str(lib), OPENSSL_MODULES=str(modules),
               ED301V2_EXPECT_OPENSSL_PREFIX=str(expect_prefix),
               ED301V2_FRESH_COPY_DIR=str(work / "fresh-modules"))


def step(name, command, env=clean, expect_failure=False):
    """Run one command, log its output, print PASS/FAIL and stop on failure."""
    log = work / "logs" / (name + ".log")
    with log.open("w") as stream:
        try:
            code = subprocess.run([str(part) for part in command], cwd="/", env=env, stdout=stream,
                                  stderr=subprocess.STDOUT, timeout=1800).returncode
        except subprocess.TimeoutExpired:
            code = None
    output = log.read_text(errors="replace")
    # A negative control must exit non-zero on its own, not time out or die from a signal.
    ok = code is not None and ((code > 0) if expect_failure else code == 0)
    print(f"{'PASS' if ok else 'FAIL'} {name}", flush=True)
    if not ok:
        print(output[-16000:] + f"\nexit={code}; log: {log}", flush=True)
        sys.exit(1)
    return output


python = [sys.executable, "-I", "-B"]
for profile in ("ed301", "x301"):
    step("profile-header-" + profile, python + [ROOT / "tools/generate_provider_profiles.py", profile,
         "--check", ROOT / "provider/common" / f"generated_{profile}_profile.h"])
step("build-support-test", python + [TESTS / "test_build_support.py"])
step("ed-fixtures", python + [TESTS / "gen_vectors.py", ROOT, generated / "vectors.h",
                              generated / "policy_vectors_data.rs"])
step("ed-fixtures-rustfmt", ["/usr/bin/rustfmt", "--edition", "2024", generated / "policy_vectors_data.rs"])
step("ed-fixtures-compare", ["/usr/bin/cmp", generated / "policy_vectors_data.rs",
                             ROOT / "provider/crates/ed301-eddsa-provider/src/policy_vectors_data.rs"])
step("x-fixtures", python + [TESTS / "x301/gen_vectors.py", generated / "generated"])

cargo = ["/usr/bin/cargo"]
step("rust-unit-tests", cargo + ["test", "--manifest-path", MANIFEST, "--release", "--locked", "--workspace"],
     build_env)

# (name, package, cargo feature, built library, installed module name)
variants = [
    ("ed-normal", "ed301-eddsa-provider", "", "ed301_eddsa_v2", "ed301_eddsa_v2"),
    ("ed-pki", "ed301-eddsa-provider", "pki-experiment", "ed301_eddsa_v2", "ed301_eddsa_v2_pki_test"),
    ("ed-tls", "ed301-eddsa-provider", "tls-experiment", "ed301_eddsa_v2", "ed301_eddsa_v2_tls"),
    ("ed-collider", "ed301-eddsa-provider", "tls-collider", "ed301_eddsa_v2", "ed301_eddsa_v2_tls_collider"),
    ("ed-failpoint", "ed301-eddsa-provider", "test-failpoint", "ed301_eddsa_v2", "ed301_eddsa_v2_failpoint"),
    ("x-normal", "x301-provider", "", "x301_v2", "x301_v2"),
    ("x-pki", "x301-provider", "pki-experiment", "x301_v2", "x301_v2_pki_test"),
    ("x-tls", "x301-provider", "tls-x301-mlkem1024", "x301_v2", "x301_v2_tls"),
    ("x-failpoint", "x301-provider", "test-failpoint", "x301_v2", "x301_v2_failpoint"),
]
for variant, package, feature, library, module in variants:
    command = cargo + ["build", "--manifest-path", MANIFEST, "--release", "--locked", "-p", package]
    step("build-" + variant, command + (["--features", feature] if feature else []), build_env)
    destination = modules / (module + ".so")
    destination.unlink(missing_ok=True)
    shutil.copy2(work / "target/release" / f"lib{library}.so", destination)
    destination.chmod(0o555)
    exports = step("exports-" + variant, ["/usr/bin/nm", "-D", "--defined-only", destination])
    functions = [line.split()[-1] for line in exports.splitlines() if " T " in line]
    if functions != ["OSSL_provider_init"]:
        print(f"FAIL exports-{variant}: unexpected exported functions {functions}")
        sys.exit(1)

# provider_load_fresh loads the same module from a second, physically separate file.
fresh = work / "fresh-modules/ed301_eddsa_v2_pki_test.so"
fresh.unlink(missing_ok=True)
shutil.copy2(modules / "ed301_eddsa_v2_pki_test.so", fresh)
if fresh.stat().st_ino == (modules / "ed301_eddsa_v2_pki_test.so").stat().st_ino:
    print("FAIL fresh-copy: not a separate file")
    sys.exit(1)

ed_harnesses = ["provider_load", "provider_keymgmt", "provider_signature", "provider_serialization",
                "provider_oid_collision", "provider_pki", "provider_rand", "provider_rand_boundary",
                "provider_password_policy", "provider_lifecycle", "provider_tls", "provider_hardening",
                "provider_load_fresh", "provider_shim_unit", "provider_param_helpers", "val01_decoder_bio",
                "val03_retry", "val05_codepoint", "provider_context_contract", "provider_generation_policy",
                "provider_discovery_order", "provider_tls_lengths", "provider_tls_tcp"]
x_harnesses = ["provider_x301_contract", "provider_x301_hybrid_contract",
               "provider_x301_nested_properties", "provider_x301_hybrid_kat"]


def compile_harness(name, source, extra=(), rpath=True):
    command = ["/usr/bin/gcc", "-std=c11", "-D_GNU_SOURCE", "-O2", "-Wall", "-Wextra", "-Werror",
               f"-I{include}", f"-I{generated}", f"-I{TESTS}", *extra, source, "-o", bin_dir / name, f"-L{lib}"]
    command += [f"-Wl,-rpath,{lib}"] if rpath else []
    step("compile-" + name, command + ["-lssl", "-lcrypto", "-ldl", "-pthread"])


for name in ed_harnesses:
    compile_harness(name, TESTS / f"{name}.c")
for name in x_harnesses:
    compile_harness(name, TESTS / f"x301/{name}.c")
# Four ed301 harnesses double as X301 codec/RAND tests when built with -DX301_CODEC_TEST.
for source, name in (("provider_serialization", "x301_serialization"), ("val01_decoder_bio", "x301_decoder"),
                     ("provider_password_policy", "x301_password_policy"),
                     ("provider_rand_boundary", "x301_rand_boundary")):
    compile_harness(name, TESTS / f"{source}.c", ["-DX301_CODEC_TEST"])
compile_harness("x301_tls_contract", TESTS / "x301/provider_x301_contract.c", ['-DX301_PROVIDER="x301_v2_tls"'])
compile_harness("x301_failpoint_contract", TESTS / "x301/provider_x301_contract.c",
                ['-DX301_PROVIDER="x301_v2_failpoint"'])
compile_harness("provider_load_no_rpath", TESTS / "provider_load.c", rpath=False)
# X301 shim ABI-table and core-version checks, linked directly without loading a module.
compile_harness("x301_shim_unit", TESTS / "x301/provider_x301_shim_unit.c")
compile_harness("x301_shim_unit_hybrid", TESTS / "x301/provider_x301_shim_unit.c",
                ["-DX301_ENABLE_HYBRID_MLKEM1024=1", ROOT / "provider/crates/x301-provider/c/hybrid_kem.c"])

for name in ed_harnesses:
    if name not in ("val03_retry", "provider_tls_tcp", "provider_oid_collision"):  # run with modes below
        step("run-" + name, [bin_dir / name], runtime)
for name in x_harnesses:
    step("run-" + name, [bin_dir / name] + ([] if name == "provider_x301_hybrid_kat" else [modules]), runtime)
for name in ("x301_serialization", "x301_decoder", "x301_password_policy", "x301_rand_boundary"):
    step("run-" + name, [bin_dir / name], runtime)
for name in ("x301_shim_unit", "x301_shim_unit_hybrid"):
    step("run-" + name, [bin_dir / name], runtime)
step("run-x301-tls-contract", [bin_dir / "x301_tls_contract", modules], runtime)
step("run-x301-failpoints", [bin_dir / "x301_failpoint_contract", modules],
     dict(runtime, X301_V2_PROVIDER_FAILPOINT_MODE="active"))
step("run-x301-inert-hooks", [bin_dir / "provider_x301_contract", modules],
     dict(runtime, X301_V2_PROVIDER_FAILPOINT_MODE="inert"))
for group in ("X301", "X301MLKEM1024"):
    step("run-ed-tls-" + group, [bin_dir / "provider_tls"], dict(runtime, ED301V2_TLS_GROUP=group))
for mode in ("free", "object-only", "exact", "occupied-oid", "occupied-name", "sigid-conflict",
             "digest-slot", "public-slot"):
    step("oid-collision-" + mode, [bin_dir / "provider_oid_collision", mode], runtime)
for mode in ("exact-fast", "exact-stalled", "conflict"):
    step("retry-" + mode, [bin_dir / "val03_retry", mode, modules], runtime)
step("run-provider_tls_tcp", [bin_dir / "provider_tls_tcp"], runtime)

# Negative control 1: a mutated signature policy must be reported as a FAIL.
output = step("negative-policy-mutation", [bin_dir / "provider_signature"],
              dict(runtime, ED301V2_POLICY_MUTATE="1"), expect_failure=True)
if "FAIL" not in output:
    print("FAIL negative-policy-mutation: failed without a policy-check failure")
    sys.exit(1)

# Negative control 2: without rpath and LD_LIBRARY_PATH the harness must reject the
# libcrypto it gets. If OpenSSL sits in a default loader directory the loader still finds
# it, so the harness is told to expect an empty decoy prefix instead.
wrong_env = {key: value for key, value in runtime.items() if key != "LD_LIBRARY_PATH"}
if str(lib.resolve()) in ("/lib", "/lib64", "/usr/lib", "/usr/lib64"):
    (work / "decoy-prefix/lib").mkdir(parents=True, exist_ok=True)
    wrong_env["ED301V2_EXPECT_OPENSSL_PREFIX"] = str(work / "decoy-prefix")
output = step("negative-runtime-binding", [bin_dir / "provider_load_no_rpath"], wrong_env, expect_failure=True)
if not any(text in output for text in ("FATAL: runtime OpenSSL", "FATAL: libcrypto resolved",
                                       "error while loading shared libraries")):
    print("FAIL negative-runtime-binding: failed for an unexplained reason")
    sys.exit(1)
print("ALL PASS", flush=True)
