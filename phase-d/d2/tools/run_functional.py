#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Fresh offline provider builds and non-network functional acceptance, one ABI lane."""

import argparse
import json
from pathlib import Path
import shutil
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from d2_common import OPENSSL_EVIDENCE, ROOT, TOOLS, Receipt, canonical_build_source, digest

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--source-sha", required=True)
parser.add_argument("--openssl-lane", type=Path, required=True)
parser.add_argument("--version", choices=OPENSSL_EVIDENCE, required=True)
parser.add_argument("--output", type=Path, required=True)
args = parser.parse_args()
receipt = Receipt(args.output, args.source_sha, "non-network-functional")
out = receipt.output
build_root = canonical_build_source(receipt)
version = args.version
receipt.identity.update(openssl_version=version, openssl_evidence_sha256=OPENSSL_EVIDENCE[version],
                        tcp="separate required stage", native_c_optimization="release OPT_LEVEL=3",
                        rust_profile="O3/ThinLTO/CGU1/overflow-on/panic-unwind")
receipt.write_identity()
receipt.run("materialize-openssl", ["/bin/sh", TOOLS / "materialize_openssl_lane.sh",
            args.openssl_lane.resolve(), version, OPENSSL_EVIDENCE[version], out / "openssl"])
prefix = out / "openssl/inst" / version
lib = prefix / "lib"
for name in ("cargo-home", "targets", "markers", "modules", "fresh-modules", "bin", "generated"):
    (out / name).mkdir(mode=0o700)
receipt.run("cargo-config", ["/usr/bin/python3", "-I", "-B", ROOT / "rust/scripts/write-cargo-config.py",
                            out / "cargo-home/config.toml", build_root / "rust/vendor"])
runtime = dict(receipt.clean, OPENSSL_CONF="/dev/null", LD_LIBRARY_PATH=str(lib),
               OPENSSL_MODULES=str(out / "modules"), ED301V2_EXPECT_OPENSSL_PREFIX=str(prefix),
               ED301V2_FRESH_COPY_DIR=str(out / "fresh-modules"))
toolchain = receipt.run("rustc-identity", ["/usr/bin/rustc", "--version", "--verbose"])
receipt.run("cargo-identity", ["/usr/bin/cargo", "--version", "--verbose"])
receipt.run("gcc-identity", ["/usr/bin/gcc", "--version"])
receipt.run("openssl-identity", [prefix / "bin/openssl", "version", "-a"], runtime)
for profile in ("ed301", "x301"):
    receipt.run("profile-generation-" + profile, ["/usr/bin/python3", "-I", "-B",
                TOOLS / "generate_provider_profiles.py", profile, "--check",
                ROOT / "provider/common" / ("generated_" + profile + "_profile.h")])
receipt.run("ed-fixtures", ["/usr/bin/python3", "-I", "-B", ROOT / "provider-tests/gen_vectors.py",
            ROOT, out / "generated/vectors.h", out / "generated/policy_vectors_data.rs"])
receipt.run("ed-fixture-format", ["/usr/bin/rustfmt", "--edition", "2024",
                                 out / "generated/policy_vectors_data.rs"])
receipt.run("ed-fixture-compare", ["/usr/bin/cmp", out / "generated/policy_vectors_data.rs",
                                 ROOT / "provider/crates/ed301-eddsa-provider/src/policy_vectors_data.rs"])
receipt.run("x-fixtures", ["/usr/bin/python3", "-I", "-B", ROOT / "provider-tests/x301/gen_vectors.py",
                          out / "generated/generated"])


def build_environment(variant, guarded=True):
    env = dict(receipt.clean, CARGO_HOME=str(out / "cargo-home"),
               CARGO_TARGET_DIR=str(out / "targets" / variant), CARGO_NET_OFFLINE="true",
               CARGO_INCREMENTAL="0", CCACHE_DISABLE="1", CC="/usr/bin/gcc", AR="/usr/bin/ar",
               ED301_HERMETIC_PROVIDER_BUILD="1", X301_HERMETIC_PROVIDER_BUILD="1",
               OPENSSL_INCLUDE_DIR=str(prefix / "include"), OPENSSL_LIB_DIR=str(lib),
               OPENSSL_CONF="/dev/null", LD_LIBRARY_PATH=str(lib))
    if guarded:
        marker = out / "markers" / variant
        marker.mkdir(mode=0o700)
        (marker / "toolchain.txt").write_text(toolchain)
        env.update(ED301_PROFILE_MARKER_DIR=str(marker),
                   RUSTC_WRAPPER=str(build_root / "phase-d/d2/tools/rustc_profile_guard.sh"))
    return env


cargo = ["/usr/bin/cargo"]
manifest = build_root / "provider/Cargo.toml"
qa = build_environment("qa-analysis", False)
receipt.run("fmt", cargo + ["fmt", "--manifest-path", manifest, "--all", "--", "--check"], qa)
receipt.run("metadata", cargo + ["metadata", "--manifest-path", manifest,
                                "--locked", "--offline", "--format-version=1"], qa)
receipt.run("clippy", cargo + ["clippy", "--manifest-path", manifest, "--release",
                              "--locked", "--offline", "--workspace", "--all-targets", "--", "-D", "warnings"], qa)
receipt.run("documentation", cargo + ["doc", "--manifest-path", manifest, "--release", "--locked",
                                     "--offline", "--workspace", "--no-deps"], dict(qa, RUSTDOCFLAGS="-D warnings"))
unit_env = build_environment("unit")
unit_json = receipt.run("unit-build", cargo + ["test", "--manifest-path", manifest, "--release",
                        "--locked", "--offline", "--workspace", "--no-run", "--message-format=json"], unit_env)
receipt.run("unit-profile", ["/bin/sh", ROOT / "rust/scripts/check-profile-markers.sh", out / "markers/unit",
                            "crypto_bigint=on", "ed301_eddsa=on", "x301_core=on",
                            "ed301_eddsa_v2=on", "x301_v2=on"])
executables = set()
for line in unit_json.splitlines():
    if not line.startswith("{"):
        continue
    row = json.loads(line)
    if row.get("reason") == "compiler-artifact" and row.get("profile", {}).get("test") and row.get("executable"):
        executables.add(row["executable"])
if len(executables) != 2:
    raise SystemExit(f"expected both provider Rust unit-test binaries, found {len(executables)}")
for i, executable in enumerate(sorted(executables)):
    preserved = out / "bin" / f"rust-unit-{i}"
    shutil.copy2(executable, preserved)
    receipt.run(f"unit-run-{i}", [preserved], runtime)

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
module_hashes = {}
for variant, package, feature, library, module in variants:
    command = cargo + ["build", "--manifest-path", manifest, "--release", "--locked", "--offline",
                       "-vv", "-p", package]
    if feature:
        command += ["--features", feature]
    receipt.run("build-" + variant, command, build_environment(variant))
    requirements = ["crypto_bigint=on", library + "=on",
                    "ed301_eddsa=on" if package.startswith("ed301") else "x301_core=on"]
    receipt.run("profile-" + variant, ["/bin/sh", ROOT / "rust/scripts/check-profile-markers.sh",
                                     out / "markers" / variant] + requirements)
    destination = out / "modules" / (module + ".so")
    shutil.copy2(out / "targets" / variant / "release" / ("lib" + library + ".so"), destination)
    destination.chmod(0o555)
    module_hashes[module] = digest(destination)
    exports = receipt.run("exports-" + variant, ["/usr/bin/nm", "-D", "--defined-only", destination])
    public_functions = [line.split()[-1] for line in exports.splitlines() if " T " in line]
    if public_functions != ["OSSL_provider_init"]:
        raise SystemExit(f"unexpected exported functions: {module}: {public_functions}")
    receipt.run("ldd-" + variant, ["/usr/bin/ldd", destination], runtime)

# Same immutable manifest-derived source, independent clean target directories.
# No compiler, profile or source adjustments are permitted between the builds.
for variant, package, feature, library, module in (variants[0], variants[2], variants[5], variants[7]):
    again = variant + "-rebuild"
    command = cargo + ["build", "--manifest-path", manifest, "--release", "--locked", "--offline", "-p", package]
    if feature:
        command += ["--features", feature]
    receipt.run("build-" + again, command, build_environment(again))
    rebuilt = out / "targets" / again / "release" / ("lib" + library + ".so")
    if digest(rebuilt) != module_hashes[module]:
        raise SystemExit(f"non-reproducible DSO: {module}")
    receipt.run("profile-" + again, ["/bin/sh", ROOT / "rust/scripts/check-profile-markers.sh",
                out / "markers" / again, "crypto_bigint=on", library + "=on"])
    receipt.identity.setdefault("reproducible_dsos", []).append(module)

shutil.copy2(out / "modules/ed301_eddsa_v2_pki_test.so", out / "fresh-modules/ed301_eddsa_v2_pki_test.so")
if (out / "modules/ed301_eddsa_v2_pki_test.so").stat().st_ino == (out / "fresh-modules/ed301_eddsa_v2_pki_test.so").stat().st_ino:
    raise SystemExit("fresh-load fixture is not a separate physical file")

ed_harnesses = ["provider_load", "provider_keymgmt", "provider_signature", "provider_serialization", "provider_oid_collision",
                "provider_pki", "provider_rand", "provider_lifecycle", "provider_tls", "provider_hardening",
                "provider_load_fresh", "provider_shim_unit", "val01_decoder_bio", "val03_retry",
                "val05_codepoint", "provider_context_contract", "provider_generation_policy", "provider_discovery_order", "provider_tls_lengths", "provider_tls_tcp"]
x_harnesses = ["provider_x301_contract", "provider_x301_hybrid_contract",
               "provider_x301_nested_properties", "provider_x301_hybrid_kat"]


def compile_harness(name, source, extra=(), rpath=True):
    command = ["/usr/bin/gcc", "-std=c11", "-D_GNU_SOURCE", "-O2", "-Wall", "-Wextra", "-Werror",
               "-I" + str(prefix / "include"), "-I" + str(out / "generated"),
               "-I" + str(ROOT / "provider-tests")] + list(extra)
    command += [source, "-o", out / "bin" / name, "-L" + str(lib)]
    if rpath:
        command += ["-Wl,-rpath," + str(lib)]
    command += ["-lssl", "-lcrypto", "-ldl", "-pthread"]
    receipt.run("compile-" + name, command)


for name in ed_harnesses:
    compile_harness(name, ROOT / "provider-tests" / (name + ".c"))
for name in x_harnesses:
    compile_harness(name, ROOT / "provider-tests/x301" / (name + ".c"))
for source, name in (("provider_serialization", "x301_serialization"), ("val01_decoder_bio", "x301_decoder")):
    compile_harness(name, ROOT / "provider-tests" / (source + ".c"), ["-DX301_CODEC_TEST"])
compile_harness("x301_tls_contract", ROOT / "provider-tests/x301/provider_x301_contract.c",
                ['-DX301_PROVIDER="x301_v2_tls"'])
compile_harness("x301_failpoint_contract", ROOT / "provider-tests/x301/provider_x301_contract.c",
                ['-DX301_PROVIDER="x301_v2_failpoint"'])
compile_harness("provider_load_no_rpath", ROOT / "provider-tests/provider_load.c", rpath=False)
artifacts = {str(path.relative_to(out)): digest(path)
             for directory in ("modules", "bin", "generated", "fresh-modules")
             for path in (out / directory).rglob("*") if path.is_file()}
(out / "PRE_EXECUTION.json").write_text(json.dumps(artifacts, indent=2) + "\n")
for name in ed_harnesses:
    if name not in {"val03_retry", "provider_tls_tcp", "provider_oid_collision"}:
        receipt.run("run-" + name, [out / "bin" / name], runtime)
for name in x_harnesses:
    command = [out / "bin" / name]
    if name != "provider_x301_hybrid_kat":
        command.append(out / "modules")
    receipt.run("run-" + name, command, runtime)
for name in ("x301_serialization", "x301_decoder"):
    receipt.run("run-" + name, [out / "bin" / name], runtime)
receipt.run("run-x301-tls-contract", [out / "bin/x301_tls_contract", out / "modules"], runtime)
receipt.run("run-x301-failpoints", [out / "bin/x301_failpoint_contract", out / "modules"],
            dict(runtime, X301_V2_PROVIDER_FAILPOINT_MODE="active"))
receipt.run("run-x301-inert-hooks", [out / "bin/provider_x301_contract", out / "modules"],
            dict(runtime, X301_V2_PROVIDER_FAILPOINT_MODE="inert"))
for group in ("X301", "X301MLKEM1024"):
    receipt.run("run-ed-tls-" + group, [out / "bin/provider_tls"], dict(runtime, ED301V2_TLS_GROUP=group))
for mode in ("free", "object-only", "exact", "occupied-oid", "occupied-name", "sigid-conflict", "digest-slot", "public-slot"):
    receipt.run("oid-" + mode, [out / "bin/provider_oid_collision", mode], runtime)
for mode in ("exact-fast", "exact-stalled", "conflict"):
    receipt.run("retry-" + mode, [out / "bin/val03_retry", mode, out / "modules"], runtime)
negative = receipt.run("policy-observer-negative", [out / "bin/provider_signature"],
                       dict(runtime, ED301V2_POLICY_MUTATE="1"), expected=None)
if "FAIL" not in negative:
    raise SystemExit("policy mutation failed without a policy-check failure")
wrong_env = dict(runtime)
del wrong_env["LD_LIBRARY_PATH"]
negative = receipt.run("runtime-binding-negative", [out / "bin/provider_load_no_rpath"], wrong_env, expected=None)
if not any(text in negative for text in ("FATAL: runtime OpenSSL", "FATAL: libcrypto resolved", "error while loading shared libraries")):
    raise SystemExit("runtime negative control failed for an unexplained reason")

# OpenSSL's native evp_test allocates a private test libctx itself and loads
# null into the process default context. This config registers only the OID;
# provider activation is exclusively its explicit -provider argument.
native_config = out / "native-evp.cnf"
native_config.write_text("openssl_conf = init\n[init]\noid_section = oids\n[oids]\n"
                         "Ed301-EdDSA = 1.3.6.1.4.1.66282.301.5\n")
native = out / "openssl/src" / ("openssl-" + version) / "test/evp_test"
receipt.run("native-ed-evp", [native, "-config", native_config, "-provider", "ed301_eddsa_v2",
                            out / "generated/openssl_evp_ed301.txt"], runtime)
receipt.run("native-mlkem", [native, "-provider", "default", native.parent
                            / "recipes/30-test_evp_data/evppkey_ml_kem_encap_decap.txt"], runtime)
for name, checksum in artifacts.items():
    if digest(out / name) != checksum:
        raise SystemExit(f"executed artifact changed: {name}")
receipt.run("openssl-final-verification", ["/bin/sh", TOOLS / "verify_openssl_lane.sh",
            out / "openssl", version, OPENSSL_EVIDENCE[version]])
receipt.identity.update(module_sha256=module_hashes,
                        actual_v1_first="separate required stage with bound legacy modules",
                        cli="separate required stage", memory="separate required stage",
                        codegen="separate required stage", timing="separate required stage")
canonical_build_source(receipt)
receipt.seal()
