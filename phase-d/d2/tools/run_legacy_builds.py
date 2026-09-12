#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Build the exact bound v1 donors separately for version controls and same-layer timing."""

import argparse
from pathlib import Path
import shutil
import sys
import tarfile

sys.path.insert(0, str(Path(__file__).resolve().parent))
from d2_common import ROOT, Receipt, digest, verify_receipt

DONORS = {
    "ed": ("5c688206a15f6ab88a50d53fe503665a302cec4d", "1e8d540bf75e09011c0ffb728cb0e6fd264ce46f1d9161f8bd6b4510dfb02ffb"),
    "x": ("569dc4ff10e0e5e19d106cbe490d2a5aaeac935e", "179cdb066b5b8f74dd6f87b78f5d9576710fef9500e388b53747d427d73d9755"),
}
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--source-sha", required=True)
parser.add_argument("--functional", type=Path, required=True)
parser.add_argument("--functional-sha", required=True)
parser.add_argument("--ed-archive", type=Path, required=True)
parser.add_argument("--x-archive", type=Path, required=True)
parser.add_argument("--output", type=Path, required=True)
args = parser.parse_args()
functional = args.functional.resolve(strict=True)
if digest(functional / "SHA256SUMS") != args.functional_sha:
    raise SystemExit("functional receipt digest mismatch")
identity = verify_receipt(functional)
if identity["source_manifest_sha256"] != args.source_sha:
    raise SystemExit("legacy-build controller and v2 stages must use one D2 source snapshot")
receipt = Receipt(args.output, args.source_sha, "bound-v1-comparison-builds")
out = receipt.output
version = identity["openssl_version"]
prefix = functional / "openssl/inst" / version
receipt.identity.update(openssl_version=version, functional_receipt_sha256=args.functional_sha,
                        donor_identities=DONORS, v1_sources_modified=False,
                        legacy_x_native_profile="bound build.rs has no -O flag (C O0)",
                        legacy_x_crypto_bigint_overflow_checks=False,
                        v2_profile_unchanged="all crates overflow-on; C release O3")
receipt.write_identity()
for name in ("targets", "modules", "markers", "input", "generation-control-modules"):
    (out / name).mkdir(mode=0o700)
toolchain = receipt.run("toolchain", ["/usr/bin/rustc", "--version", "--verbose"])
for donor, archive in (("ed", args.ed_archive), ("x", args.x_archive)):
    if archive.is_symlink() or digest(archive) != DONORS[donor][1]:
        raise SystemExit("v1 donor archive identity mismatch")
    saved = out / "input" / (donor + ".tar.gz")
    shutil.copy2(archive, saved)
    source = out / (donor + "-source")
    source.mkdir(mode=0o700)
    with tarfile.open(saved, "r:gz") as bundle:
        seen = set()
        for member in bundle.getmembers():
            path = Path(member.name)
            if path.is_absolute() or ".." in path.parts or member.name in seen or not (member.isfile() or member.isdir()):
                raise SystemExit("unsafe donor archive member")
            seen.add(member.name)
        bundle.extractall(source, filter="data")
    source_files = sorted(path for path in source.rglob("*") if path.is_file())
    manifest = "".join(f"{digest(path)}  {path.relative_to(source).as_posix()}\n" for path in source_files)
    (out / (donor + "-SOURCE_SHA256SUMS")).write_text(manifest)
    for path in source_files:
        path.chmod(0o555 if path.stat().st_mode & 0o111 else 0o444)
    for path in sorted(source.rglob("*"), reverse=True):
        if path.is_dir():
            path.chmod(0o555)
    source.chmod(0o555)
    cargo_home = out / (donor + "-cargo-home")
    cargo_home.mkdir(mode=0o700)
    receipt.run(donor + "-cargo-config", ["/usr/bin/python3", "-I", "-B", ROOT / "rust/scripts/write-cargo-config.py",
                                        cargo_home / "config.toml", source / "vendor"])
    if donor == "ed":
        variants = (("ed-normal", "", "ed301_eddsa_v1"),
                    ("ed-pki", "pki-experiment", "ed301_eddsa_v1_pki_test"),
                    ("ed-tls", "tls-experiment", "ed301_eddsa_v1_tls_test"))
        package, library = "ed301-eddsa-provider", "ed301_eddsa_v1"
    else:
        variants = (("x-normal", "", "x301"), ("x-tls", "tls-x301-mlkem1024", "x301"))
        package, library = "x301-provider", "x301"
    for variant, feature, module in variants:
        marker = out / "markers" / variant
        marker.mkdir(mode=0o700)
        (marker / "toolchain.txt").write_text(toolchain)
        env = dict(receipt.clean, CARGO_HOME=str(cargo_home), CARGO_TARGET_DIR=str(out / "targets" / variant),
                   CARGO_NET_OFFLINE="true", CARGO_INCREMENTAL="0", CCACHE_DISABLE="1", CC="/usr/bin/gcc", AR="/usr/bin/ar",
                   ED301_HERMETIC_PROVIDER_BUILD="1", X301_HERMETIC_PROVIDER_BUILD="1",
                   OPENSSL_INCLUDE_DIR=str(prefix / "include"), OPENSSL_LIB_DIR=str(prefix / "lib"),
                   LD_LIBRARY_PATH=str(prefix / "lib"), OPENSSL_CONF="/dev/null",
                   ED301_PROFILE_MARKER_DIR=str(marker), RUSTC_WRAPPER=str(source / "scripts/rustc-profile-guard.sh"))
        if donor == "x":
            env["ED301_PROFILE_EXCEPTIONS"] = "crypto_bigint=off"
        command = ["/usr/bin/cargo", "build", "--manifest-path", source / "provider/Cargo.toml", "--release",
                   "--locked", "--offline", "-vv", "-p", package]
        if feature:
            command += ["--features", feature]
        receipt.run("build-" + variant, command, env)
        receipt.run("profile-" + variant, ["/bin/sh", source / "scripts/check-profile-markers.sh", marker,
                    "crypto_bigint=" + ("off" if donor == "x" else "on"), "ed301_eddsa=on", library + "=on"])
        directory = out / "modules" / variant
        directory.mkdir(mode=0o700)
        destination = directory / (module + ".so")
        shutil.copy2(out / "targets" / variant / "release" / ("lib" + library + ".so"), destination)
        destination.chmod(0o555)
        receipt.identity.setdefault("module_sha256", {})[str(destination.relative_to(out))] = digest(destination)
        if variant in {"ed-normal", "x-normal"}:
            shutil.copy2(destination, out / "generation-control-modules" / destination.name)
    if manifest != "".join(f"{digest(path)}  {path.relative_to(source).as_posix()}\n" for path in source_files):
        raise SystemExit("legacy source changed during compilation")
runtime = dict(receipt.clean, OPENSSL_CONF="/dev/null", OPENSSL_MODULES=str(functional / "modules"),
               LD_LIBRARY_PATH=str(prefix / "lib"), ED301V2_EXPECT_OPENSSL_PREFIX=str(prefix))
receipt.run("actual-generation-policy", [functional / "bin/provider_generation_policy",
            out / "generation-control-modules"], runtime)
receipt.run("compile-version-control", ["/usr/bin/gcc", "-std=c11", "-D_GNU_SOURCE", "-O2", "-Wall", "-Wextra", "-Werror",
            "-I" + str(prefix / "include"), "-I" + str(ROOT / "provider-tests"),
            ROOT / "provider-tests/provider_version_isolation.c", "-o", out / "provider_version_isolation",
            "-L" + str(prefix / "lib"), "-Wl,-rpath," + str(prefix / "lib"), "-lssl", "-lcrypto", "-ldl", "-pthread"])
receipt.run("version-control", [out / "provider_version_isolation", out / "modules", functional / "modules"], runtime)
verify_receipt(functional)
receipt.seal()
