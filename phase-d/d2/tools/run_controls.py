#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Self-controls for source/build admission and relocated OpenSSL evidence verification."""

import argparse
from pathlib import Path
import shutil
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from d2_common import OPENSSL_EVIDENCE, ROOT, TOOLS, Receipt, digest, verify_receipt

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
    raise SystemExit("control and functional stages must use one source snapshot")
receipt = Receipt(args.output, args.source_sha, "evidence-and-build-controls")
out = receipt.output
version = identity["openssl_version"]
prefix = functional / "openssl/inst" / version
receipt.identity.update(openssl_version=version, functional_receipt_sha256=args.functional_sha,
                        modified_libraries_executed=False, original_openssl_artifacts_modified=False)
receipt.write_identity()


def reseal_outer(lane):
    manifest = lane / "logs" / version / "evidence_manifest.sha256"
    lines = []
    for line in manifest.read_text().splitlines():
        _, name = line.split("  ", 1)
        lines.append(f"{digest(lane / name)}  {name}\n")
    manifest.write_text("".join(lines))
    return digest(manifest)


for name in ("wrong-digest", "tar-bytes", "prefix-extra", "prefix-missing", "prefix-link",
             "native-evp-bytes", "empty-seal", "duplicate-seal-member", "mixed-origin", "member-bytes"):
    lane = out / name
    shutil.copytree(functional / "openssl", lane, symlinks=True)
    for path in [lane] + list(lane.rglob("*")):
        if not path.is_symlink():
            path.chmod(path.stat().st_mode | 0o200)
    command = ["/bin/sh", TOOLS / "verify_openssl_lane.sh", lane, version]
    receipt.run("positive-" + name, command + [OPENSSL_EVIDENCE[version]])
    expected = OPENSSL_EVIDENCE[version]
    logs = lane / "logs" / version
    installed = lane / "inst" / version
    if name == "wrong-digest":
        expected = "0" * 64
    elif name == "tar-bytes":
        with (lane / "input" / ("openssl-" + version + ".tar.gz")).open("ab") as stream:
            stream.write(b"\x00")
    elif name == "prefix-extra":
        (installed / "unlisted-test-file").write_text("controlled inventory test\n")
    elif name == "prefix-missing":
        (installed / "include/openssl/asn1.h").unlink()
    elif name == "prefix-link":
        link = installed / "lib/libcrypto.so"
        target = link.resolve()
        link.unlink()
        link.symlink_to(target)
    elif name == "native-evp-bytes":
        with (lane / "src" / ("openssl-" + version) / "test/evp_test").open("ab") as stream:
            stream.write(b"\x00")
    elif name == "empty-seal":
        (logs / "source_manifest_post.sha256.seal").write_text("")
        expected = reseal_outer(lane)
    elif name == "duplicate-seal-member":
        seal = logs / "installed_prefix_manifest.seal"
        text = seal.read_text()
        seal.write_text(text + text.splitlines()[0] + "\n")
        expected = reseal_outer(lane)
    elif name == "mixed-origin":
        seal = logs / "installed_prefix_manifest.seal"
        rows = seal.read_text().splitlines()
        checksum, old = rows[0].split("  ", 1)
        rows[0] = checksum + f"  /tmp/different-test-origin/logs/{version}/" + Path(old).name
        seal.write_text("\n".join(rows) + "\n")
        expected = reseal_outer(lane)
    elif name == "member-bytes":
        member = logs / "source_manifest_post.sha256"
        member.write_text(member.read_text() + "\n")
        expected = reseal_outer(lane)
    log = receipt.run("negative-" + name, command + [expected], expected=None)
    required = {"empty-seal": "legacy seal member inventory mismatch",
                "duplicate-seal-member": "duplicate legacy seal member",
                "mixed-origin": "legacy seals disagree", "member-bytes": "legacy seal hash mismatch"}.get(name)
    if required is not None and required not in log:
        raise SystemExit("relocation control failed outside the intended inner-seal check")

# Compile the real native boundaries; an artificial old header must fail by
# the explicit admission guard, never merely because an API name is missing.
override = out / "old-header.h"
override.write_text("#include <openssl/opensslv.h>\n#undef OPENSSL_VERSION_MAJOR\n"
                    "#undef OPENSSL_VERSION_MINOR\n#undef OPENSSL_VERSION_PATCH\n"
                    "#define OPENSSL_VERSION_MAJOR 2\n#define OPENSSL_VERSION_MINOR 0\n#define OPENSSL_VERSION_PATCH 0\n")
for provider in ("ed301-eddsa-provider", "x301-provider"):
    source = ROOT / "provider/crates" / provider / "c/provider_shim.c"
    command = ["/usr/bin/gcc", "-std=c11", "-D_GNU_SOURCE", "-fsyntax-only", "-Wall", "-Wextra",
               "-I" + str(prefix / "include"), source]
    receipt.run("header-positive-" + provider, command)
    log = receipt.run("header-negative-" + provider, command[:1] + ["-include", override] + command[1:], expected=None)
    if "#error" not in log or any(word in log for word in ("implicit declaration", "undeclared", "did you mean")):
        raise SystemExit("header admission did not fail cleanly through its explicit version guard")
runtime = dict(receipt.clean, LD_LIBRARY_PATH=str(prefix / "lib"), OPENSSL_CONF="/dev/null",
               ED301V2_EXPECT_OPENSSL_PREFIX=str(prefix))
for hybrid in (False, True):
    name = "x-shim-hybrid" if hybrid else "x-shim-ordinary"
    command = ["/usr/bin/gcc", "-std=c11", "-D_GNU_SOURCE", "-O2", "-Wall", "-Wextra", "-Werror",
               "-I" + str(prefix / "include"), ROOT / "provider-tests/x301/provider_x301_shim_unit.c"]
    if hybrid:
        command += ["-DX301_ENABLE_HYBRID_MLKEM1024=1", ROOT / "provider/crates/x301-provider/c/hybrid_kem.c"]
    command += ["-o", out / name, "-L" + str(prefix / "lib"), "-Wl,-rpath," + str(prefix / "lib"), "-lcrypto", "-ldl", "-pthread"]
    receipt.run("compile-" + name, command)
    receipt.run("run-" + name, [out / name], runtime)

for name, source, flags in (
    ("ed", ROOT / "provider/crates/ed301-eddsa-provider/c/provider_shim.c", ["-DED301V2_TLS_EXPERIMENT_ARTIFACT=1"]),
    ("x", ROOT / "provider/crates/x301-provider/c/provider_shim.c", ["-DX301_ENABLE_HYBRID_MLKEM1024=1", "-DX301_PKI_EXPERIMENT_ARTIFACT=1"]),
    ("hybrid", ROOT / "provider/crates/x301-provider/c/hybrid_kem.c", ["-DX301_ENABLE_HYBRID_MLKEM1024=1"]),
):
    common = ["-std=c11", "-D_GNU_SOURCE", "-Wall", "-Wextra", "-Werror", "-I" + str(prefix / "include")] + flags
    receipt.run("gcc-analyzer-" + name, ["/usr/bin/gcc", "-fanalyzer"] + common
                + ["-c", source, "-o", out / (name + ".analyzer.o")])
    receipt.run("clang-analyzer-" + name, ["/usr/bin/scan-build", "--status-bugs", "--use-cc=/usr/bin/clang",
                "-o", out / (name + "-scan-build"), "/usr/bin/clang"] + common
                + ["-c", source, "-o", out / (name + ".scan-build.o")])

sample = out / "profile_control.rs"
sample.write_text("pub fn add(a: u64, b: u64) -> u64 { a + b }\n")
for name, flags in (("accepted", []), ("overflow-off", ["-Coverflow-checks=off"]),
                    ("panic-abort", ["-Cpanic=abort"]), ("o2", ["-Copt-level=2"]),
                    ("cgu2", ["-Ccodegen-units=2"]), ("debug", ["-Cdebug-assertions=on"])):
    marker = out / ("profile-" + name)
    marker.mkdir(mode=0o700)
    env = dict(receipt.clean, ED301_PROFILE_MARKER_DIR=str(marker))
    command = ["/bin/sh", TOOLS / "rustc_profile_guard.sh", "/usr/bin/rustc", "--crate-name", "profile_control",
               "--crate-type", "lib", sample, "-o", out / (name + ".rlib")] + flags
    receipt.run("rust-profile-" + name, command, env, expected=0 if name == "accepted" else None)
    successes = list(marker.glob("*.success"))
    if (name == "accepted" and len(successes) != 1) or (name != "accepted" and successes):
        raise SystemExit("profile guard success attestation mismatch")
verify_receipt(functional)
receipt.seal()
