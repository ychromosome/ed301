#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Build and taint-check the current core with a clean, enforced Rust profile."""

import hashlib
import json
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]
RUST = ROOT / "rust"
WORK = Path(tempfile.mkdtemp(prefix="ED301-v2_core-taint_", dir=ROOT.parent))
for name in ("home", "cargo-home", "target", "markers", "logs"):
    (WORK / name).mkdir(mode=0o700)
COMMANDS = []


def run(command, env, name):
    print(f"STEP: {name}", flush=True)
    result = subprocess.run(command, cwd="/", env=env, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    print(result.stdout, end="", flush=True)
    log = WORK / "logs" / f"{len(COMMANDS):03d}.log"
    log.write_text(result.stdout)
    COMMANDS.append({"command": command, "environment": env, "step": name,
                     "log": str(log.relative_to(WORK)), "exit": result.returncode})
    (WORK / "commands.json").write_text(json.dumps(COMMANDS, indent=2) + "\n")
    if result.returncode:
        raise SystemExit(f"FAIL: {name}: exit {result.returncode}; artifacts retained in {WORK}")
    return result.stdout


clean = {"PATH": "/usr/bin:/bin", "HOME": str(WORK / "home"), "LC_ALL": "C"}
print(f"artifact_directory={WORK}", flush=True)
sources = sorted(p for p in RUST.rglob("*") if p.is_file())
source_manifest = "".join(f"{hashlib.sha256(p.read_bytes()).hexdigest()}  {p.relative_to(ROOT)}\n"
                          for p in sources)
(WORK / "SOURCE_SHA256SUMS").write_text(source_manifest)
run(["/usr/bin/python3", "-I", "-B", str(RUST / "scripts/write-cargo-config.py"),
     str(WORK / "cargo-home/config.toml"), str(RUST / "vendor")], clean, "isolated Cargo configuration")
build = dict(clean, CARGO_HOME=str(WORK / "cargo-home"), CARGO_TARGET_DIR=str(WORK / "target"),
             CARGO_NET_OFFLINE="true", CARGO_INCREMENTAL="0", CCACHE_DISABLE="1",
             CC="/usr/bin/gcc", AR="/usr/bin/ar", ED301_HERMETIC_NATIVE_BUILD="1",
             ED301_PROFILE_MARKER_DIR=str(WORK / "markers"),
             RUSTC_WRAPPER=str(RUST / "scripts/rustc-profile-guard.sh"))
toolchain = run(["/usr/bin/rustc", "--version", "--verbose"], clean, "compiler identity")
(WORK / "markers/toolchain.txt").write_text(toolchain)
run(["/usr/bin/cargo", "build", "--manifest-path", str(RUST / "secret-taint/Cargo.toml"),
     "--locked", "--offline", "--release"], build, "instrumented core build")
run(["/bin/sh", str(RUST / "scripts/check-profile-markers.sh"), str(WORK / "markers"),
     "crypto_bigint=on", "ed301_eddsa=on", "ed301_valgrind_client=on", "ed301_eddsa_secret_taint=on"],
    clean, "enforced per-crate build profile")
vector_bytes = (ROOT / "vectors/ed301-eddsa-v2.json").read_bytes()
if hashlib.sha256(vector_bytes).hexdigest() != "4dbbd93f5814f4e676b8007b13973037a7924872d46d328cdaeb314cd3190e82":
    raise SystemExit("FAIL: approved vector hash")
binary = WORK / "target/release/ed301-eddsa-secret-taint"
cases = json.loads(vector_bytes)["signing"]
for case in cases:
    test_env = dict(clean, ED301_CT_SECRET_HEX=case["seed_hex"],
                    ED301_CT_EXPECTED_PUBLIC_HEX=case["trace"]["public_key"],
                    ED301_CT_EXPECTED_SIGNATURE_HEX=case["trace"]["signature"],
                    ED301_CT_MESSAGE_HEX=case["message_hex"],
                    ED301_CT_CONTEXT_HEX=case["context_hex"])
    for mode in ("defined", "tainted"):
        for operation in ("public", "sign"):
            run(["/usr/bin/valgrind", "--tool=memcheck", "--vgdb=no", "--error-exitcode=99",
                 "--track-origins=yes", "--undef-value-errors=yes", "--leak-check=full",
                 "--errors-for-leak-kinds=definite,indirect,possible", "--quiet", str(binary),
                 f"--case={operation}", f"--mode={mode}"], test_env, f"{case['id']}/{operation}/{mode}")
summary = {"status": "PASS", "scope": "core taint public/sign; not provider or timing approval",
           "vectors": len(cases), "valgrind_runs": len(cases) * 4,
           "input_taint_state_checked": True,
           "source_manifest_sha256": hashlib.sha256(source_manifest.encode()).hexdigest(),
           "runner_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
           "artifact_directory": str(WORK), "binary_sha256": hashlib.sha256(binary.read_bytes()).hexdigest()}
(WORK / "SUMMARY.json").write_text(json.dumps(summary, indent=2) + "\n")
if source_manifest != "".join(f"{hashlib.sha256(p.read_bytes()).hexdigest()}  {p.relative_to(ROOT)}\n"
                             for p in sources):
    raise SystemExit("FAIL: source changed during taint test")
receipt_files = sorted(p for p in WORK.rglob("*") if p.is_file()
                       and "target" not in p.relative_to(WORK).parts and p.name != "SHA256SUMS")
(WORK / "SHA256SUMS").write_text("".join(f"{hashlib.sha256(p.read_bytes()).hexdigest()}  {p.relative_to(WORK)}\n"
                                        for p in receipt_files))
print(json.dumps(summary, sort_keys=True))
