#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Fresh offline correctness/profile/no_std receipt, separate from timing gates."""
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]
RUST = ROOT / "rust"
WORK = Path(tempfile.mkdtemp(prefix="ED301-v2_core-check_", dir=ROOT.parent))
for part in ("home", "cargo-home", "target", "markers", "logs", "downstream/src"):
    (WORK / part).mkdir(parents=True)
clean = {"PATH": "/usr/bin:/bin", "HOME": str(WORK / "home"), "LC_ALL": "C"}
commands = []
print(f"artifact_directory={WORK}", flush=True)


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def run(command, name, env=None, cwd="/"):
    command = list(map(str, command))
    print(f"STEP: {name}", flush=True)
    result = subprocess.run(command, cwd=cwd, env=env or clean, text=True,
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    log = WORK / "logs" / f"{len(commands):03d}-{name}.log"
    log.write_text(result.stdout)
    commands.append({"command": command, "step": name, "cwd": str(cwd),
                     "environment": env or clean, "exit": result.returncode,
                     "log": str(log.relative_to(WORK))})
    (WORK / "commands.json").write_text(json.dumps(commands, indent=2) + "\n")
    print(result.stdout, end="", flush=True)
    if result.returncode:
        raise SystemExit(f"FAIL: {name}; artifacts retained at {WORK}")
    return result.stdout


def sources():
    return "".join(f"{digest(p)}  {p.relative_to(ROOT)}\n"
                   for p in sorted(RUST.rglob("*")) if p.is_file())


manifest = sources()
(WORK / "SOURCE_SHA256SUMS").write_text(manifest)
run(["python3", "-I", "-B", ROOT / "phase-c/tools/generate_rust_parameters.py", "--check",
     RUST / "crates/ed301-eddsa/src/generated_parameters.rs"],
    "generated-parameters")
run(["python3", "-I", "-B", ROOT / "phase-c/tools/check_field_bounds.py"], "field-bounds")
run(["python3", "-I", "-B", RUST / "scripts/check-vendor-forks.py"], "vendor-forks", cwd=RUST)
run(["python3", "-I", "-B", RUST / "scripts/write-cargo-config.py",
     WORK / "cargo-home/config.toml", RUST / "vendor"], "cargo-config")
toolchain = run(["rustc", "--version", "--verbose"], "toolchain")
(WORK / "markers/toolchain.txt").write_text(toolchain)
env = dict(clean, CARGO_HOME=str(WORK / "cargo-home"), CARGO_TARGET_DIR=str(WORK / "target"),
           CARGO_NET_OFFLINE="true", CARGO_INCREMENTAL="0", CCACHE_DISABLE="1",
           ED301_PROFILE_MARKER_DIR=str(WORK / "markers"),
           RUSTC_WRAPPER=str(RUST / "scripts/rustc-profile-guard.sh"))
common = ["--manifest-path", RUST / "Cargo.toml", "--locked", "--offline", "--release"]
normal = run(["cargo", "test", *common], "release-tests", env)
checked = run(["cargo", "test", *common, "--features", "sign-self-verify"],
              "self-verify-tests", env)
run(["cargo", "test", *common, "--", "--list"], "test-inventory", env)
# The code-generation guard intentionally accepts only canonical rustc, not
# clippy-driver. Linting is isolated and is not a measured production binary.
lint_env = dict(env, CARGO_TARGET_DIR=str(WORK / "clippy-target"))
lint_env.pop("RUSTC_WRAPPER")
lint_env.pop("ED301_PROFILE_MARKER_DIR")
run(["cargo", "clippy", *common, "--all-targets", "--", "-D", "warnings"], "clippy", lint_env)
run(["cargo", "fmt", "--manifest-path", RUST / "Cargo.toml", "--all", "--", "--check"],
    "rust-format", env)
run(["rustfmt", "--edition", "2024", "--check", ROOT / "phase-c/benchmarks/core_matrix.rs",
     ROOT / "phase-c/timing/src/lib.rs", RUST / "secret-taint/src/main.rs"], "harness-format")
if "54 passed; 0 failed" not in normal or "54 passed; 0 failed" not in checked:
    raise SystemExit("FAIL: unexpected core test count")

# A separate consuming library, not the core's cfg(test) build. This proves
# no_std API consumption on this host, not support for another target/OS.
downstream = WORK / "downstream"
(downstream / "Cargo.toml").write_text(
    '[workspace]\n[package]\nname="ed301-nostd-probe"\nversion="0.0.0"\n'
    'edition="2024"\npublish=false\n[dependencies]\ned301-eddsa={path='
    + json.dumps(str(RUST / "crates/ed301-eddsa")) + ',default-features=false}\n'
    '[profile.release]\nopt-level=3\nlto="thin"\ncodegen-units=1\n'
    'panic="unwind"\noverflow-checks=true\n')
(downstream / "src/lib.rs").write_text(
    '#![no_std]\n#![forbid(unsafe_code)]\n'
    'pub fn roundtrip(seed: &[u8; 38], message: &[u8], context: &[u8]) -> bool {\n'
    '    let key = ed301_eddsa::SigningKey::from_seed(seed).unwrap();\n'
    '    let expanded = key.expand().unwrap();\n'
    '    let signature = expanded.sign_with_context(message, context).unwrap();\n'
    '    expanded.verifying_key().verify_with_context(message, context, &signature)\n}\n')
run(["cargo", "generate-lockfile", "--manifest-path", downstream / "Cargo.toml", "--offline"],
    "nostd-lock", env)
run(["cargo", "build", "--manifest-path", downstream / "Cargo.toml", "--release", "--offline",
     "--locked"], "nostd-consumer", env)
run(["cargo", "tree", "--manifest-path", downstream / "Cargo.toml", "--locked", "--offline",
     "-e", "normal,build,features"], "nostd-feature-tree", env)
run(["sh", RUST / "scripts/check-profile-markers.sh", WORK / "markers", "crypto_bigint=on",
     "ed301_eddsa=on", "ed301_nostd_probe=on"], "crate-profiles")
run(["python3", "-B", ROOT / "tools/check_phase_b.py"], "frozen-phase-b-replay", cwd=ROOT)
if sources() != manifest:
    raise SystemExit("FAIL: Rust sources changed during correctness run")
summary = {"status": "PASS", "release_tests": 54, "sign_self_verify_tests": 54,
           "nostd_host_consumer": True, "frozen_phase_b_replay": "8/8",
           "source_manifest_sha256": digest(WORK / "SOURCE_SHA256SUMS"),
           "runner_sha256": digest(Path(__file__)),
           "scope": "x86-64 Rust core correctness; no Gate-C/product approval"}
(WORK / "SUMMARY.json").write_text(json.dumps(summary, indent=2) + "\n")
files = sorted(p for p in WORK.rglob("*") if p.is_file()
               and not {"target", "clippy-target"}.intersection(p.relative_to(WORK).parts)
               and p.name != "SHA256SUMS")
(WORK / "SHA256SUMS").write_text("".join(f"{digest(p)}  {p.relative_to(WORK)}\n" for p in files))
print(json.dumps(summary, sort_keys=True), flush=True)
