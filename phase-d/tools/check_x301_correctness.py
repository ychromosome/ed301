#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Fresh offline X301 correctness/no_std checks plus unchanged Ed301 regression."""
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile
import tarfile

ROOT = Path(__file__).resolve().parents[2]
RUST = ROOT / "rust"
WORK = Path(tempfile.mkdtemp(prefix="X301-v2_D1-check_", dir=ROOT.parent))
for part in ("home", "cargo-home", "target", "markers", "logs", "downstream/src", "donor"):
    (WORK / part).mkdir(parents=True)
clean = {"PATH": "/usr/bin:/bin", "HOME": str(WORK / "home"), "LC_ALL": "C"}
commands = []
print(f"artifact_directory={WORK}", flush=True)


def sha(path): return hashlib.sha256(path.read_bytes()).hexdigest()


def run(command, label, env=None, cwd="/"):
    command = list(map(str, command))
    print(f"STEP: {label}", flush=True)
    result = subprocess.run(command, cwd=cwd, env=env or clean, text=True,
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    log = WORK / "logs" / f"{len(commands):03d}-{label}.log"
    log.write_text(result.stdout)
    commands.append({"command": command, "step": label, "environment": env or clean,
                     "cwd": str(cwd), "exit": result.returncode, "log": str(log.relative_to(WORK))})
    (WORK / "commands.json").write_text(json.dumps(commands, indent=2) + "\n")
    if result.returncode:
        print(result.stdout, end="", flush=True)
        raise SystemExit(f"FAIL: {label}; artifacts retained at {WORK}")
    return result.stdout


def sources():
    return "".join(f"{sha(p)}  {p.relative_to(ROOT)}\n" for p in sorted(RUST.rglob("*")) if p.is_file())


manifest = sources()
(WORK / "SOURCE_SHA256SUMS").write_text(manifest)
run(["sha256sum", "--strict", "--check", "--status", ROOT / "phase-c/PHASE_C_SOURCE_MANIFEST.sha256"],
    "unchanged-phase-c-files", cwd=ROOT)
run(["python3", "-I", "-B", ROOT / "phase-d/tools/generate_x301_parameters.py", "--check",
     RUST / "crates/x301/src/x_generated_parameters.rs"], "x301-constant-chain")
run(["python3", "-I", "-B", RUST / "scripts/check-vendor-forks.py"], "vendor-forks", cwd=RUST)
donor = ROOT.parent / "X301-v1_D1_DONOR_2026-09-10.tar.gz"
if sha(donor) != "af4f808bb04a03946021569d051cead20dc8689923ac6e56a9630fb0a9acee30":
    raise SystemExit("FAIL: donor archive hash")
with tarfile.open(donor) as archive:
    archive.extractall(WORK / "donor", filter="data")
run(["sha256sum", "--strict", "--check", "--status", ROOT / "phase-d/provenance/X301_V1_DONOR_SHA256SUMS"],
    "fresh-donor-source-hashes", cwd=WORK / "donor")
run(["python3", "-I", "-B", RUST / "scripts/write-cargo-config.py", WORK / "cargo-home/config.toml", RUST / "vendor"], "cargo-config")
toolchain = run(["rustc", "--version", "--verbose"], "toolchain")
(WORK / "markers/toolchain.txt").write_text(toolchain)
env = dict(clean, CARGO_HOME=str(WORK / "cargo-home"), CARGO_TARGET_DIR=str(WORK / "target"),
           CARGO_NET_OFFLINE="true", CARGO_INCREMENTAL="0", CCACHE_DISABLE="1",
           CC="/usr/bin/gcc", AR="/usr/bin/ar", ED301_HERMETIC_NATIVE_BUILD="1",
           ED301_PROFILE_MARKER_DIR=str(WORK / "markers"), RUSTC_WRAPPER=str(RUST / "scripts/rustc-profile-guard.sh"))
common = ["--manifest-path", RUST / "crates/x301/Cargo.toml", "--locked", "--offline", "--release"]
normal = run(["cargo", "test", *common], "release-tests", env)
instrumented = run(["cargo", "test", *common, "--features", "secret-taint-instrumentation"], "instrumented-feature-tests", env)
if "25 passed; 0 failed" not in normal or "25 passed; 0 failed" not in instrumented:
    raise SystemExit("FAIL: unexpected X301 test count")
lint = dict(env, CARGO_TARGET_DIR=str(WORK / "clippy-target"))
lint.pop("RUSTC_WRAPPER")
lint.pop("ED301_PROFILE_MARKER_DIR")
run(["cargo", "clippy", *common, "--all-targets", "--all-features", "--", "-D", "warnings"], "clippy", lint)
run(["rustfmt", "--edition", "2024", "--config", "skip_children=true", "--check",
     *sorted((RUST / "crates/x301/src").glob("*.rs")), RUST / "x301-secret-taint/src/main.rs",
     ROOT / "phase-d/timing/src/lib.rs", ROOT / "phase-d/benchmarks/x301_core_bench.rs"], "format")
downstream = WORK / "downstream"
(downstream / "Cargo.toml").write_text(
    '[workspace]\n[package]\nname="x301-nostd-probe"\nversion="0.0.0"\nedition="2024"\npublish=false\n'
    '[dependencies]\nx301-core={path=' + json.dumps(str(RUST / "crates/x301")) + ',default-features=false}\n'
    '[profile.release]\nopt-level=3\nlto="thin"\ncodegen-units=1\npanic="unwind"\noverflow-checks=true\n')
(downstream / "src/lib.rs").write_text(
    '#![no_std]\n#![forbid(unsafe_code)]\n'
    'pub fn derive(secret: &[u8], peer: &[u8]) -> Result<x301_core::SharedSecret, x301_core::X301Error> {\n'
    '    x301_core::shared_secret(secret, peer)\n}\n')
run(["cargo", "generate-lockfile", "--manifest-path", downstream / "Cargo.toml", "--offline"], "nostd-lock", env)
run(["cargo", "build", "--manifest-path", downstream / "Cargo.toml", "--locked", "--offline", "--release"], "nostd-consumer", env)
run(["cargo", "tree", "--manifest-path", downstream / "Cargo.toml", "--locked", "--offline", "-e", "normal,build,features"], "feature-tree", env)
run(["sh", RUST / "scripts/check-profile-markers.sh", WORK / "markers", "crypto_bigint=on", "x301_core=on", "x301_nostd_probe=on"], "profiles")
regression = run(["python3", "-I", "-B", ROOT / "phase-c/tools/check_core_correctness.py"], "ed301-and-phase-b-regression")
if sources() != manifest:
    raise SystemExit("FAIL: Rust source set/content changed during checks")
summary = {"status": "PASS", "x301_release_tests": 25, "x301_instrumented_feature_tests": 25,
           "nostd_host_consumer": True, "ed301_regression_and_phase_b": "PASS",
           "source_manifest_sha256": sha(WORK / "SOURCE_SHA256SUMS"), "runner_sha256": sha(Path(__file__)),
           "donor_snapshot_sha256": sha(donor), "scope": "D1 host core checks; not Gate-D or provider approval"}
(WORK / "SUMMARY.json").write_text(json.dumps(summary, indent=2) + "\n")
files = sorted(p for p in WORK.rglob("*") if p.is_file()
               and not {"target", "clippy-target", "donor"}.intersection(p.relative_to(WORK).parts)
               and p.name != "SHA256SUMS")
(WORK / "SHA256SUMS").write_text("".join(f"{sha(p)}  {p.relative_to(WORK)}\n" for p in files))
print(json.dumps(summary, sort_keys=True), flush=True)
