#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Fresh Phase-E checks, retaining every named Gate-C/D1 test and immutable seals."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--baseline", type=Path, required=True,
                    help="immutable approved Gate-D source tree")
parser.add_argument("--previous", type=Path,
                    help="also rebuild the previous Phase-E source and retain all its named tests")
args = parser.parse_args()
baseline = args.baseline.resolve()
work = Path(tempfile.mkdtemp(prefix="ED301-v2_PHASE_E_core-check_", dir=ROOT.parent))
for part in ("home", "logs"):
    (work / part).mkdir()
clean = {"PATH": "/usr/bin:/bin", "HOME": str(work / "home"), "LC_ALL": "C"}
commands = []
print(f"artifact_directory={work}", flush=True)


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def run(command, label, env=None, cwd="/"):
    command = list(map(str, command))
    print(f"STEP: {label}", flush=True)
    result = subprocess.run(command, cwd=cwd, env=env or clean, text=True,
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    log = work / "logs" / f"{len(commands):04d}-{label}.log"
    log.write_text(result.stdout)
    commands.append({"command": command, "step": label, "cwd": str(cwd),
                     "environment": env or clean, "exit": result.returncode,
                     "log": str(log.relative_to(work))})
    (work / "commands.json").write_text(json.dumps(commands, indent=2) + "\n")
    if result.returncode:
        print(result.stdout, end="", flush=True)
        raise SystemExit(f"FAIL: {label}; retained at {work}")
    return result.stdout


def manifest(root):
    return "".join(f"{sha(p)}  {p.relative_to(root)}\n"
                   for p in sorted((root / "rust").rglob("*")) if p.is_file())


before = manifest(ROOT)
old_before = manifest(baseline)
previous = args.previous.resolve() if args.previous else None
previous_before = manifest(previous) if previous else None
(work / "SOURCE_SHA256SUMS").write_text(before)
(work / "BASELINE_RUST_SHA256SUMS").write_text(old_before)
if previous:
    (work / "PREVIOUS_RUST_SHA256SUMS").write_text(previous_before)
# Historical manifests apply only to their approved source, never to optimized
# code. Do not rewrite or bypass them to make a later phase appear unchanged.
for seal in ("phase-c/PHASE_C_SOURCE_MANIFEST.sha256", "phase-d/D1_SOURCE_MANIFEST.sha256"):
    run(["sha256sum", "--strict", "--check", "--status", baseline / seal],
        "baseline-" + Path(seal).stem, cwd=baseline)
# Phase-B steps 2/3 cover packages outside PHASE_B_SOURCE_MANIFEST. Check the
# current packages before building; a later baseline replay cannot attest them.
for directory, package_manifest, label in (
    ("provenance/phase-a/2026-09-09", "PHASE_A_MANIFEST.sha256", "current-gate-a-package"),
    ("provenance/v2-search", "RUN_MANIFEST.sha256", "current-signed-search-package"),
):
    current_package = ROOT / directory
    historical_package = baseline / directory
    if (current_package / package_manifest).read_bytes() != (historical_package / package_manifest).read_bytes():
        raise SystemExit("FAIL: current provenance manifest differs from the approved baseline: " + directory)
    run(["sha256sum", "--strict", "--check", package_manifest], label, cwd=current_package)
for runner, output in (
    ("phase-c/tools/generate_rust_parameters.py", "rust/crates/ed301-eddsa/src/generated_parameters.rs"),
    ("phase-d/tools/generate_x301_parameters.py", "rust/crates/x301/src/x_generated_parameters.rs"),
):
    run(["python3", "-I", "-B", ROOT / runner, "--check", ROOT / output], Path(runner).stem)
run(["python3", "-I", "-B", ROOT / "phase-c/tools/check_field_bounds.py"], "field-bounds")
run(["python3", "-I", "-B", ROOT / "rust/scripts/check-vendor-forks.py"], "vendor-forks", cwd=ROOT / "rust")
toolchain = run(["rustc", "--version", "--verbose"], "toolchain")
inventories = {}
sources = [("baseline", baseline)]
if previous:
    sources.append(("previous", previous))
sources.append(("current", ROOT))
for label, source in sources:
    build = work / label
    for part in ("cargo-home", "target", "markers"):
        (build / part).mkdir(parents=True)
    rust = source / "rust"
    run(["python3", "-I", "-B", rust / "scripts/write-cargo-config.py",
         build / "cargo-home/config.toml", rust / "vendor"], label + "-cargo-config")
    (build / "markers/toolchain.txt").write_text(toolchain)
    env = dict(clean, CARGO_HOME=str(build / "cargo-home"), CARGO_TARGET_DIR=str(build / "target"),
               CARGO_NET_OFFLINE="true", CARGO_INCREMENTAL="0", CCACHE_DISABLE="1",
               CC="/usr/bin/gcc", AR="/usr/bin/ar", ED301_HERMETIC_NATIVE_BUILD="1",
               ED301_PROFILE_MARKER_DIR=str(build / "markers"),
               RUSTC_WRAPPER=str(rust / "scripts/rustc-profile-guard.sh"))
    variants = (("ed", "Cargo.toml", ""), ("x", "crates/x301/Cargo.toml", ""))
    if label == "current":
        variants += (("ed-self-verify", "Cargo.toml", "sign-self-verify"),
                     ("x-taint-feature", "crates/x301/Cargo.toml", "secret-taint-instrumentation"))
    for name, cargo, feature in variants:
        common = ["--manifest-path", rust / cargo, "--locked", "--offline", "--release"]
        if feature:
            common += ["--features", feature]
        output = run(["cargo", "test", *common], label + "-" + name + "-tests", env)
        passed = sorted(re.findall(r"^test (\S+)(?: - should panic)? \.\.\. ok$", output, re.M))
        totals = re.findall(r"test result: ok\. (\d+) passed; 0 failed; (\d+) ignored; (\d+) measured; (\d+) filtered out", output)
        if not passed or not totals or any(any(int(v) for v in row[1:]) for row in totals):
            raise SystemExit("FAIL: missing, ignored or filtered tests")
        if len(set(passed)) != len(passed) or sum(int(row[0]) for row in totals) != len(passed):
            raise SystemExit("FAIL: inconsistent named test inventory")
        inventories[label + "-" + name] = passed
    if label == "current":
        lint = dict(env, CARGO_TARGET_DIR=str(build / "clippy-target"))
        lint.pop("RUSTC_WRAPPER")
        lint.pop("ED301_PROFILE_MARKER_DIR")
        for name, cargo in (("ed", "Cargo.toml"), ("x", "crates/x301/Cargo.toml")):
            common = ["--manifest-path", rust / cargo, "--locked", "--offline", "--release"]
            run(["cargo", "clippy", *common, "--all-targets", "--all-features", "--", "-D", "warnings"], name + "-clippy", lint)
            run(["cargo", "fmt", "--manifest-path", rust / cargo, "--all", "--", "--check"], name + "-format", env)
        probe = build / "downstream"
        (probe / "src").mkdir(parents=True)
        (probe / "Cargo.toml").write_text(
            '[workspace]\n[package]\nname="phase-e-nostd-probe"\nversion="0.0.0"\nedition="2024"\npublish=false\n'
            '[dependencies]\ned301-eddsa={path=' + json.dumps(str(rust / "crates/ed301-eddsa")) + ',default-features=false}\n'
            'x301-core={path=' + json.dumps(str(rust / "crates/x301")) + ',default-features=false}\n'
            '[profile.release]\nopt-level=3\nlto="thin"\ncodegen-units=1\npanic="unwind"\noverflow-checks=true\n')
        (probe / "src/lib.rs").write_text(
            '#![no_std]\n#![forbid(unsafe_code)]\n'
            'pub fn sign(seed: &[u8; 38], message: &[u8]) -> bool {\n'
            ' let key=ed301_eddsa::SigningKey::from_seed(seed).unwrap().expand().unwrap();\n'
            ' let sig=key.sign_with_context(message, &[]).unwrap();\n'
            ' key.verifying_key().verify_with_context(message, &[], &sig)\n}\n'
            'pub fn public(secret: &[u8]) -> Result<[u8;38],x301_core::X301Error> {x301_core::public_from_secret(secret)}\n'
            'pub fn shared(secret: &[u8], peer: &[u8]) -> Result<x301_core::SharedSecret,x301_core::X301Error> {x301_core::shared_secret(secret,peer)}\n')
        run(["cargo", "generate-lockfile", "--manifest-path", probe / "Cargo.toml", "--offline"], "nostd-lock", env)
        run(["cargo", "build", "--manifest-path", probe / "Cargo.toml", "--locked", "--offline", "--release"], "nostd-consumer", env)
        run(["cargo", "tree", "--manifest-path", probe / "Cargo.toml", "--locked", "--offline", "-e", "normal,build,features"], "nostd-feature-tree", env)
        run(["sh", rust / "scripts/check-profile-markers.sh", build / "markers", "crypto_bigint=on",
             "ed301_eddsa=on", "x301_core=on", "ed301_valgrind_client=on", "phase_e_nostd_probe=on"], "profiles")
for name, count in (("ed", 54), ("x", 25)):
    original = inventories["baseline-" + name]
    if len(original) != count or not set(original).issubset(inventories["current-" + name]):
        raise SystemExit("FAIL: a named Gate-C/D1 test was lost")
if inventories["current-ed"] != inventories["current-ed-self-verify"] or inventories["current-x"] != inventories["current-x-taint-feature"]:
    raise SystemExit("FAIL: feature test inventories differ")
if previous:
    for name in ("ed", "x"):
        if not set(inventories["previous-" + name]).issubset(inventories["current-" + name]):
            raise SystemExit("FAIL: a named previous Phase-E test was lost")
# Bind Phase-B inputs to the approved baseline, except the maintained README
# and the exact documented edits below. Replay the unchanged historical package.
phase_b_manifest = "phase-b/PHASE_B_SOURCE_MANIFEST.sha256"
if (ROOT / phase_b_manifest).read_bytes() != (baseline / phase_b_manifest).read_bytes():
    raise SystemExit("FAIL: historical Phase-B manifest was changed")
public_import_note = (
    "\nPublic-key import processes only public data; its running time may depend on\n"
    "the supplied public key. Callers must not pass confidential data to this path.\n"
    "Secret-key derivation and signing do not use the public-key import checks.\n"
    "This API does not promise to conceal a public key that an application has\n"
    "chosen to keep confidential.\n"
).encode()
anchor = ("A public key must decode canonically, differ from the identity, and satisfy\n"
          "`[q]A = O`. R must decode canonically, but need not have prime order.\n").encode()
reference_reorders = {
    "reference/x301.py": (b"    u = curve.decode_field(u_encoding)\n",
                          b"    scalar = decode_secret_scalar(secret)\n"),
    "reference/node/x301.mjs": (b"  const u = decode(peer);\n",
                               b"  const scalar = little(clamp(secret));\n"),
}
phase_b_binding = []
for line in (baseline / phase_b_manifest).read_text().splitlines():
    expected, name = line.split("  ", 1)
    relative = Path(name)
    if relative.is_absolute() or ".." in relative.parts:
        raise SystemExit("FAIL: unsafe historical Phase-B input name")
    old = baseline / relative
    new = ROOT / relative
    if sha(old) != expected:
        raise SystemExit("FAIL: historical Phase-B input differs: " + name)
    old_bytes = old.read_bytes()
    new_bytes = new.read_bytes()
    if name == "README.md":
        # The overview is maintained independently of the historical snapshot.
        change = "maintained project overview; historical README checked during baseline replay"
    elif name == "specifications/Ed301-EdDSA-v2.md":
        if old_bytes.count(anchor) != 1 or new_bytes != old_bytes.replace(anchor, anchor + public_import_note, 1):
            raise SystemExit("FAIL: specification differs beyond the authorized E8 public-import note")
        change = "exact public-input timing note; no byte-contract change"
    elif name in reference_reorders:
        peer_line, secret_line = reference_reorders[name]
        old_order = peer_line + secret_line
        if old_bytes.count(old_order) != 1 or new_bytes != old_bytes.replace(old_order, secret_line + peer_line, 1):
            raise SystemExit("FAIL: reference differs beyond the reviewed secret-first ordering: " + name)
        change = "exact secret-first input-validation reorder; no arithmetic change"
    else:
        if new_bytes != old_bytes:
            raise SystemExit("FAIL: current Phase-B executable/reference input changed: " + name)
        change = "byte-identical"
    phase_b_binding.append({"path": name, "baseline_sha256": expected, "current_sha256": sha(new), "change": change})
(work / "PHASE_B_CURRENT_BINDING.json").write_text(json.dumps(phase_b_binding, indent=2) + "\n")
run(["python3", "-B", baseline / "tools/check_phase_b.py"], "phase-b-replay", cwd=baseline)
run(["python3", "-B", "-m", "unittest", "discover", "-s", "tests", "-v"], "current-python", cwd=ROOT)
for script in ("check_vectors.mjs", "check_x301_vectors.mjs", "check_x301_error_precedence.mjs"):
    run(["node", ROOT / "reference/node" / script], "current-" + script, cwd=ROOT)
if manifest(ROOT) != before or manifest(baseline) != old_before:
    raise SystemExit("FAIL: source changed during checks")
if previous and manifest(previous) != previous_before:
    raise SystemExit("FAIL: previous Phase-E source changed during checks")
(work / "TEST_INVENTORIES.json").write_text(json.dumps(inventories, indent=2) + "\n")
summary = {"status": "PASS", "test_counts": {key: len(value) for key, value in inventories.items()},
           "all_named_gate_c_d1_tests_retained": True, "nostd_host_consumer": True,
           "phase_b_replay": "8/8", "phase_b_current_binding": "exact E8 public-import note and secret-first reference reorder; maintained README; other inputs unchanged",
           "rustc": toolchain, "source_manifest_sha256": sha(work / "SOURCE_SHA256SUMS"),
           "baseline_rust_manifest_sha256": sha(work / "BASELINE_RUST_SHA256SUMS"),
           "all_named_previous_phase_e_tests_retained": bool(previous),
           "previous_rust_manifest_sha256": sha(work / "PREVIOUS_RUST_SHA256SUMS") if previous else None,
           "runner_sha256": sha(Path(__file__)), "scope": "host correctness, not timing or Gate-E approval"}
(work / "SUMMARY.json").write_text(json.dumps(summary, indent=2) + "\n")
files = sorted(p for p in work.rglob("*") if p.is_file() and p.name != "SHA256SUMS"
               and not {"target", "clippy-target"}.intersection(p.relative_to(work).parts))
(work / "SHA256SUMS").write_text("".join(f"{sha(p)}  {p.relative_to(work)}\n" for p in files))
print(json.dumps(summary, indent=2), flush=True)
