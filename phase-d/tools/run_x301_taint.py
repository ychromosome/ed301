#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Fresh isolated X301-v2 taint build and full Gate-B input/output corpus."""
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]
RUST = ROOT / "rust"
WORK = Path(tempfile.mkdtemp(prefix="X301-v2_D1-taint_", dir=ROOT.parent))
for part in ("home", "cargo-home", "target", "markers", "logs"):
    (WORK / part).mkdir()
clean = {"PATH": "/usr/bin:/bin", "HOME": str(WORK / "home"), "LC_ALL": "C"}
commands = []
print(f"artifact_directory={WORK}", flush=True)


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def run(command, label, env=None):
    command = list(map(str, command))
    print(f"STEP: {label}", flush=True)
    result = subprocess.run(command, cwd="/", env=env or clean, text=True,
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    log = WORK / "logs" / f"{len(commands):04d}.log"
    log.write_text(result.stdout)
    commands.append({"command": command, "step": label, "environment": env or clean,
                     "exit": result.returncode, "log": str(log.relative_to(WORK))})
    (WORK / "commands.json").write_text(json.dumps(commands, indent=2) + "\n")
    if result.returncode:
        print(result.stdout, end="", flush=True)
        raise SystemExit(f"FAIL: {label}; artifacts retained at {WORK}")
    return result.stdout


def sources():
    return "".join(f"{sha(p)}  {p.relative_to(ROOT)}\n" for p in sorted(RUST.rglob("*")) if p.is_file())


manifest = sources()
(WORK / "SOURCE_SHA256SUMS").write_text(manifest)
run(["python3", "-I", "-B", RUST / "scripts/write-cargo-config.py", WORK / "cargo-home/config.toml",
     RUST / "vendor"], "offline-config")
toolchain = run(["rustc", "--version", "--verbose"], "toolchain")
(WORK / "markers/toolchain.txt").write_text(toolchain)
env = dict(clean, CARGO_HOME=str(WORK / "cargo-home"), CARGO_TARGET_DIR=str(WORK / "target"),
           CARGO_NET_OFFLINE="true", CARGO_INCREMENTAL="0", CCACHE_DISABLE="1",
           CC="/usr/bin/gcc", AR="/usr/bin/ar", ED301_HERMETIC_NATIVE_BUILD="1",
           ED301_PROFILE_MARKER_DIR=str(WORK / "markers"),
           RUSTC_WRAPPER=str(RUST / "scripts/rustc-profile-guard.sh"))
run(["cargo", "build", "--manifest-path", RUST / "x301-secret-taint/Cargo.toml", "--release", "--locked", "--offline"],
    "instrumented-build", env)
run(["sh", RUST / "scripts/check-profile-markers.sh", WORK / "markers", "crypto_bigint=on",
     "x301_core=on", "ed301_valgrind_client=on", "x301_core_taint=on"], "profiles")
binary = WORK / "target/release/x301-core-taint"
vector_path = ROOT / "vectors/x301-v2.json"
if sha(vector_path) != "b675f677f0d717a09f3c1cc55bf0c2ad97d17ca14a7890565a41916222cc80f0":
    raise SystemExit("FAIL: Gate-B vector hash")
data = json.loads(vector_path.read_text())
keys = {k["id"]: k for k in data["keys"]}
base = json.loads((ROOT / "provenance/phase-a/2026-09-09/parameter/ed301-v2.json").read_text())["basepoint"]["G_montgomery_u_little_endian_hex"]
cases = []
for key in data["keys"]:
    cases += [(key["id"] + "-public", "public", key["secret_hex"], base, key["public_hex"], ""),
              (key["id"] + "-import", "import", key["secret_hex"], "", key["secret_hex"], "")]
for case in data["evaluations"]:
    cases.append((case["id"], "shared", keys[case["key"]]["secret_hex"], case["u_hex"], case["result_hex"], ""))
for case in data["errors"]:
    error = {"decode-secret": "secret-length", "result": "all-zero"}.get(case["stage"])
    if error is None:
        error = "public-length" if len(case["u_hex"]) != 76 else "noncanonical-public"
    cases.append((case["id"], "shared", case["secret_hex"], case["u_hex"], "", error))
for case in data["weak_secrets"]:
    for operation, peer in (("public", base), ("import", ""), ("shared", base)):
        cases.append((case["id"] + "-" + operation, operation, case["secret_hex"], peer, "", "weak-secret"))
for label, operation, secret, peer, expected, error in cases:
    test_env = dict(clean, X301_CT_SECRET=secret, X301_CT_PEER=peer, X301_CT_EXPECTED=expected, X301_CT_ERROR=error)
    for mode in ("defined", "tainted"):
        run(["valgrind", "--tool=memcheck", "--vgdb=no", "--enable-debuginfod=no", "--error-exitcode=99",
             "--track-origins=yes", "--undef-value-errors=yes", "--leak-check=full",
             "--errors-for-leak-kinds=definite,indirect,possible", "--quiet", binary, operation, mode],
            label + "/" + mode, test_env)
if sources() != manifest:
    raise SystemExit("FAIL: Rust source set/content changed during taint run")
summary = {"status": "PASS", "cases": len(cases), "valgrind_runs": len(cases) * 2,
           "successful_public_and_import_cases": 14, "successful_shared_cases": 24,
           "ordinary_error_cases": 33, "weak_secret_cases": 64 * 3,
           "input_vbits_checked": True, "shared_output_keeps_taint": True,
           "source_manifest_sha256": sha(WORK / "SOURCE_SHA256SUMS"), "binary_sha256": sha(binary),
           "runner_sha256": sha(Path(__file__)), "scope": "instrumented X301 core, not provider or universal CT proof"}
(WORK / "SUMMARY.json").write_text(json.dumps(summary, indent=2) + "\n")
files = sorted(p for p in WORK.rglob("*") if p.is_file() and "target" not in p.relative_to(WORK).parts and p.name != "SHA256SUMS")
(WORK / "SHA256SUMS").write_text("".join(f"{sha(p)}  {p.relative_to(WORK)}\n" for p in files))
print(json.dumps(summary, sort_keys=True), flush=True)
