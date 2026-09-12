#!/usr/bin/env python3
"""Run the actual Shared implementation natively and in bounded Miri schedules."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[1]
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--toolchain-root", type=Path, required=True)
parser.add_argument("--nightly", default="nightly-2026-09-11")
parser.add_argument("--seeds", type=int, default=16)
parser.add_argument("--output", type=Path, required=True)
args = parser.parse_args()
if not 1 <= args.seeds <= 128:
    parser.error("require 1..128 schedules per alias model")
out = args.output.resolve()
out.mkdir(mode=0o700)
(out / "logs").mkdir()
(out / "home").mkdir()
tool = args.toolchain_root.resolve()
manifest = ROOT / "assessment/shared/Cargo.toml"
sources = [ROOT / "provider/common/allocation.rs", Path(__file__), manifest,
           manifest.with_name("Cargo.lock"), *sorted((manifest.parent / "src").rglob("*.rs"))]
sha = lambda path: hashlib.sha256(path.read_bytes()).hexdigest()
binding = {str(path.relative_to(ROOT)): sha(path) for path in sources}
records = []
native = {"PATH": "/usr/bin:/bin", "HOME": str(out / "home"), "LC_ALL": "C",
          "CARGO_HOME": str(out / "cargo-home"), "CARGO_TARGET_DIR": str(out / "native-target"),
          "CARGO_NET_OFFLINE": "true"}
miri = {**native, "PATH": str(tool / "cargo/bin") + ":/usr/bin:/bin",
        "HOME": str(tool / "home"), "CARGO_HOME": str(tool / "cargo"),
        "RUSTUP_HOME": str(tool / "rustup"), "CARGO_TARGET_DIR": str(out / "miri-target")}


def run(label, argv, env, expected=0):
    print("STEP " + label, flush=True)
    result = subprocess.run(list(map(str, argv)), env=env, cwd=ROOT,
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=300)
    log = out / "logs" / (label + ".log")
    log.write_bytes(result.stdout)
    records.append({"label": label, "argv": list(map(str, argv)), "exit": result.returncode,
                    "miri_flags": env.get("MIRIFLAGS"), "log_sha256": sha(log)})
    (out / "commands.json").write_text(json.dumps(records, indent=2) + "\n")
    if result.returncode != expected:
        print(result.stdout.decode(errors="replace"))
        raise SystemExit("FAIL: " + label)
    return result.stdout.decode(errors="replace")


native_identity = run("native-toolchain", ["rustc", "--version", "--verbose"], native)
common = ["--manifest-path", manifest, "--locked", "--offline"]
run("native-clippy", ["cargo", "clippy", *common, "--all-targets", "--", "-D", "warnings"], native)
run("native-tests", ["cargo", "test", *common, "--release", "--lib", "--", "--test-threads=1"], native)
run("native-allocation-failure", ["cargo", "run", *common, "--release", "--bin", "allocation-failure"], native)
miri_command = [tool / "cargo/bin/cargo", "+" + args.nightly, "miri"]
miri_identity = run("miri-version", [*miri_command, "--version"], miri)
run("miri-rustc", [tool / "cargo/bin/rustc", "+" + args.nightly, "--version", "--verbose"], miri)
for model, option in (("default", ""), ("tree", "-Zmiri-tree-borrows")):
    for seed in range(args.seeds):
        flags = f"-Zmiri-strict-provenance -Zmiri-symbolic-alignment-check -Zmiri-preemption-rate=0.25 -Zmiri-seed={seed} {option}".strip()
        env = dict(miri, MIRIFLAGS=flags)
        output = run(f"miri-{model}-{seed}", [*miri_command, "test", *common,
            "--lib", "--", "--test-threads=1"], env)
        if "11 passed; 0 failed; 0 ignored" not in output:
            raise SystemExit("Miri test inventory mismatch")
    run(f"miri-{model}-allocation-failure", [*miri_command, "run", *common,
        "--bin", "allocation-failure"], dict(miri, MIRIFLAGS=flags))

# Compile-time rejection of payloads that do not satisfy the actual Send/Sync bounds.
for name, payload, required in (("rc-send", "std::rc::Rc<u8>", "Send"),
                                ("cell-sync", "std::cell::Cell<u8>", "Sync")):
    source = out / (name + ".rs")
    source.write_text("#![allow(dead_code)]\nfn hit_alloc_failpoint(_: &str) -> bool {false}\n"
        + "#[path=" + json.dumps(str(ROOT / "provider/common/allocation.rs")) + "]\nmod allocation;\n"
        + f"fn require<T: {required}>() {{}}\nfn main() {{require::<allocation::Shared<{payload}>>();}}\n")
    output = run(name, ["rustc", "--edition=2024", source, "-o", out / name], native, expected=1)
    if "E0277" not in output:
        raise SystemExit("compile-fail control failed for an unrelated reason")
if binding != {str(path.relative_to(ROOT)): sha(path) for path in sources}:
    raise SystemExit("source changed during assessment")
result = {"status": "PASS", "source_sha256": binding, "native": native_identity,
          "miri": miri_identity, "miri_schedules": args.seeds * 2, "tests_per_schedule": 11,
          "alias_models": ["default", "tree"], "allocation_failure_modes": 3,
          "compile_fail_controls": 2,
          "limits": "Bounded schedules, not exhaustive soundness or shipping-binary erasure proof"}
(out / "RESULT.json").write_text(json.dumps(result, indent=2) + "\n")
print("SHARED_ASSESSMENT=PASS", flush=True)
