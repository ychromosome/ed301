#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Diagnose the exact sealed DER benchmark without changing its timed boundary."""

import argparse
import json
from pathlib import Path
import re
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "phase-d/d2/tools"))
from d2_common import digest, verify_receipt

parser = argparse.ArgumentParser(description=__doc__)
for name in ("functional", "legacy", "benchmark"):
    parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--" + name + "-sha", required=True)
parser.add_argument("--output", type=Path, required=True)
args = parser.parse_args()
inputs = {}
for name in ("functional", "legacy", "benchmark"):
    path = getattr(args, name).resolve(strict=True)
    expected = getattr(args, name + "_sha")
    if digest(path / "SHA256SUMS") != expected:
        raise SystemExit("input receipt digest mismatch: " + name)
    inputs[name] = {"path": path, "sha256": expected, "identity": verify_receipt(path)}
identities = [item["identity"] for item in inputs.values()]
if len({item["source_manifest_sha256"] for item in identities}) != 1:
    raise SystemExit("profile inputs must share one bound source")
versions = {item["openssl_version"] for item in identities}
if len(versions) != 1 or not versions.issubset({"3.5.8", "4.0.2"}):
    raise SystemExit("profile inputs must share one approved ABI")
version = versions.pop()
out = args.output.absolute()
if out.exists() or out.is_symlink() or ROOT in out.parents:
    parser.error("output must be new and outside the checkout")
out.mkdir(mode=0o700)
for name in ("home", "logs"):
    (out / name).mkdir(mode=0o700)
clean = {"PATH": "/usr/bin:/bin", "HOME": str(out / "home"), "LC_ALL": "C"}
functional = inputs["functional"]["path"]
legacy = inputs["legacy"]["path"]
benchmark = inputs["benchmark"]["path"]
prefix = functional / "openssl/inst" / version
runtime = dict(clean, OPENSSL_CONF="/dev/null", LD_LIBRARY_PATH=str(prefix / "lib"))
commands = []
print("artifact_directory=" + str(out), flush=True)


def run(name, command, env=clean):
    print("STEP: " + name, flush=True)
    command = list(map(str, command))
    result = subprocess.run(command, cwd="/", env=env, text=True,
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=120)
    log = out / "logs" / (name + ".log")
    log.write_text(result.stdout)
    commands.append({"step": name, "command": command, "environment": env,
                     "exit": result.returncode, "log": str(log.relative_to(out)),
                     "log_sha256": digest(log)})
    (out / "commands.json").write_text(json.dumps(commands, indent=2) + "\n")
    if result.returncode:
        raise SystemExit("profile step failed; evidence retained: " + name)
    return result.stdout


run("valgrind-version", ["valgrind", "--version"])
source = Path(identities[0]["source_root"])
harness = source / "phase-d/d2/benchmarks/codec_bench.c"
if digest(harness) != digest(ROOT / "phase-d/d2/benchmarks/codec_bench.c"):
    raise SystemExit("profile harness differs from original benchmark")
bound = [Path(__file__), ROOT / "phase-d/d2/tools/d2_common.py", harness,
         benchmark / "bin/codec", prefix / "lib/libcrypto.so", prefix / "lib/libssl.so",
         source / "provider/common/provider_codec.h",
         source / "provider/crates/ed301-eddsa-provider/c/provider_shim.c",
         source / "provider/crates/ed301-eddsa-provider/src/sig_ffi.rs"]
cases = []
all_metrics = []
for generation, algorithm, directory, provider in (
    ("v1", "Ed301-EdDSA-v1", legacy / "modules/ed-tls", "ed301_eddsa_v1_tls_test"),
    ("v2", "Ed301-EdDSA", functional / "modules", "ed301_eddsa_v2_tls_test"),
):
    bound.append(directory / (provider + ".so"))
    for count in (1, 10):
        label = generation + "-" + str(count)
        raw = out / ("callgrind." + label)
        command = [benchmark / "bin/codec", "encode", "private", "DER", algorithm,
                   "provider=" + provider, directory, provider, count]
        run(label, ["valgrind", "--tool=callgrind", "--quiet", "--collect-jumps=yes",
                    "--callgrind-out-file=" + str(raw), *command], runtime)
        annotation = run(label + "-annotated", ["callgrind_annotate", "--auto=no",
            "--inclusive=yes", "--tree=calling", "--threshold=100", raw])
        # Parse complete function and incoming-edge rows. Inclusive counts must
        # never be added across a caller and its descendants.
        functions = {}
        incoming = {}
        pattern = r"^\s*([0-9,]+)\s+\([^)]*\)\s+([*>])\s+\?\?\?:(.+?)\s+\[([^]]+)\]$"
        for line in annotation.splitlines():
            match = re.match(pattern, line)
            if match is None:
                continue
            instructions, kind, function, obj = match.groups()
            if kind == "*":
                functions[function] = functions.get(function, 0) + int(instructions.replace(",", ""))
            else:
                edge = re.fullmatch(r"(.+) \(([0-9,]+)x\)", function)
                if edge is not None:
                    name, calls = edge.groups()
                    incoming[name] = incoming.get(name, 0) + int(calls.replace(",", ""))
        def calls(suffix):
            return sum(value for name, value in incoming.items() if name.endswith(suffix))
        metrics = {"generation": generation, "loop_count": count,
                   "encoder_context_calls": calls("OSSL_ENCODER_CTX_new_for_pkey"),
                   "encoder_output_calls": calls("OSSL_ENCODER_to_data"),
                   "provider_encode_calls": calls("codec_encode"),
                   "get_private_calls": calls("::sig_ffi::key_get_private"),
                   "import_calls": calls("::sig_ffi::key_import"),
                   "validate_calls": calls("key_validate"),
                   "encoder_import_object_calls": calls("codec_import_object"),
                   "collected_name_calls": calls("collect_name"),
                   "encoder_name_test_calls": calls("OSSL_ENCODER_is_a"),
                   "context_instructions": functions.get("OSSL_ENCODER_CTX_new_for_pkey", 0),
                   "output_instructions": functions.get("OSSL_ENCODER_to_data", 0),
                   "collect_encoder_instructions": functions.get("collect_encoder", 0)}
        (out / (label + "-metrics.json")).write_text(json.dumps(metrics, indent=2) + "\n")
        if any(metrics[key] != count + 1 for key in (
                "encoder_context_calls", "encoder_output_calls", "provider_encode_calls", "get_private_calls")):
            raise SystemExit("unexpected encoder call inventory: " + label)
        if metrics["import_calls"] != 1 or metrics["validate_calls"] or metrics["encoder_import_object_calls"]:
            raise SystemExit("unexpected key validation or reimport path: " + label)
        if not all(metrics[key] > 0 for key in ("context_instructions", "output_instructions", "collect_encoder_instructions")):
            raise SystemExit("missing measured encoder functions: " + label)
        expected_names = 2 if generation == "v1" else 3
        if metrics["collected_name_calls"] != expected_names * (count + 1):
            raise SystemExit("algorithm alias inventory changed: " + label)
        (out / (label + "-functions.json")).write_text(json.dumps(
            {"inclusive_instructions": functions, "incoming_calls": incoming}, indent=2) + "\n")
        all_metrics.append(metrics)
        cases.append({"generation": generation, "count": count, "command": list(map(str, command)),
                      "callgrind_sha256": digest(raw)})
for item in inputs.values():
    if digest(item["path"] / "SHA256SUMS") != item["sha256"]:
        raise SystemExit("input receipt changed during profile")
    verify_receipt(item["path"])
summary = {"status": "PASS", "openssl_version": version,
           "source_manifest_sha256": identities[0]["source_manifest_sha256"],
           "input_receipts": {key: {"path": str(value["path"]), "sha256": value["sha256"]}
                              for key, value in inputs.items()},
           "bindings": {str(path): digest(path) for path in bound}, "cases": cases,
           "measurements": all_metrics, "runtime_changes": False,
           "conclusion": "no seed re-expansion in measured encoder loop; lookup context dominates",
           "scope": "diagnostic instruction/call counts only; Valgrind elapsed time is not a benchmark"}
(out / "SUMMARY.json").write_text(json.dumps(summary, indent=2) + "\n")
files = sorted(path for path in out.rglob("*") if path.is_file() and path.name != "SHA256SUMS")
(out / "SHA256SUMS").write_text("".join(f"{digest(path)}  {path.relative_to(out)}\n" for path in files))
print(json.dumps({"status": "PASS", "measurements": all_metrics}, indent=2), flush=True)
