#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Verify the complete local Gate-E bundle; optionally replay sealed native tests."""

import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parent))
from handoff_common import (check_command_logs, check_members, check_source,
                            check_source_comparison, digest, manifest_rows,
                            read_json, relative_path)
from handoff_inputs import (BASE_COMMIT, BUILD_SHA, CONTROL_FIXTURES, DONORS, EXTENDED_GATES,
                            FINAL_CORE, SOURCE_SHA, STAGES, STEP_BENCHMARKS, VERSIONS)


def verify(bundle, expected):
    seal = bundle / "BUNDLE_MANIFEST.json"
    if seal.is_symlink() or digest(seal) != expected:
        raise SystemExit("bundle manifest digest mismatch")
    manifest = read_json(seal)
    actual = {p.relative_to(bundle).as_posix() for p in bundle.rglob("*")}
    if actual != set(manifest) | {"BUNDLE_MANIFEST.json"}:
        raise SystemExit("bundle inventory mismatch")
    for name, record in manifest.items():
        path = bundle / relative_path(name)
        if record["type"] == "symlink":
            link = record["target"]
            if (not path.is_symlink() or os.readlink(path) != link or Path(link).is_absolute()
                    or ".." in Path(link).parts or not path.resolve(strict=True).is_relative_to(bundle)):
                raise SystemExit("symlink inventory mismatch: " + name)
        else:
            if path.is_symlink() or path.stat().st_mode & 0o777 != record["mode"]:
                raise SystemExit("type/mode mismatch: " + name)
            if record["type"] == "directory":
                if not path.is_dir():
                    raise SystemExit("missing directory: " + name)
            elif record["type"] != "file" or not path.is_file() or digest(path) != record["sha256"]:
                raise SystemExit("file hash mismatch: " + name)
    index = read_json(bundle / "reports/PHASE_E_EVIDENCE_INDEX.json")
    if (index["format"] != "ed301-v2-phase-e-final-index-v1" or index["source_manifest_sha256"] != SOURCE_SHA
            or index["build_source_sha256"] != BUILD_SHA or index["base_commit"] != BASE_COMMIT
            or index["gate_e_approval"] or index["stage_2_authorized"] or index["system_installation"]):
        raise SystemExit("incorrect Gate-E scope or source binding")
    expected_stages = {stage + "-" + version for stage in STAGES for version in VERSIONS}
    if set(index["stages"]) != expected_stages:
        raise SystemExit("incomplete stage inventory")
    evidence = bundle / "evidence"
    source_rows = check_source(evidence / "source", evidence / "SOURCE_SHA256SUMS", SOURCE_SHA)
    if len(source_rows) != index["source_files"] or read_json(evidence / "SOURCE_IDENTITY.json") != index["source_identity"]:
        raise SystemExit("source identity mismatch")
    omissions = read_json(bundle / "OMITTED_CONTROL_FIXTURES.json")
    for name in omissions:
        path = relative_path(name)
        if (len(path.parts) < 3 or path.parts[0] not in {"controls-" + v for v in VERSIONS}
                or path.parts[1] not in CONTROL_FIXTURES):
            raise SystemExit("invalid omission scope")
    for name, record in index["stages"].items():
        relative = relative_path(record["relative_path"])
        expected_relative = name.replace("tcp-", "tcp-approved-", 1) if name.startswith("tcp-") else name
        if str(relative) != expected_relative:
            raise SystemExit("unexpected stage path")
        directory = evidence / relative
        omitted = {key[len(str(relative)) + 1:]: value for key, value in omissions.items()
                   if key.startswith(str(relative) + "/")}
        rows = check_members(directory, "SHA256SUMS", record["manifest_sha256"], omitted)
        identity = read_json(directory / "IDENTITY.json")
        if (identity != record["identity"] or identity.get("status") != "PASS"
                or identity.get("source_manifest_sha256") != SOURCE_SHA):
            raise SystemExit("stage identity mismatch")
        if check_command_logs(directory, rows) != record["command_count"]:
            raise SystemExit("stage command inventory mismatch")
    sources = {"final": evidence / "source"}
    for name, record in index["source_snapshots"].items():
        if record["relative_path"] != "snapshots/" + relative_path(name).as_posix():
            raise SystemExit("snapshot path mismatch")
        directory = bundle / record["relative_path"]
        check_source(directory / "source", directory / "SOURCE_SHA256SUMS", record["manifest_sha256"])
        sources[name] = directory / "source"
    expected_supplements = set(FINAL_CORE) | set(EXTENDED_GATES) | {"benchmark-" + step for step in STEP_BENCHMARKS} | {
        "halving-reference", "e6-profile-3.5.8", "e6-profile-4.0.2", "core-layout"}
    if set(index["supplementary"]) != expected_supplements:
        raise SystemExit("incomplete supplementary evidence")
    for name, record in index["supplementary"].items():
        if record["relative_path"] != "supplementary/" + name:
            raise SystemExit("supplementary path mismatch")
        directory = bundle / record["relative_path"]
        rows = check_members(directory, "SHA256SUMS", record["manifest_sha256"])
        if check_command_logs(directory, rows) != record["command_count"]:
            raise SystemExit("supplementary command inventory mismatch")
        for metadata in ("IDENTITY.json", "SUMMARY.json", "SUMMARY.txt"):
            if metadata in record:
                actual_metadata = ((directory / metadata).read_text() if metadata.endswith(".txt")
                                   else read_json(directory / metadata))
                if actual_metadata != record[metadata]:
                    raise SystemExit("supplementary metadata mismatch")
        for comparison in record["source_comparisons"]:
            count = check_source_comparison(directory, comparison["manifest"], sources[comparison["source"]],
                                            comparison["prefix"], comparison["all_rust"])
            if count != comparison["files"]:
                raise SystemExit("source comparison inventory mismatch")
        for filename, binary in record["extra_binaries"].items():
            if digest(directory / relative_path(filename)) != binary["sha256"]:
                raise SystemExit("supplementary binary mismatch")
    for name, checksum in index["post_execution_files"].items():
        relative = relative_path(name)
        if relative.parts[0] != "phase-e" or digest(bundle / "reports" / relative.relative_to("phase-e")) != checksum:
            raise SystemExit("post-execution report/tool mismatch")
    final_rows = manifest_rows(bundle / "reports/FINAL_HANDOFF_SOURCE_MANIFEST.sha256")
    if set(final_rows) != set(source_rows) | set(index["post_execution_files"]) | {"phase-e/PHASE_E_EVIDENCE_INDEX.json"}:
        raise SystemExit("final commit manifest inventory mismatch")
    for name, checksum in final_rows.items():
        path = (evidence / "source" / name if name in source_rows
                else bundle / "reports" / Path(name).relative_to("phase-e"))
        if digest(path) != checksum:
            raise SystemExit("final commit manifest member mismatch: " + name)
    for name, checksum in DONORS.items():
        if digest(bundle / "donors" / name) != checksum:
            raise SystemExit("donor archive mismatch")
    if set(index["authorization_inputs"]) != {"GATE_D_FREIGABE_UND_PHASE_E_START_2026-09-10.md",
                                              "AUFTRAG_EMMY_PHASE_E_OPTIMIERUNG_2026-09-10.md"}:
        raise SystemExit("incomplete Phase-E authorization inputs")
    for name, checksum in index["authorization_inputs"].items():
        if digest(bundle / "authorizations" / relative_path(name)) != checksum:
            raise SystemExit("authorization input mismatch")
    return index


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bundle", required=True, type=Path)
    parser.add_argument("--manifest-sha", required=True)
    parser.add_argument("--replay-output", type=Path)
    parser.add_argument("--tcp", action="store_true", help="include owned 127.0.0.1:0 endpoints")
    args = parser.parse_args()
    bundle = args.bundle.resolve(strict=True)
    index = verify(bundle, args.manifest_sha)
    print("bundle_verification=PASS", flush=True)
    if args.replay_output is None:
        if args.tcp:
            parser.error("--tcp requires --replay-output")
    else:
        replay(bundle, args.manifest_sha, index, args.replay_output, args.tcp)


def replay(bundle, expected, index, out, tcp):
    out = out.absolute()
    if out.exists() or out.is_symlink() or bundle in out.parents:
        raise SystemExit("replay output must be new and outside the bundle")
    out.mkdir(mode=0o700)
    (out / "home").mkdir(mode=0o700)
    original = index["evidence_root"]
    evidence = bundle / "evidence"
    records = []
    status = {"status": "RUNNING", "bundle_manifest_sha256": expected,
              "scope": "sealed native functional and structured tests plus optional owned TCP; no rebuild or timing replay",
              "tcp": tcp, "bundle_unchanged_after_replay": False}
    (out / "IDENTITY.json").write_text(json.dumps(status, indent=2) + "\n")
    try:
        for version in VERSIONS:
            for stage in (("functional", "structured", "tcp") if tcp else ("functional", "structured")):
                name = stage + "-" + version
                directory = evidence / index["stages"][name]["relative_path"]
                for command in read_json(directory / "commands.json"):
                    step = command["step"]
                    if stage == "functional" and not step.startswith(("run-", "native-", "oid-", "retry-", "unit-run-")):
                        continue
                    if command["exit"] != 0 or command.get("timeout", False):
                        raise SystemExit("replay selection contains a non-success command")
                    argv = [part.replace(original, str(evidence)) for part in command["command"]]
                    if not Path(argv[0]).resolve(strict=True).is_relative_to(evidence):
                        raise SystemExit("replay executable outside sealed evidence")
                    env = {key: value.replace(original, str(evidence)) for key, value in command["environment"].items()}
                    env["HOME"] = str(out / "home")
                    log = out / (name + "-" + step + ".log")
                    started = time.monotonic()
                    timed_out = False
                    with log.open("w") as stream:
                        try:
                            result = subprocess.run(argv, env=env, cwd="/", stdout=stream,
                                                    stderr=subprocess.STDOUT, timeout=1200)
                            code = result.returncode
                        except subprocess.TimeoutExpired:
                            code, timed_out = -1, True
                    records.append({"stage": name, "step": step, "argv": argv, "environment": env,
                                    "exit": code, "timeout": timed_out, "seconds": time.monotonic() - started,
                                    "log_sha256": digest(log)})
                    (out / "commands.json").write_text(json.dumps(records, indent=2) + "\n")
                    if code != 0:
                        raise SystemExit("native replay failed; retained log: " + str(log))
                    print("PASS " + name + "/" + step, flush=True)
        verify(bundle, expected)
        status.update(status="PASS", command_count=len(records), bundle_unchanged_after_replay=True)
    finally:
        if status["status"] != "PASS":
            status["status"] = "FAIL"
        (out / "IDENTITY.json").write_text(json.dumps(status, indent=2) + "\n")
        (out / "SHA256SUMS").write_text("".join(f"{digest(path)}  {path.name}\n"
            for path in sorted(out.iterdir()) if path.is_file() and path.name != "SHA256SUMS"))
    print("replay=PASS commands=" + str(len(records)), flush=True)


if __name__ == "__main__":
    main()
