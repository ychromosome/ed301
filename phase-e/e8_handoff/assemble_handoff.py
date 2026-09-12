#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Assemble completed Phase-E evidence without changing any executed input."""

import argparse
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from handoff_common import (check_command_logs, check_members, check_source,
                            check_source_comparison, digest, manifest_rows, read_json)
from handoff_inputs import (BASE_COMMIT, BUILD_SHA, CONTROL_FIXTURES, CORRECTNESS_SOURCES, DONORS, EXTENDED_GATES,
                            FINAL_CORE, REFERENCE, SOURCE_SHA, STAGES,
                            STEP_BENCHMARKS, VERSIONS, WORKSPACE)

CHECKOUT = Path(__file__).resolve().parents[2]
FINAL_SEAL = "phase-e/E8_FINAL_HANDOFF_SOURCE_MANIFEST.sha256"
AUTHORIZATIONS = {
    "PHASE_E_E8_WEITERE_OPTIMIERUNGEN_2026-09-10.md":
        "77b24b157f51ddd03ee264ceccf952e781a3c4641a49b11f89195080d9d799af",
    "PHASE_E_E8b_LEITERRUNDE_R1_CLAUDE.diff":
        "2c6231dcecae2795a626d147d3670445231cefb499a2242d7b86ac57348b0c36",
    "PHASE_E_E8_MESSUNGEN_CLAUDE.txt":
        "356bf0a1b8c90bef14e8d948d2d6908408c9c1b129df18140cbb33e22e7dfc03",
    "BEWERTUNG_DRITTES_REVIEW_74d30ba_2026-09-10.md":
        "e102e50710a3119bc7b7184ab731c71ec3fd86574caf6a9859a876161af7c094",
    "ANTWORT_E8a_JACOBI_2026-09-10.md":
        "5be6d054b2761993665875555ae6ce89b26a95ee4b15b85c3ea1c532e1ff0c74",
    "GATE_D_FREIGABE_UND_PHASE_E_START_2026-09-10.md":
        "0eff72f3c509a70e7d87ebc13fc1f794be4d63c6819bf52e5a6ea72d7d7b8ddd",
    "AUFTRAG_EMMY_PHASE_E_OPTIMIERUNG_2026-09-10.md":
        "5faf1c1fa7c5c4fd8f6473ef298b6fdea3a9df7b9dedf320ae00ff566c6c2b93",
}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence", required=True, type=Path)
    parser.add_argument("--index", required=True, type=Path)
    parser.add_argument("--bundle", type=Path)
    args = parser.parse_args()
    root = args.evidence.resolve(strict=True)
    source_rows = check_source(root / "source", root / "SOURCE_SHA256SUMS", SOURCE_SHA)
    if len(source_rows) != 1929:
        raise SystemExit("unexpected final source inventory")
    source_identity = read_json(root / "SOURCE_IDENTITY.json")
    if (source_identity.get("branch") != "Testing" or source_identity.get("base_commit") != BASE_COMMIT
            or source_identity.get("source_manifest_sha256") != SOURCE_SHA or source_identity.get("file_count") != 1929):
        raise SystemExit("unexpected final source identity")
    index = {
        "format": "ed301-v2-phase-e-e8-final-index-v1", "evidence_root": str(root),
        "source_manifest_sha256": SOURCE_SHA, "source_files": len(source_rows),
        "build_source_sha256": BUILD_SHA, "base_commit": BASE_COMMIT,
        "source_identity": source_identity,
        "architecture": "native x86_64 only", "gate_e_approval": False,
        "stage_2_authorized": False, "system_installation": False,
        "stages": {}, "supplementary": {}, "source_snapshots": {},
        "benchmarks": {}, "timing": {}, "post_execution_files": {},
        "final_commit_manifest": FINAL_SEAL,
        "authorization_inputs": AUTHORIZATIONS,
        "evidence_policy": "fresh E8 results; no E1-E7 or Gate-C/D PASS receipt transferred",
    }
    for version in VERSIONS:
        for stage in STAGES:
            name = stage + "-" + version
            relative = ("tcp-approved" if stage == "tcp" else stage) + "-" + version
            directory = root / relative
            seal = digest(directory / "SHA256SUMS")
            rows = check_members(directory, "SHA256SUMS", seal)
            identity = read_json(directory / "IDENTITY.json")
            if (identity.get("status") != "PASS" or identity.get("openssl_version") != version
                    or identity.get("source_manifest_sha256") != SOURCE_SHA):
                raise SystemExit("failed or mixed-source final stage: " + name)
            if "build_source_sha256" in identity and identity["build_source_sha256"] != BUILD_SHA:
                raise SystemExit("mixed compiled inputs")
            index["stages"][name] = {
                "path": str(directory), "relative_path": relative, "manifest_sha256": seal,
                "command_count": check_command_logs(directory, rows), "identity": identity}
        functional_sha = index["stages"]["functional-" + version]["manifest_sha256"]
        for stage in STAGES[1:]:
            if index["stages"][stage + "-" + version]["identity"].get("functional_receipt_sha256") != functional_sha:
                raise SystemExit("stage is not bound to the final functional receipt")
        benchmark_record = index["stages"]["benchmarks-" + version]
        if benchmark_record["identity"]["legacy_receipt_sha256"] != index["stages"]["legacy_builds-" + version]["manifest_sha256"]:
            raise SystemExit("benchmark donor binding mismatch")
        if index["stages"]["codegen-" + version]["identity"]["benchmark_receipt_sha256"] != benchmark_record["manifest_sha256"]:
            raise SystemExit("codegen is not bound to the measured final core binaries")
        results = read_json(root / ("benchmarks-" + version) / "SUMMARY.json")
        if len(results) != 128 or any(row["repetitions"] != 9 for row in results):
            raise SystemExit("incomplete final benchmark matrix")
        index["benchmarks"][version] = results
        index["timing"][version] = {algorithm: (root / ("timing-" + version) /
            (algorithm + "_SUMMARY.txt")).read_text() for algorithm in ("ed301", "x301")}

    def supplemental(name, path, expected, scope):
        rows = check_members(path, "SHA256SUMS", expected)
        record = {"path": str(path), "relative_path": "supplementary/" + name,
                  "manifest_sha256": expected, "scope": scope,
                  "command_count": check_command_logs(path, rows),
                  "source_comparisons": [], "extra_binaries": {}}
        for metadata in ("IDENTITY.json", "SUMMARY.json", "SUMMARY.txt"):
            if (path / metadata).is_file():
                record[metadata] = ((path / metadata).read_text() if metadata.endswith(".txt")
                                    else read_json(path / metadata))
        index["supplementary"][name] = record
        return record

    def compare(record, manifest, source, source_name, prefix=""):
        count = check_source_comparison(Path(record["path"]), manifest, source, prefix, all_rust=True)
        record["source_comparisons"].append({"manifest": manifest, "source": source_name,
                                            "prefix": prefix, "files": count, "all_rust": True})

    for name, (path, expected) in FINAL_CORE.items():
        directory = WORKSPACE / path
        record = supplemental(name, directory, expected, "fresh final Phase-E core gate")
        compare(record, "SOURCE_SHA256SUMS", root / "source", "final")
        if name.endswith("timing"):
            if "=PASS" not in record.get("SUMMARY.txt", ""):
                raise SystemExit("core timing did not pass")
        elif record.get("SUMMARY.json", {}).get("status") != "PASS":
            raise SystemExit("core correctness or taint did not pass")
        if name.endswith("taint"):
            filename = "ed301-eddsa-secret-taint" if name.startswith("ed-") else "x301-core-taint"
            binary = directory / "target/release" / filename
            checksum = record["SUMMARY.json"]["binary_sha256"]
            if binary.is_symlink() or digest(binary) != checksum:
                raise SystemExit("final taint binary changed")
            record["extra_binaries"]["binaries/" + filename] = {"path": str(binary), "sha256": checksum}
        runner = {"core-correctness": "phase-e/tools/check_core_correctness.py",
                  "ed-core-taint": "phase-c/tools/run_core_taint.py",
                  "x-core-taint": "phase-e/tools/run_x301_taint.py",
                  "ed-core-timing": "phase-c/tools/run_core_timing.py",
                  "x-core-timing": "phase-d/tools/run_x301_timing.py"}[name]
        metadata = record["IDENTITY.json"] if name.endswith("timing") else record["SUMMARY.json"]
        if metadata["runner_sha256"] != digest(root / "source" / runner):
            raise SystemExit("core receipt runner differs from the final source: " + name)
    correctness = index["supplementary"]["core-correctness"]["SUMMARY.json"]
    if correctness["test_counts"] != {"baseline-ed": 54, "baseline-x": 25,
            "previous-ed": 62, "previous-x": 56, "current-ed": 65, "current-x": 57,
            "current-ed-self-verify": 65, "current-x-taint-feature": 57}:
        raise SystemExit("final core test inventory mismatch")
    if (correctness["phase_b_replay"] != "8/8" or not correctness["all_named_gate_c_d1_tests_retained"]
            or not correctness["all_named_previous_phase_e_tests_retained"]):
        raise SystemExit("missing retained correctness gates")
    if index["supplementary"]["ed-core-taint"]["SUMMARY.json"]["valgrind_runs"] != 36:
        raise SystemExit("incomplete Ed301 taint gate")
    x_taint = index["supplementary"]["x-core-taint"]["SUMMARY.json"]
    if x_taint["valgrind_runs"] != 526 or not x_taint["shared_output_keeps_taint"]:
        raise SystemExit("incomplete X301 taint gate")
    if correctness["runner_sha256"] != digest(root / "source/phase-e/tools/check_core_correctness.py"):
        raise SystemExit("correctness runner differs from the final source")
    correctness_path = Path(index["supplementary"]["core-correctness"]["path"])
    phase_b_binding = read_json(correctness_path / "PHASE_B_CURRENT_BINDING.json")
    if {row["path"] for row in phase_b_binding} != set(manifest_rows(root / "source/phase-b/PHASE_B_SOURCE_MANIFEST.sha256")):
        raise SystemExit("incomplete current Phase-B binding")
    for row in phase_b_binding:
        if digest(root / "source" / row["path"]) != row["current_sha256"]:
            raise SystemExit("Phase-B receipt input differs from the final source")

    for name in ("public-import-boundary", "codegen-driver-control", "provenance-control"):
        directory = root / name
        record = supplemental(name, directory, digest(directory / "SHA256SUMS"),
                              "fresh E8 focused boundary or evidence-integrity control")
        identity = record["IDENTITY.json"]
        if identity["status"] != "PASS" or identity["source_manifest_sha256"] != SOURCE_SHA:
            raise SystemExit("focused E8 control is not bound to the final source")
        if name == "public-import-boundary":
            core = index["supplementary"]["ed-core-taint"]
            if (identity["core_taint_receipt_sha256"] != core["manifest_sha256"]
                    or identity["binary_sha256"] != core["SUMMARY.json"]["binary_sha256"]
                    or record["command_count"] != 3):
                raise SystemExit("public-import control is not bound to the checked core ELF")
        elif name == "codegen-driver-control":
            actual = root / "functional-3.5.8/modules/ed301_eddsa_v2.so"
            if identity["elf_sha256"] != digest(actual) or identity["synthetic_expected_exit"] != 47:
                raise SystemExit("codegen driver control binding mismatch")
        else:
            changed = identity["changed_member"]
            if (identity["runner_sha256"] != correctness["runner_sha256"]
                    or identity["expected_rejection_step"] != 4
                    or identity["original_member_sha256"] != source_rows.get(changed)):
                raise SystemExit("provenance negative control binding mismatch")
            fixture = directory / "fixture/source"
            if [name for name, sha in source_rows.items() if digest(fixture / name) != sha] != [changed]:
                raise SystemExit("provenance fixture differs beyond its one controlled member")

    # Retain the exact historical sources rebuilt by this new E8 correctness
    # receipt, not historical PASS receipts. Compare every Rust file, too.
    for manifest, (path, expected) in CORRECTNESS_SOURCES.items():
        snapshot = WORKSPACE / path
        snapshot_name = snapshot.name
        check_source(snapshot / "source", snapshot / "SOURCE_SHA256SUMS", expected)
        index["source_snapshots"][snapshot_name] = {
            "path": str(snapshot), "relative_path": "snapshots/" + snapshot_name,
            "manifest_sha256": expected}
        compare(index["supplementary"]["core-correctness"], manifest,
                snapshot / "source", snapshot_name)
        if manifest == "BASELINE_RUST_SHA256SUMS":
            for package, seal in (("provenance/phase-a/2026-09-09", "PHASE_A_MANIFEST.sha256"),
                                  ("provenance/v2-search", "RUN_MANIFEST.sha256")):
                package_sha = digest(snapshot / "source" / package / seal)
                current_seal = root / "source" / package / seal
                if digest(current_seal) != package_sha:
                    raise SystemExit("current provenance package manifest differs from the approved baseline")
                # The signed search manifest intentionally binds ../../AGENTS.md
                # and ../../LICENSE. Resolve only names from that byte-identical
                # approved manifest, and require every target inside the sealed
                # source. Ordinary receipt path admission remains strict.
                seen = set()
                for line in current_seal.read_text().splitlines():
                    match = re.fullmatch(r"([0-9a-f]{64})  ([^\r\n]+)", line)
                    if match is None or match[2] in seen or Path(match[2]).is_absolute():
                        raise SystemExit("invalid approved provenance package row")
                    seen.add(match[2])
                    member = (current_seal.parent / match[2]).resolve(strict=True)
                    if not member.is_relative_to(root / "source"):
                        raise SystemExit("approved provenance member escapes the sealed source")
                    relative = member.relative_to(root / "source").as_posix()
                    if source_rows.get(relative) != match[1] or digest(member) != match[1]:
                        raise SystemExit("current provenance package member differs from its approved input")
            if index["supplementary"]["provenance-control"]["IDENTITY.json"]["baseline_source_sha256"] != expected:
                raise SystemExit("provenance-control baseline mismatch")

    for step, (path, expected) in STEP_BENCHMARKS.items():
        directory = WORKSPACE / path
        record = supplemental("benchmark-" + step, directory, expected, "same-run v1/before/after Phase-E measurement")
        if len(record["SUMMARY.json"]) != 32 or any(row["repetitions"] != 9 for row in record["SUMMARY.json"]):
            raise SystemExit("incomplete per-step benchmark")
        identity = record["IDENTITY.json"]
        harnesses = {"ed": "rust/performance/ed301-bench/src/main.rs",
                     "x": "phase-d/benchmarks/x301_core_bench.rs"}
        if (identity["runner_sha256"] != digest(root / "source/phase-e/tools/run_core_benchmarks.py")
                or identity["harness_sha256"] != {key: digest(root / "source" / path) for key, path in harnesses.items()}
                or identity["cpu_affinity"] != 2 or identity["target_ms"] != 200):
            raise SystemExit("per-step measurement runner or method mismatch")
        for side in ("before", "after"):
            old_source = Path(record["IDENTITY.json"]["binaries"]["ed-" + side]["source"]).parent
            if Path(record["IDENTITY.json"]["binaries"]["x-" + side]["source"]).parent != old_source:
                raise SystemExit("per-step Ed/X source mismatch")
            snapshot_name = old_source.parent.name
            seal = old_source.parent / "SOURCE_SHA256SUMS"
            checksum = digest(seal)
            check_source(old_source, seal, checksum)
            index["source_snapshots"][snapshot_name] = {
                "path": str(old_source.parent), "relative_path": "snapshots/" + snapshot_name,
                "manifest_sha256": checksum}
            compare(record, side + "_RUST_SHA256SUMS", old_source, snapshot_name, "rust")
            if side == "after":
                compare(record, side + "_RUST_SHA256SUMS", root / "source", "final", "rust")

    reference = supplemental("halving-reference", WORKSPACE / REFERENCE[0], REFERENCE[1],
                             "supplied independent mathematical proof replay")
    if reference["SUMMARY.json"]["status"] != "PASS" or not reference["SUMMARY.json"]["vectors_byte_equal"]:
        raise SystemExit("independent halving reference did not pass")
    for name, checksum in reference["SUMMARY.json"]["bound_inputs"].items():
        if digest(root / "source" / name) != checksum:
            raise SystemExit("reference input differs from final source")
    for version in VERSIONS:
        directory = root / ("e6-profile-" + version)
        record = supplemental("e6-profile-" + version, directory, digest(directory / "SHA256SUMS"),
                              "fresh final-DSO DER diagnosis; instruction counts, not timings")
        summary = record["SUMMARY.json"]
        if summary["status"] != "PASS" or summary["source_manifest_sha256"] != SOURCE_SHA:
            raise SystemExit("final E6 profile did not pass on final source")
        for key, stage in (("functional", "functional"), ("legacy", "legacy_builds"), ("benchmark", "benchmarks")):
            if summary["input_receipts"][key]["sha256"] != index["stages"][stage + "-" + version]["manifest_sha256"]:
                raise SystemExit("final E6 profile input binding mismatch")

    for name, (relative, source_manifest, case_count, extra_elf) in EXTENDED_GATES.items():
        directory = root / relative
        record = supplemental(name, directory, digest(directory / "SHA256SUMS"),
                              "fresh complete Gate-C/D1-method final-source measurement")
        identity = record["IDENTITY.json"]
        summary = record["SUMMARY.json"]
        if len(summary) != case_count or identity["cpu_affinity"] != 2:
            raise SystemExit("incomplete extended measurement: " + name)
        if source_manifest is not None:
            compare(record, source_manifest, root / "source", "final")
            if identity["baseline_commit"] != "5c688206a15f6ab88a50d53fe503665a302cec4d":
                raise SystemExit("extended measurement baseline mismatch")
        if name.endswith("resources"):
            if (identity["stack_repetitions"] != 3 or identity["rss_repetitions"] != 9
                    or any(row["stack_B"]["repetitions"] != 3 or row["rss_KiB"]["repetitions"] != 9 for row in summary)):
                raise SystemExit("incomplete extended resource rotations")
            controls = identity["controls"]
            if isinstance(controls, dict):
                controls = [controls]
            if any(control["status"] != "PASS" for control in controls):
                raise SystemExit("extended resource positive control failed")
        elif (identity["repetitions"] != 9 or identity["target_ms"] != 100
              or any(row["repetitions"] != 9 for row in summary)):
            raise SystemExit("extended benchmark method mismatch")
        if extra_elf is not None:
            for version in ("v1", "v2"):
                binary = directory / version / "target/release" / extra_elf
                checksum = identity[version]["binary_sha256"]
                if binary.is_symlink() or digest(binary) != checksum:
                    raise SystemExit("extended measured binary changed")
                record["extra_binaries"]["binaries/" + extra_elf + "-" + version] = {
                    "path": str(binary), "sha256": checksum}
        if name == "x-core-resources":
            if (identity["status"] != "PASS" or identity["source_manifest_sha256"] != SOURCE_SHA
                    or identity["benchmark_receipt_sha256"] != index["stages"]["benchmarks-3.5.8"]["manifest_sha256"]
                    or identity["ed_resources_receipt_sha256"] != index["supplementary"]["ed-core-resources"]["manifest_sha256"]):
                raise SystemExit("X301 resource input linkage mismatch")
            expected_binaries = [root / "benchmarks-3.5.8/bin" / ("x-" + v) for v in ("v1", "v2")]
            expected_binaries.append(root / EXTENDED_GATES["ed-core-resources"][0] / "binaries/ed301-resources-v2")
            if identity["binaries"] != {str(path): digest(path) for path in expected_binaries}:
                raise SystemExit("X301 resource binary identity mismatch")

    directory = root / "core-layout"
    layout = supplemental("core-layout", directory, digest(directory / "SHA256SUMS"),
                          "fresh size, section and fixed-base table inventory of 14 measured ELFs")
    if (layout["IDENTITY.json"]["status"] != "PASS"
            or layout["IDENTITY.json"]["source_manifest_sha256"] != SOURCE_SHA
            or len(layout["SUMMARY.json"]) != 14):
        raise SystemExit("incomplete final binary layout inventory")
    layout_inputs = [index["stages"]["benchmarks-" + v] for v in VERSIONS]
    layout_inputs += [index["supplementary"][name] for name in
                      ("core-matrix", "core-microbenchmarks", "ed-core-resources")]
    if layout["IDENTITY.json"]["input_receipts"] != {r["path"]: r["manifest_sha256"] for r in layout_inputs}:
        raise SystemExit("final binary layout receipt linkage mismatch")
    for row in layout["SUMMARY.json"]:
        if digest(Path(row["binary"])) != row["binary_sha256"]:
            raise SystemExit("final binary layout ELF changed")

    # Existing executed files remain byte-identical. Only additive final reports,
    # handoff controllers and the final commit seal may be new in the checkout.
    for name, checksum in source_rows.items():
        if digest(CHECKOUT / name) != checksum:
            raise SystemExit("checkout differs from executed source: " + name)
    listed = subprocess.check_output(["git", "-C", str(CHECKOUT), "ls-files", "-z", "--cached", "--others", "--exclude-standard"])
    for raw in sorted(set(listed.split(b"\0")) - {b""}):
        name = raw.decode()
        if name in source_rows or name in {FINAL_SEAL, "provenance/v2-search/RUN_MANIFEST.sha256.ots.bak"} or CHECKOUT / name == args.index.absolute():
            continue
        path = CHECKOUT / name
        if (path.is_symlink() or not path.is_file() or not name.startswith("phase-e/")
                or not (path.suffix == ".md" or name.startswith("phase-e/e8_handoff/"))):
            raise SystemExit("unexecuted runtime or test input: " + name)
        index["post_execution_files"][name] = digest(path)
    args.index.write_text(json.dumps(index, indent=2) + "\n")
    print("index=" + str(args.index.absolute()), flush=True)
    print("index_sha256=" + digest(args.index), flush=True)
    if args.bundle is not None:
        create_bundle(args.bundle, root, args.index, index)


def create_bundle(bundle, root, index_path, index):
    bundle = bundle.absolute()
    if bundle.exists() or bundle.is_symlink() or root in bundle.parents or CHECKOUT in bundle.parents:
        raise SystemExit("bundle must be new and outside evidence and checkout")
    if not (CHECKOUT / FINAL_SEAL).is_file():
        raise SystemExit("create the final source manifest before packaging")
    final_rows = check_members(CHECKOUT, FINAL_SEAL, digest(CHECKOUT / FINAL_SEAL))
    expected_rows = set(manifest_rows(root / "SOURCE_SHA256SUMS")) | set(index["post_execution_files"]) | {
        index_path.absolute().relative_to(CHECKOUT).as_posix()}
    if set(final_rows) != expected_rows:
        raise SystemExit("final commit seal does not cover exactly source, reports, tools and index")
    bundle.mkdir(mode=0o700)
    omissions = {}

    def copy_member(path, target):
        target.parent.mkdir(parents=True, exist_ok=True)
        if path.is_symlink():
            link = os.readlink(path)
            if Path(link).is_absolute() or ".." in Path(link).parts:
                raise SystemExit("unsafe evidence link")
            target.symlink_to(link)
        elif path.is_dir():
            target.mkdir(exist_ok=True)
        elif path.is_file():
            shutil.copy2(path, target)
        else:
            raise SystemExit("special evidence file")

    def copy_tree(top, destination, stage=False):
        for path in [top] + sorted(top.rglob("*")):
            relative = path.relative_to(top)
            if stage and "targets" in relative.parts:
                continue
            if stage and top.name.startswith("controls-") and relative.parts and relative.parts[0] in CONTROL_FIXTURES:
                name = (Path(top.name) / relative).as_posix()
                if path.is_symlink():
                    omissions[name] = {"type": "symlink", "target": os.readlink(path)}
                elif path.is_file():
                    omissions[name] = {"type": "file", "sha256": digest(path)}
                continue
            copy_member(path, destination / relative)

    copy_tree(root / "source", bundle / "evidence/source")
    for name in ("SOURCE_SHA256SUMS", "SOURCE_IDENTITY.json"):
        copy_member(root / name, bundle / "evidence" / name)
    for record in index["stages"].values():
        copy_tree(Path(record["path"]), bundle / "evidence" / record["relative_path"], stage=True)
    for record in index["source_snapshots"].values():
        original = Path(record["path"])
        target = bundle / record["relative_path"]
        copy_tree(original / "source", target / "source")
        for name in ("SOURCE_SHA256SUMS", "SOURCE_IDENTITY.json"):
            copy_member(original / name, target / name)
    for record in index["supplementary"].values():
        original = Path(record["path"])
        target = bundle / record["relative_path"]
        # Original receipts deliberately exclude build caches. Preserve every
        # sealed member; add taint binaries with their original summary hashes.
        for name in list(manifest_rows(original / "SHA256SUMS")) + ["SHA256SUMS"]:
            copy_member(original / name, target / name)
        for name, binary in record["extra_binaries"].items():
            copy_member(Path(binary["path"]), target / name)
    for name in index["post_execution_files"]:
        copy_member(CHECKOUT / name, bundle / "reports" / Path(name).relative_to("phase-e"))
    copy_member(index_path, bundle / "reports/E8_EVIDENCE_INDEX.json")
    copy_member(CHECKOUT / FINAL_SEAL, bundle / "reports/E8_FINAL_HANDOFF_SOURCE_MANIFEST.sha256")
    (bundle / "OMITTED_CONTROL_FIXTURES.json").write_text(json.dumps(omissions, indent=2) + "\n")
    for name, checksum in DONORS.items():
        if digest(WORKSPACE / name) != checksum:
            raise SystemExit("bound donor archive mismatch")
        copy_member(WORKSPACE / name, bundle / "donors" / name)
    for name, checksum in AUTHORIZATIONS.items():
        if digest(WORKSPACE / name) != checksum:
            raise SystemExit("Phase-E authorization input mismatch")
        copy_member(WORKSPACE / name, bundle / "authorizations" / name)
    manifest = {}
    readonly_roots = ["evidence/source"] + [record["relative_path"] + "/source"
                                          for record in index["source_snapshots"].values()]
    for path in sorted(bundle.rglob("*")):
        name = path.relative_to(bundle).as_posix()
        if path.is_symlink():
            manifest[name] = {"type": "symlink", "target": os.readlink(path)}
        elif path.is_dir():
            readonly = any(name == prefix or name.startswith(prefix + "/") for prefix in readonly_roots)
            path.chmod(0o555 if readonly else 0o700)
            manifest[name] = {"type": "directory", "mode": path.stat().st_mode & 0o777}
        else:
            manifest[name] = {"type": "file", "mode": path.stat().st_mode & 0o777, "sha256": digest(path)}
    (bundle / "BUNDLE_MANIFEST.json").write_text(json.dumps(manifest, indent=2) + "\n")
    print("bundle=" + str(bundle), flush=True)
    print("bundle_manifest_sha256=" + digest(bundle / "BUNDLE_MANIFEST.json"), flush=True)


if __name__ == "__main__":
    main()
