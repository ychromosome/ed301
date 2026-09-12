#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Check frozen receipts and emit the commit-bound Gate-C evidence index on stdout."""
import hashlib
import json
import os
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
CASES = [
    ("available-benchmarks", "ED301-v2_C1C2-benchmark_sklybrw7", "2112b9d64abc30788b7ebe93a95a93fdb9df444aaa29a43c925391db080516ff", "V2_SOURCE_SHA256SUMS"),
    ("core-matrix", "ED301-v2_core-matrix_fo_7z8pb", "95c405be00664f91f2fc25584aeaca14f3e92b06930fd1c1fd80ec604c7fdeda", "V2_SOURCE_SHA256SUMS"),
    ("microbenchmarks", "ED301-v2_microbench_il4cilr_", "5ca2ff2ac462d06d3f05132f10cd94166c19ebd74d8a37a0b1209220bdf3f710", "SOURCE_SHA256SUMS"),
    ("resources", "ED301-v2_resources_8s_1_ann", "f18518b3d26a8bc7b3b35015bf0b7cf4fe6c4a793a68b6cb8f48fce2f7ca8afe", "SOURCE_SHA256SUMS"),
    ("taint", "ED301-v2_core-taint_aif6mcv7", "92778789689a26b6805b2b49d3bdd088be44d21447186235877d6af9472cb9fe", "SOURCE_SHA256SUMS"),
    ("codegen", "ED301-v2_core-codegen_2026-09-10_01", "c0322ec6fc169cb4a7ae1511435ca6895eae6a879e392a479b98ef4bc3af8d9f", None),
    ("timing-first", "ED301-v2_core-timing_0y75y2en", "1f1ee0ffcb9a192e569f12becc0aecf97143b9dae76c2c1f06aeca0d6fd388dc", "SOURCE_SHA256SUMS"),
    ("timing-current", "ED301-v2_core-timing_t_imai6j", "1aaf6c74628de4f945377052a45e4f6374c06a2f31cf89e04c82da71871f0597", "SOURCE_SHA256SUMS"),
    ("correctness", "ED301-v2_core-check_c8tnk9tg", "8f48d0f4c505e29b3a555ed9d38d7f615efb2bb2f0245c3fe7ccedb25d6666fe", "SOURCE_SHA256SUMS"),
]


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def entries(path, codegen_absolute=False):
    for line in path.read_text().splitlines():
        digest, name = line.split("  ", 1)
        allowed_absolute = codegen_absolute and ROOT.parent in Path(name).parents
        if len(digest) != 64 or (Path(name).is_absolute() and not allowed_absolute) or ".." in Path(name).parts:
            raise RuntimeError(f"non-flat receipt path: {name}")
        yield digest, name


def record(path, expected=None):
    if not path.is_file() or path.is_symlink():
        raise RuntimeError(f"not a regular file: {path}")
    actual = sha(path)
    if expected is not None and actual != expected:
        raise RuntimeError(f"hash mismatch: {path}: {actual} != {expected}")
    return {"original_path": str(path), "sha256": actual, "bytes": path.stat().st_size}


index = {"schema": "ed301-phase-c-evidence-v1", "status": "review-candidate-not-approved",
         "baselines": [
             {"id": "ed301-v1", "path": str(ROOT.parent / "ed301-eddsa-github"),
              "commit": "5c688206a15f6ab88a50d53fe503665a302cec4d"},
             {"id": "x301-v1", "path": str(ROOT.parent / "x301-integration"),
              "commit": "569dc4ff10e0e5e19d106cbe490d2a5aaeac935e"}],
         "artifacts": []}
for identifier, directory, expected, source_manifest in CASES:
    root = ROOT.parent / directory
    receipt = record(root / "SHA256SUMS", expected)
    for digest, name in entries(root / "SHA256SUMS", identifier == "codegen"):
        record(root / name, digest)
    item = {"id": identifier, "original_directory": str(root), "receipt": receipt,
            "source_manifest": source_manifest, "binaries": []}
    metadata = json.loads((root / "IDENTITY.json").read_text()) if (root / "IDENTITY.json").exists() else {}
    if identifier == "available-benchmarks":
        item["binaries"] = [record(Path(name), value) for name, value in metadata["binary_sha256"].items()]
    elif identifier in ("core-matrix", "microbenchmarks"):
        binary = "ed301-core-matrix" if identifier == "core-matrix" else "ed301-microbench"
        item["binaries"] = [record(root / version / "target/release" / binary, metadata[version]["binary_sha256"])
                            for version in ("v1", "v2")]
    elif identifier == "resources":
        item["binaries"] = [record(root / "binaries" / ("ed301-resources-" + version), metadata[version]["binary_sha256"])
                            for version in ("v1", "v2")]
    elif identifier == "taint":
        summary = json.loads((root / "SUMMARY.json").read_text())
        item["binaries"] = [record(root / "target/release/ed301-eddsa-secret-taint", summary["binary_sha256"])]
    elif identifier == "codegen":
        item["binaries"] = [record(ROOT.parent / "ED301-v2_C1C2-benchmark_sklybrw7/ed301-v2-core/target/release/ed301-benchmark",
                                   "cdddffc53b6330dd1d1a86aca86a7b86690f5f70b2fded7aa01f652e2c9f11df")]
        item["sources_from_artifact"] = "available-benchmarks"
        # The inherited receipt binds four absolute paths. Preserve that receipt
        # verbatim and separately bind all supporting instruction/control files.
        item["additional_files"] = [record(p) for p in sorted(root.rglob("*"))
                                    if p.is_file() and p.name != "SHA256SUMS"]
    elif identifier.startswith("timing-"):
        item["binaries"] = [record(root / "core_timing", metadata["harness_sha256"]),
                            record(root / "libed301_core_timing_adapter.so", metadata["adapter_sha256"])]
    elif identifier == "correctness":
        item["binaries"] = [record(p) for p in sorted((root / "target/release/deps").glob("ed301_eddsa-*"))
                            if p.is_file() and os.access(p, os.X_OK)]
        if len(item["binaries"]) != 2:
            raise RuntimeError("expected exactly two checked Rust unit-test executables")
    if source_manifest:
        mappings = []
        for digest, name in entries(root / source_manifest):
            current = ROOT / name
            archived = ROOT / "phase-c/archived-source-blobs" / digest
            path = current if current.is_file() and sha(current) == digest else archived
            record(path, digest)
            mappings.append({"source_path": name, "sha256": digest,
                             "available_at": str(path.relative_to(ROOT))})
        item["source_file_count"] = len(mappings)
        item["source_overrides"] = [m for m in mappings if m["source_path"] != m["available_at"]]
    index["artifacts"].append(item)

standards = ROOT.parent / "ED301-v2_GATE_C_STANDARDS_2026-09-10"
index["standards"] = {"directory": str(standards), "receipt": record(standards / "SHA256SUMS",
    "6ddc5ee36b7c34d8acf114eac8565bc9fcfd44d66e9d106397b79fd8f59ed227")}
for digest, name in entries(standards / "SHA256SUMS"):
    record(standards / name, digest)
legacy = ROOT.parent / "ed301_technischer_abschluss"
index["legacy_curve"] = {"directory": str(legacy), "receipt": record(legacy / "SHA256SUMS"),
                         "parents_manifest": record(legacy / "SOURCE_SHA256SUMS")}
index["legacy_parents"] = [record((legacy / name).resolve(), digest)
                           for digest, name in (line.split("  ", 1)
                                                for line in (legacy / "SOURCE_SHA256SUMS").read_text().splitlines())]
review = Path("/home/martin/Projekte/Claude/OpenSSL-Fork/review/ed301-v2-curve-search-2026-09-09")
index["approvals"] = [
    record(review / "GATE_A_FREIGABE_2026-09-09.md", "7c8857b938edf27e41d831e7da90dc21637b3142246a9d3dfcc05cca30672786"),
    record(review / "GATE_B_FREIGABE_2026-09-10.md", "74bc58fa88beb6f905c4c2cd0fc480a3225cf84d0b977353c5faaf65a6e328a0"),
    record(review / "gate_b_independent_check.py", "ec1bcdcaf6002d8d0afa65f50e5707fb518c8c6271a57a6aa31395bbfc81c314")]
index["context_inputs"] = [record(ROOT.parent / name) for name in (
    "AUFTRAG_EMMY_ED301-v2_IMPLEMENTIERUNG_2026-09-09.md",
    "VORSCHLAG_PUNKTE_5_6_7_ED301-v2_2026-09-09.md",
    "NEUE_KURVE_VORABFRAGEN_2026-09-09.md", "X301-v2_EINGABEVERTRAG_2026-09-10.md")]
print(json.dumps(index, indent=2))
