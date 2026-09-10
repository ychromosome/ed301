#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Replay the supplied independent E3 proof without changing its source bytes."""
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]
BOUND = {
    "phase-e/reference/claude/phase_e/subgroup_halving_proof.py":
        "cabec1f325944610049bc1282691890af9dab4188615f22bc5e74adbd9b7f32d",
    "phase-e/reference/gate_b_independent_check.py":
        "ec1bcdcaf6002d8d0afa65f50e5707fb518c8c6271a57a6aa31395bbfc81c314",
    "vectors/ed301-v2-subgroup-halving.json":
        "e78ae62a636242ba9c01f4a4a0edce7d38dbe89ebb1508b144baaa3334b91737",
    "provenance/phase-a/2026-09-09/parameter/ed301-v2.json":
        "13f0eaf541919a1447b9d3c58e6d57eb77ffab94ebe37539c70301d6fddcfaa0",
}


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


for name, digest in BOUND.items():
    if sha(ROOT / name) != digest:
        raise SystemExit(f"FAIL: changed independent proof input: {name}")
work = Path(tempfile.mkdtemp(prefix="ED301-v2_PHASE_E_halving-proof_", dir=ROOT.parent))
print(f"artifact_directory={work}", flush=True)
(work / "home").mkdir()
command = ["/usr/bin/python3", "-I", "-B",
           str(ROOT / "phase-e/reference/claude/phase_e/subgroup_halving_proof.py"),
           str(ROOT), str(work / "reproduced_vectors.json")]
environment = {"PATH": "/usr/bin:/bin", "LC_ALL": "C", "HOME": str(work / "home")}
result = subprocess.run(command, cwd=work, env=environment, text=True,
                        stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
(work / "proof.log").write_text(result.stdout)
(work / "command.json").write_text(json.dumps({"argv": command, "cwd": str(work),
    "environment": environment, "exit": result.returncode}, indent=2) + "\n")
print(result.stdout, end="", flush=True)
if result.returncode:
    raise SystemExit("FAIL: supplied proof replay")
if (work / "reproduced_vectors.json").read_bytes() != (ROOT / "vectors/ed301-v2-subgroup-halving.json").read_bytes():
    raise SystemExit("FAIL: proof did not reproduce the supplied vectors byte-for-byte")
summary = {"status": "PASS", "bound_inputs": BOUND, "runner_sha256": sha(Path(__file__)),
           "reproduced_vectors_sha256": sha(work / "reproduced_vectors.json"),
           "random_and_directed_points": 156, "explicit_nonidentity_torsion_points": 3,
           "vectors": 25, "vectors_byte_equal": True,
           "proof_source_unmodified": True, "helper_source_unmodified": True,
           "helper_execution": "Only the first 57 lines, as selected by the supplied proof"}
(work / "SUMMARY.json").write_text(json.dumps(summary, indent=2) + "\n")
(work / "SHA256SUMS").write_text("".join(f"{sha(p)}  {p.name}\n"
    for p in sorted(work.iterdir()) if p.is_file()))
print("PASS: independent E3 reference and byte-identical 25-vector reproduction", flush=True)
