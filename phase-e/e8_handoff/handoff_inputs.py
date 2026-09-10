# SPDX-License-Identifier: Apache-2.0
"""Explicit fresh E8 evidence inputs, not an approval of Gate E."""

from pathlib import Path

WORKSPACE = Path("/home/martin/Dokumente/ED301")
SOURCE_SHA = "1b9e7aecf9d69b1a5b38cf5b81f12b399b951770d99b03ac2fe77d0c1f8fde35"
BUILD_SHA = "1a2e43552e6aa794c97f2c82ebfa1e70ca6be1e2a31bc8ed7d69c68e12b0f1e2"
BASE_COMMIT = "74d30ba7f463ea7898249dc5560032f39358569b"
VERSIONS = ("3.5.8", "4.0.2")
STAGES = ("functional", "cli", "tcp", "memory", "controls", "codegen",
          "legacy_builds", "structured", "timing", "benchmarks")
CONTROL_FIXTURES = {"wrong-digest", "tar-bytes", "prefix-extra", "prefix-missing",
                    "prefix-link", "native-evp-bytes", "empty-seal",
                    "duplicate-seal-member", "mixed-origin", "member-bytes"}

# Fresh E8 receipts. Every Rust input and each gate runner is compared with
# the final source; no E1-E7 or Gate-C/D PASS substitutes for a new E8 run.
FINAL_CORE = {
    "core-correctness": (
        "ED301-v2_PHASE_E_e8_optionc_candidate_07_2026-09-10/ED301-v2_PHASE_E_core-check_5qb51d3e",
        "bbbc5be2f5155885e5cf983297efaa7001b0a86040015ed10b79345cf275f012"),
    "ed-core-taint": (
        "ED301-v2_PHASE_E_e8_optionc_candidate_04_2026-09-10/ED301-v2_core-taint_o_dk5v9b",
        "40a2f8c45e7ed53ab73e77c790f5563a404774cc9a213b2dbee3fee3fe194f62"),
    "x-core-taint": (
        "ED301-v2_PHASE_E_e8_final_01_2026-09-10/X301-v2_PHASE_E-taint_tf5wt119",
        "ab2f616cdb006445c6167ad06c68e6f60262f53cdbb839eebf0d66e7d9b56e62"),
    "ed-core-timing": (
        "ED301-v2_PHASE_E_e8_final_01_2026-09-10/ED301-v2_core-timing_ym55j2l4",
        "2a8443fd04a8d249fb3f222823087c4e167f414b14919981e7bb9b890bd7d1d9"),
    "x-core-timing": (
        "ED301-v2_PHASE_E_e8_final_01_2026-09-10/X301-v2_D1-timing_w8bq52bk",
        "0ca535b30c6ad52199a836a02f8c972a58fb4abe38ec82648a5d8c8d024a8a95"),
}
CORRECTNESS_SOURCES = {
    "BASELINE_RUST_SHA256SUMS": (
        "ED301-v2_PHASE_E_e4_before_2026-09-10",
        "90862f77901233f72525e616a5c6d9a5ddb393d7e367d6fb69c49e66ace5c437"),
    "PREVIOUS_RUST_SHA256SUMS": (
        "ED301-v2_PHASE_E_e8_before_2026-09-10",
        "969a4bd2efcec0878b77f6fea8b5a4a7ef124e47543004dd5dff73e5af591172"),
}
STEP_BENCHMARKS = {
    "E8": (
        "ED301-v2_PHASE_E_e8_optionc_candidate_05_2026-09-10/ED301-v2_PHASE_E_core-bench_8kbjtkpw",
        "6b6fbc54a363250cd5032ab8d5a1691561eec6f13083bebe6fcf3189a8fea4a2"),
}
REFERENCE = (
    "ED301-v2_PHASE_E_e8_optionc_candidate_07_2026-09-10/ED301-v2_PHASE_E_halving-proof_f36wem1w",
    "f338c414bb7e714ecb986273474df4dc99dd15631c9b8615719c39ece180629f")
# Children of the final immutable-source evidence root. The assembler refuses
# incomplete matrices and binds each completed receipt hash in the final index.
EXTENDED_GATES = {
    "core-matrix": ("ED301-v2_core-matrix_ug_inbwh", "V2_SOURCE_SHA256SUMS", 98,
                    "ed301-core-matrix"),
    "core-microbenchmarks": ("ED301-v2_microbench_q5ji_gp5", "SOURCE_SHA256SUMS", 38,
                             "ed301-microbench"),
    "ed-core-resources": ("ED301-v2_resources_3mbf8yyk", "SOURCE_SHA256SUMS", 52, None),
    "x-core-resources": ("x-core-resources", None, 15, None),
}
DONORS = {
    "ED301-v2_D2_ED_DONOR_2026-09-10.tar.gz":
        "1e8d540bf75e09011c0ffb728cb0e6fd264ce46f1d9161f8bd6b4510dfb02ffb",
    "ED301-v2_D2_X_DONOR_2026-09-10.tar.gz":
        "179cdb066b5b8f74dd6f87b78f5d9576710fef9500e388b53747d427d73d9755",
}
