# SPDX-License-Identifier: Apache-2.0
"""Explicit fresh E7 evidence inputs, not an approval of Gate E."""

from pathlib import Path

WORKSPACE = Path("/home/martin/Dokumente/ED301")
SOURCE_SHA = "00defea7ec46cfb503f3f14c65e9b4f2f8d3f086adefa1d68e219440a1725e79"
BUILD_SHA = "ce0a57d9763452a99e3b2632f83f102c85399e18bacb82913167724a6b81291d"
BASE_COMMIT = "a83511cf26ade60c9355998ab1ccbc11f73d83c8"
VERSIONS = ("3.5.8", "4.0.2")
STAGES = ("functional", "cli", "tcp", "memory", "controls", "codegen",
          "legacy_builds", "structured", "timing", "benchmarks")
CONTROL_FIXTURES = {"wrong-digest", "tar-bytes", "prefix-extra", "prefix-missing",
                    "prefix-link", "native-evp-bytes", "empty-seal",
                    "duplicate-seal-member", "mixed-origin", "member-bytes"}

# Fresh E7 receipts. Every recorded Rust input is compared with the final
# source; no older E1-E6 or Gate-C/D PASS receipt substitutes for a new run.
FINAL_CORE = {
    "core-correctness": (
        "ED301-v2_PHASE_E_e7_after_02_2026-09-10/ED301-v2_PHASE_E_core-check_y6waj_7w",
        "066222842b7a08d0605256918a2da18b4c8b5c4fa6fd9d9e05ee6058e664bd91"),
    "ed-core-taint": (
        "ED301-v2_PHASE_E_e7_final_01_2026-09-10/ED301-v2_core-taint_ou4nkswl",
        "fae576d7e0912ab08e8e1f1b6b80dbebd75703ed64d7f73a27cb26a633c8385d"),
    "x-core-taint": (
        "ED301-v2_PHASE_E_e7_final_01_2026-09-10/X301-v2_PHASE_E-taint_c0i1s0y2",
        "3fb03b2612439fd2e5ae0b81bf870c274c4fc64154b43912ca7c581205790c6c"),
    "ed-core-timing": (
        "ED301-v2_PHASE_E_e7_final_02_2026-09-10/ED301-v2_core-timing_tpbyngu1",
        "ebe668e9ab7ce7d1caf8d73753ab15fe021b89569673eca11cdb17ce06d6f7ac"),
    "x-core-timing": (
        "ED301-v2_PHASE_E_e7_final_02_2026-09-10/X301-v2_D1-timing_3697kgu4",
        "573c1129ca916640c7a62f9d990e393f84db21c03a9a627f6bfda661d5e2120d"),
}
CORRECTNESS_SOURCES = {
    "BASELINE_RUST_SHA256SUMS": (
        "ED301-v2_PHASE_E_e4_before_2026-09-10",
        "90862f77901233f72525e616a5c6d9a5ddb393d7e367d6fb69c49e66ace5c437"),
    "PREVIOUS_RUST_SHA256SUMS": (
        "ED301-v2_PHASE_E_e7_before_2026-09-10",
        "e979a4b6abbea0f1915f7a714d6396bff82b328d34dea310f9e3ad2359f469c7"),
}
STEP_BENCHMARKS = {
    "E7": (
        "ED301-v2_PHASE_E_e7_after_02_2026-09-10/ED301-v2_PHASE_E_core-bench_jghg3aii",
        "3ca6f86c5f75b30a7f469a762c22730524bdf7ddf49b52e327c12814081c2f7e"),
}
REFERENCE = (
    "ED301-v2_PHASE_E_e7_final_01_2026-09-10/ED301-v2_PHASE_E_halving-proof__4y2ukzo",
    "576c640917f3dfeb9cdf73b06f10660116678534449dfabb7a35f12eb5ac8949")
# Children of the final immutable-source evidence root. The assembler refuses
# incomplete matrices and binds each completed receipt hash in the final index.
EXTENDED_GATES = {
    "core-matrix": ("ED301-v2_core-matrix_45ebwkhy", "V2_SOURCE_SHA256SUMS", 98,
                    "ed301-core-matrix"),
    "core-microbenchmarks": ("ED301-v2_microbench_rih_0li7", "SOURCE_SHA256SUMS", 38,
                             "ed301-microbench"),
    "ed-core-resources": ("ED301-v2_resources_7_6t8hc0", "SOURCE_SHA256SUMS", 52, None),
    "x-core-resources": ("x-core-resources", None, 15, None),
}
DONORS = {
    "ED301-v2_D2_ED_DONOR_2026-09-10.tar.gz":
        "1e8d540bf75e09011c0ffb728cb0e6fd264ce46f1d9161f8bd6b4510dfb02ffb",
    "ED301-v2_D2_X_DONOR_2026-09-10.tar.gz":
        "179cdb066b5b8f74dd6f87b78f5d9576710fef9500e388b53747d427d73d9755",
}
