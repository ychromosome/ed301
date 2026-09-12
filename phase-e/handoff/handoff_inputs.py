# SPDX-License-Identifier: Apache-2.0
"""Explicit inputs to the local Gate-E handoff, not an approval of Gate E."""

from pathlib import Path

WORKSPACE = Path("/home/martin/Dokumente/ED301")
SOURCE_SHA = "16e13fc68b35812c553b6659f3101b4e956b57d6f980ce9819216205536deb8a"
BUILD_SHA = "0aa116bc145efcbe553dbe8f46ad99fd3a841642ccbec37a9fabc886976f88fa"
BASE_COMMIT = "27092c158f159ece0264317b65bd22282b32c353"
VERSIONS = ("3.5.8", "4.0.2")
STAGES = ("functional", "cli", "tcp", "memory", "controls", "codegen",
          "legacy_builds", "structured", "timing", "benchmarks")
CONTROL_FIXTURES = {"wrong-digest", "tar-bytes", "prefix-extra", "prefix-missing",
                    "prefix-link", "native-evp-bytes", "empty-seal",
                    "duplicate-seal-member", "mixed-origin", "member-bytes"}

# These are fresh Phase-E runs, not transferred Gate-C/D1 results. Source
# manifests are compared file by file with the final source before packaging.
FINAL_CORE = {
    "core-correctness": (
        "ED301-v2_PHASE_E_e5_after_01_2026-09-10/ED301-v2_PHASE_E_core-check_mf3w_bl_",
        "d9d1c3bb56e45c7bcdb224ff31cfe23e6e5a5e4172ecb5f285e7554050341908"),
    "ed-core-taint": (
        "ED301-v2_PHASE_E_e5_after_01_2026-09-10/ED301-v2_core-taint_iz1eldhx",
        "44d3204405fc7405be22bd3796c5d06a51b161c350d9fe4d672cd9c5903a4a6e"),
    "x-core-taint": (
        "ED301-v2_PHASE_E_e5_after_01_2026-09-10/X301-v2_PHASE_E-taint_1q657xnv",
        "2d0a745b35f190f3165c34026c6c0b8dfc7d39a60df9aa9374a9491680c3566c"),
    "ed-core-timing": (
        "ED301-v2_PHASE_E_final_01_2026-09-10/ED301-v2_core-timing_h73k7n0s",
        "8a16ebc82c7b354de669b5ae2fe3fb40d83fa0d6479fc8ffbbe5f348ec0cdea3"),
    "x-core-timing": (
        "ED301-v2_PHASE_E_final_01_2026-09-10/X301-v2_D1-timing_98o1ej_t",
        "ff949805ca56919dae0d2e103d24f95492026c3699bc2f5f77d112f2356b31b8"),
}
STEP_BENCHMARKS = {
    "E4": ("ED301-v2_PHASE_E_core-bench_totko0gp",
           "aaa8b11bb506aa1d1bdeff5839fba9caedbfd8dc9467dbc233156f15497e19f4"),
    "E1": ("ED301-v2_PHASE_E_core-bench_1wbr9rpf",
           "0e23dcfe89e53c6d962355c27b0ab1be36eb0b062342b85cc176a4143cfeb7a0"),
    "E2": ("ED301-v2_PHASE_E_core-bench_aq2zplo3",
           "5b92d58ed348c52eb46e70e319a724b0640adf56a1298ee75c2d63d63ef56331"),
    "E3": ("ED301-v2_PHASE_E_core-bench__a_s9r42",
           "2383e43abc05f15259872bbb231b37b324b15cfbff4b2909f32fff4ca2fa8105"),
    "E5": ("ED301-v2_PHASE_E_core-bench_xbc_fsnd",
           "6a7b7372dd69188b3a6087ed2e2c9ca148cc900a8169e865612c3bf94227ee72"),
}
REFERENCE = ("ED301-v2_PHASE_E_halving-proof_6j8zqqw0",
             "90ae593503b283665a4fbb8275f89599477f75261cf3b23670acd4d272a49f52")
# All paths below are children of the final immutable-source evidence root.
# Their completed receipt hashes are calculated and frozen in the final index.
EXTENDED_GATES = {
    "core-matrix": ("ED301-v2_core-matrix_tea98dtt", "V2_SOURCE_SHA256SUMS", 98,
                    "ed301-core-matrix"),
    "core-microbenchmarks": ("ED301-v2_microbench_t6jpj9uj", "SOURCE_SHA256SUMS", 38,
                             "ed301-microbench"),
    "ed-core-resources": ("ED301-v2_resources_0jsa7m53", "SOURCE_SHA256SUMS", 52, None),
    "x-core-resources": ("x-core-resources", None, 15, None),
}
DONORS = {
    "ED301-v2_D2_ED_DONOR_2026-09-10.tar.gz":
        "1e8d540bf75e09011c0ffb728cb0e6fd264ce46f1d9161f8bd6b4510dfb02ffb",
    "ED301-v2_D2_X_DONOR_2026-09-10.tar.gz":
        "179cdb066b5b8f74dd6f87b78f5d9576710fef9500e388b53747d427d73d9755",
}
