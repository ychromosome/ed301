#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Fresh Phase-E x86-64 policy on the measured cores and linked provider DSOs."""

import argparse
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "phase-d/d2/tools"))
from d2_common import ROOT, Receipt, digest, verify_receipt

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--source-sha", required=True)
parser.add_argument("--functional", type=Path, required=True)
parser.add_argument("--functional-sha", required=True)
parser.add_argument("--benchmark", type=Path, required=True)
parser.add_argument("--benchmark-sha", required=True)
parser.add_argument("--output", type=Path, required=True)
args = parser.parse_args()
functional = args.functional.resolve(strict=True)
benchmark = args.benchmark.resolve(strict=True)
identities = []
for directory, checksum in ((functional, args.functional_sha), (benchmark, args.benchmark_sha)):
    if digest(directory / "SHA256SUMS") != checksum:
        raise SystemExit("codegen input receipt digest mismatch")
    identity = verify_receipt(directory)
    if identity["source_manifest_sha256"] != args.source_sha:
        raise SystemExit("all codegen stages must use one Phase-E source snapshot")
    identities.append(identity)
if identities[0]["openssl_version"] != identities[1]["openssl_version"]:
    raise SystemExit("codegen ABI mismatch")
if identities[1]["functional_receipt_sha256"] != args.functional_sha:
    raise SystemExit("benchmark does not bind the same functional DSOs")
receipt = Receipt(args.output, args.source_sha, "phase-e-core-provider-codegen-x86-64")
receipt.identity.update(openssl_version=identities[0]["openssl_version"],
                        functional_receipt_sha256=args.functional_sha,
                        benchmark_receipt_sha256=args.benchmark_sha,
                        scope="classified optimized arithmetic, public exponent provenance and zeroization; not a universal CT proof")
receipt.write_identity()
checker = ROOT / "phase-e/tools/check_codegen.sh"
for profile, variant, module in (
    ("ed", "ed-normal", "ed301_eddsa_v2"), ("ed", "ed-tls", "ed301_eddsa_v2_tls"),
    ("x", "x-normal", "x301_v2"), ("x", "x-tls", "x301_v2_tls"),
):
    receipt.run(module, ["/bin/sh", checker, profile + "-provider",
                         functional / "modules" / (module + ".so"),
                         functional / "markers" / variant / "toolchain.txt", receipt.output / module])
for profile in ("ed", "x"):
    receipt.run(profile + "-core", ["/bin/sh", checker, profile + "-core",
                benchmark / "bin" / (profile + "-v2"),
                benchmark / "markers" / (profile + "-v2") / "toolchain.txt", receipt.output / (profile + "-core")])
verify_receipt(functional)
verify_receipt(benchmark)
receipt.seal()
