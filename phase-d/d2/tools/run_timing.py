#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Dudect on actual provider DSOs; process-local CPU affinity, no host tuning."""

import argparse
import os
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from d2_common import ROOT, Receipt, digest, verify_receipt

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--source-sha", required=True)
parser.add_argument("--functional", type=Path, required=True)
parser.add_argument("--functional-sha", required=True)
parser.add_argument("--output", type=Path, required=True)
parser.add_argument("--cpu", type=int, default=2)
parser.add_argument("--measurements", type=int, default=200000)
args = parser.parse_args()
if args.cpu not in os.sched_getaffinity(0) or not 200000 <= args.measurements <= 10000000:
    parser.error("invalid CPU or sample count")
functional = args.functional.resolve(strict=True)
if digest(functional / "SHA256SUMS") != args.functional_sha:
    raise SystemExit("functional receipt digest mismatch")
identity = verify_receipt(functional)
if identity["source_manifest_sha256"] != args.source_sha:
    raise SystemExit("timing and functional stages must use one source snapshot")
receipt = Receipt(args.output, args.source_sha, "provider-dudect")
out = receipt.output
version = identity["openssl_version"]
prefix = functional / "openssl/inst" / version
header = ROOT / "phase-c/timing/third_party/dudect/dudect.h"
if digest(header) != "6dcf713c9e43ac1d736e21e84af738013fb2a4b05b66931dddc971bb43e899f5":
    raise SystemExit("dudect dependency hash mismatch")
receipt.identity.update(openssl_version=version, functional_receipt_sha256=args.functional_sha,
                        cpu=args.cpu, requested_measurements=args.measurements,
                        positive_control_required=True, detection_sticky_across_batches=True,
                        threshold_abs_t=10, host_tuning=False,
                        load_before=Path("/proc/loadavg").read_text().strip(),
                        measured_modules={name: identity["module_sha256"][name]
                                          for name in ("ed301_eddsa_v2", "x301_v2_tls")})
receipt.write_identity()
runtime = dict(receipt.clean, OPENSSL_CONF="/dev/null", OPENSSL_MODULES=str(functional / "modules"),
               LD_LIBRARY_PATH=str(prefix / "lib"), ED301V2_EXPECT_OPENSSL_PREFIX=str(prefix))
for name, source in (("ed301", "provider-tests/provider_timing.c"),
                     ("x301", "provider-tests/x301/provider_x301_timing.c")):
    binary = out / (name + "_timing")
    receipt.run("compile-" + name, ["/usr/bin/gcc", "-std=c11", "-D_GNU_SOURCE", "-O2", "-Wall", "-Wextra", "-Werror",
                "-I" + str(prefix / "include"), "-I" + str(functional / "generated"),
                "-I" + str(ROOT / "provider-tests"), ROOT / source, "-o", binary,
                "-L" + str(prefix / "lib"), "-Wl,-rpath," + str(prefix / "lib"), "-lcrypto", "-ldl", "-pthread", "-lm"])
    log = receipt.run("dudect-" + name, ["/usr/bin/taskset", "-c", args.cpu, binary,
                      functional / "modules", args.measurements], runtime, timeout=7200)
    summary = "\n".join(line for line in log.splitlines()
                        if line.startswith(("ed301_timing", "x301_timing", "P0 ", "T1 ", "T2 ", "T3 ", "T4 ", "T5 ")))
    (out / (name + "_SUMMARY.txt")).write_text(summary + "\n")
    if name + "_timing=PASS" not in log:
        raise SystemExit("dudect did not emit its explicit pass marker")
    print(summary, flush=True)
receipt.identity["load_after"] = Path("/proc/loadavg").read_text().strip()
verify_receipt(functional)
receipt.seal()
