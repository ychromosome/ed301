#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Generate the assigned v2 identifier containers with OpenSSL ASN.1 APIs."""

import argparse
import hashlib
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[3]
DECISION = ROOT / "phase-d/d2/inputs/D1_BEWERTUNG_UND_D2_ENTSCHEIDUNGEN_2026-09-10.md"
DECISION_SHA256 = "c5c18ad17baa32718cb6d5d3805d206334800facfa26896ae08b49766f04e0c7"
PROFILES = {
    "ed301": ("ED301V2", "1.3.6.1.4.1.66282.301.5"),
    "x301": ("X301V2", "1.3.6.1.4.1.66282.301.6"),
}


def generate(profile):
    if hashlib.sha256(DECISION.read_bytes()).hexdigest() != DECISION_SHA256:
        raise SystemExit("decision input is not the approved D2 revision")
    prefix, oid = PROFILES[profile]
    zero_key = "00" * 38
    configurations = {
        "oid": f"asn1=OID:{oid}\n",
        "algorithm": "asn1=SEQUENCE:algorithm\n",
        "spki": "asn1=SEQUENCE:spki\n[spki]\nalgorithm=SEQUENCE:algorithm\n"
                f"public=FORMAT:HEX,BITSTRING:{zero_key}\n",
        "pkcs8": "asn1=SEQUENCE:private\n[private]\nversion=INTEGER:0\n"
                 "algorithm=SEQUENCE:algorithm\n"
                 f"private=OCTWRAP,FORMAT:HEX,OCTETSTRING:{zero_key}\n",
    }
    encoded = {}
    with tempfile.TemporaryDirectory(prefix="ed301-v2-profile-") as directory:
        work = Path(directory)
        for name, config in configurations.items():
            config += f"[algorithm]\noid=OID:{oid}\n"
            conf = work / f"{name}.cnf"
            der = work / f"{name}.der"
            conf.write_text(config, encoding="ascii")
            subprocess.run(["/usr/bin/openssl", "asn1parse", "-genconf", str(conf),
                            "-out", str(der), "-noout"], check=True,
                           env={"PATH": "/usr/bin:/bin", "HOME": directory,
                                "LC_ALL": "C", "OPENSSL_CONF": "/dev/null"})
            encoded[name] = der.read_bytes()
    if (len(encoded["oid"]), len(encoded["algorithm"]), len(encoded["spki"]),
            len(encoded["pkcs8"])) != (13, 15, 58, 62):
        raise SystemExit("assigned OIDs have unexpected OpenSSL-generated container lengths")
    if encoded["spki"][-38:] != bytes(38) or encoded["pkcs8"][-38:] != bytes(38):
        raise SystemExit("OpenSSL did not encode the exact fixed-width key payload")
    if encoded["algorithm"][2:] != encoded["oid"]:
        raise SystemExit("AlgorithmIdentifier parameters must be absent")
    lines = ["/* Generated with OpenSSL ASN.1 generation; do not edit. */",
             f"/* Decision SHA-256: {DECISION_SHA256} */",
             f"#ifndef {prefix}_GENERATED_PROFILE_H", f"#define {prefix}_GENERATED_PROFILE_H",
             "#include <stddef.h>", f'#define {prefix}_OID_TEXT "{oid}"']
    if profile == "ed301":
        lines.append("#define ED301V2_TLS_SIGALG_CODE_POINT ((unsigned int)0xfe85)")
    else:
        lines.extend(["#define X301V2_TLS_HYBRID_GROUP_ID ((unsigned int)0xfe2f)",
                      "#define X301V2_TLS_RAW_GROUP_ID ((unsigned int)0xfe30)"])
    for name, data in (("ALGORITHM_ID_DER", encoded["algorithm"]),
                       ("SPKI_PREFIX", encoded["spki"][:-38]),
                       ("PKCS8_PREFIX", encoded["pkcs8"][:-38])):
        lines.append(f"static const unsigned char {prefix}_{name}[] = {{")
        for offset in range(0, len(data), 12):
            lines.append("    " + ", ".join(f"0x{x:02x}" for x in data[offset:offset + 12]) + ",")
        lines.append("};")
    lines.extend([f"#define {prefix}_OID_TLV_BYTES ((size_t){len(encoded['oid'])})",
                  f"#define {prefix}_MAX_ENCODED_KEY_BYTES {len(encoded['pkcs8'])}",
                  "#endif", ""])
    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("profile", choices=PROFILES)
    parser.add_argument("--check", type=Path)
    args = parser.parse_args()
    output = generate(args.profile)
    if args.check:
        if args.check.read_text() != output:
            raise SystemExit(f"generated profile differs: {args.check}")
        print(f"PASS: {args.profile} identifier containers")
    else:
        print(output, end="")


if __name__ == "__main__":
    main()
