#!/usr/bin/env python3
"""Check current contract identifiers and portable local documentation links."""
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[1]
FILES = ("README.md", "specifications/CURRENT_PROFILE.md", "docs/INTEGRATION.md",
         "docs/OID_REGISTRY.md", "docs/DEPENDENCIES.md", "rust/THIRD_PARTY_NOTICES.md",
         "phase-e/README.md")
profile = (ROOT / FILES[1]).read_text()
count = 0
for algorithm in ("ed301", "x301"):
    header = (ROOT / f"provider/common/generated_{algorithm}_profile.h").read_text()
    oid = re.search(r'#define \w+_OID_TEXT "([0-9.]+)"', header).group(1)
    assert f"`{oid}`" in profile, oid
    for code in re.findall(r'#define \w+(?:CODE_POINT|GROUP_ID) \(\(unsigned int\)(0x[0-9a-f]+)\)', header):
        assert f"`0x{int(code, 16):04X}`" in profile, code
        count += 1
    count += 1
links = 0
for filename in FILES:
    path = ROOT / filename
    text = path.read_text()
    assert "/home/" not in text, filename
    assert text.count("```") % 2 == 0, filename
    for target in re.findall(r'\]\(([^\s)]+)\)', text):
        if target.startswith(("https://", "http://")):
            continue
        assert not target.startswith("/"), (filename, target)
        assert (path.parent / target.split("#")[0]).exists(), (filename, target)
        links += 1
print(f"current contract: PASS; {count} generated identifiers, {links} local links")
