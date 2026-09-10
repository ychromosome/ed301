#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Bind reviewed E1/E3 public counters and exponent provenance in linked ELFs.

Companion to check_codegen.sh, not a general taint engine or a universal CT
proof. The shell policy checks every conditional edge/call and arithmetic leaf;
this checker adds the operand origins behind the new fixed-base and pow paths.
"""

import argparse
from dataclasses import dataclass, replace
import hashlib
import json
from pathlib import Path
import re
import struct


def require(value, message):
    if not value:
        raise ValueError(message)


@dataclass(frozen=True)
class Instruction:
    address: int
    mnemonic: str
    operands: str
    comment: str

    @property
    def operation(self):
        return self.mnemonic + " " + self.operands


def canonical(name):
    return re.sub(r"^<(.*?)>::", r"\1::", name, count=1)


def parse(text):
    result = {}
    active = None
    for line in text.splitlines():
        header = re.fullmatch(r"\s*([0-9a-f]+) <(.+)>:", line)
        if header:
            active = []
            result.setdefault(canonical(header[2]), []).append(active)
            continue
        instruction = re.match(r"\s*([0-9a-f]+):\s+(\S+)(?:\s+(.*))?$", line)
        if instruction and active is not None:
            operands, _, comment = (instruction[3] or "").partition("#")
            active.append(Instruction(int(instruction[1], 16), instruction[2],
                                      operands.strip(), comment.strip()))
    return result


def single(symbols, name):
    instances = symbols.get(name, [])
    require(len(instances) == 1, "expected one symbol: " + name)
    return instances[0]


def register(name):
    name = name.strip()
    if re.fullmatch(r"%r1[2345][dwb]?", name):
        return name.rstrip("dwb")
    for base, aliases in {"rax": ("eax", "ax", "al", "ah"),
                          "rbx": ("ebx", "bx", "bl", "bh"),
                          "rcx": ("ecx", "cx", "cl", "ch"),
                          "rdx": ("edx", "dx", "dl", "dh"),
                          "rsi": ("esi", "si", "sil"),
                          "rdi": ("edi", "di", "dil")}.items():
        if name in ["%" + item for item in (base, *aliases)]:
            return "%" + base
    return name


def writes(item, target):
    if re.fullmatch(r"i?mul[qwl]?", item.mnemonic) and "," not in item.operands:
        return register(target) in ("%rax", "%rdx")
    if re.match(r"^(cmp|test|push|j|call|ret|nop|data16)", item.mnemonic):
        return False
    return register(item.operands.rsplit(",", 1)[-1]) == register(target)


def last_write(items, end, target):
    for index in range(end - 1, -1, -1):
        if writes(items[index], target):
            return index, items[index]
    raise ValueError("missing register origin: " + target)


def loop(items, branch_index):
    branch = items[branch_index]
    destination = int(branch.operands.split()[0], 16)
    starts = [i for i, item in enumerate(items) if item.address == destination]
    require(len(starts) == 1 and starts[0] < branch_index, "not a backward loop")
    return starts[0], items[starts[0]:branch_index]


def fixed_base(items):
    branches = [i for i, item in enumerate(items) if item.mnemonic == "jb"]
    require(len(branches) == 2, "fixed-base accumulation must have two loops")
    for branch, initial, row in zip(branches, ("$0xffffffffffffffff", "$0xfffffffffffffffe"),
                                    ("%r15", "%r12")):
        start, body = loop(items, branch)
        require(items[branch - 1].operation == "cmp $0x4a,%rbx", "fixed-base bound")
        require(last_write(items, start, "%rbx")[1].operation == "mov " + initial + ",%rbx",
                "fixed-base counter origin")
        require([item.operation for item in body if writes(item, "%rbx")] == ["add $0x2,%rbx"],
                "fixed-base counter update")
        require(last_write(items, start, row)[1].operation == "xor " + row + "d," + row + "d",
                "fixed-base public row origin")
        require([item.operation for item in body if writes(item, row)] == ["inc " + row],
                "fixed-base public row update")
        selections = [i for i in range(start, branch) if items[i].mnemonic == "call"
                      and "::edwards::select_basepoint>" in items[i].operands]
        require(len(selections) == 1, "one full table scan per public row")
        require(last_write(items, selections[0], "%rsi")[1].operation == "mov " + row + ",%rsi",
                "table row is not the public loop counter")
    # The two 76-byte wipe loops, normal and unwind, have public zero origins.
    wipes = [i for i, item in enumerate(items) if item.mnemonic == "jne" and i
             and items[i - 1].operation in ("cmp $0x4c,%rax", "cmp $0x4c,%rcx")]
    require(len(wipes) == 2, "both digit-owner wipe paths required")
    for branch in wipes:
        counter = items[branch - 1].operands.rsplit(",", 1)[-1]
        start, body = loop(items, branch)
        narrow = "%e" + counter[2:]
        require(last_write(items, start, counter)[1].operation == "xor " + narrow + "," + narrow,
                "wipe counter origin")
        require([item.operation for item in body if writes(item, counter)] == ["inc " + counter],
                "wipe counter update")
        stores = [item for item in body if item.mnemonic == "movb"]
        require(len(stores) == 1 and re.fullmatch(r"\$0x0,0x[0-9a-f]+\(%rsp,"
                + re.escape(counter) + r",1\)", stores[0].operands), "nonzero or non-linear wipe")
    return {"accumulation_rounds": [38, 38], "table_rows": [38, 38], "digit_wipes": [76, 76]}


def readonly_bytes(elf, address, count):
    require(elf[:6] == b"\x7fELF\x02\x01", "requires little-endian ELF64")
    section_offset = struct.unpack_from("<Q", elf, 40)[0]
    entry_size, section_count = struct.unpack_from("<HH", elf, 58)
    require(entry_size == 64 and section_count > 0, "unsupported ELF section table")
    require(section_offset + entry_size * section_count <= len(elf), "truncated ELF sections")
    for index in range(section_count):
        values = struct.unpack_from("<IIQQQQIIQQ", elf, section_offset + index * entry_size)
        _, kind, flags, base, offset, size, *_ = values
        if base <= address and address + count <= base + size:
            require(kind == 1 and flags & 2 and not flags & 1, "exponent is not allocated read-only data")
            start = offset + address - base
            require(start + count <= len(elf), "truncated exponent bytes")
            return elf[start:start + count]
    raise ValueError("exponent address outside read-only sections")


def rip_origin(items, before, target):
    index, item = last_write(items, before, target)
    if item.mnemonic == "mov":
        source = item.operands.split(",", 1)[0]
        require(source in ("%rbx", "%r12", "%r13", "%r14", "%r15"),
                "exponent copy does not come from a callee-saved constant pointer")
        return rip_origin(items, index, source)
    require(item.mnemonic == "lea" and "(%rip)," in item.operands, "exponent is not RIP-constant")
    found = re.match(r"([0-9a-f]+) ", item.comment)
    require(found is not None, "missing RIP constant target")
    return int(found[1], 16)


def exponent_sites(symbols, elf):
    name = "ed301_eddsa::field_5x64::Fe301::pow_fixed_window4"
    importer = "ed301_eddsa::signature::VerifyingKey::from_bytes"
    decoder = "ed301_eddsa::edwards::EdwardsPoint::decode"
    p = (1 << 301) - (1 << 89) + 907
    expected = {decoder: [(p - 3) // 4], importer: [(p + 1) // 4, (p - 1) // 2, (p - 1) // 2]}
    observed = {}
    sites = []
    for symbol, instances in symbols.items():
        for items in instances:
            calls = [i for i, item in enumerate(items) if item.mnemonic == "call"
                     and canonical(item.operands.split("<", 1)[-1].removesuffix(">")) == name]
            for index in calls:
                address = rip_origin(items, index, "%rdx")
                value = int.from_bytes(readonly_bytes(elf, address, 40), "little")
                observed.setdefault(symbol, []).append(value)
                sites.append({"caller": symbol, "call": hex(items[index].address),
                              "readonly_exponent": hex(address), "value": hex(value)})
            if symbol == importer:
                require(len(calls) == 3, "halving must execute sqrt and both Euler calls")
                require(not any(item.mnemonic.startswith("j") for item in items[calls[0]:calls[-1]]),
                        "early branch between halving exponentiations")
                first_later_branch = next(item for item in items[calls[-1] + 1:]
                                          if item.mnemonic.startswith("j"))
                require(first_later_branch.mnemonic == "je", "missing combined subgroup decision")
    require(observed == expected, "linked exponent call set or constant bytes differ")
    return sites


def pow_structure(items):
    operations = [item.operation for item in items]
    require(operations.count("mov %rdx,-0x10(%rsp)") == 1, "exponent pointer capture")
    require([item.operation for item in items if item.operands.endswith(",-0x10(%rsp)")]
            == ["mov %rdx,-0x10(%rsp)"], "exponent pointer slot overwritten")
    require([item.operation for item in items if item.operands.endswith(",-0x58(%rsp)")]
            == ["mov %rcx,-0x58(%rsp)", "mov %rdx,-0x58(%rsp)"], "public counter slots overwritten")
    require(operations.count("mov $0x48,%ecx") == 1 and operations.count("add $0x28,%rcx") == 1
            and operations.count("cmp $0x2a0,%rcx") == 1, "15-entry precomputation bounds")
    require(operations.count("mov $0x4a,%edx") == 1 and operations.count("mov $0x128,%esi") == 1,
            "75-window counter origin")
    origin = operations.index("mov $0x4a,%edx")
    require(operations[origin:origin + 6] == ["mov $0x4a,%edx", "mov $0x128,%esi",
            "xor %r14d,%r14d", "xor %r9d,%r9d", "xor %r10d,%r10d", "xor %r11d,%r11d"],
            "window counters overwritten before loop entry")
    entry = operations.index("mov %rsi,-0x48(%rsp)")
    require(items[origin + 6].mnemonic == "jmp"
            and int(items[origin + 6].operands.split()[0], 16) == items[entry].address
            and operations[entry + 1] == "mov %rdx,-0x58(%rsp)", "window counter initial edge")
    require(operations.count("add $0xffffffffffffffff,%rdx") == 2
            and operations.count("add $0xfffffffffffffffc,%rsi") == 2,
            "both zero/nonzero public digit paths must decrement identically")
    # All accesses with a scaled index are classified: ten precompute accesses,
    # one read of the public exponent, and five limbs at its public table digit.
    indexed = [item.operation for item in items if re.search(r"\([^)]*,[^)]*\)", item.operands)
               and not item.mnemonic.startswith("lea") and "nop" not in item.operation]
    expected = ["mov -0x38(%rsp,%rax,1),%rcx", "mov -0x30(%rsp,%rax,1),%r8",
                "mov -0x28(%rsp,%rax,1),%r8", "mov -0x20(%rsp,%rax,1),%r13",
                "mov -0x18(%rsp,%rax,1),%r8", "mov %rcx,-0x10(%rsp,%rsi,1)",
                "mov %r10,-0x8(%rsp,%rcx,1)", "mov %rax,(%rsp,%rcx,1)",
                "mov %rdx,0x8(%rsp,%rcx,1)", "mov %r14,0x10(%rsp,%rcx,1)",
                "mov (%rcx,%rax,8),%rax", "mov 0x10(%rsp,%rcx,8),%r14",
                "mov 0x18(%rsp,%rcx,8),%r12", "mov 0x20(%rsp,%rcx,8),%r8",
                "mov 0x28(%rsp,%rcx,8),%rdi", "mov 0x30(%rsp,%rcx,8),%rcx"]
    require(indexed == expected, "unclassified exponentiator indexed access")
    for operation in expected[:5]:
        index = operations.index(operation)
        require(last_write(items, index, "%rax")[1].operation == "mov -0x58(%rsp),%rax",
                "precomputation index does not come from fixed counter")
    index = operations.index("mov (%rcx,%rax,8),%rax")
    require(operations[index - 3:index] == ["mov %rdx,%rax", "shr $0x4,%rax",
                                           "mov -0x10(%rsp),%rcx"], "exponent limb index origin")
    require(operations[index + 1:index + 5] == ["mov %esi,%ecx", "and $0x3c,%cl",
                                               "shr %cl,%rax", "and $0xf,%rax"], "public digit extraction")
    require(items[index + 5].mnemonic == "je"
            and operations[index + 6] == "lea (%rax,%rax,4),%rcx", "public table index origin")
    require(last_write(items, index, "%rdx")[1].operation == "mov -0x58(%rsp),%rdx"
            and last_write(items, index, "%rsi")[1].operation == "mov -0x48(%rsp),%rsi",
            "digit counters do not come from the public loop state")
    zero_target = int(items[index + 5].operands.split()[0], 16)
    zero_index = next(i for i, item in enumerate(items) if item.address == zero_target)
    require(operations[zero_index:zero_index + 3] == ["mov %r13,%r14",
            "add $0xfffffffffffffffc,%rsi", "add $0xffffffffffffffff,%rdx"],
            "zero-digit loop update")
    require(items[zero_index + 3].mnemonic == "jae" and zero_index + 4 == entry,
            "zero-digit fixed-count edge")
    updates = [i for i, item in enumerate(items) if item.operation == "add $0xffffffffffffffff,%rdx"]
    nonzero_index = updates[-1]
    require(last_write(items, nonzero_index, "%rdx")[1].operation == "mov -0x58(%rsp),%rdx",
            "nonzero-digit counter origin")
    require(items[nonzero_index + 1].mnemonic == "jb"
            and int(items[nonzero_index + 1].operands.split()[0], 16) == items[entry].address,
            "nonzero-digit fixed-count edge")
    return {"precomputed_powers": 15, "windows": 75, "indexed_accesses": len(indexed)}


def rejects(action, label):
    try:
        action()
    except ValueError:
        return label
    raise ValueError("negative control accepted: " + label)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profile", choices=("ed", "x"), required=True)
    parser.add_argument("--elf", type=Path, required=True)
    parser.add_argument("--evidence", type=Path, required=True)
    args = parser.parse_args()
    symbols = parse((args.evidence / "core.objdump").read_text())
    name = ("ed301_eddsa::edwards::EdwardsPoint::scalar_mul_base_encoded" if args.profile == "ed"
            else "x301_core::x301::SecretKey::public_key")
    fixed = single(symbols, name)
    result = {"fixed_base": fixed_base(fixed), "negative_controls": []}
    bad_fixed = [replace(item, operands="$0xfffffffffffffffd,%rbx")
                 if item.operation == "mov $0xffffffffffffffff,%rbx" else item for item in fixed]
    result["negative_controls"].append(rejects(lambda: fixed_base(bad_fixed), "wrong-fixed-base-origin"))
    if args.profile == "ed":
        power = single(symbols, "ed301_eddsa::field_5x64::Fe301::pow_fixed_window4")
        result["pow"] = pow_structure(power)
        elf = args.elf.read_bytes()
        result["exponents"] = exponent_sites(symbols, elf)
        bad_power = [replace(item, operands="$0x49,%edx") if item.operation == "mov $0x4a,%edx"
                     else item for item in power]
        result["negative_controls"].append(rejects(lambda: pow_structure(bad_power), "shortened-pow-counter"))
        # Corrupt only the in-memory test copy; the measured ELF stays untouched.
        exponent = bytes.fromhex(result["exponents"][0]["value"][2:].zfill(80))[::-1]
        require(elf.count(exponent) == 1, "ambiguous exponent negative-control bytes")
        bad_elf = elf.replace(exponent, bytes([exponent[0] ^ 1]) + exponent[1:], 1)
        result["negative_controls"].append(rejects(lambda: exponent_sites(symbols, bad_elf), "wrong-readonly-exponent"))
        importer = "ed301_eddsa::signature::VerifyingKey::from_bytes"
        body = single(symbols, importer)
        first_power = next(i for i, item in enumerate(body) if item.mnemonic == "call"
                           and "::pow_fixed_window4>" in item.operands)
        mutated = list(body)
        mutated[first_power + 1] = replace(mutated[first_power + 1], mnemonic="je", operands="0")
        bad_symbols = dict(symbols, **{importer: [mutated]})
        result["negative_controls"].append(rejects(lambda: exponent_sites(bad_symbols, elf), "early-symbol-exit"))
    result["elf_sha256"] = hashlib.sha256(args.elf.read_bytes()).hexdigest()
    result["checker_sha256"] = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    destination = args.evidence / "dataflow.json"
    require(not destination.exists(), "dataflow evidence already exists")
    destination.write_text(json.dumps(result, indent=2) + "\n")
    print("PASS phase_e_dataflow=" + args.profile + " controls=" + str(len(result["negative_controls"])))


if __name__ == "__main__":
    main()
