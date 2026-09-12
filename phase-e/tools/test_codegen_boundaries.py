#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Inert parser fixtures for transfer closure, zero writes and owner pointers."""

from dataclasses import replace
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent))
from check_codegen_dataflow import BYTE_ZEROIZER, Instruction, byte_zeroizer, parse, x_key_drop_owners

TOOLS = Path(__file__).resolve().parent


class Transfers(unittest.TestCase):
    def scan(self, body, mode="sequence", policy="", got=""):
        with tempfile.TemporaryDirectory(prefix="ed301-transfer-parser-") as directory:
            root = Path(directory)
            (root / "got").write_text(got)
            (root / "body").write_text(body)
            return subprocess.run(["/usr/bin/awk", "-v", "mode=" + mode, "-v", "policy=" + policy,
                "-f", str(TOOLS / "codegen_transfers.awk"), str(root / "got"), str(root / "body")],
                text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10)

    def test_internal_forward_and_backward_edges(self):
        body = "10 <f>:\n10: jmp 20 <f+0x10>\n20: jmp 10 <f>\n"
        self.assertEqual(self.scan(body).stdout, "")
        self.assertEqual(self.scan(body, "closure", "^$").returncode, 0)

    def test_direct_calls_and_external_tails_share_policy(self):
        for instruction in ("call", "callq", "jmp", "jmpq"):
            body = f"10 <f>:\n10: {instruction} 80 <helper>\n"
            with self.subTest(instruction=instruction):
                self.assertEqual(self.scan(body).stdout, "helper\n")
                self.assertEqual(self.scan(body, "closure", "helper").returncode, 0)
                self.assertEqual(self.scan(body, "closure", "other").returncode, 1)
                self.assertEqual(self.scan(body, "contains", "helper").returncode, 0)

    def test_external_numeric_target_not_disguised_by_local_name(self):
        for target in ("11 <f+0x1>", "80 <f+0x70>", "80 <helper_vartime>"):
            with self.subTest(target=target):
                result = self.scan("10 <f>:\n10: jmp " + target + "\n20: ret\n", "closure", "helper")
                self.assertEqual(result.returncode, 1)

    def test_relative_got_tails(self):
        body = "10 <f>:\n10: jmp *0x20(%rip) # 80 <GOT+0x10>\n"
        self.assertEqual(self.scan(body, got="80\thelper\n").stdout, "helper\n")
        self.assertEqual(self.scan(body, "closure", "helper", "80\thelper\n").returncode, 0)
        self.assertEqual(self.scan(body, "closure", "helper").returncode, 1)

    def test_unknown_indirect_tails_fail_closed(self):
        for target in ("*%rax", "*0x10(%rbx)", "80"):
            body = "10 <f>:\n10: jmp " + target + "\n"
            with self.subTest(target=target):
                self.assertEqual(self.scan(body, "closure", ".*").returncode, 1)
                self.assertEqual(self.scan(body, "contains", "optional_helper").returncode, 1)

    def test_memcpy_register_tail_and_clobbers(self):
        load = "10 <f>:\n10: mov 0x20(%rip),%r15 # 80 <memcpy@GLIBC_2.14>\n"
        tail = "30: jmp *%r15\n"
        self.assertEqual(self.scan(load + tail).stdout, "memcpy\n")
        for clobber in ("xor %r15d,%r15d", "pop %r15", "xchg %r15,%rax"):
            with self.subTest(clobber=clobber):
                self.assertEqual(self.scan(load + "20: " + clobber + "\n" + tail,
                                           "closure", "memcpy").returncode, 1)

    def test_instances_do_not_share_addresses_or_register_origins(self):
        body = "10 <f>:\n10: jmp 80 <f>\n80 <f>:\n80: ret\n"
        self.assertEqual(self.scan(body).stdout, "f\n")
        body = ("10 <f>:\n10: mov 0x20(%rip),%r15 # 90 <memcpy@GLIBC_2.14>\n20: ret\n"
                "80 <f>:\n80: jmp *%r15\n")
        self.assertEqual(self.scan(body, "closure", "memcpy").returncode, 1)

    def test_skipped_or_conditional_pointer_origin(self):
        for edge in ("jmp", "jne"):
            body = (f"10 <f>:\n10: {edge} 30 <f+0x20>\n"
                    "20: mov 0x20(%rip),%r15 # 80 <memcpy@GLIBC_2.14>\n30: jmp *%r15\n")
            with self.subTest(edge=edge):
                self.assertEqual(self.scan(body, "closure", "memcpy").returncode, 1)

    def test_loop_and_both_branch_origins(self):
        body = ("10 <f>:\n10: mov 0x20(%rip),%r15 # 80 <memcpy@GLIBC_2.14>\n"
                "20: call *%r15\n30: jne 20 <f+0x10>\n40: jmp *%r15\n")
        self.assertEqual(self.scan(body).stdout, "memcpy\nmemcpy\n")
        body = ("10 <f>:\n10: jne 40 <f+0x30>\n"
                "20: mov 0x20(%rip),%r15 # 80 <memcpy@GLIBC_2.14>\n30: jmp 50 <f+0x40>\n"
                "40: mov 0x20(%rip),%r15 # 80 <memcpy@GLIBC_2.14>\n50: jmp *%r15\n")
        self.assertEqual(self.scan(body).stdout, "memcpy\n")
        self.assertEqual(self.scan(body.replace("40: mov", "40: xor"), "closure", "memcpy").returncode, 1)

    def test_partial_width_and_address_loads_are_not_pointer_origins(self):
        for operation in ("mov 0x20(%rip),%r15d", "mov 0x20(%rip),%r15w", "mov 0x20(%rip),%r15b",
                          "movl 0x20(%rip),%r15d", "lea 0x20(%rip),%r15"):
            body = "10 <f>:\n10: " + operation + " # 80 <memcpy@GLIBC_2.14>\n20: jmp *%r15\n"
            with self.subTest(operation=operation):
                self.assertEqual(self.scan(body, "closure", "memcpy").returncode, 1)

    def test_legacy_and_v0_symbols_match(self):
        body = "10 <f>:\n10: jmp 80 <<Type>::method>\n"
        self.assertEqual(self.scan(body).stdout, "Type::method\n")


class Wipes(unittest.TestCase):
    def fixture(self):
        return [Instruction(i, "movb", f"$0x0,0x{i:x}(%rdi)", "") for i in range(38)] + [
            Instruction(38, "add", "$0x25,%rdi", ""), Instruction(39, "ret", "", "")]

    def test_complete_owner_and_padding(self):
        body = self.fixture()
        body.insert(1, Instruction(40, "lea", "0x1(%rdi),%rax", ""))
        body.append(Instruction(41, "int3", "", ""))
        self.assertEqual(byte_zeroizer(body)["zero_bytes"], 38)

    def test_incomplete_or_duplicate_byte(self):
        body = self.fixture()
        for altered in (body[1:], [body[0], *body[2:]], [body[0], body[0], *body[2:]]):
            with self.assertRaises(ValueError):
                byte_zeroizer(altered)

    def test_store_values_addresses_and_widths(self):
        for operation in ("movb $0x1,0x0(%rdi)", "movb $0x0,0x26(%rdi)",
                          "movb $0x0,-0x1(%rdi)", "movb $0x0,0x0(%rax)",
                          "movw $0x0,0x0(%rdi)", "movb $0x0,(%rdi,%rax,1)"):
            with self.subTest(operation=operation), self.assertRaises(ValueError):
                mnemonic, operands = operation.split(" ", 1)
                byte_zeroizer([Instruction(0, mnemonic, operands, ""), *self.fixture()[1:]])

    def test_early_pointer_changes_or_early_return(self):
        for operation in ("add $0x25,%rdi", "lea 0x1(%rdi),%rdi", "mov %rax,%rdi", "ret "):
            with self.subTest(operation=operation), self.assertRaises(ValueError):
                mnemonic, operands = operation.split(" ", 1)
                byte_zeroizer([Instruction(0, mnemonic, operands, ""), *self.fixture()])

    def drop_fixture(self):
        lines = ["push %r14", "push %rbx", "push %rax", "mov %rdi,%rbx",
                 "call 80 <" + BYTE_ZEROIZER + ">", "add $0x26,%rbx", "mov %rbx,%rdi",
                 "add $0x8,%rsp", "pop %rbx", "pop %r14", "jmp 80 <" + BYTE_ZEROIZER + ">",
                 "mov %rax,%r14", "add $0x26,%rbx", "mov %rbx,%rdi",
                 "call 80 <" + BYTE_ZEROIZER + ">", "mov %r14,%rdi",
                 "call 90 <_Unwind_Resume@plt>", "call *0x20(%rip)"]
        return parse("0 <drop>:\n" + "\n".join(f"{i:x}: {line}" for i, line in enumerate(lines)))["drop"][0]

    def test_normal_and_landing_pad_owners(self):
        result = x_key_drop_owners(self.drop_fixture(), {0x80})
        self.assertEqual(result["first_owner_offset"], 0)
        self.assertEqual(result["normal_second_owner_offset"], 38)
        self.assertEqual(result["landing_pad_second_owner_offset"], 38)

    def test_both_second_owner_offsets_are_bound(self):
        for index in (5, 12):
            with self.subTest(index=index), self.assertRaises(ValueError):
                body = self.drop_fixture()
                body[index] = replace(body[index], operands="$0x25,%rbx")
                x_key_drop_owners(body, {0x80})

    def test_original_pointer_and_wipe_entry_are_bound(self):
        body = self.drop_fixture()
        with self.assertRaises(ValueError):
            x_key_drop_owners(body, {0x81})
        body[3] = replace(body[3], operands="%rax,%rbx")
        with self.assertRaises(ValueError):
            x_key_drop_owners(body, {0x80})


if __name__ == "__main__":
    unittest.main()
