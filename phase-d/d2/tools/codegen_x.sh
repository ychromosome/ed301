# Byte zeroizers and the safegcd arithmetic leaf remain straight-line.
check_all_branch_free byte_zeroize \
    'core::ptr::drop_glue::<zeroize::Zeroizing<[u8; 38]>>' 2
check_branch_free safegcd_lincomb \
    '<crypto_bigint::modular::safegcd::SignedInt<5>>::lincomb_int::<1>' \
    0 0 no '^$' allow
extract_symbol 'x301_core::x301::ladder301' "$EVIDENCE/ladder.asm"
check_exact_call_graph ladder "$EVIDENCE/ladder.asm" 'memcpy'

# One backward carry edge visits public counter values 300 through 0.
# Scalar indexing, spill/reload and counter origin are tied to this lowering.
extract_full_ladder_loop() {
    /usr/bin/gawk '
    /^[[:space:]]*[[:xdigit:]]+:/ {
        address = $1
        sub(/:$/, "", address)
        if ($2 ~ /^j/) {
            branches++
            if ($2 == "jb" && strtonum("0x" $3) < strtonum("0x" address)) {
                first = strtonum("0x" $3)
                last = strtonum("0x" address)
                if (previous != "add $0xffffffffffffffff,%rcx")
                    exit 1
            }
        }
        if ($2 !~ /nop/ && $0 !~ /nop/)
            previous = $2 " " $3
    }
    { line[NR] = $0 }
    END {
        if (branches != 1 || !first || !last)
            exit 1
        initialized = 0
        last_pre_counter_write = ""
        last_loop_counter_write = ""
        penultimate_loop_counter_write = ""
        for (i = 1; i <= NR; i++) {
            split(line[i], p, /[[:space:]]+/)
            if (p[2] ~ /^[[:xdigit:]]+:$/) {
                a = p[2]; sub(/:$/, "", a); a = strtonum("0x" a)
                if (a < first && p[3] == "mov" && p[4] == "$0x12c,%ecx")
                    initialized++
                operands = split(p[4], operand, ",")
                writes_counter = (operand[operands] == "%ecx" || operand[operands] == "%rcx") &&
                    p[3] !~ /^(cmp|test|push|j|call|ret|nop)/
                if (writes_counter && a < first)
                    last_pre_counter_write = p[3] " " p[4]
                if (writes_counter && a >= first && a <= last) {
                    penultimate_loop_counter_write = last_loop_counter_write
                    last_loop_counter_write = p[3] " " p[4]
                }
                if (a >= first && a <= last)
                    print line[i]
            }
        }
        if (initialized != 1 || last_pre_counter_write != "mov $0x12c,%ecx" ||
            penultimate_loop_counter_write != "mov 0x200(%rsp),%rcx" ||
            last_loop_counter_write != "add $0xffffffffffffffff,%rcx")
            exit 1
    }' "$1" >"$2"
}
extract_full_ladder_loop "$EVIDENCE/ladder.asm" "$EVIDENCE/ladder-loop.asm"
LOOP=$EVIDENCE/ladder-loop.asm
test -s "$LOOP"
/usr/bin/grep -Eq 'mov[[:space:]]+%rcx,0x200\(%rsp\)$' "$LOOP"
/usr/bin/grep -Eq 'mov[[:space:]]+0x200\(%rsp\),%rcx$' "$LOOP"
/usr/bin/grep -Eq 'shr[[:space:]]+\$0x3,%rcx$' "$LOOP"
/usr/bin/grep -Eq 'mov[[:space:]]+0x308\(%rsp\),%rdx$' "$LOOP"
/usr/bin/grep -Eq 'and[[:space:]]+\$0x7,%edx$' "$LOOP"
/usr/bin/grep -Eq 'bt[[:space:]]+%edx,%ecx$' "$LOOP"
test "$(/usr/bin/grep -Ec ',0x200\(%rsp\)$' "$LOOP")" -eq 1
/usr/bin/awk '
    /^[[:space:]]*[[:xdigit:]]+:/ && $0 ~ /\([^)]*,[^)]*\)/ &&
    $2 !~ /^lea/ && index($0, "nop") == 0 { print }
' "$LOOP" >"$EVIDENCE/ladder-indexed-memory.txt"
test "$(/usr/bin/awk 'END { print NR+0 }' "$EVIDENCE/ladder-indexed-memory.txt")" -eq 1
/usr/bin/grep -Eq 'movzbl[[:space:]]+\(%rdx,%rcx,1\),%ecx$' "$EVIDENCE/ladder-indexed-memory.txt"
test "$(count_mnemonic '^cmov' "$LOOP")" -ge 20
test "$(count_mnemonic '^call' "$LOOP")" -eq 0
if contains_forbidden_instruction "$LOOP" allow-conditional; then
    echo 'FAIL trap or division in ladder loop' >&2
    exit 1
fi
/usr/bin/sed 's/\$0x12c,%ecx/\$0x12d,%ecx/' "$EVIDENCE/ladder.asm" >"$EVIDENCE/bad-counter.asm"
if (extract_full_ladder_loop "$EVIDENCE/bad-counter.asm" "$EVIDENCE/bad-counter-loop.asm") >/dev/null 2>&1; then
    echo 'FAIL accepted wrong ladder counter' >&2
    exit 1
fi
# An earlier unrelated 300 constant cannot legitimize an overwritten counter.
{ printf '   0: mov $0x12c,%%ecx\n'; /usr/bin/cat "$EVIDENCE/bad-counter.asm"; } \
    >"$EVIDENCE/decoy-counter.asm"
if (extract_full_ladder_loop "$EVIDENCE/decoy-counter.asm" "$EVIDENCE/decoy-counter-loop.asm") >/dev/null 2>&1; then
    echo 'FAIL accepted decoy counter initialization' >&2
    exit 1
fi
printf 'PASS ladder rounds=301 counter=300-to-0 indexed_scalar_reads=1 loop_calls=0 cmov=%s\n' \
    "$(count_mnemonic '^cmov' "$LOOP")" | tee -a "$SUMMARY"

# Inversion is inlined here: two fixed GCD loop edges, then the published
# all-zero status boundary. Not every API-boundary branch is branch-free.
check_expected_branches multiply 'x301_core::x301::multiply' \
    'dec %edx|jne
sub 0x10(%rsp),%ecx|jne
cmpb $0x0,0x20(%rsp)|je'
/usr/bin/gawk '
    /^[[:space:]]*[[:xdigit:]]+:/ && $2 ~ /^j/ && $2 !~ /^jmp/ {
        a=$1; sub(/:$/,"",a); n++
        backwards = strtonum("0x" $3) < strtonum("0x" a)
        if ((n <= 2 && !backwards) || (n == 3 && backwards)) bad=1
    }
    END { exit (bad || n != 3) ? 1 : 0 }
' "$EVIDENCE/multiply.asm"
check_exact_call_graph multiply "$EVIDENCE/multiply.asm" \
    'x301_core::x301::ladder301
<crypto_bigint::modular::safegcd::SignedInt<5>>::lincomb_int_reduce_shift::<1>
<crypto_bigint::modular::safegcd::SignedInt<5>>::lincomb_int_reduce_shift::<1>
<crypto_bigint::modular::safegcd::SignedInt<5>>::lincomb_int_reduce_shift_mod::<1>
<crypto_bigint::modular::safegcd::SignedInt<5>>::lincomb_int_reduce_shift_mod::<1>
core::ptr::drop_glue::<zeroize::Zeroizing<[u8; 38]>>
_Unwind_Resume@plt'

# The provider uses D1's object API; the one-shot benchmark wrappers are
# not linked. Inspect the actual secret import and the one linked key drop.
extract_symbol '<x301_core::x301::SecretKey>::from_bytes' "$EVIDENCE/secret_import.asm"
if contains_forbidden_instruction "$EVIDENCE/secret_import.asm" allow-conditional-terminal-call; then
    echo 'FAIL forbidden instruction in SecretKey import' >&2
    exit 1
fi
check_exact_call_graph secret_import "$EVIDENCE/secret_import.asm" \
    'core::ptr::drop_glue::<zeroize::Zeroizing<[u8; 38]>>'
extract_symbol 'core::ptr::drop_glue::<x301_core::x301::SecretKey>' "$EVIDENCE/key_drop.asm"
if contains_forbidden_instruction "$EVIDENCE/key_drop.asm" allow-terminal-call; then
    echo 'FAIL conditional control flow in key drop' >&2
    exit 1
fi
check_exact_call_graph key_drop "$EVIDENCE/key_drop.asm" \
    'core::ptr::drop_glue::<zeroize::Zeroizing<[u8; 38]>>
core::ptr::drop_glue::<zeroize::Zeroizing<[u8; 38]>>
_Unwind_Resume@plt
core::panicking::panic_in_cleanup'
test "$(/usr/bin/awk '/^[[:space:]]*[[:xdigit:]]+:/ && $2 ~ /^jmp/ { n++; if ($0 !~ /<core::ptr::drop_glue::<zeroize::Zeroizing<\[u8; 38\]>>>$/) bad=1 } END { print (bad || n != 1) ? 0 : 1 }' "$EVIDENCE/key_drop.asm")" -eq 1
printf 'PASS key_drop raw_and_clamped_owners=1 linked_instances=1\n' | tee -a "$SUMMARY"

check_expected_branches safegcd_shift \
    '<crypto_bigint::modular::safegcd::SignedInt<5>>::lincomb_int_reduce_shift::<1>' \
    'cmp $0x40,%eax|jae
cmp $0x40,%ebp|jae
test %ebp,%ebp|je' '' allow-terminal-call
check_expected_branches safegcd_shift_mod \
    '<crypto_bigint::modular::safegcd::SignedInt<5>>::lincomb_int_reduce_shift_mod::<1>' \
    'cmp $0x40,%edi|jae
cmp $0x40,%ebp|je
je TARGET|jae
mov %ebp,0xc(%rsp)|je' \
    'cmp $0x40,%r11d|jae
cmp $0x40,%ebp|je
je TARGET|jae
test %ebp,%ebp|je' allow-terminal-call

check_exact_call_graph safegcd_shift "$EVIDENCE/safegcd_shift.asm" \
    '<crypto_bigint::modular::safegcd::SignedInt<5>>::lincomb_int::<1>
core::option::expect_failed
core::option::expect_failed
core::panicking::panic_bounds_check'
check_exact_call_graph safegcd_shift_mod "$EVIDENCE/safegcd_shift_mod.asm" \
    '<crypto_bigint::modular::safegcd::SignedInt<5>>::lincomb_int::<1>
core::option::expect_failed
core::panicking::panic_bounds_check'

CALL_ANCHOR=ladder
PUBLIC_CONTROL=x301_key_import
