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
                if (previous != "add $0xffffffffffffffff,%rax")
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
                if (a < first && p[3] == "mov" && p[4] == "$0x12c,%eax")
                    initialized++
                operands = split(p[4], operand, ",")
                writes_counter = (operand[operands] == "%eax" || operand[operands] == "%rax") &&
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
        if (initialized != 1 || last_pre_counter_write != "mov $0x12c,%eax" ||
            penultimate_loop_counter_write != "mov 0xf8(%rsp),%rax" ||
            last_loop_counter_write != "add $0xffffffffffffffff,%rax")
            exit 1
    }' "$1" >"$2"
}
extract_full_ladder_loop "$EVIDENCE/ladder.asm" "$EVIDENCE/ladder-loop.asm"
LOOP=$EVIDENCE/ladder-loop.asm
test -s "$LOOP"
/usr/bin/grep -Eq 'mov[[:space:]]+%rax,0xf8\(%rsp\)$' "$LOOP"
/usr/bin/grep -Eq 'mov[[:space:]]+0xf8\(%rsp\),%rax$' "$LOOP"
/usr/bin/grep -Eq 'shr[[:space:]]+\$0x3,%rax$' "$LOOP"
/usr/bin/grep -Eq 'mov[[:space:]]+0x1e8\(%rsp\),%rcx$' "$LOOP"
/usr/bin/grep -Eq 'and[[:space:]]+\$0x7,%ecx$' "$LOOP"
/usr/bin/grep -Eq 'bt[[:space:]]+%ecx,%eax$' "$LOOP"
test "$(/usr/bin/grep -Ec ',0xf8\(%rsp\)$' "$LOOP")" -eq 1
/usr/bin/awk '
    /^[[:space:]]*[[:xdigit:]]+:/ && $0 ~ /\([^)]*,[^)]*\)/ &&
    $2 !~ /^lea/ && index($0, "nop") == 0 { print }
' "$LOOP" >"$EVIDENCE/ladder-indexed-memory.txt"
test "$(/usr/bin/awk 'END { print NR+0 }' "$EVIDENCE/ladder-indexed-memory.txt")" -eq 1
/usr/bin/grep -Eq 'movzbl[[:space:]]+\(%rcx,%rax,1\),%eax$' "$EVIDENCE/ladder-indexed-memory.txt"
test "$(count_mnemonic '^cmov' "$LOOP")" -ge 20
test "$(count_mnemonic '^call' "$LOOP")" -eq 0
if contains_forbidden_instruction "$LOOP" allow-conditional; then
    echo 'FAIL trap or division in ladder loop' >&2
    exit 1
fi
/usr/bin/sed 's/\$0x12c,%eax/\$0x12d,%eax/' "$EVIDENCE/ladder.asm" >"$EVIDENCE/bad-counter.asm"
if (extract_full_ladder_loop "$EVIDENCE/bad-counter.asm" "$EVIDENCE/bad-counter-loop.asm") >/dev/null 2>&1; then
    echo 'FAIL accepted wrong ladder counter' >&2
    exit 1
fi
# An earlier unrelated 300 constant cannot legitimize an overwritten counter.
{ printf '   0: mov $0x12c,%%eax\n'; /usr/bin/cat "$EVIDENCE/bad-counter.asm"; } \
    >"$EVIDENCE/decoy-counter.asm"
if (extract_full_ladder_loop "$EVIDENCE/decoy-counter.asm" "$EVIDENCE/decoy-counter-loop.asm") >/dev/null 2>&1; then
    echo 'FAIL accepted decoy counter initialization' >&2
    exit 1
fi
printf 'PASS ladder rounds=301 counter=300-to-0 indexed_scalar_reads=1 loop_calls=0 cmov=%s\n' \
    "$(count_mnemonic '^cmov' "$LOOP")" | tee -a "$SUMMARY"
if contains_forbidden_instruction "$EVIDENCE/ladder.asm" allow-conditional; then
    echo 'FAIL trap or division in ladder finalization' >&2
    exit 1
fi

# E1 links the same Edwards fixed-base leaves under the X301 crate identity.
# The negation has been inlined into select_basepoint: preserve its original
# borrow/select minima there in addition to the no-secret-index policy.
check_branch_free point_double \
    '<x301_core::edwards::EdwardsPoint>::double' 20 35 no '^$' allow
check_branch_free point_add_affine \
    '<x301_core::edwards::EdwardsPoint>::add_affine' 20 30 no '^$' allow
check_branch_free affine_select \
    '<x301_core::edwards::AffineNielsPoint>::conditional_select' 0 16 no '^$' reject
check_branch_free basepoint_select \
    'x301_core::edwards::select_basepoint' 8 10 no unrestricted reject
check_exact_call_graph basepoint_select "$EVIDENCE/basepoint_select.asm" \
    '<x301_core::edwards::AffineNielsPoint>::conditional_select
memcpy
<x301_core::edwards::AffineNielsPoint>::conditional_select
memcpy
<x301_core::edwards::AffineNielsPoint>::conditional_select
memcpy
<x301_core::edwards::AffineNielsPoint>::conditional_select
memcpy
<x301_core::edwards::AffineNielsPoint>::conditional_select
memcpy
<x301_core::edwards::AffineNielsPoint>::conditional_select
memcpy
<x301_core::edwards::AffineNielsPoint>::conditional_select
memcpy
<x301_core::edwards::AffineNielsPoint>::conditional_select
memcpy
<x301_core::edwards::AffineNielsPoint>::conditional_select'

# Five fixed recoding/accumulation/wipe branches precede finalization. The
# next three branches consume the published status/canonical public output;
# the last loop wipes digits on unwinding. Full dataflow is bound separately.
check_expected_branches fixed_base_public '<x301_core::x301::SecretKey>::public_key' \
    'cmp $0x4d,%rax|jne
cmp $0x4c,%rax|je
cmp $0x4a,%rbx|jb
cmp $0x4a,%rbx|jb
cmp $0x4c,%rax|jne
cmpb $0x1,0x239(%rsp)|jne
cmp %rbp,%rdi|jbe
or %r8b,%bl|je
cmp $0x4c,%rcx|jne'
check_exact_call_graph fixed_base_public "$EVIDENCE/fixed_base_public.asm" \
    'memcpy
memcpy
x301_core::edwards::select_basepoint
<x301_core::edwards::EdwardsPoint>::add_affine
memcpy
memcpy
<x301_core::edwards::EdwardsPoint>::double
<x301_core::edwards::EdwardsPoint>::double
<x301_core::edwards::EdwardsPoint>::double
<x301_core::edwards::EdwardsPoint>::double
memcpy
memcpy
x301_core::edwards::select_basepoint
<x301_core::edwards::EdwardsPoint>::add_affine
memcpy
memcpy
memcpy
x301_core::x301::finalize_projective
core::ptr::drop_glue::<zeroize::Zeroizing<[u8; 38]>>
_Unwind_Resume@plt
_Unwind_Resume@plt'

# Inversion is inlined here: two fixed GCD loop edges, then the published
# all-zero status boundary. Not every API-boundary branch is branch-free.
check_expected_branches finalize_projective 'x301_core::x301::finalize_projective' \
    'dec %edx|jne
sub 0x8(%rsp),%ecx|jne
cmpb $0x0,0x30(%rsp)|je'
/usr/bin/gawk '
    /^[[:space:]]*[[:xdigit:]]+:/ && $2 ~ /^j/ && $2 !~ /^jmp/ {
        a=$1; sub(/:$/,"",a); n++
        backwards = strtonum("0x" $3) < strtonum("0x" a)
        if ((n <= 2 && !backwards) || (n == 3 && backwards)) bad=1
    }
    END { exit (bad || n != 3) ? 1 : 0 }
' "$EVIDENCE/finalize_projective.asm"
check_exact_call_graph finalize_projective "$EVIDENCE/finalize_projective.asm" \
    '<crypto_bigint::modular::safegcd::SignedInt<5>>::lincomb_int_reduce_shift::<1>
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
if [ "$MODE" = core ]; then
    KEY_DROPS=2
else
    KEY_DROPS=1
fi
extract_symbol_instances 'core::ptr::drop_glue::<x301_core::x301::SecretKey>' "$KEY_DROPS" "$EVIDENCE/key_drop.asm"
if contains_forbidden_instruction "$EVIDENCE/key_drop.asm" allow-terminal-call; then
    echo 'FAIL conditional control flow in key drop' >&2
    exit 1
fi
KEY_DROP_CALLS='core::ptr::drop_glue::<zeroize::Zeroizing<[u8; 38]>>
core::ptr::drop_glue::<zeroize::Zeroizing<[u8; 38]>>
_Unwind_Resume@plt
core::panicking::panic_in_cleanup'
if [ "$MODE" = core ]; then
    KEY_DROP_CALLS="$KEY_DROP_CALLS
$KEY_DROP_CALLS"
fi
check_exact_call_graph key_drop "$EVIDENCE/key_drop.asm" "$KEY_DROP_CALLS"
test "$(/usr/bin/awk -v expected="$KEY_DROPS" '/^[[:space:]]*[[:xdigit:]]+:/ && $2 ~ /^jmp/ { n++; if ($0 !~ /<core::ptr::drop_glue::<zeroize::Zeroizing<\[u8; 38\]>>>$/) bad=1 } END { print (bad || n != expected) ? 0 : 1 }' "$EVIDENCE/key_drop.asm")" -eq 1
printf 'PASS key_drop raw_and_clamped_owners=1 linked_instances=%s\n' "$KEY_DROPS" | tee -a "$SUMMARY"

if [ "$MODE" = core ]; then
    check_expected_branches public 'x301_core::x301::public_from_secret' \
        'cmpb $0x1,0x8(%rsp)|jne
cmpb $0x1,0x8(%rsp)|jne' '' allow-terminal-call
    check_exact_call_graph public "$EVIDENCE/public.asm" \
        '<x301_core::x301::SecretKey>::from_bytes
<x301_core::x301::SecretKey>::public_key
core::ptr::drop_glue::<zeroize::Zeroizing<[u8; 38]>>
core::ptr::drop_glue::<zeroize::Zeroizing<[u8; 38]>>
core::ptr::drop_glue::<zeroize::Zeroizing<[u8; 38]>>
core::panicking::panic_in_cleanup
core::ptr::drop_glue::<x301_core::x301::SecretKey>
_Unwind_Resume@plt
core::panicking::panic_in_cleanup'
    check_expected_branches raw 'x301_core::x301::x301' \
        'cmpb $0x1,0x50(%rsp)|jne
cmp $0x26,%r15|jne
cmp %r15,%rdi|jbe
mov $0x3,%r8b|je' '' allow-terminal-call
    check_exact_call_graph raw "$EVIDENCE/raw.asm" \
        '<x301_core::x301::SecretKey>::from_bytes
core::ptr::drop_glue::<zeroize::Zeroizing<[u8; 38]>>
x301_core::x301::ladder301
x301_core::x301::finalize_projective
core::ptr::drop_glue::<zeroize::Zeroizing<[u8; 38]>>
core::ptr::drop_glue::<zeroize::Zeroizing<[u8; 38]>>
core::ptr::drop_glue::<zeroize::Zeroizing<[u8; 38]>>
core::panicking::panic_in_cleanup
core::ptr::drop_glue::<x301_core::x301::SecretKey>
core::panicking::panic_in_cleanup
core::ptr::drop_glue::<zeroize::Zeroizing<[u8; 38]>>
_Unwind_Resume@plt
core::panicking::panic_in_cleanup'
fi

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
if [ "$MODE" = provider ]; then
    PUBLIC_CONTROL=x301_key_import
else
    PUBLIC_CONTROL=x301_core_benchmark::main
fi
