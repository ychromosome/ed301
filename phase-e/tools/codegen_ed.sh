# These are the actual Thin-LTO symbols in the linked core benchmark. Minimum
# counts retain the v1 baseline policy: any materially different
# compiler result fails closed and requires manual review.
# The five-limb field helpers are `#[inline(always)]` since the lazy-reduction
# port; the compiler may still emit a local symbol.  Either disposition is
# accepted: an emitted symbol must be branch-free, and an inlined helper must
# not be called from anywhere (its body is then checked inside the point
# arithmetic symbols below).
check_optional_field_symbol() {
    label=$1
    symbol=$2
    minimum_sbb=$3
    minimum_cmov=$4
    instances=$(symbol_instance_count "$symbol")
    case "$instances" in
        0)
            if contains_call_target "$DUMP" "${symbol#ed301_eddsa::}"; then
                printf 'FAIL %s call exists without a local checked symbol\n' \
                    "$symbol" >&2
                exit 1
            fi
            printf 'PASS optional_symbol=%s disposition=inlined\n' "$label" \
                | tee -a "$SUMMARY"
            ;;
        1)
            check_branch_free "$label" "$symbol" "$minimum_sbb" \
                "$minimum_cmov" no '^$' allow
            ;;
        *)
            printf 'FAIL unexpected final-binary instances of %s: %s\n' \
                "$symbol" "$instances" >&2
            exit 1
            ;;
    esac
}
check_optional_field_symbol field_reduce \
    'ed301_eddsa::field_5x64::reduce_wide' 2 5
check_optional_field_symbol field_square \
    'ed301_eddsa::field_5x64::square_wide' 0 0
check_optional_field_symbol field_multiply \
    'ed301_eddsa::field_5x64::multiply_wide' 0 0
check_branch_free point_double \
    '<ed301_eddsa::edwards::EdwardsPoint>::double' 20 35 no \
    'ed301_eddsa::field_5x64::(reduce_wide|square_wide|multiply_wide)' allow
# The lazily reduced formulas canonicalise only their four outputs, so the
# full addition carries fewer conditional corrections than the canonical
# lowering (reviewed shape on Rust 1.98.0: sbb=31 cmov=35).
check_branch_free point_add \
    '<ed301_eddsa::edwards::EdwardsPoint>::add' 25 35 no \
    'ed301_eddsa::field_5x64::(reduce_wide|multiply_wide)' allow
check_branch_free point_add_affine \
    '<ed301_eddsa::edwards::EdwardsPoint>::add_affine' 20 30 no \
    'ed301_eddsa::field_5x64::(reduce_wide|multiply_wide)' allow
check_branch_free point_is_valid \
    '<ed301_eddsa::edwards::EdwardsPoint>::is_valid' 10 25 no \
    'ed301_eddsa::field_5x64::(reduce_wide|square_wide|multiply_wide)' allow
check_branch_free affine_select \
    '<ed301_eddsa::edwards::AffineNielsPoint>::conditional_select' 0 16 no \
    '^$' reject
check_branch_free affine_negate \
    '<ed301_eddsa::edwards::AffineNielsPoint>::negate' 8 10 no '^$' allow
check_branch_free scalar_reduce \
    '<ed301_eddsa::scalar::Scalar>::reduce_hash_le' 2 5 yes \
    unrestricted allow
check_branch_free basepoint_select \
    'ed301_eddsa::edwards::select_basepoint' 0 0 no \
    unrestricted reject

# Branch-sensitive leaf helpers reached from the secret scalar reducer are
# checked in the same final DSO. The duplicate zeroize instance is expected
# from Thin LTO and both copies must remain straight-line.
check_branch_free scalar_uint_from_le38 \
    'ed301_eddsa::scalar::uint_from_le38' 0 0 no '^$' allow
check_branch_free scalar_retrieve \
    '<crypto_bigint::modular::const_monty_form::ConstMontyForm<ed301_eddsa::scalar::ScalarModulus, 5>>::retrieve' \
    0 0 no '^$' allow
check_all_branch_free scalar_zeroize \
    'core::ptr::drop_glue::<zeroize::Zeroizing<[u8; 38]>>' 2
check_branch_free safegcd_lincomb \
    '<crypto_bigint::modular::safegcd::SignedInt<5>>::lincomb_int::<1>' \
    0 0 no '^$' allow

check_expected_branches field_invert \
    '<ed301_eddsa::field_5x64::Fe301>::invert' \
    'dec %edx|jne
sub %r13d,%ecx|jne'
check_expected_branches montgomery_mul \
    'crypto_bigint::modular::mul::mul_montgomery_form::<5>' \
    'cmp $0x5,%rdx|jne'
check_expected_branches scalar_mul_base \
    '<ed301_eddsa::edwards::EdwardsPoint>::scalar_mul_base_encoded' \
    'cmp $0x4d,%rax|jne
cmp $0x4c,%rax|je
cmp $0x4a,%rbx|jb
cmp $0x4a,%rbx|jb
cmp $0x4c,%rax|jne
cmp $0x4c,%rcx|jne' \
    'cmp $0x4d,%rax|jne
cmp $0x4c,%rax|je
cmp $0x4a,%rbx|jb
cmp $0x4a,%rbx|jb
cmp $0x4c,%rax|jne'
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

# Exact reviewed call closure for every non-leaf secret-path symbol above.
# The manifests deliberately include unwind/panic-only edges: a compiler bump
# that adds, removes, or relocates work into a helper requires fresh review.
check_exact_call_graph scalar_reduce "$EVIDENCE/scalar_reduce.asm" \
    'ed301_eddsa::scalar::uint_from_le38
ed301_eddsa::scalar::uint_from_le38
crypto_bigint::modular::mul::mul_montgomery_form::<5>
crypto_bigint::modular::mul::mul_montgomery_form::<5>
crypto_bigint::modular::mul::mul_montgomery_form::<5>
<crypto_bigint::modular::const_monty_form::ConstMontyForm<ed301_eddsa::scalar::ScalarModulus, 5>>::retrieve
core::ptr::drop_glue::<zeroize::Zeroizing<[u8; 38]>>
core::ptr::drop_glue::<zeroize::Zeroizing<[u8; 38]>>
core::ptr::drop_glue::<zeroize::Zeroizing<[u8; 38]>>
core::ptr::drop_glue::<zeroize::Zeroizing<[u8; 38]>>
_Unwind_Resume@plt
core::panicking::panic_in_cleanup' \
    'ed301_eddsa::scalar::uint_from_le38
ed301_eddsa::scalar::uint_from_le38
crypto_bigint::modular::mul::mul_montgomery_form::<5>
crypto_bigint::modular::mul::mul_montgomery_form::<5>
crypto_bigint::modular::mul::mul_montgomery_form::<5>
<crypto_bigint::modular::const_monty_form::ConstMontyForm<ed301_eddsa::scalar::ScalarModulus, 5>>::retrieve
core::ptr::drop_glue::<zeroize::Zeroizing<[u8; 38]>>
core::ptr::drop_glue::<zeroize::Zeroizing<[u8; 38]>>'
check_exact_call_graph basepoint_select "$EVIDENCE/basepoint_select.asm" \
    '<ed301_eddsa::edwards::AffineNielsPoint>::conditional_select
memcpy
<ed301_eddsa::edwards::AffineNielsPoint>::conditional_select
memcpy
<ed301_eddsa::edwards::AffineNielsPoint>::conditional_select
memcpy
<ed301_eddsa::edwards::AffineNielsPoint>::conditional_select
memcpy
<ed301_eddsa::edwards::AffineNielsPoint>::conditional_select
memcpy
<ed301_eddsa::edwards::AffineNielsPoint>::conditional_select
memcpy
<ed301_eddsa::edwards::AffineNielsPoint>::conditional_select
memcpy
<ed301_eddsa::edwards::AffineNielsPoint>::conditional_select
memcpy
<ed301_eddsa::edwards::AffineNielsPoint>::negate
<ed301_eddsa::edwards::AffineNielsPoint>::conditional_select'
check_exact_call_graph field_invert "$EVIDENCE/field_invert.asm" \
    'crypto_bigint::modular::mul::mul_montgomery_form::<5>
<crypto_bigint::modular::safegcd::SignedInt<5>>::lincomb_int_reduce_shift::<1>
<crypto_bigint::modular::safegcd::SignedInt<5>>::lincomb_int_reduce_shift::<1>
<crypto_bigint::modular::safegcd::SignedInt<5>>::lincomb_int_reduce_shift_mod::<1>
<crypto_bigint::modular::safegcd::SignedInt<5>>::lincomb_int_reduce_shift_mod::<1>'
check_exact_call_graph montgomery_mul "$EVIDENCE/montgomery_mul.asm" ''
check_exact_call_graph scalar_mul_base "$EVIDENCE/scalar_mul_base.asm" \
    'memcpy
memcpy
ed301_eddsa::edwards::select_basepoint
<ed301_eddsa::edwards::EdwardsPoint>::add_affine
memcpy
memcpy
<ed301_eddsa::edwards::EdwardsPoint>::double
<ed301_eddsa::edwards::EdwardsPoint>::double
<ed301_eddsa::edwards::EdwardsPoint>::double
<ed301_eddsa::edwards::EdwardsPoint>::double
memcpy
memcpy
ed301_eddsa::edwards::select_basepoint
<ed301_eddsa::edwards::EdwardsPoint>::add_affine
memcpy
memcpy
_Unwind_Resume@plt'
check_exact_call_graph safegcd_shift "$EVIDENCE/safegcd_shift.asm" \
    '<crypto_bigint::modular::safegcd::SignedInt<5>>::lincomb_int::<1>
core::option::expect_failed
core::option::expect_failed
core::panicking::panic_bounds_check'
check_exact_call_graph safegcd_shift_mod "$EVIDENCE/safegcd_shift_mod.asm" \
    '<crypto_bigint::modular::safegcd::SignedInt<5>>::lincomb_int::<1>
core::option::expect_failed
core::panicking::panic_bounds_check'

# E3: this exponentiator branches/indexes only on fixed public exponents.
# The companion dataflow check verifies every linked call site and the actual
# read-only exponent bytes, including both Euler calls before mask acceptance.
check_expected_branches field_pow \
    '<ed301_eddsa::field_5x64::Fe301>::pow_fixed_window4' \
    'cmp $0x2a0,%rcx|jne
add $0xffffffffffffffff,%rdx|jae
and $0xf,%rax|je
add $0xffffffffffffffff,%rdx|jb'
check_exact_call_graph field_pow "$EVIDENCE/field_pow.asm" ''
if [ "$MODE" = provider ]; then
    IMPORT_BRANCHES='cmp $0x26,%rdx|jne
cmpb $0x0,0x3b0(%rsp)|jne
cmpb $0x0,0x3b0(%rsp)|je
cmpb $0x0,0x3b0(%rsp)|je'
    IMPORT_CALLS='<ed301_eddsa::edwards::EdwardsPoint>::decode
memcpy
memcpy
memcpy
<ed301_eddsa::field_5x64::Fe301>::pow_fixed_window4
<ed301_eddsa::field_5x64::Fe301>::pow_fixed_window4
<ed301_eddsa::field_5x64::Fe301>::pow_fixed_window4
<ed301_eddsa::edwards::EdwardsPoint>::prepare_vartime_table
memcpy'
else
    # Thin LTO inlines the unchanged public table builder into the core
    # benchmark. All six additional loops occur after subgroup acceptance.
    IMPORT_BRANCHES='cmp $0x26,%rdx|jne
cmpb $0x0,0xcb0(%rsp)|jne
cmpb $0x0,0xcb0(%rsp)|je
cmpb $0x0,0xcb0(%rsp)|je
cmp $0x2800,%r14|jne
cmp $0x2760,%r12|jne
cmp $0xa00,%rax|jne
cmp $0xa00,%rdx|jne
cmp $0x2800,%r14|jne
cmp $0xfffffffffffff600,%rcx|jne'
    IMPORT_CALLS='<ed301_eddsa::edwards::EdwardsPoint>::decode
memcpy
memcpy
memcpy
<ed301_eddsa::field_5x64::Fe301>::pow_fixed_window4
<ed301_eddsa::field_5x64::Fe301>::pow_fixed_window4
<ed301_eddsa::field_5x64::Fe301>::pow_fixed_window4
memcpy
memcpy
memcpy
memcpy
<ed301_eddsa::edwards::EdwardsPoint>::double
memcpy
<ed301_eddsa::edwards::EdwardsPoint>::add
memcpy
<ed301_eddsa::field_5x64::Fe301>::invert
memcpy
memcpy
memcpy
memcpy
memcpy'
fi
check_expected_branches public_import \
    '<ed301_eddsa::signature::VerifyingKey>::from_bytes' "$IMPORT_BRANCHES"
check_exact_call_graph public_import "$EVIDENCE/public_import.asm" "$IMPORT_CALLS"

CALL_ANCHOR=basepoint_select
if [ "$MODE" = provider ]; then
    PUBLIC_CONTROL=ed301v2_key_import
else
    PUBLIC_CONTROL=ed301_benchmark::main
fi
