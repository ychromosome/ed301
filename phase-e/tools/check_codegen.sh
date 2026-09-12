#!/bin/sh
set -eu

PATH=/usr/bin:/bin
export PATH LC_ALL=C

# Phase E: retain the Phase-C/D1/D2 parser, minima and negative controls.
# New optimized symbols and exact lowering are reviewed in the E policies.
TOOLS=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)

if [ "$#" -ne 4 ]; then
    printf 'usage: %s <ed-core|x-core|ed-provider|x-provider> <linked-elf> <toolchain-marker> <evidence-directory>\n' \
        "$0" >&2
    exit 2
fi
PROFILE=$1
MODULE=$2
TOOLCHAIN=$3
EVIDENCE=$4
case "$PROFILE" in
    ed-core|x-core) MODE=core ;;
    ed-provider|x-provider) MODE=provider ;;
    *) exit 2 ;;
esac
PROFILE=${PROFILE%-*}

if [ "$PROFILE" = x ] && [ ! -x /usr/bin/gawk ]; then
    echo "missing canonical codegen-gate tool: /usr/bin/gawk (GNU awk required for X301)" >&2
    exit 127
fi

for tool in /usr/bin/awk /usr/bin/cat /usr/bin/grep /usr/bin/mkdir \
        /usr/bin/nm /usr/bin/objdump /usr/bin/readelf /usr/bin/sha256sum; do
    test -x "$tool" || {
        echo "missing canonical codegen-gate tool: $tool" >&2
        exit 127
    }
done
test -f "$MODULE" && test ! -L "$MODULE" || {
    echo "provider DSO must be a regular non-symlink file: $MODULE" >&2
    exit 2
}
test -s "$TOOLCHAIN" && test ! -L "$TOOLCHAIN" || {
    echo "missing regular toolchain marker: $TOOLCHAIN" >&2
    exit 2
}
test ! -e "$EVIDENCE" || {
    echo "codegen evidence directory already exists: $EVIDENCE" >&2
    exit 2
}
/usr/bin/mkdir -m 700 "$EVIDENCE"

ELF_HEADER=$EVIDENCE/elf-header.txt
/usr/bin/readelf -h "$MODULE" >"$ELF_HEADER"
if [ "$MODE" = provider ]; then
    ELF_TYPE='Shared object file'
else
    ELF_TYPE='Position-Independent Executable file'
fi
/usr/bin/grep -Eq "Type:[[:space:]]+DYN \\($ELF_TYPE\\)$" \
    "$ELF_HEADER" || {
        echo "codegen input does not match the required ELF type" >&2
        exit 1
    }
/usr/bin/grep -Eq \
    'Machine:[[:space:]]+Advanced Micro Devices X86-64$' "$ELF_HEADER" || {
        echo "the current codegen policy is defined only for x86-64" >&2
        exit 1
    }
/usr/bin/readelf -S "$MODULE" >"$EVIDENCE/elf-sections.txt"
/usr/bin/grep -Eq '[[:space:]]\.symtab[[:space:]]+SYMTAB[[:space:]]' \
    "$EVIDENCE/elf-sections.txt" || {
        echo "final provider DSO lacks the review-required symbol table" >&2
        exit 1
    }

DUMP=$EVIDENCE/core.objdump
SUMMARY=$EVIDENCE/summary.txt
/usr/bin/objdump -d -C --no-show-raw-insn --disassemble-zeroes --wide \
    "$MODULE" >"$DUMP"
/usr/bin/nm -C --defined-only "$MODULE" >"$EVIDENCE/core.nm"
/usr/bin/nm -n -C --defined-only "$MODULE" \
    >"$EVIDENCE/core.nm-by-address"
/usr/bin/readelf -rW "$MODULE" >"$EVIDENCE/core.relocations"
/usr/bin/objdump --version >"$EVIDENCE/objdump-version.txt"
: >"$SUMMARY"

# Rust's two supported symbol-mangling schemes differ only in the presentation
# emitted by the demangler for inherent methods: v0 prints `<Type>::method`,
# while legacy mangling prints `Type::method`.  Canonicalize that outer pair of
# brackets before comparing symbol identities.  Generic brackets inside the
# type and method remain untouched.  This is naming normalization only; every
# instruction-shape, count and exact-call-graph policy below remains unchanged.
canonicalize_symbol_stream() {
    /usr/bin/awk '
        function canonical_symbol(value, marker) {
            if (substr(value, 1, 1) == "<" &&
                    (marker = index(value, ">::")) != 0)
                value = substr(value, 2, marker - 2) \
                    substr(value, marker + 1)
            return value
        }
        { print canonical_symbol($0) }
    '
}

CANONICALIZATION=$EVIDENCE/rust-symbol-canonicalization.txt
printf '%s\n' \
    '<ed301_eddsa::edwards::EdwardsPoint>::double' \
    'ed301_eddsa::edwards::EdwardsPoint::double' \
    '<crypto_bigint::modular::safegcd::SignedInt<5>>::lincomb_int::<1>' \
    'crypto_bigint::modular::safegcd::SignedInt<5>::lincomb_int::<1>' \
    | canonicalize_symbol_stream >"$CANONICALIZATION"
if [ "$(/usr/bin/cat "$CANONICALIZATION")" != \
        'ed301_eddsa::edwards::EdwardsPoint::double
ed301_eddsa::edwards::EdwardsPoint::double
crypto_bigint::modular::safegcd::SignedInt<5>::lincomb_int::<1>
crypto_bigint::modular::safegcd::SignedInt<5>::lincomb_int::<1>' ]; then
    echo "FAIL Rust-symbol canonicalization self-test" >&2
    exit 1
fi
printf '%s\n' 'PASS rust_symbol_canonicalization=legacy-and-v0' \
    | tee -a "$SUMMARY"

# Resolve local R_X86_64_RELATIVE GOT entries back to their named functions.
# This lets the call-closure check name Rust panic/cleanup callees without
# pinning the policy to load addresses or RIP displacements.
/usr/bin/awk '
    function normalize(value) {
        sub(/^0+/, "", value)
        return value == "" ? "0" : value
    }
    FNR == NR && $1 ~ /^[[:xdigit:]]+$/ && $2 ~ /^[A-Za-z]$/ {
        address = normalize($1)
        $1 = ""
        $2 = ""
        sub(/^[[:space:]]+/, "")
        symbols[address] = $0
        next
    }
    FNR != NR && $3 == "R_X86_64_RELATIVE" {
        got = normalize($1)
        target = normalize($NF)
        # Most relative relocations point to anonymous read-only data rather
        # than callable symbols. Record only named code targets; a call through
        # any unrecorded entry still fails below as UNRESOLVED_RELATIVE_GOT.
        if (target in symbols)
            printf "%s\t%s\n", got, symbols[target]
    }
' "$EVIDENCE/core.nm-by-address" "$EVIDENCE/core.relocations" \
    >"$EVIDENCE/relative-got-targets.txt"

extract_symbol() {
    extract_symbol_instances "$1" 1 "$2"
}

extract_symbol_instances() {
    symbol=$1
    expected_count=$2
    destination=$3
    : >"$destination"
    count=$(/usr/bin/awk -v symbol="$symbol" -v destination="$destination" '
        function canonical_symbol(value, marker) {
            if (substr(value, 1, 1) == "<" &&
                    (marker = index(value, ">::")) != 0)
                value = substr(value, 2, marker - 2) \
                    substr(value, marker + 1)
            return value
        }
        function header_symbol(line, value) {
            value = line
            sub(/^[[:space:]]*[[:xdigit:]]+[[:space:]]+</, "", value)
            sub(/>:[[:space:]]*$/, "", value)
            return canonical_symbol(value)
        }
        BEGIN { symbol = canonical_symbol(symbol) }
        /^[[:space:]]*[[:xdigit:]]+ <.*>:/ {
            active = header_symbol($0) == symbol
            if (active)
                count++
        }
        active { print > destination }
        END { print count + 0 }
    ' "$DUMP")
    if [ "$count" -ne "$expected_count" ]; then
        if [ "$expected_count" -eq 1 ]; then
            printf 'expected exactly one final-binary symbol %s, found %s\n' \
                "$symbol" "$count" >&2
        else
            printf 'expected %s final-binary instances of %s, found %s\n' \
                "$expected_count" "$symbol" "$count" >&2
        fi
        exit 1
    fi
    test -s "$destination"
}

symbol_instance_count() {
    symbol=$1
    /usr/bin/awk -v symbol="$symbol" '
        function canonical_symbol(value, marker) {
            if (substr(value, 1, 1) == "<" &&
                    (marker = index(value, ">::")) != 0)
                value = substr(value, 2, marker - 2) \
                    substr(value, marker + 1)
            return value
        }
        function header_symbol(line, value) {
            value = line
            sub(/^[[:space:]]*[[:xdigit:]]+[[:space:]]+</, "", value)
            sub(/>:[[:space:]]*$/, "", value)
            return canonical_symbol(value)
        }
        BEGIN { symbol = canonical_symbol(symbol) }
        /^[[:space:]]*[[:xdigit:]]+ <.*>:/ {
            if (header_symbol($0) == symbol)
                count++
        }
        END { print count + 0 }
    ' "$DUMP"
}

contains_call_target() {
    file=$1
    pattern=$2
    /usr/bin/awk -v pattern="$pattern" '
        function canonical_symbol(value, marker) {
            if (substr(value, 1, 1) == "<" &&
                    (marker = index(value, ">::")) != 0)
                value = substr(value, 2, marker - 2) \
                    substr(value, marker + 1)
            return value
        }
        function call_target(line, target, position) {
            position = index(line, "<")
            if (position == 0)
                return ""
            target = substr(line, position + 1)
            sub(/>[[:space:]]*$/, "", target)
            return canonical_symbol(target)
        }
        /^[[:space:]]*[[:xdigit:]]+:/ && $2 ~ /^call/ {
            target = call_target($0)
            if (target ~ ("(^|::)" pattern "$"))
                found = 1
        }
        END { exit found ? 0 : 1 }
    ' "$file"
}

# Return success only when a forbidden transfer, variable-time division or
# deliberate trap is present. Trailing compiler padding is outside the
# executable body only when it follows a return or a non-returning call and
# every remaining instruction is padding. Exact call-graph checks below bind
# the latter case to reviewed panic targets.
contains_forbidden_instruction() {
    mode=${2:-reject-conditional}
    /usr/bin/awk -v mode="$mode" '
        /^[[:space:]]*[[:xdigit:]]+ <.*>:/ {
            block++
            next
        }
        /^[[:space:]]*[[:xdigit:]]+:/ {
            if (block == 0)
                block = 1
            n[block]++
            mnemonic[block, n[block]] = $2
            instruction[block, n[block]] = $0
        }
        END {
            for (b = 1; b <= block; b++) {
                terminal = n[b]
                while (terminal > 0 &&
                        (mnemonic[b, terminal] == "int3" ||
                         mnemonic[b, terminal] ~ /^nop/ ||
                         mnemonic[b, terminal] == "data16"))
                    terminal--
                padding_ok = terminal > 0 &&
                    (mnemonic[b, terminal] ~ /^ret/ ||
                     ((mode == "allow-terminal-call" ||
                       mode == "allow-conditional-terminal-call") &&
                      mnemonic[b, terminal] ~ /^call/))

                for (i = 1; i <= n[b]; i++) {
                    conditional = mnemonic[b, i] ~ /^j/ &&
                        mnemonic[b, i] !~ /^jmpq?$/
                    terminal_padding = padding_ok && i > terminal &&
                        mnemonic[b, i] == "int3"
                    if ((mode !~ /allow-conditional/ && conditional) ||
                            mnemonic[b, i] ~ /^loop/ ||
                            mnemonic[b, i] ~ /^div/ ||
                            mnemonic[b, i] ~ /^idiv/ ||
                            mnemonic[b, i] == "ud2" ||
                            (mnemonic[b, i] == "int3" &&
                             !terminal_padding)) {
                        print instruction[b, i]
                        found = 1
                    }
                }
            }
        }
        END { exit found ? 0 : 1 }
    ' "$1"
    result=$?
    case "$result" in
        0|1) return "$result" ;;
        *) echo 'FAIL codegen instruction scanner error' >&2; exit 1 ;;
    esac
}

count_mnemonic() {
    pattern=$1
    file=$2
    /usr/bin/awk -v pattern="$pattern" '
        /^[[:space:]]*[[:xdigit:]]+:/ && $2 ~ pattern { count++ }
        END { print count + 0 }
    ' "$file"
}

check_no_indexed_load() {
    file=$1
    if /usr/bin/awk '
        /^[[:space:]]*[[:xdigit:]]+:/ &&
                $0 ~ /\([^)]*,[^)]*\)/ &&
                $2 !~ /^lea/ &&
                $0 !~ /[[:space:]]nop[a-z]*[[:space:]]/ {
            print
            found = 1
        }
        END { exit found ? 0 : 1 }
    ' "$file"; then
        echo "FAIL indexed memory access in constant-time selector" >&2
        exit 1
    fi
}

check_call_closure() {
    file=$1
    allowed=$2
    if /usr/bin/awk -v allowed="$allowed" '
        function canonical_symbol(value, marker) {
            if (substr(value, 1, 1) == "<" &&
                    (marker = index(value, ">::")) != 0)
                value = substr(value, 2, marker - 2) \
                    substr(value, marker + 1)
            return value
        }
        function call_target(line, target, position) {
            position = index(line, "<")
            if (position == 0)
                return ""
            target = substr(line, position + 1)
            sub(/>[[:space:]]*$/, "", target)
            return canonical_symbol(target)
        }
        BEGIN { exact = "^(" allowed ")$" }
        /^[[:space:]]*[[:xdigit:]]+:/ && $2 ~ /^call/ {
            target = call_target($0)
            if (target == "" || target !~ exact) {
                print
                found = 1
            }
        }
        END { exit found ? 0 : 1 }
    ' "$file"; then
        echo "FAIL unexpected call in branch-free arithmetic symbol" >&2
        exit 1
    fi
}

# Record the exact direct and resolved-indirect call sequence of a reviewed
# secret-path symbol. Register-indirect memcpy calls are accepted only when
# the register was populated from the named memcpy GOT slot and has not been
# overwritten. Any unresolved or newly introduced call therefore changes the
# manifest and fails closed.
check_exact_call_graph() {
    label=$1
    file=$2
    expected=$3
    alternative=${4-}
    observed=$EVIDENCE/$label.calls

    /usr/bin/awk '
        function canonical_symbol(value, marker) {
            if (substr(value, 1, 1) == "<" &&
                    (marker = index(value, ">::")) != 0)
                value = substr(value, 2, marker - 2) \
                    substr(value, marker + 1)
            return value
        }
        function normalize_address(value) {
            sub(/^0+/, "", value)
            return value == "" ? "0" : value
        }
        function canonical_register(value) {
            gsub(/[[:space:]]/, "", value)
            sub(/^\*/, "", value)
            if (value ~ /^%(r|e)?bx$/ || value ~ /^%b[lh]$/)
                return "%rbx"
            if (value ~ /^%(r|e)?bp$/ || value == "%bpl")
                return "%rbp"
            if (value ~ /^%r1[2345]([dwb])?$/) {
                sub(/[dwb]$/, "", value)
                return value
            }
            return value
        }
        function comment_symbol(line, target, position) {
            position = index(line, "<")
            if (position == 0)
                return ""
            target = substr(line, position + 1)
            sub(/>[[:space:]]*$/, "", target)
            if (target ~ /^memcpy@/)
                target = "memcpy"
            return canonical_symbol(target)
        }
        function got_address(line, tail, parts) {
            tail = line
            sub(/^.*#[[:space:]]*/, "", tail)
            split(tail, parts, /[[:space:]]+/)
            return normalize_address(parts[1])
        }
        FNR == NR {
            tab = index($0, "\t")
            if (tab != 0)
                got[normalize_address(substr($0, 1, tab - 1))] = \
                    canonical_symbol(substr($0, tab + 1))
            next
        }
        /^[[:space:]]*[[:xdigit:]]+:/ {
            mnemonic = $2
            operands = $3
            line = $0

            # Track only named, callee-saved register loads. Calls preserve
            # these registers under the x86-64 ABI; any explicit write below
            # invalidates the provenance before a later indirect call.
            loaded_register = ""
            loaded_target = ""
            if (mnemonic ~ /^(mov|lea)/ && line ~ /<memcpy@/) {
                count = split(operands, pieces, ",")
                loaded_register = canonical_register(pieces[count])
                loaded_target = "memcpy"
            }

            if (mnemonic ~ /^call/) {
                target = ""
                if (line ~ /<memcpy@/) {
                    target = "memcpy"
                } else if (operands ~ /^\*.*\(%rip\)/ &&
                        line ~ /#[[:space:]]*[[:xdigit:]]+/) {
                    address = got_address(line)
                    target = got[address]
                    if (target == "")
                        target = "UNRESOLVED_RELATIVE_GOT:" address
                } else if (index(line, "<") != 0) {
                    target = comment_symbol(line)
                } else if (operands ~ /^\*%/) {
                    register = canonical_register(operands)
                    target = register_target[register]
                    if (target == "")
                        target = "UNRESOLVED_REGISTER:" register
                } else {
                    target = "UNRESOLVED_CALL:" operands
                }
                print target
            }

            # Most AT&T instructions write their last register operand. The
            # exclusions below are read-only/control instructions. Clear a
            # tracked target before installing a new reviewed GOT load.
            count = split(operands, pieces, ",")
            destination = canonical_register(pieces[count])
            if (destination in register_target &&
                    mnemonic !~ /^(cmp|test|push|call|j|ret|nop|data16)/)
                delete register_target[destination]
            if (mnemonic ~ /^(xchg|xadd)/) {
                source_register = canonical_register(pieces[1])
                delete register_target[source_register]
            }
            if (loaded_register == "%rbx" || loaded_register == "%rbp" ||
                    loaded_register ~ /^%r1[2345]$/)
                register_target[loaded_register] = loaded_target
        }
    ' "$EVIDENCE/relative-got-targets.txt" "$file" >"$observed"

    expected=$(printf '%s\n' "$expected" | canonicalize_symbol_stream)
    actual=$(/usr/bin/cat "$observed")
    matched=no
    if [ "$actual" = "$expected" ]; then
        matched=yes
    elif [ -n "$alternative" ]; then
        alternative=$(printf '%s\n' "$alternative" \
            | canonicalize_symbol_stream)
        if [ "$actual" = "$alternative" ]; then
            matched=yes
        fi
    fi
    if [ "$matched" != yes ]; then
        printf 'FAIL changed or unresolved call graph in %s\n' "$label" >&2
        /usr/bin/cat "$observed" >&2
        exit 1
    fi
    printf 'PASS call_graph=%s sha256=%s\n' "$label" \
        "$(/usr/bin/sha256sum "$observed" | /usr/bin/awk '{ print $1 }')" \
        | tee -a "$SUMMARY"
}

check_branch_free() {
    label=$1
    symbol=$2
    minimum_sbb=$3
    minimum_cmov=$4
    allow_jmp=$5
    call_pattern=$6
    indexed_policy=$7
    section=$EVIDENCE/$label.asm

    extract_symbol "$symbol" "$section"
    if contains_forbidden_instruction "$section"; then
        echo "FAIL conditional control flow in final symbol $symbol" >&2
        exit 1
    fi
    if [ "$allow_jmp" = no ] \
            && [ "$(count_mnemonic '^jmpq?$' "$section")" -ne 0 ]; then
        echo "FAIL unexpected jump in straight-line symbol $symbol" >&2
        exit 1
    fi
    if [ "$call_pattern" != unrestricted ]; then
        check_call_closure "$section" "$call_pattern"
    fi
    if [ "$indexed_policy" = reject ]; then
        check_no_indexed_load "$section"
    fi

    sbb=$(count_mnemonic '^sbb' "$section")
    cmov=$(count_mnemonic '^cmov' "$section")
    setcc=$(count_mnemonic '^set' "$section")
    if [ "$sbb" -lt "$minimum_sbb" ] || [ "$cmov" -lt "$minimum_cmov" ]; then
        printf 'FAIL changed borrow/select lowering in %s: sbb=%s cmov=%s\n' \
            "$symbol" "$sbb" "$cmov" >&2
        exit 1
    fi
    printf 'PASS symbol=%s sbb=%s cmov=%s setcc=%s\n' \
        "$symbol" "$sbb" "$cmov" "$setcc" | tee -a "$SUMMARY"
}

check_all_branch_free() {
    label=$1
    symbol=$2
    expected_count=$3
    section=$EVIDENCE/$label.asm

    extract_symbol_instances "$symbol" "$expected_count" "$section"
    if contains_forbidden_instruction "$section" \
            || [ "$(count_mnemonic '^jmpq?$' "$section")" -ne 0 ]; then
        echo "FAIL control flow in final symbol instances $symbol" >&2
        exit 1
    fi
    check_call_closure "$section" '^$'
    printf 'PASS symbol_instances=%s count=%s branch_free=1\n' \
        "$symbol" "$expected_count" | tee -a "$SUMMARY"
}

check_expected_branches() {
    label=$1
    symbol=$2
    expected=$3
    alternative=${4-}
    terminal_call=${5-}
    section=$EVIDENCE/$label.asm
    observed=$EVIDENCE/$label.branches
    extract_symbol "$symbol" "$section"
    /usr/bin/awk '
        /^[[:space:]]*[[:xdigit:]]+:/ {
            mnemonic = $2
            operands = $3
            if (mnemonic ~ /^j/ && mnemonic !~ /^jmpq?$/)
                print previous_mnemonic " " previous_operands "|" mnemonic
            previous_mnemonic = mnemonic
            previous_operands = mnemonic ~ /^j/ ? "TARGET" : operands
        }
    ' "$section" >"$observed"
    actual=$(/usr/bin/cat "$observed")
    if [ "$actual" != "$expected" ] \
            && { [ -z "$alternative" ] || [ "$actual" != "$alternative" ]; };
    then
        printf 'FAIL changed fixed-loop shape in %s\n' "$symbol" >&2
        /usr/bin/cat "$observed" >&2
        exit 1
    fi
    scanner_mode=allow-conditional
    if [ "$terminal_call" = allow-terminal-call ]; then
        scanner_mode=allow-conditional-terminal-call
    fi
    if contains_forbidden_instruction "$section" "$scanner_mode"; then
        echo "FAIL forbidden instruction in fixed-loop symbol $symbol" >&2
        exit 1
    fi
    printf 'PASS classified_control_flow_symbol=%s branches=%s\n' \
        "$symbol" "$(count_mnemonic '^j' "$section")" | tee -a "$SUMMARY"
}


. "$TOOLS/codegen_$PROFILE.sh"

/usr/bin/python3 -I -B "$TOOLS/check_codegen_dataflow.py" \
    --profile "$PROFILE" --elf "$MODULE" --evidence "$EVIDENCE" \
    >"$EVIDENCE/dataflow.stdout"
# Do not pipe the checker into tee: POSIX sh would otherwise report tee's
# success even when the dataflow checker rejects the linked binary.
/usr/bin/cat "$EVIDENCE/dataflow.stdout" | tee -a "$SUMMARY"

# Both accepted core harness identities contain the identical historical
# harness source. Exactly one must be linked; this changes only the public
# negative-control anchor, never arithmetic policy.
if [ "$MODE" = core ]; then
    primary_count=$(symbol_instance_count "$PUBLIC_CONTROL")
    phase_e_count=$(symbol_instance_count 'phase_e_core_bench::main')
    test "$((primary_count + phase_e_count))" -eq 1
    if [ "$phase_e_count" -eq 1 ]; then
        PUBLIC_CONTROL=phase_e_core_bench::main
    fi
fi

# Keep terminal alignment bytes distinct from executable traps. The positive
# controls cover both terminal forms used by the reviewed Rust binaries; the
# negative control proves that an in-body trap still fails.
PADDING_RET=$EVIDENCE/terminal-padding-after-ret.asm
PADDING_CALL=$EVIDENCE/terminal-padding-after-call.asm
PADDING_BAD=$EVIDENCE/in-body-trap-negative-control.asm
MISSING_HELPER=$EVIDENCE/missing-local-helper-negative-control.asm
CALL_SUFFIX=$EVIDENCE/call-target-suffix-negative-control.asm
printf '%s\n' '0 <padding_after_ret>:' '   0: ret' '   1: int3' \
    '   2: int3' >"$PADDING_RET"
printf '%s\n' '0 <padding_after_call>:' \
    '   0: call 0 <core::panicking::panic_bounds_check>' \
    '   1: int3' >"$PADDING_CALL"
printf '%s\n' '0 <in_body_trap>:' '   0: int3' '   1: ret' \
    >"$PADDING_BAD"
printf '%s\n' '0 <missing_local_helper>:' \
    '   0: call 0 <ed301_eddsa::field_5x64::multiply_wide>' \
    '   1: ret' >"$MISSING_HELPER"
printf '%s\n' '0 <call_target_suffix>:' \
    '   0: call 0 <ed301_eddsa::field_5x64::multiply_wide_vartime>' \
    '   1: ret' >"$CALL_SUFFIX"
if contains_forbidden_instruction "$PADDING_RET" \
        || contains_forbidden_instruction "$PADDING_CALL" \
            allow-terminal-call \
        || contains_forbidden_instruction "$PADDING_CALL" \
            allow-conditional-terminal-call; then
    echo 'FAIL terminal-padding positive control' >&2
    exit 1
fi
if ! contains_forbidden_instruction "$PADDING_CALL" >/dev/null; then
    echo 'FAIL terminal-call padding scope control' >&2
    exit 1
fi
if ! contains_forbidden_instruction "$PADDING_BAD" >/dev/null; then
    echo 'FAIL in-body trap negative control' >&2
    exit 1
fi
if ! contains_call_target "$MISSING_HELPER" \
        'field_5x64::multiply_wide'; then
    echo 'FAIL missing-local-helper negative control' >&2
    exit 1
fi
if ! (check_call_closure "$MISSING_HELPER" \
        'ed301_eddsa::field_5x64::multiply_wide') >/dev/null 2>&1; then
    echo 'FAIL exact call-closure positive control' >&2
    exit 1
fi
if contains_call_target "$CALL_SUFFIX" 'field_5x64::multiply_wide'; then
    echo 'FAIL call-target suffix negative control' >&2
    exit 1
fi
if (check_call_closure "$CALL_SUFFIX" \
        'ed301_eddsa::field_5x64::multiply_wide') >/dev/null 2>&1; then
    echo 'FAIL exact call-closure negative control' >&2
    exit 1
fi
printf '%s\n' 'PASS terminal_padding=ret-or-explicit-noreturn-call' \
    | tee -a "$SUMMARY"

# Prove that the closure checker itself rejects a newly introduced helper
# edge. Run it in a subshell because the normal failure path intentionally
# exits immediately.
CALL_NEGATIVE=$EVIDENCE/call-graph-negative-control.asm
/usr/bin/awk '{ print } END {
    print "   deadbeef: call   0 <unexpected::secret_helper>"
}' "$EVIDENCE/$CALL_ANCHOR.asm" >"$CALL_NEGATIVE"
if (check_exact_call_graph call_graph_negative_control "$CALL_NEGATIVE" \
        "$(/usr/bin/cat "$EVIDENCE/$CALL_ANCHOR.calls")" \
        >/dev/null 2>&1); then
    echo "FAIL call-graph checker accepted an unexpected helper" >&2
    exit 1
fi
printf '%s\n' 'PASS negative_control=unexpected-call-rejected' \
    | tee -a "$SUMMARY"

# E1/E3/E7 keep memcpy in additional callee-saved registers, including rbp
# after E7's row-wise square changes allocation in public table preparation.
# A named GOT load is required; narrow-register writes invalidate provenance.
for register in rbp r12 r13 r14 r15; do
    CONTROL=$EVIDENCE/memcpy-$register-positive.asm
    printf '0 <memcpy_register>:\n   0: mov 0(%%rip),%%%s # 0 <memcpy@GLIBC_2.14>\n   1: call *%%%s\n   2: ret\n' \
        "$register" "$register" >"$CONTROL"
    check_exact_call_graph "memcpy_${register}_positive" "$CONTROL" 'memcpy'
    for clobber in alias exchange; do
        BAD=$EVIDENCE/memcpy-$register-$clobber-negative.asm
        if [ "$clobber" = alias ]; then
            case "$register" in
                rbp) narrow=ebp ;;
                *) narrow=${register}d ;;
            esac
            instruction="xor %${narrow},%${narrow}"
        else
            instruction="xchg %${register},%rax"
        fi
        /usr/bin/awk -v instruction="$instruction" '/call/ { print "   1: " instruction } { print }' \
            "$CONTROL" >"$BAD"
        if (check_exact_call_graph "memcpy_${register}_${clobber}_negative" "$BAD" 'memcpy') >/dev/null 2>&1; then
            echo 'FAIL memcpy register clobber control' >&2
            exit 1
        fi
    done
done
printf '%s\n' 'PASS memcpy_register_provenance=named-load-and-no-clobber' | tee -a "$SUMMARY"

# The C import entry branches on public buffer/selection validity and must
# fail a branch-free rule. This is a same-DSO instrumentation control.
extract_symbol "$PUBLIC_CONTROL" "$EVIDENCE/negative-control.asm"
if ! contains_forbidden_instruction "$EVIDENCE/negative-control.asm" \
        >"$EVIDENCE/negative-control-detected.txt"; then
    echo 'FAIL same-DSO codegen negative control' >&2
    exit 1
fi
printf 'PASS negative_control=public-%s-entry-jcc-detected\n' "$MODE" | tee -a "$SUMMARY"
if /usr/bin/grep -Eq '(ed301_eddsa|x301_core)::.*(tests::|rem_wide|div3by2|is_prime_subgroup_with_table|is_nonzero_square_euler|audit_public_import|public_import_count_for_diagnostics|square_wide_column_oracle|accumulate_product|accumulate_double_product|accumulate_192|emit_square_column)' "$EVIDENCE/core.nm"; then
    echo 'FAIL test-only arithmetic oracle in final provider DSO' >&2
    exit 1
fi
# The pinned Jacobi implementation is inlined into the separately classified
# Ed301 public predicate. New standalone variants require their own review.
if /usr/bin/grep -Eq 'JacobiSymbol|jacobi_symbol' "$EVIDENCE/core.nm"; then
    echo 'FAIL unclassified standalone Jacobi implementation in final ELF' >&2
    exit 1
fi
/usr/bin/sha256sum "$MODULE" "$TOOLCHAIN" "$DUMP" "$SUMMARY" >"$EVIDENCE/SHA256SUMS"
printf 'PASS phase_e_codegen profile=%s module_sha256=%s evidence=%s\n' \
    "$PROFILE" "$(sha256sum "$MODULE" | awk '{print $1}')" "$EVIDENCE"
