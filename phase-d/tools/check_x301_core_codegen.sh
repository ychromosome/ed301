#!/bin/sh
set -eu

PATH=/usr/bin:/bin
export PATH LC_ALL=C

# Parser, call-resolution and trap controls reused from the approved Phase-C checker.
# Source SHA-256: 0f980d2777ca9e9df004e847b08f15814e4b5709c6db107af6fd413723173a41.
# D1 policy: full 301-round canonical X301 ladder, not the v1 scaled/fixed-bit shortcut.
# Scope is this linked x86-64 benchmark ELF, not a provider or another platform.
if [ "$#" -ne 3 ]; then
    printf 'usage: %s <core-benchmark-elf> <toolchain-marker> <evidence-directory>\n' \
        "$0" >&2
    exit 2
fi
MODULE=$1
TOOLCHAIN=$2
EVIDENCE=$3

for tool in /usr/bin/awk /usr/bin/cat /usr/bin/grep /usr/bin/mkdir \
        /usr/bin/nm /usr/bin/objdump /usr/bin/readelf /usr/bin/sha256sum; do
    test -x "$tool" || {
        echo "missing canonical codegen-gate tool: $tool" >&2
        exit 127
    }
done
test -f "$MODULE" && test ! -L "$MODULE" || {
    echo "core benchmark must be a regular non-symlink file: $MODULE" >&2
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
/usr/bin/grep -Eq 'Type:[[:space:]]+DYN \(Position-Independent Executable file\)$' \
    "$ELF_HEADER" || {
        echo "codegen input is not a PIE executable" >&2
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
        echo "final core benchmark lacks the review-required symbol table" >&2
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
            if (value ~ /^%r13([dwb])?$/)
                return "%r13"
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
            if (loaded_register == "%rbx" || loaded_register == "%r13")
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

for item in \
    'secret_import:<x301_core::x301::SecretKey>::from_bytes' \
    'public:x301_core::x301::public_from_secret' \
    'raw:x301_core::x301::x301'; do
    label=${item%%:*}
    symbol=${item#*:}
    extract_symbol "$symbol" "$EVIDENCE/$label.asm"
    if contains_forbidden_instruction "$EVIDENCE/$label.asm" allow-conditional-terminal-call; then
        echo "FAIL forbidden instruction in API boundary $symbol" >&2
        exit 1
    fi
    /usr/bin/awk '/^[[:space:]]*[[:xdigit:]]+:/ && $2 ~ /^j/ { print }' \
        "$EVIDENCE/$label.asm" >"$EVIDENCE/$label.branches"
done
check_exact_call_graph secret_import "$EVIDENCE/secret_import.asm" \
    'core::ptr::drop_glue::<zeroize::Zeroizing<[u8; 38]>>'
check_exact_call_graph public "$EVIDENCE/public.asm" \
    '<x301_core::x301::SecretKey>::from_bytes
x301_core::x301::multiply
core::ptr::drop_glue::<zeroize::Zeroizing<[u8; 38]>>
core::ptr::drop_glue::<zeroize::Zeroizing<[u8; 38]>>
core::ptr::drop_glue::<zeroize::Zeroizing<[u8; 38]>>
core::ptr::drop_glue::<zeroize::Zeroizing<[u8; 38]>>
core::panicking::panic_in_cleanup
core::ptr::drop_glue::<x301_core::x301::SecretKey>
_Unwind_Resume@plt
core::panicking::panic_in_cleanup'
check_exact_call_graph raw "$EVIDENCE/raw.asm" \
    '<x301_core::x301::SecretKey>::from_bytes
core::ptr::drop_glue::<zeroize::Zeroizing<[u8; 38]>>
x301_core::x301::multiply
core::ptr::drop_glue::<zeroize::Zeroizing<[u8; 38]>>
core::ptr::drop_glue::<zeroize::Zeroizing<[u8; 38]>>
core::ptr::drop_glue::<zeroize::Zeroizing<[u8; 38]>>
core::panicking::panic_in_cleanup
core::ptr::drop_glue::<x301_core::x301::SecretKey>
core::panicking::panic_in_cleanup
core::ptr::drop_glue::<zeroize::Zeroizing<[u8; 38]>>
_Unwind_Resume@plt
core::panicking::panic_in_cleanup'

extract_symbol_instances 'core::ptr::drop_glue::<x301_core::x301::SecretKey>' 2 "$EVIDENCE/key_drop.asm"
if contains_forbidden_instruction "$EVIDENCE/key_drop.asm" allow-terminal-call; then
    echo 'FAIL conditional control flow in key drop' >&2
    exit 1
fi
check_exact_call_graph key_drop "$EVIDENCE/key_drop.asm" \
    'core::ptr::drop_glue::<zeroize::Zeroizing<[u8; 38]>>
core::ptr::drop_glue::<zeroize::Zeroizing<[u8; 38]>>
_Unwind_Resume@plt
core::panicking::panic_in_cleanup
core::ptr::drop_glue::<zeroize::Zeroizing<[u8; 38]>>
core::ptr::drop_glue::<zeroize::Zeroizing<[u8; 38]>>
_Unwind_Resume@plt
core::panicking::panic_in_cleanup'
test "$(/usr/bin/awk '/^[[:space:]]*[[:xdigit:]]+:/ && $2 ~ /^jmp/ { n++; if ($0 !~ /<core::ptr::drop_glue::<zeroize::Zeroizing<\[u8; 38\]>>>$/) bad=1 } END { print (bad || n != 2) ? 0 : 1 }' "$EVIDENCE/key_drop.asm")" -eq 1
printf 'PASS key_drop deterministic_two_owner_path=1\n' | tee -a "$SUMMARY"

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
}' "$EVIDENCE/ladder.asm" >"$CALL_NEGATIVE"
if (check_exact_call_graph call_graph_negative_control "$CALL_NEGATIVE" \
        "$(/usr/bin/cat "$EVIDENCE/ladder.calls")" \
        >/dev/null 2>&1); then
    echo "FAIL call-graph checker accepted an unexpected helper" >&2
    exit 1
fi
printf '%s\n' 'PASS negative_control=unexpected-call-rejected' \
    | tee -a "$SUMMARY"

# Same-binary negative control: the benchmark CLI legitimately branches on public
# arguments and therefore must fail the branch-free rule.
extract_symbol x301_core_benchmark::main "$EVIDENCE/negative-control.asm"
negative_jcc=$(count_mnemonic '^j' "$EVIDENCE/negative-control.asm")
if [ "$negative_jcc" -lt 1 ] \
        || ! contains_forbidden_instruction \
            "$EVIDENCE/negative-control.asm" \
            >"$EVIDENCE/negative-control-detected.txt"; then
    echo "FAIL same-binary codegen checker negative control" >&2
    exit 1
fi
printf '%s\n' 'PASS negative_control=benchmark-main-jcc-detected' \
    | tee -a "$SUMMARY"

if /usr/bin/grep -Eq 'x301_core::.*(tests::|rem_wide|div3by2)' "$EVIDENCE/core.nm"; then
    echo 'FAIL test-only oracle or wide division in final X301 artifact' >&2
    exit 1
fi
/usr/bin/sha256sum "$MODULE" "$TOOLCHAIN" "$DUMP" "$SUMMARY" >"$EVIDENCE/SHA256SUMS"
printf 'PASS x301_core_codegen binary_sha256=%s toolchain_sha256=%s evidence=%s\n' \
    "$(/usr/bin/sha256sum "$MODULE" | /usr/bin/awk '{print $1}')" \
    "$(/usr/bin/sha256sum "$TOOLCHAIN" | /usr/bin/awk '{print $1}')" "$EVIDENCE"
