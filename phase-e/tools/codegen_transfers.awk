# SPDX-License-Identifier: Apache-2.0
# Shared direct/resolved-indirect call and external-tail classification.
# Input 1: relative GOT targets. Input 2: one or more objdump symbol instances.
function canonical(value, marker) {
    if (substr(value, 1, 1) == "<" && (marker = index(value, ">::")) != 0)
        value = substr(value, 2, marker - 2) substr(value, marker + 1)
    return value
}
function normalize(value) {
    sub(/^0+/, "", value)
    return value == "" ? "0" : value
}
function reg(value) {
    gsub(/[[:space:]]/, "", value)
    sub(/^\*/, "", value)
    if (value ~ /^%(r|e)?bx$/ || value ~ /^%b[lh]$/) return "%rbx"
    if (value ~ /^%(r|e)?bp$/ || value == "%bpl") return "%rbp"
    if (value ~ /^%r1[2345]([dwb])?$/) sub(/[dwb]$/, "", value)
    return value
}
function symbol(line, target, position) {
    position = index(line, "<")
    if (position == 0) return ""
    target = substr(line, position + 1)
    sub(/>[[:space:]]*$/, "", target)
    if (target ~ /^memcpy@/) target = "memcpy"
    return canonical(target)
}
function got_address(line, tail, parts) {
    tail = line
    sub(/^.*#[[:space:]]*/, "", tail)
    split(tail, parts, /[[:space:]]+/)
    return normalize(parts[1])
}
function tracked(register) {
    return register ~ /^%(rbx|rbp|r12|r13|r14|r15)$/
}
function loaded_register(b, i, operand, parts, n) {
    operand = operands_by_index[b, i]
    # A narrow load, or the address of a GOT slot, is not the function pointer.
    if (mnemonics[b, i] !~ /^movq?$/ || lines[b, i] !~ /<memcpy@/ ||
            operand !~ /^(-?0x[[:xdigit:]]+|-?[0-9]+)?\(%rip\),%(rbx|rbp|r12|r13|r14|r15)$/)
        return ""
    n = split(operand, parts, ",")
    return parts[n]
}
function clobbers(b, i, register, mnemonic, operand, parts, n) {
    mnemonic = mnemonics[b, i]
    operand = operands_by_index[b, i]
    if (mnemonic ~ /^(leave|enter)/ && register == "%rbp") return 1
    if (mnemonic ~ /^(cmp|test|push|call|j|ret|nop|data16)/) return 0
    n = split(operand, parts, ",")
    return reg(parts[n]) == register || (mnemonic ~ /^(xchg|xadd)/ && reg(parts[1]) == register)
}
function proven_origin(b, at, register, todo, seen, parents, top, node, n, p, k, origin) {
    if (!tracked(register)) return 0
    todo[++top] = at
    while (top) {
        node = todo[top--]
        # Function entry and disconnected landing-pad entries start unknown.
        if (node == 1 || predecessors[b, node] == "") return 0
        if (node in seen) continue
        seen[node] = 1
        n = split(predecessors[b, node], parents, " ")
        for (k = 1; k <= n; k++) {
            p = parents[k]
            if (loaded_register(b, p) == register) {
                origin = 1
            } else if (clobbers(b, p, register)) {
                return 0
            } else {
                todo[++top] = p
            }
        }
    }
    return origin == 1
}
function resolve(line, operands, b, i, target, address, register) {
    if (operands ~ /^\*.*\(%rip\)/ && line ~ /#[[:space:]]*[[:xdigit:]]+/) {
        if (line ~ /<memcpy@/) return "memcpy"
        address = got_address(line)
        return address in got ? got[address] : "UNRESOLVED_RELATIVE_GOT:" address
    }
    if (operands ~ /^\*%/) {
        register = reg(operands)
        return proven_origin(b, i, register) ? "memcpy" : "UNRESOLVED_REGISTER:" register
    }
    if (operands ~ /^[[:xdigit:]]+$/ && (target = symbol(line)) != "")
        return target
    return "UNRESOLVED_TRANSFER:" operands
}
FILENAME == ARGV[1] {
    tab = index($0, "\t")
    if (tab != 0)
        got[normalize(substr($0, 1, tab - 1))] = canonical(substr($0, tab + 1))
    next
}
/^[[:space:]]*[[:xdigit:]]+ <.*>:/ { block++; next }
/^[[:space:]]*[[:xdigit:]]+:/ {
    if (!block) block = 1
    index_in_block = ++count[block]
    address = $1
    sub(/:$/, "", address)
    addresses[block, normalize(address)] = index_in_block
    mnemonics[block, index_in_block] = $2
    operands_by_index[block, index_in_block] = $3
    lines[block, index_in_block] = $0
}
END {
    if (mode != "sequence" && mode != "closure" && mode != "contains") exit 2
    for (b = 1; b <= block; b++) {
        # Direct control-flow predecessors, with no fallthrough after tails.
        for (i = 1; i <= count[b]; i++) {
            mnemonic = mnemonics[b, i]
            operands = operands_by_index[b, i]
            if (mnemonic ~ /^j/ && operands ~ /^[[:xdigit:]]+$/ &&
                    ((b, normalize(operands)) in addresses)) {
                target_index = addresses[b, normalize(operands)]
                predecessors[b, target_index] = predecessors[b, target_index] " " i
            }
            if (i < count[b] && mnemonic !~ /^(jmpq?|retq?|ud2|int3)$/)
                predecessors[b, i + 1] = predecessors[b, i + 1] " " i
        }
        for (i = 1; i <= count[b]; i++) {
            mnemonic = mnemonics[b, i]
            operands = operands_by_index[b, i]
            line = lines[b, i]
            internal = mnemonic ~ /^jmpq?$/ && operands ~ /^[[:xdigit:]]+$/ \
                && ((b, normalize(operands)) in addresses)
            if (mnemonic ~ /^callq?$/ || (mnemonic ~ /^jmpq?$/ && !internal)) {
                target = resolve(line, operands, b, i)
                if (mode == "sequence") print target
                if (mode == "closure" && (target ~ /^UNRESOLVED_/ || target !~ ("^(" policy ")$"))) {
                    print line
                    found = 1
                }
                if (mode == "contains" && target !~ /^UNRESOLVED_/ && target ~ ("(^|::)" policy "$"))
                    found = 1
            }
        }
    }
    if (mode == "contains") exit found ? 0 : 1
    if (mode == "closure") exit found ? 1 : 0
}
