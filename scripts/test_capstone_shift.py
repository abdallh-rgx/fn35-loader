#!/usr/bin/env python3
"""Verify capstone's shift representation for uxtw-indexed loads
(the DSR address computation depends on it)."""
import capstone, struct
from capstone.arm64 import ARM64_OP_MEM

md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_LITTLE_ENDIAN)
md.detail = True

def ldr_reg_off(rt, rn, rm, option, s):
    return ((0b1011100101 << 23) | (rm << 20) | (option << 13) |
            (s << 12) | (rn << 5) | rt) & 0xFFFFFFFF

cases = [
    ("ldr w8,[x21,w8,uxtw#2]", 8, 21, 8, 0b011, 1),
    ("ldr w8,[x21,w8,uxtw#0]", 8, 21, 8, 0b011, 0),
    ("ldr w8,[x21,w8,lsl#2]", 8, 21, 8, 0b011, 1),   # lsl = option 011 on 64-bit base
]
for label, rt, rn, rm, opt, s in cases:
    b = struct.pack("<I", ldr_reg_off(rt, rn, rm, opt, s))
    try:
        ins = next(md.disasm(b, 0))
    except StopIteration:
        print(label, "no decode for word 0x%08x" % ldr_reg_off(rt, rn, rm, opt, s))
        continue
    mos = [o for o in ins.operands if o.type == ARM64_OP_MEM]
    if mos:
        mo = mos[0]
        print("%-26s %-6s %-26s shift=%r" % (label, ins.mnemonic,
                                             ins.op_str, mo.shift))
    else:
        print("%-26s %-6s %-26s (no mem operand! ops=%r)"
              % (label, ins.mnemonic, ins.op_str,
                 [(o.type) for o in ins.operands]))
