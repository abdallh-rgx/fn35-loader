#!/usr/bin/env python3
"""disas_crash.py — disassemble around the crash return addresses.

The crash snapshot gave us stack return addrs. The deepest (most recent)
is 0x103691e42 (its frame slot at sp+0x20). Disassemble backwards/forwards
around each to identify the call instruction that jumped to NULL.
"""
import sys

sys.path.insert(0, "/home/z/my-project/scripts")
from fn35_macho import MachO

BIN = ("/home/z/my-project/fn35/extracted/Payload/"
       "FortniteClient.app/FortniteClient")

import capstone

md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
md.detail = False

mo = MachO(BIN)


def vaddr_to_off(va):
    for s in mo.segments:
        if s.vmaddr <= va < s.vmaddr + s.vmsize:
            return s.fileoff + (va - s.vmaddr)
    return None


def show(va, back=96, fwd=24, label=""):
    off = vaddr_to_off(va)
    if off is None:
        print("?? %s va=0x%x not mapped" % (label, va))
        return
    with open(BIN, "rb") as f:
        f.seek(max(0, off - back))
        code = f.read(back + fwd)
    start_va = va - back
    print("=== %s around 0x%x (call site: lr) ===" % (label, va))
    # capstone stops at the first undecodable word; a mid-instruction
    # start yields nothing. Slide the start until the window decodes
    # all the way past the target.
    for slide in range(0, back, 4):
        got = list(md.disasm(code[slide:], start_va + slide))
        if got and got[-1].address >= va - 4:
            for ins in got:
                hit = " <<< RETURN ADDR" if ins.address <= va - 4 \
                    < ins.address + ins.size else ""
                print("  0x%x  %-8s %-40s%s"
                      % (ins.address, ins.mnemonic, ins.op_str, hit))
            print()
            return
    print("  (no decode with any alignment)\n")


def is_call_site(va):
    """True if the instruction right BEFORE va is a bl/blr (a return
    address always follows its call instruction)."""
    off = vaddr_to_off(va - 4)
    if off is None:
        return False
    with open(BIN, "rb") as f:
        f.seek(off)
        b = f.read(4)
    if len(b) < 4:
        return False
    w = int.from_bytes(b, "little")
    # BL  imm26: 100101 xx...  (bits 31..26 == 100101)
    if (w >> 26) == 0b100101:
        return True
    # BLR Xn: 1101011 0000 1111 0000 00 Rn 00000
    if (w & 0xFFFFFC1F) == 0xD63F0000:
        return True
    # BR Xn:  1101011 0000 1111 0000 00 Rn 00000
    if (w & 0xFFFFFC1F) == 0xD61F0000:
        return True
    return False


if __name__ == "__main__":
    # stack return addresses from the crash scan (sp + off)
    slots = [
        (0x020, 0x103691e42), (0x028, 0x1057d0000), (0x030, 0x103465086),
        (0x048, 0x10273abec), (0x058, 0x100ff6740), (0x088, 0x10233cadc),
        (0x138, 0x10188acf0), (0x158, 0x100e56b98), (0x178, 0x1011a3638),
        (0x200, 0x105569b40), (0x228, 0x100dcbfd8), (0x238, 0x1026e8c74),
        (0x248, 0x100a02e18), (0x260, 0x1033d8124), (0x268, 0x1034fb57a),
        (0x278, 0x1055cbd30), (0x280, 0x1055cbd80), (0x2d0, 0x105569b40),
    ]
    if len(sys.argv) > 1:
        slots = [(0, int(x, 0)) for x in sys.argv[1:]]
    for off, va in slots:
        tag = "CALL-SITE" if is_call_site(va) else "data-ptr"
        print("+0x%03x 0x%x  %s" % (off, va, tag))
    print()
    # show context only for real call sites
    for off, va in slots:
        if is_call_site(va):
            show(va, label="+0x%03x" % off)
