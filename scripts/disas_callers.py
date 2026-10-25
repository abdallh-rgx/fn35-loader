#!/usr/bin/env python3
"""Disassemble around the spin-loop callers from the frame chain."""
import sys
sys.path.insert(0, "/home/z/my-project/scripts")
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN
from fn35_macho import MachO

BIN = "/home/z/my-project/fn35/extracted/Payload/FortniteClient.app/FortniteClient"
mo = MachO(BIN)

def read_at(va, n):
    for seg in mo.segments:
        if seg.vmaddr <= va < seg.vmaddr + seg.vmsize:
            with open(BIN, "rb") as f:
                f.seek(seg.fileoff + (va - seg.vmaddr))
                return f.read(n)
    return None

md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
for lr, ctx in ((0x1026e0c28, "caller-B (calls the loop)"),
                (0x101885c24, "caller-A (outer)")):
    print("=== %s lr=0x%x ===" % (ctx, lr))
    data = read_at(lr - 0x60, 0xc0)
    for ins in md.disasm(data, lr - 0x60):
        mark = " <== RET-HERE" if ins.address == lr else ""
        print("0x%x: %-8s %s%s" % (ins.address, ins.mnemonic, ins.op_str, mark))
    print()
