#!/usr/bin/env python3
"""Disassemble the other LOOP-FN caller + find CALLER-A prologue."""
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

print("=== other LOOP-FN caller @ 0x101756668 ===")
data = read_at(0x101756620, 0x70)
for ins in md.disasm(data, 0x101756620):
    mark = " <== BL" if ins.address == 0x101756668 else ""
    print("0x%x: %-8s %s%s" % (ins.address, ins.mnemonic, ins.op_str, mark))

print()
print("=== CALLER-A prologue search (0x1018859c0..0x101885b10) ===")
data = read_at(0x1018859c0, 0x150)
for ins in md.disasm(data, 0x1018859c0):
    if ins.mnemonic in ("stp", "sub", "pacibsp") and "sp" in ins.op_str.split(",")[0]:
        print("0x%x: %-8s %s   <<< candidate prologue" %
              (ins.address, ins.mnemonic, ins.op_str))
    elif ins.mnemonic == "ret":
        print("0x%x: ret" % ins.address)

# find BL xrefs to CALLER-A start candidates afterwards
print()
print("=== CALLER-A body: 0x101885ae0..0x101885c30 ===")
data = read_at(0x101885ae0, 0x160)
for ins in md.disasm(data, 0x101885ae0):
    print("0x%x: %-8s %s" % (ins.address, ins.mnemonic, ins.op_str))
