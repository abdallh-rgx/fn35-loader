#!/usr/bin/env python3
"""xref2.py — find ADRP refs to a PAGE, list following instrs."""
import sys, struct
sys.path.insert(0, "/home/z/my-project/scripts")
from fn35_macho import MachO
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM

mo = MachO("/home/z/my-project/fn35/extracted/Payload/FortniteClient.app/FortniteClient")
mo.load_symbols()
TEXT = None
for s in mo.segments:
    if s.name == "__TEXT":
        TEXT = (s.vmaddr, s.fileoff, s.filesize)
va, off, size = TEXT
buf = mo.buf[off:off + size]

tpage = int(sys.argv[1], 0) & ~0xFFF
limit = int(sys.argv[2], 0) if len(sys.argv) > 2 else 40

hits = []
i = 0
n = len(buf) - 8
while i < n:
    w = struct.unpack_from("<I", buf, i)[0]
    if (w >> 31) == 1 and ((w >> 24) & 0x1F) == 0x10:
        immlo = (w >> 29) & 0x3
        immhi = (w >> 5) & 0x7FFFF
        imm = (immhi << 2) | immlo
        if imm & (1 << 20):
            imm -= 1 << 21
        page = ((va + i) & ~0xFFF) + (imm << 12)
        if page == tpage:
            hits.append(va + i)
    i += 4
    if len(hits) >= limit:
        break

md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
print("ADRP -> page 0x%x : %d hits" % (tpage, len(hits)))
for h in hits[:12]:
    print("--- at 0x%x ---" % h)
    code = mo.buf[off + (h - va): off + (h - va) + 24]
    for ins in md.disasm(code, h):
        print("   0x%x %-9s %s" % (ins.address, ins.mnemonic, ins.op_str))
