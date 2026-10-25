#!/usr/bin/env python3
"""xref.py — find ADRP+ADD references to a target address in __TEXT."""
import sys, struct
sys.path.insert(0, "/home/z/my-project/scripts")
from fn35_macho import MachO

mo = MachO("/home/z/my-project/fn35/extracted/Payload/FortniteClient.app/FortniteClient")
mo.load_symbols()

TEXT = None
for s in mo.segments:
    if s.name == "__TEXT":
        TEXT = (s.vmaddr, s.fileoff, s.filesize)
va, off, size = TEXT
buf = mo.buf[off:off + size]

target = int(sys.argv[1], 0)          # e.g. 0x1036dc0b4
tpage = target & ~0xFFF
tlow = target & 0xFFF

hits = []
i = 0
n = len(buf) - 8
while i < n:
    w = struct.unpack_from("<I", buf, i)[0]
    # ADRP: op=1, 10010, immlo bits 30-29, immhi bits 23-5
    if (w >> 31) == 1 and ((w >> 24) & 0x1F) == 0x10:
        immlo = (w >> 29) & 0x3
        immhi = (w >> 5) & 0x7FFFF
        imm = (immhi << 2) | immlo
        if imm & (1 << 20):
            imm -= 1 << 21
        page = ((va + i) & ~0xFFF) + (imm << 12)
        if page == tpage:
            # check next insn for ADD imm == tlow (add Xd, Xn, #imm)
            w2 = struct.unpack_from("<I", buf, i + 4)[0]
            # ADD imm: 100010 sh imm12 Rn Rd
            if (w2 & 0x7F000000) == 0x11000000:
                imm12 = (w2 >> 10) & 0xFFF
                if imm12 == tlow:
                    hits.append(va + i)
    i += 4

print("xrefs to 0x%x: %s" % (target, [hex(h) for h in hits]))
