#!/usr/bin/env python3
"""find_16384_cluster.py — find all functions using the 16384-entry chunking
(lsr w?, w?, #0xe) and/or umaddl-by-24, then group into clusters to locate
the missing GROW/INIT side of the 0x1056ecfb8 table."""
import sys, struct
sys.path.insert(0, "/home/z/my-project/scripts")
from fn35_macho import MachO
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM

mo = MachO("/home/z/my-project/fn35/extracted/Payload/FortniteClient.app/FortniteClient")
va, off, size = None, None, None
for s in mo.segments:
    if s.name == "__TEXT":
        va, off, size = s.vmaddr, s.fileoff, s.filesize
buf = mo.buf[off:off + size]
md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)

# scan for lsr wD, wN, #0xe  (chunk = index >> 14)
sites = []
i = 0
while i + 4 <= len(buf):
    w = struct.unpack_from("<I", buf, i)[0]
    # LSL (immediate) / LSR (immediate): sf=0 opc=01 -> 0x13xxxxxx variants
    # LSR Wd, Wn, #imm: 0x53... with shift; easier: decode via capstone on hits
    if (w & 0xFF80001F) == 0x53000000 | (14 << 16):  # rough
        pass
    if (w >> 23) == (0x130 >> 1) or True:
        pass
    i += 4

# simpler: full linear disasm in 1MB windows is slow; use raw word pattern:
# LSR Wd, Wn, #14 == 0x53 0x03 0x80 ... let's compute: sf=0, opc=01, 100101
# bits: 0 0 1 1 0 0 1 0 1  imm6=001110  Rn Rd
# byte little-endian: Rd | (Rn<<5) | (14<<10) | (0x69400000>>?) ...
# Just use: (w & 0xFFC00000) == 0x53400000 and ((w>>16)&0x3F)==14
i = 0
hits = []
while i + 4 <= len(buf):
    w = struct.unpack_from("<I", buf, i)[0]
    if (w & 0xFFC00000) == 0x53400000 and ((w >> 16) & 0x3F) == 14:
        hits.append(va + i)
    i += 4
print("lsr #14 sites: %d" % len(hits))

# umaddl/madd with 24: "mov w10, #0x18" = 0x52800300 + reg bits
mov24 = []
i = 0
while i + 4 <= len(buf):
    w = struct.unpack_from("<I", buf, i)[0]
    if (w & 0xFFE0001F) == 0x52800000 | (24 << 5) and ((w >> 5) & 0xFFFF) >> 0:
        if ((w >> 5) & 0x1FFFFF) == 24 << 0:
            pass
    # MOV Wd, #24: sf=0 opc=10 100101 hw=00 imm16=24
    if (w & 0xFFE00000) == 0x52800000 and ((w >> 5) & 0xFFFF) == 24:
        mov24.append(va + i)
    i += 4
print("mov w?, #24 sites: %d" % len(mov24))

# cluster hits: for each lsr14 site, check ±0x40 for mov24
both = []
for h in hits:
    for m in mov24:
        if abs(m - h) < 0x60:
            both.append((h, m))
            break
print("\nsites with BOTH (the 16384x24 pattern): %d" % len(both))
for h, m in both:
    print("  lsr14@0x%x  mov24@0x%x (d=%+d)" % (h, m, m - h))
