#!/usr/bin/env python3
"""find_grow2.py — find code computing table+0x108 (chunks array base) near
the >>14 chunk math: add x?, x?, #0x108 OR ldr/str [x?, #0x108] anywhere in
the same function as an lsr#14."""
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

lsr14 = []
i = 0
while i + 4 <= len(buf):
    w = struct.unpack_from("<I", buf, i)[0]
    if (w & 0xFFC00000) == 0x53400000 and ((w >> 16) & 0x3F) == 14:
        lsr14.append(va + i)
    i += 4

hits = []
for site in lsr14:
    fo = site - va
    lo = max(0, fo - 0x200)
    hi = min(len(buf), fo + 0x200)
    code = buf[lo:hi]
    base = va + lo
    for ins in md.disasm(code, base):
        if ins.mnemonic == "add" and "#0x108" in ins.op_str:
            hits.append((site, ins.address, ins.op_str))
            break

print("lsr#14 + add#0x108 co-located: %d" % len(hits))
for s, a, o in hits:
    print("  lsr14@0x%x  add@0x%x: %s" % (s, a, o))
