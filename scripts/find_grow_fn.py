#!/usr/bin/env python3
"""find_grow_fn.py — find the function that WRITES chunk pointers into a
table passed in a register: pattern = lsr w?,w?,#14 near str [x?,#0x108],
or any 'str x,[x,#0x108]' co-located with >>14 chunk math."""
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

# 1. collect lsr#14 sites
lsr14 = []
i = 0
while i + 4 <= len(buf):
    w = struct.unpack_from("<I", buf, i)[0]
    if (w & 0xFFC00000) == 0x53400000 and ((w >> 16) & 0x3F) == 14:
        lsr14.append(va + i)
    i += 4
print("lsr#14 sites: %d" % len(lsr14))

# 2. for each, disassemble +-0x180 and look for stores with #0x108 offset
found = []
for site in lsr14:
    fo = site - va
    lo = max(0, fo - 0x180)
    code = buf[lo:fo + 0x180]
    base = va + lo
    has_store = False
    txt = []
    for ins in md.disasm(code, base):
        txt.append((ins.address, ins.mnemonic, ins.op_str))
        if ins.mnemonic.startswith("st") and "#0x108" in ins.op_str:
            has_store = True
    if has_store:
        found.append((site, txt))

print("sites with a store [+0x108] nearby: %d\n" % len(found))
for site, txt in found[:8]:
    print("=== around lsr14 @ 0x%x ===" % site)
    for a, m, o in txt:
        mark = " <<<" if abs(a - site) < 8 else ""
        print("  0x%x  %-6s %s%s" % (a, m, o, mark))
    print()
