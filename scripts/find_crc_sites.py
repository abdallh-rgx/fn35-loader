#!/usr/bin/env python3
"""find_crc_sites.py — locate every ARMv8 CRC32 instruction in __TEXT."""
import sys, struct
sys.path.insert(0, "/home/z/my-project/scripts")
from fn35_macho import MachO
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM

VARY = 0x800f1c87
FIXED0 = 0x6530a358
CONST1 = 0x1ac04020 & ~VARY & 0xFFFFFFFF   # fixed one-bits

mo = MachO("/home/z/my-project/fn35/extracted/Payload/FortniteClient.app/FortniteClient")
mo.load_symbols()
cs = Cs(CS_ARCH_ARM64, CS_MODE_ARM)

sites = []
for seg in mo.segments:
    if seg.name != "__TEXT" or seg.filesize == 0:
        continue
    with open(mo.path, "rb") as f:
        f.seek(seg.fileoff)
        data = f.read(seg.filesize)
    for off in range(0, len(data) - 3, 4):
        w = struct.unpack_from("<I", data, off)[0]
        if (w & ~VARY & 0xFFFFFFFF) == CONST1 and not (w & FIXED0):
            va = seg.vmaddr + off
            ins = next(cs.disasm(data[off:off+4], va), None)
            if ins and ins.mnemonic.startswith("crc32"):
                sites.append((va, ins.mnemonic, ins.op_str))

print("crc32 instruction sites: %d" % len(sites))
from collections import Counter
print(Counter(m for _, m, _ in sites))
for va, m, ops in sites[:15]:
    print("  0x%x  %s %s" % (va, m, ops))
