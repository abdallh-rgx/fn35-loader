#!/usr/bin/env python3
"""find_uproject_reader.py — locate code referencing the
'Failed to read file' / uproject-related strings, then disassemble the
referencing function to see WHICH file API it calls (fopen vs open vs
ifstream)."""
import sys, struct
sys.path.insert(0, "/home/z/my-project/scripts")
from fn35_macho import MachO
import capstone

BIN = ("/home/z/my-project/fn35/extracted/Payload/"
       "FortniteClient.app/FortniteClient")
mo = MachO(BIN)
md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
md.skipdata = True

# find the string in __TEXT or __cstring... search ALL file bytes
with open(BIN, "rb") as f:
    blob = f.read()

def find_str(s):
    out = []
    b = s.encode() + b"\x00"
    start = 0
    while True:
        i = blob.find(b, start)
        if i < 0:
            break
        # convert file offset -> vmaddr
        va = mo.off2va(i)
        if va:
            out.append(va)
        start = i + 1
        if len(out) > 6:
            break
    return out

for s in ("Failed to read file", "FortniteGame.uproject",
          "Could not find a valid project file"):
    addrs = find_str(s)
    print("%r -> %s" % (s, [hex(a) for a in addrs]))

# now sweep __TEXT for adrp+add referencing the first 'Failed to read file'
target_sets = find_str("Failed to read file")
seg = [s for s in mo.segments if s.name == "__TEXT"][0]
with open(BIN, "rb") as f:
    f.seek(seg.fileoff)
    text = f.read(seg.filesize)

hits = []
i = 0
n = len(text) - 8
adrp_cache = {}
while i < n:
    w = struct.unpack_from("<I", text, i)[0]
    pc = seg.vmaddr + i
    if (w >> 24) == 0x90:  # adrp
        immlo = (w >> 29) & 3
        immhi = (w >> 5) & 0x7FFFF
        imm = (immhi << 2) | immlo
        if imm & 0x100000:
            imm -= 0x200000
        page = (pc & ~0xFFF) + (imm << 12)
        rd = w & 0x1F
        adrp_cache[rd] = (pc, page)
    else:
        # add xD, xN, #imm (0x91xxxxxx)
        if (w & 0xFF000000) == 0x91000000:
            rd = w & 0x1F
            rn = (w >> 5) & 0x1F
            imm12 = (w >> 10) & 0xFFF
            sh = (w >> 22) & 3
            if rn in adrp_cache:
                pc0, page = adrp_cache[rn]
                if pc - pc0 < 0x40:
                    va = page + (imm12 << (12 if sh else 0))
                    for t in target_sets:
                        if t - 0x20 <= va <= t + 0x20 or va == t:
                            hits.append((pc0, pc, va))
    i += 4

print("\nadrp+add refs near 'Failed to read file': %d" % len(hits))
for pc0, pc, va in hits[:8]:
    print("  adrp@0x%x add@0x%x -> str@0x%x" % (pc0, pc, va))
