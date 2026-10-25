#!/usr/bin/env python3
"""Find the address of the 'Failed to read file' cstring + all code refs.

Stage 1: locate the string bytes in the read-only data.
Stage 2: linear-sweep __TEXT for adrp+add/ldr pairs hitting it.
"""
import sys, struct
sys.path.insert(0, "/home/z/my-project/scripts")
from fn35_macho import MachO

BIN = "/home/z/my-project/fn35/extracted/Payload/FortniteClient.app/FortniteClient"
mo = MachO(BIN)

# ---- stage 1: find the string in the mapped file ----
needles = [b"Failed to read file \x00", b"Failed to read file\x00",
           b"Could not find a valid project file\x00"]
found = {}
with open(BIN, "rb") as f:
    blob = f.read()
for nd in needles:
    i = 0
    while True:
        i = blob.find(nd, i)
        if i < 0:
            break
        # file offset -> vmaddr
        for seg in mo.segments:
            if seg.fileoff <= i < seg.fileoff + seg.filesize:
                va = seg.vmaddr + (i - seg.fileoff)
                found.setdefault(nd, []).append(va)
        i += 1
for nd, vas in found.items():
    print("%r -> %s" % (nd, [hex(v) for v in vas]))

# ---- stage 2: xref via adrp sweep ----
import capstone
md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_LITTLE_ENDIAN)
md.skipdata = True

seg = [s for s in mo.segments if s.name == "__TEXT"][0]
text = blob[seg.fileoff:seg.fileoff + seg.filesize]
base = seg.vmaddr

targets = set()
for vas in found.values():
    targets.update(vas)
pages = {t & ~0xFFF for t in targets}

n = len(text) // 4
words = struct.unpack("<%dI" % n, text[:n * 4])
hits = []
for i, w in enumerate(words):
    if (w >> 24) == 0x90 and ((w >> 29) & 3) == 1:      # adrp page-imm form
        # decode: op=1 (adrp), immlo=(w>>29)&3, immhi=(w>>5)&0x7ffff
        rd = w & 0x1F
        immlo = (w >> 29) & 3
        immhi = (w >> 5) & 0x7FFFF
        imm = (immhi << 2) | immlo
        if imm & (1 << 20):
            imm -= 1 << 21
        page = (base + i * 4) & ~0xFFF
        tgt_page = page + (imm << 12)
        if tgt_page in pages:
            pc = base + i * 4
            # next 4 instrs: add xN, xN, #lo12 or ldr xN, [xN, #off]
            for j in range(1, 5):
                w2 = words[i + j] if i + j < n else 0
                if (w2 & 0xFF800000) == 0x91000000:   # add imm
                    rn2 = (w2 >> 5) & 0x1F
                    if rn2 == rd:
                        imm12 = (w2 >> 10) & 0xFFF
                        if tgt_page + imm12 in targets:
                            hits.append((pc, tgt_page + imm12))
                            break
                elif (w2 & 0xFFC00000) == 0xF9400000:  # ldr imm unsigned
                    rn2 = (w2 >> 5) & 0x1F
                    if rn2 == rd:
                        off = ((w2 >> 10) & 0xFFF) * 8
                        if tgt_page + off in targets:
                            hits.append((pc, tgt_page + off))
                            break
print("\ncode refs (adrp site -> string):")
for pc, sv in hits:
    print("  adrp@0x%x -> 0x%x" % (pc, sv))
