#!/usr/bin/env python3
"""xref_string.py — find code referencing the two "Missing global shader"
strings via a full linear capstone sweep of __TEXT.

Handles all reference styles (adrp+add, adrp+ldr-literal, etc.) by
decoding adrp targets and following the next few instructions.
"""
import sys

sys.path.insert(0, "/home/z/my-project/scripts")
from fn35_macho import MachO
import capstone

BIN = ("/home/z/my-project/fn35/extracted/Payload/"
       "FortniteClient.app/FortniteClient")
STRS = [0x103562b06, 0x1037072fe]

mo = MachO(BIN)
md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
md.skipdata = True

seg = [s for s in mo.segments if s.name == "__TEXT"][0]
with open(BIN, "rb") as f:
    f.seek(seg.fileoff)
    text = f.read(seg.filesize)

pages = {s & ~0xFFF: s for s in STRS}

# linear sweep; collect adrp results
refs = {}
base = seg.vmaddr
for ins in md.disasm(text, base):
    if ins.mnemonic == "adrp":
        try:
            tgt = int(ins.op_str.split(", ")[1].replace("#", ""), 0)
        except Exception:
            continue
        if tgt in pages:
            refs.setdefault(tgt, []).append(ins.address)
    if ins.mnemonic in ("b", "ret"):
        continue

for page, lst in refs.items():
    print("=== refs to page 0x%x (string +0x%x) ===" % (page,
                                                         pages[page] & 0xFFF))
    for a in lst:
        print("  adrp @ 0x%x" % a)
        # show the following instructions
        off = a - base
        code = text[off:off + 24]
        for i2 in md.disasm(code, a):
            print("    0x%x  %-8s %s" % (i2.address, i2.mnemonic,
                                          i2.op_str))
