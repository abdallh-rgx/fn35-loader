#!/usr/bin/env python3
"""disas_vtcall.py — decode the null-vtable crash site: find the function
containing 0x102a90c24, what x19 is, and what member +0x20 should hold."""
import sys
sys.path.insert(0, "/home/z/my-project/scripts")
from fn35_macho import MachO
import capstone

BIN = ("/home/z/my-project/fn35/extracted/Payload/"
       "FortniteClient.app/FortniteClient")
mo = MachO(BIN)
md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
md.skipdata = True


def read(va, n):
    return mo.read_va(va, n) if hasattr(mo, "read_va") else None


def find_owner(pc):
    name, addr = mo.nearest_symbol(pc) if hasattr(mo, "nearest_symbol") \
        else (None, None)
    return name, addr


# 1. owner of the crash site + the caller at 0x102b16638
for site in (0x102a90c24, 0x102b16638, 0x102a90c18):
    nm, sa = find_owner(site)
    print("0x%x: %s+0x%x" % (site, nm or "?", site - (sa or site)))

# 2. disassemble backwards from the crash: the function prologue is found
# by scanning for a stp x29 frame push below the crash pc
base = 0x102a90c24
blob = None
for s in mo.segments:
    if s.vmaddr <= base < s.vmaddr + s.filesize:
        off = base - s.vmaddr + s.fileoff - 256
        blob = open(BIN, "rb").read()[off:off + 256 + 64]
        break
insns = list(md.disasm(blob, base - 256))
for i in insns:
    print("0x%x  %-8s %s" % (i.address, i.mnemonic, i.op_str))
