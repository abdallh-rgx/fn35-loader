#!/usr/bin/env python3
"""Disassemble the MainAppThread spin region (segAN heartbeat samples)."""
import sys
sys.path.insert(0, "/home/z/my-project/scripts")
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN
from fn35_macho import MachO

mo = MachO("/home/z/my-project/fn35/extracted/Payload/FortniteClient.app/FortniteClient")

# the full obfuscated loop body (heartbeat PCs + dispatch tables)
pcs = set()
lo = 0x101838ab0
hi = 0x101839660

# translate vmaddr -> file offset via segments
off = None
for seg in mo.segments:
    if seg.vmaddr <= lo < seg.vmaddr + seg.vmsize:
        off = seg.fileoff + (lo - seg.vmaddr)
        break
assert off is not None, "vmaddr not in any segment"
with open("/home/z/my-project/fn35/extracted/Payload/FortniteClient.app/FortniteClient", "rb") as f:
    f.seek(off)
    data = f.read(hi - lo)
md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
print("=== region 0x%x..0x%x ===" % (lo, hi))
for ins in md.disasm(data, lo):
    mark = " <== HB" if ins.address in pcs else ""
    print("0x%x: %-8s %s%s" % (ins.address, ins.mnemonic, ins.op_str, mark))
