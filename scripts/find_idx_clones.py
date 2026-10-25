#!/usr/bin/env python3
"""find_idx_clones.py — locate all IndexToObject-style chunk-table lookups (real bytes)."""
import sys, struct
sys.path.insert(0, "/home/z/my-project/scripts")
from fn35_macho import MachO
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM

mo = MachO("/home/z/my-project/fn35/extracted/Payload/FortniteClient.app/FortniteClient")
mo.load_symbols()
syms = sorted(mo.symbols.items(), key=lambda kv: kv[1]) if hasattr(mo, "symbols") else []

def read_at(va, n):
    for seg in mo.segments:
        if seg.name in ("__PAGEZERO",) or seg.filesize == 0:
            continue
        if seg.vmaddr <= va and va + n <= seg.vmaddr + seg.filesize:
            with open(mo.path, "rb") as f:
                f.seek(seg.fileoff + va - seg.vmaddr)
                return f.read(n)
    return None

# canonical bytes from the known crash site
real = read_at(0x102def954, 20)
print("site bytes:", real.hex())
cs = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
for i in cs.disasm(real, 0x102def954):
    print("  0x%x %s %s" % (i.address, i.mnemonic, i.op_str))

hits = []
for seg in mo.segments:
    if seg.name in ("__PAGEZERO",) or seg.filesize == 0:
        continue
    with open(mo.path, "rb") as f:
        f.seek(seg.fileoff)
        data = f.read(seg.filesize)
    off = 0
    while True:
        i = data.find(real, off)
        if i < 0:
            break
        va = seg.vmaddr + i + 20  # position of the faulting ldr pair
        hits.append(va)
        off = i + 4
print("clone sites (first ldr): %d" % len(hits))
import bisect
addrs = [a for _, a in syms]
names = {a: n for n, a in syms}
for va in hits:
    k = bisect.bisect_right(addrs, va) - 1
    nm = names[addrs[k]] if k >= 0 else "?"
    print("  0x%x  %s+0x%x" % (va, nm[:56], va - addrs[k] if k >= 0 else 0))
