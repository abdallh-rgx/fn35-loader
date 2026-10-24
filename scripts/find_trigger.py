#!/usr/bin/env python3
"""find_trigger.py — locate the Trigger (stlr [x?, #0x98]) counterpart of the spin wait."""
import sys
sys.path.insert(0, "/home/z/my-project/scripts")
from fn35_macho import MachO
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
import keystone

ks = keystone.Ks(keystone.KS_ARCH_ARM64, keystone.KS_MODE_LITTLE_ENDIAN)
cs = Cs(CS_ARCH_ARM64, CS_MODE_ARM)

mo = MachO("/home/z/my-project/fn35/extracted/Payload/FortniteClient.app/FortniteClient")
mo.load_symbols()

# stlr wN, [xM, #0x98] variants for w0..w9, x19..x23
encs = {}
for rn in range(10):
    for base in (19, 20, 21, 22, 23, 0, 1):
        try:
            e, _ = ks.asm("stlr w%d, [x%d, #0x98]" % (rn, base))
            encs[bytes(e)] = ("stlr w%d, [x%d, #0x98]" % (rn, base))
        except Exception:
            pass

hits = []
for seg in mo.segments:
    if seg.name in ("__PAGEZERO",) or seg.filesize == 0:
        continue
    with open(mo.path, "rb") as f:
        f.seek(seg.fileoff)
        data = f.read(seg.filesize)
    for pat, desc in encs.items():
        off = 0
        while True:
            i = data.find(pat, off)
            if i < 0:
                break
            va = seg.vmaddr + i
            hits.append((va, desc))
            off = i + 4
print("trigger candidates (stlr .. #0x98): %d" % len(hits))
syms = sorted((a, n) for n, a in (mo.symtab or {}).items()) if hasattr(mo, 'symtab') else []
import bisect
addrs = [a for a, _ in syms]
names = {a: n for a, n in syms}
for va, desc in hits[:40]:
    k = bisect.bisect_right(addrs, va) - 1
    nm = names[addrs[k]] if k >= 0 else "?"
    print("  0x%x  %-28s in %s+0x%x" % (va, desc, nm[:40], va - addrs[k] if k >= 0 else 0))
