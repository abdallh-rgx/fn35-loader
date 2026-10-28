#!/usr/bin/env python3
"""symbolize: map guest PCs to nearest binary symbols (lower_bound)."""
import sys, bisect
sys.path.insert(0, "/home/z/my-project/scripts")
import fn35_macho

mo = fn35_macho.MachO(
    "/home/z/my-project/fn35/extracted/Payload/"
    "FortniteClient.app/FortniteClient")
mo.load_symbols()
syms = []
for s in mo.syms:
    if not s.value:
        continue
    try:
        nm = mo.cstr_at(mo.stroff + s.strx)
    except Exception:
        nm = None
    if nm:
        syms.append((s.value, nm))
syms.sort()
addrs = [a for a, _ in syms]

def sym_of(pc):
    i = bisect.bisect_right(addrs, pc) - 1
    if i < 0:
        return "?"
    a, n = syms[i]
    return "%s+0x%x" % (n, pc - a)

for arg in sys.argv[1:]:
    pc = int(arg, 0)
    print("0x%x -> %s" % (pc, sym_of(pc)))
