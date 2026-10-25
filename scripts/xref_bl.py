#!/usr/bin/env python3
"""xref_bl.py — find all `bl target` call sites by scanning __TEXT words."""
import sys, struct
sys.path.insert(0, "/home/z/my-project/scripts")
from fn35_macho import MachO

TARGET = int(sys.argv[1], 0)
mo = MachO("/home/z/my-project/fn35/extracted/Payload/FortniteClient.app/FortniteClient")
mo.load_symbols()
syms = sorted((a, n) for n, a in mo.symbols.items()) if hasattr(mo, "symbols") else []
import bisect
addrs = [a for a, _ in syms]
names = {a: n for a, n in syms}

hits = []
for seg in mo.segments:
    if seg.name in ("__PAGEZERO",) or seg.filesize == 0:
        continue
    if seg.vmaddr > TARGET or TARGET >= seg.vmaddr + seg.vmsize:
        # only scan __TEXT (executable); still, bl only exists there
        if seg.name not in ("__TEXT",):
            continue
    if seg.name != "__TEXT":
        continue
    with open(mo.path, "rb") as f:
        f.seek(seg.fileoff)
        data = f.read(seg.filesize)
    base = seg.vmaddr
    n = len(data)
    for off in range(0, n - 3, 4):
        w = struct.unpack_from("<I", data, off)[0]
        if (w >> 26) == 0x25:  # BL
            imm = w & 0x3FFFFFF
            if imm & 0x2000000:
                imm -= 1 << 26
            tgt = base + off + (imm << 2)
            if tgt == TARGET:
                va = base + off
                k = bisect.bisect_right(addrs, va) - 1
                nm = names.get(addrs[k], "?") if k >= 0 else "?"
                hits.append((va, nm, addrs[k] if k >= 0 else 0))
print("call sites of 0x%x: %d" % (TARGET, len(hits)))
for va, nm, sa in hits[:30]:
    print("  0x%x  %s+0x%x" % (va, nm[:52], va - sa))
