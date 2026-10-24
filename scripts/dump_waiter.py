#!/usr/bin/env python3
"""dump_waiter.py — inspect the object a spinning thread waits on (vtable + fields)."""
import sys, os, json, struct
sys.path.insert(0, "/home/z/my-project/scripts")
from fn35_snap import _load_state
import unicorn.arm64_const as a64

SNAP = "/home/z/my-project/fn35/snap"
meta = json.load(open(os.path.join(SNAP, "index.json")))
CHUNK = 1 << 16
_files, _pmaps = {}, {}
def rd64(a):
    for r in meta["regions"]:
        if r["begin"] <= a and a + 8 <= r["end"]:
            f = _files.get(r["file"])
            if f is None and r["file"]:
                f = open(os.path.join(SNAP, r["file"]), "rb"); _files[r["file"]] = f
            if f is None:
                return 0
            pmap = _pmaps.setdefault(r["file"], {})
            if not pmap:
                for pos, c in enumerate(r["present"]):
                    pmap[c] = pos * CHUNK
            ci = (a - r["begin"]) // CHUNK
            off = (a - r["begin"]) % CHUNK
            if ci not in pmap:
                return 0
            f.seek(pmap[ci] + off)
            d = f.read(8)
            return struct.unpack("<Q", d)[0] if len(d) == 8 else 0
    return None

state = _load_state(os.path.join(SNAP, "state.pkl"))
for t in state["threads"].values():
    if t.tid not in (0x18b0, 0x1be8, 0x1010):
        continue
    regs = t.regs or {}
    x19 = regs.get(a64.UC_ARM64_REG_X19, 0)
    print("=== tid=0x%x pc=0x%x x19=0x%x" % (t.tid, regs.get(a64.UC_ARM64_REG_PC, 0), x19))
    if not x19:
        continue
    vt = rd64(x19)
    print("  [x19+0x00] vtable = 0x%x" % vt)
    for off in (0x90, 0x98, 0xa0, 0xf8, 0x100, 0x108, 0x110, 0x118):
        print("  [x19+0x%03x] = 0x%x" % (off, rd64(x19 + off) or 0))
    # first vtable entries
    if vt:
        for i in range(6):
            v = rd64(vt + 8 * i)
            print("  vt[%d] = 0x%x" % (i, v or 0))
