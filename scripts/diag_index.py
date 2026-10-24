#!/usr/bin/env python3
"""diag_index.py — read the object index + chunk table state from crash snapshot."""
import sys, os, json, struct
sys.path.insert(0, "/home/z/my-project/scripts")

SNAP = "/home/z/my-project/fn35/snap_crash"
meta = json.load(open(os.path.join(SNAP, "index.json")))
CHUNK = 1 << 16

regions = meta["regions"]
_files = {}
def rdmem(addr, n):
    for r in regions:
        if r["begin"] <= addr and addr + n <= r["end"]:
            f = _files.get(r["file"])
            if f is None:
                f = open(os.path.join(SNAP, r["file"]), "rb")
                _files[r["file"]] = f
            out = b""
            a = addr
            left = n
            while left > 0:
                ci = (a - r["begin"]) // CHUNK
                off_in = (a - r["begin"]) % CHUNK
                if ci not in r["present"]:
                    return b"\x00" * n   # zero chunk
                f.seek(ci * CHUNK + off_in)
                take = min(left, CHUNK - off_in)
                d = f.read(take)
                out += d
                a += take
                left -= take
            return out
    return None

def rd32(a):
    d = rdmem(a, 4)
    return struct.unpack("<I", d)[0] if d else None

def rd64(a):
    d = rdmem(a, 8)
    return struct.unpack("<Q", d)[0] if d else None

# ---- the faulting index source: x19 (stack) ----
X19 = 0x700000bfe758
idx = rd32(X19)
print("index @0x%x = %d (0x%x)" % (X19, idx or -1, idx or 0))
if idx is not None:
    chunk = idx // 16384
    within = idx % 16384
    print("  -> chunk = %d, within = %d (0x%x)" % (chunk, within, within))
    print("  -> fault addr should be within*8 = 0x%x (observed 0x11d8)" % (within * 8))

# ---- registers of MainAppThread ----
from fn35_snap import _load_state
state = _load_state(os.path.join(SNAP, "state.pkl"))
main_t = None
for t in state["threads"].values():
    if t.name.startswith("of.MainAppThread"):
        main_t = t
        break
regs = getattr(main_t, "regs", {})
# unicorn arm64: X0=199..X28=227, FP=228, LR=229, SP=230? try
for name, num in (("x0",199),("x1",200),("x8",207),("x9",208),("x16",215),("x19",218),("x20",219),("x29",228),("x30",229)):
    v = regs.get(num)
    if v is not None:
        print("  %s = 0x%x" % (name, v & 0xFFFFFFFFFFFFFFFF))
print("  pc = 0x%x" % (regs.get(264, 0) & 0xFFFFFFFFFFFFFFFF))

# ---- chunk table state at x0=0x64000048faf0 ----
TAB = 0x64000048faf0
print("\nchunk table @0x%x:" % TAB)
nvalid = 0
for i in range(0, 40):
    p = rd64(TAB + i * 8)
    if p:
        nvalid += 1
        if i < 24 or p is None:
            print("  chunk[%d] = 0x%x" % (i, p))
    elif i < 24:
        print("  chunk[%d] = NULL" % i)
print("valid chunks in first 40 slots: %d" % nvalid)

# what does the table look like AROUND the needed chunk?
if idx is not None:
    chunk = idx // 16384
    for i in range(max(0, chunk - 3), chunk + 3):
        p = rd64(TAB + i * 8)
        print("  [need] chunk[%d] = %s" % (i, hex(p) if p else "NULL"))
