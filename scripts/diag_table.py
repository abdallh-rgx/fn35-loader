#!/usr/bin/env python3
"""diag_table.py — inspect the 24B-entry chunk table at 0x1056ecfb8 from a
snapshot (default snapA_crash). Handles the sparse chunked format:
region = {begin, end, perms, chunksz, file, present: [chunk indices]}."""
import sys, os, json, struct

snap = sys.argv[1] if len(sys.argv) > 1 else "/home/z/my-project/fn35/snapA_crash"
idx = json.load(open(os.path.join(snap, "index.json")))
regions = idx["regions"]
fhandles = {}

def read_mem(addr, n):
    for r in regions:
        b, e = r["begin"], r["end"]
        if b <= addr and addr + n <= e:
            csz = r.get("chunksz", 65536)
            ci = (addr - b) // csz
            off = (addr - b) % csz
            # clip read to this chunk
            n2 = min(n, csz - off)
            if ci not in r.get("present", []):
                return None  # unmapped hole
            pos = r["present"].index(ci) * csz + off
            fn = os.path.join(snap, r["file"])
            if fn not in fhandles:
                fhandles[fn] = open(fn, "rb")
            fhandles[fn].seek(pos)
            data = fhandles[fn].read(n2)
            if n2 < n:  # cross-chunk continuation
                rest = read_mem(addr + n2, n - n2)
                if rest is None:
                    return None
                data += rest
            return data
    return None

TABLE = 0x1056ecfb8
print("== table @ 0x%x ==" % TABLE)
hdr = read_mem(TABLE, 0x108)
if hdr is None:
    print("  (not mapped / not found)")
else:
    for off in range(0, 0x108, 8):
        v = struct.unpack_from("<Q", hdr, off)[0]
        lo, hi = struct.unpack_from("<II", hdr, off)
        print("  +0x%03x: 0x%016x  (u32: %d %d)" % (off, v, lo, hi))
print("\n== chunk slots (+0x108..+0x408) ==")
chunks = read_mem(TABLE + 0x108, 0x300)
if chunks is None:
    print("  (unmapped)")
else:
    nz = 0
    for c in range(0x300 // 8):
        v = struct.unpack_from("<Q", chunks, c * 8)[0]
        if v:
            nz += 1
            print("  chunk[%d] @+0x%x = 0x%x" % (c, 0x108 + c * 8, v))
    print("  (%d/%d non-zero)" % (nz, 0x300 // 8))

for name, a in (("x21-sib", 0x1055d8640), ("old-pool", 0x1055d64e0)):
    print("\n== %s @ 0x%x ==" % (name, a))
    p = read_mem(a, 0x40)
    if p is None:
        print("  (unmapped)")
    else:
        for off in range(0, 0x40, 8):
            v = struct.unpack_from("<Q", p, off)[0]
            print("  +0x%02x: 0x%016x" % (off, v))
