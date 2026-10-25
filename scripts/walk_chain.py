#!/usr/bin/env python3
"""Walk MainAppThread's frame chain (x29) from the snap2 guest memory."""
import os, sys, json
sys.path.insert(0, "/home/z/my-project/scripts")

SNAP = "/home/z/my-project/fn35/snap2"
META = os.path.join(SNAP, "index.json")
with open(META) as f:
    meta = json.load(f)

# build a flat page map for reads
regions = meta["regions"]
files = {r["file"]: r for r in regions if r.get("file")}
import struct

def read_mem(addr, n):
    for r in regions:
        b, e = r["begin"], r["end"]
        if b <= addr and addr + n <= e + 1:
            path = os.path.join(SNAP, r["file"])
            csz = r["chunksz"]
            out = b""
            off = addr - b
            remaining = n
            while remaining > 0:
                ci, co = divmod(off, csz)
                if ci not in r["present"]:
                    return None
                # chunks are stored contiguously in present-list ORDER
                rank = r["present"].index(ci)
                with open(path, "rb") as f:
                    f.seek(rank * csz + co)
                    chunk = f.read(min(remaining, csz - co))
                out += chunk
                remaining -= len(chunk)
                off += len(chunk)
                if not chunk:
                    break
            return out[:n]
    return None

fp = 0x700000bffce0   # MainAppThread saved x29
seen = set()
for i in range(14):
    if fp in seen or not (0x600000000000 < fp < 0x800000000000):
        break
    seen.add(fp)
    hdr = read_mem(fp, 16)
    if not hdr:
        print("frame %d: fp=0x%x UNREADABLE" % (i, fp))
        break
    nxt, lr = struct.unpack("<QQ", hdr)
    print("frame %d: fp=0x%x -> next=0x%x lr=0x%x" % (i, fp, nxt, lr))
    if not (0x100000000 <= lr < 0x104000000):
        print("   (lr out of text range)")
        break
    fp = nxt
