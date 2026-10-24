#!/usr/bin/env python3
import sys, os, json, struct
sys.path.insert(0, "/home/z/my-project/scripts")

SNAP = "/home/z/my-project/fn35/snap"
meta = json.load(open(os.path.join(SNAP, "index.json")))
CHUNK = 1 << 16
_files, _pmaps = {}, {}
def rdmem(a, n):
    for r in meta["regions"]:
        if r["begin"] <= a and a + n <= r["end"]:
            f = _files.get(r["file"])
            if f is None and r["file"]:
                f = open(os.path.join(SNAP, r["file"]), "rb"); _files[r["file"]] = f
            if f is None:
                return b"\x00" * n
            pmap = _pmaps.setdefault(r["file"], {})
            if not pmap:
                for pos, c in enumerate(r["present"]):
                    pmap[c] = pos * CHUNK
            out = b""
            addr, left = a, n
            while left > 0:
                ci = (addr - r["begin"]) // CHUNK
                off = (addr - r["begin"]) % CHUNK
                if ci not in pmap:
                    take = min(left, CHUNK - off)
                    out += b"\x00" * take; addr += take; left -= take; continue
                f.seek(pmap[ci] + off)
                take = min(left, CHUNK - off)
                out += f.read(take); addr += take; left -= take
            return out
    return None

OBJ = 0x640001e4d5c0
data = rdmem(OBJ - 0x40, 0x200)
# UTF-16LE decode attempt
try:
    s = data.decode("utf-16-le", errors="replace")
    print("UTF-16 view (obj-0x40 .. obj+0x1c0):")
    print(repr(s))
except Exception as e:
    print(e)
print()
print("ASCII-ish:", repr(data[:0x100]))
