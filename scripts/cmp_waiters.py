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

def q(a):
    d = rdmem(a, 8)
    return struct.unpack("<Q", d)[0] if d else 0

VT = 0x1043a5518
OBJ = 0x640001e4d5c0
# scan the surrounding 0x10000 for objects with this vtable
found = []
base = (OBJ - 0x8000) & ~0xF
for a in range(base, OBJ + 0x8000, 8):
    if q(a) == VT:
        found.append(a)
print("objects with vtable 0x%x near 0x%x: %d" % (VT, OBJ, len(found)))
for a in found:
    flag = q(a + 0x98) & 0xFFFFFFFF
    f100 = q(a + 0x100) & 0xFFFFFFFF
    t108 = struct.unpack("<d", struct.pack("<Q", q(a + 0x108)))[0]
    t110 = struct.unpack("<d", struct.pack("<Q", q(a + 0x110)))[0]
    # string content at +0xf8..+0x118
    raw = rdmem(a + 0xf8, 0x20) or b""
    try:
        s = raw.split(b"\x00\x00")[0].decode("utf-16-le", "replace")[:20]
    except Exception:
        s = "?"
    print("  obj 0x%x: flag98=%d f100=%d start=%.4g timeout=%.4g str@f8=%r"
          % (a, flag, f100, t108, t110, s))
