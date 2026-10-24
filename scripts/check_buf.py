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

BUF = 0x64000403b280
got = rdmem(BUF, 2832)
ref = open("fn35/pakcache/Engine/Content/Slate/Checkerboard.png", "rb").read()
print("guest buffer first 40:", got[:40].hex())
print("host file  first 40:", ref[:40].hex())
print("identical:", got == ref)
# compare chunk by chunk
diffs = [i for i in range(min(len(got), len(ref))) if got[i] != ref[i]]
print("diff bytes:", len(diffs), "first:", diffs[:10])
