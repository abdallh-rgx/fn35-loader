#!/usr/bin/env python3
"""find_value.py — search the crash snapshot for a 64-bit value."""
import sys, os, json, struct

SNAP = sys.argv[2] if len(sys.argv) > 2 else "/home/z/my-project/fn35/snap_crash"
VAL = int(sys.argv[1], 0)
meta = json.load(open(os.path.join(SNAP, "index.json")))
CHUNK = 1 << 16
_files, _pmaps = {}, {}
pat = struct.pack("<Q", VAL)

hits = 0
for r in meta["regions"]:
    if not r["file"]:
        continue
    f = _files.get(r["file"])
    if f is None:
        f = open(os.path.join(SNAP, r["file"]), "rb")
        _files[r["file"]] = f
    pmap = _pmaps.setdefault(r["file"], {})
    if not pmap:
        for pos, c in enumerate(r["present"]):
            pmap[c] = pos * CHUNK
    for ci in r["present"]:
        f.seek(pmap[ci])
        data = f.read(CHUNK)
        off = 0
        while True:
            i = data.find(pat, off)
            if i < 0:
                break
            va = r["begin"] + ci * CHUNK + i
            print("FOUND at 0x%x (region 0x%x..0x%x)" % (va, r["begin"], r["end"]))
            hits += 1
            off = i + 8
            if hits > 20:
                sys.exit(0)
print("hits:", hits)
