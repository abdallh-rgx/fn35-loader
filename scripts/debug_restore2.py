#!/usr/bin/env python3
"""debug_restore2.py — find WHICH region+chunk fails in full restore."""
import sys, os, json
sys.path.insert(0, "/home/z/my-project/scripts")
import fn35_loader as FL
from fn35_snap import _load_state, _unmap_intersecting

BASE = "/home/z/my-project"
snap = os.path.join(BASE, "fn35/snap")
macho = os.path.join(BASE, "fn35/extracted/Payload/FortniteClient.app/FortniteClient")
sandbox = os.path.join(BASE, "fn35/sandbox")

meta = json.load(open(os.path.join(snap, "index.json")))
state = _load_state(os.path.join(snap, "state.pkl"))

l = FL.FNLoader(macho, sandbox, budget=1.0, live_log=False)
l.prepare()

CHUNK = 1 << 16
for i, r in enumerate(meta["regions"]):
    b, e, perms = r["begin"], r["end"], r["perms"]
    size = e - b + 1
    _unmap_intersecting(l.uc, b, e)
    try:
        l.uc.mem_map(b, size, perms)
    except Exception as ex:
        print("REGION %d: mem_map(0x%x,0x%x) FAILED %r" % (i, b, size, ex))
        continue
    if not r["file"]:
        continue
    path = os.path.join(snap, r["file"])
    csz = r["chunksz"]
    with open(path, "rb") as f:
        for ci in r["present"]:
            data = f.read(csz)
            if len(data) < csz:
                data = data + b"\x00" * (csz - len(data))
            try:
                l.uc.mem_write(b + ci * csz, data)
            except Exception as ex:
                print("REGION %d WRITE FAIL: 0x%x-0x%x chunk %d "
                      "addr=0x%x len=%d: %r"
                      % (i, b, e, ci, b + ci * csz, len(data), ex))
                # context: is this range intersected by any earlier region?
                for j, r2 in enumerate(meta["regions"][:i]):
                    if r2["begin"] <= b + ci * csz <= r2["end"]:
                        print("   !!! address inside EARLIER region %d "
                              "(0x%x-0x%x)" % (j, r2["begin"], r2["end"]))
                sys.exit(1)
print("ALL REGIONS RESTORED OK")
