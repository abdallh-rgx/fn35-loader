#!/usr/bin/env python3
import json, os, sys
SNAP = sys.argv[1] if len(sys.argv) > 1 else "/home/z/my-project/fn35/snap"
meta = json.load(open(os.path.join(SNAP, "index.json")))
print("note:", meta.get("note", "")[:100])
bad = 0
for r in meta["regions"]:
    f = os.path.join(SNAP, r["file"])
    if not os.path.exists(f):
        print("MISSING:", r["file"]); bad += 1; continue
    sz = os.path.getsize(f)
    exp = len(r["present"]) * r["chunksz"]
    if sz != exp:
        print("SIZE MISMATCH %s: have %d expect %d (region 0x%x..0x%x)"
              % (r["file"], sz, exp, r["begin"], r["end"]))
        bad += 1
print("bad files:", bad, "of", len(meta["regions"]))
