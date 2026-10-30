#!/usr/bin/env python3
"""Search snapshot memory regions for runtime pointers to 0x1026b7500."""
import json
import struct

SNAP = "/home/z/my-project/fn35/snap"
TARGET = 0x1026b7500

meta = json.load(open(SNAP + "/index.json"))
CHUNK = meta["regions"][0].get("chunksz", 1 << 16)

packed = struct.pack("<Q", TARGET)
hits = []
for reg in meta["regions"]:
    fn = reg.get("file")
    if not fn:
        continue
    present = set(reg.get("present", []))
    base = reg["begin"]
    with open(SNAP + "/" + fn, "rb") as f:
        data = f.read()
    pos = 0
    for idx, cs in enumerate(range(0, (reg["end"] - reg["begin"] + 1), CHUNK)):
        if idx not in present:
            continue
        chunk = data[pos:pos + CHUNK]
        pos += len(chunk)
        off = 0
        while True:
            j = chunk.find(packed, off)
            if j < 0:
                break
            hits.append((base + cs + j, reg.get("perms")))
            off = j + 1
print("[snap] %d runtime pointers to 0x%x" % (len(hits), TARGET))
for a, p in hits[:20]:
    print("  0x%x perms=%s" % (a, p))
