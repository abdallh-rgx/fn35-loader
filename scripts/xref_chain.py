#!/usr/bin/env python3
"""Scan the whole __TEXT for BL instructions targeting the spin-loop chain."""
import sys, struct
sys.path.insert(0, "/home/z/my-project/scripts")
from fn35_macho import MachO

BIN = "/home/z/my-project/fn35/extracted/Payload/FortniteClient.app/FortniteClient"
mo = MachO(BIN)

targets = {
    0x101838970: "LOOP-FN (takes obj + wide '../../../FortniteGame...')",
    0x1026e0c04: "CALLER-B (calls LOOP-FN)",
    0x10305e578: "sleep-ish(w0=100)",
    0x10305ddd4: "compare-ish",
    0x10276b70c: "get-wide-path-fn",
}

# executable section range: use the __TEXT segment file extent
seg = mo.seg_by_name("__TEXT")
data = mo.buf[seg.fileoff:seg.fileoff + seg.filesize]
base = seg.vmaddr

hits = {}
n = len(data) // 4
words = struct.unpack("<%dI" % n, data[:n * 4])
for i, w in enumerate(words):
    if (w >> 26) == 0x25:                      # BL
        off = w & 0x3FFFFFF
        if off & 0x2000000:                    # sign-extend
            off -= 0x4000000
        tgt = base + i * 4 + off * 4
        if tgt in targets:
            hits.setdefault(tgt, []).append(base + i * 4)

for t, name in targets.items():
    sites = hits.get(t, [])
    print("== 0x%x %s: %d call site(s)" % (t, name, len(sites)))
    for s in sites[:12]:
        print("     bl @ 0x%x" % s)
