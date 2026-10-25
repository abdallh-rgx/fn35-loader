#!/usr/bin/env python3
"""debug_restore.py — reproduce + diagnose the snapshot restore failure."""
import sys, os, json, pickle, traceback
sys.path.insert(0, "/home/z/my-project/scripts")
import fn35_loader as FL

BASE = "/home/z/my-project"
snap = os.path.join(BASE, "fn35/snap")
macho = os.path.join(BASE, "fn35/extracted/Payload/FortniteClient.app/FortniteClient")
sandbox = os.path.join(BASE, "fn35/sandbox")

meta = json.load(open(os.path.join(snap, "index.json")))
from fn35_snap import _load_state
state = _load_state(os.path.join(snap, "state.pkl"))

l = FL.FNLoader(macho, sandbox, budget=1.0, live_log=False)
l.prepare()

print("=== fresh prepare() regions ===")
for reg in l.uc.mem_regions():
    print("  0x%x-0x%x perms=%d" % (reg[0], reg[1], reg[2]))

print("=== restore region #0 step by step ===")
r = meta["regions"][0]
b, e, perms = r["begin"], r["end"], r["perms"]
size = e - b + 1
print("snapshot region: 0x%x-0x%x size=0x%x perms=%d" % (b, e, size, perms))

# unmap intersecting
mapped = list(l.uc.mem_regions())
for reg in mapped:
    rb, re_ = reg[0], reg[1]
    if rb <= e and re_ >= b:
        print("  unmapping 0x%x-0x%x (size 0x%x)" % (rb, re_, re_ - rb + 1))
        try:
            l.uc.mem_unmap(rb, re_ - rb + 1)
        except Exception as ex:
            print("    FAILED: %r" % ex)

try:
    l.uc.mem_map(b, size, perms)
    print("  mem_map OK")
except Exception as ex:
    print("  mem_map FAILED: %r" % ex)

# try the failing chunk
ci = 1452
csz = 65536
with open(os.path.join(snap, r["file"]), "rb") as f:
    # sequential read: chunks are concatenated; need to walk to offset
    off = 0
    for c in r["present"]:
        data = f.read(csz)
        if c == ci:
            addr = b + c * csz
            print("  writing chunk %d at 0x%x len=%d" % (c, addr, len(data)))
            try:
                l.uc.mem_write(addr, data)
                print("    WRITE OK")
            except Exception as ex:
                print("    WRITE FAILED: %r" % ex)
            break
