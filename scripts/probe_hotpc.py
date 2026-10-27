#!/usr/bin/env python3
"""Where is execution actually spending time? Wide-region hot-PC
profiler over a short budget window."""
import os, sys
sys.path.insert(0, "/home/z/my-project/scripts")
os.environ["FN35_QUIET"] = "1"

import fn35_snap
from unicorn import UC_HOOK_CODE
from unicorn.arm64_const import UC_ARM64_REG_PC

BASE = "/home/z/my-project"
MACHO = BASE + "/fn35/extracted/Payload/FortniteClient.app/FortniteClient"
SNAP = os.environ.get("FN35_SNAPSHOT", BASE + "/fn35/snap")

l = fn35_snap.load_snapshot(SNAP, MACHO, BASE + "/fn35/sandbox",
                            budget=40.0, live_log=False)
uc = l.uc
print("[prof] sampling hot PCs", flush=True)

counts = {}
hits = [0]

def hook(uc_, addr, size, user):
    hits[0] += 1
    # sample 1/64 to keep overhead sane
    if hits[0] & 63:
        return
    c = counts.get(addr, 0) + 1
    counts[addr] = c

uc.hook_add(UC_HOOK_CODE, hook, begin=0x100000000, end=0x104000000)
l.run()
top = sorted(counts.items(), key=lambda kv: -kv[1])[:15]
print("[prof] total %dM instr (sampled %d pcs)"
      % (hits[0] // 1_000_000, len(counts)), flush=True)
for pc, c in top:
    print("  0x%x  %6.1f%%" % (pc, 100.0 * c / max(1, sum(counts.values()))),
          flush=True)
