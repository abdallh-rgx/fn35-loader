#!/usr/bin/env python3
"""Watch guest memory traffic OUTSIDE the spin region: is real work happening?"""
import os, sys, time
sys.path.insert(0, "/home/z/my-project/scripts")
os.environ["FN35_QUIET"] = "1"
os.environ.setdefault("FN35_NO_SYNC_HOOK", "1")

import fn35_snap
import fn35_loader as FL
from unicorn import Uc, UC_HOOK_CODE, UC_HOOK_MEM_READ, UC_HOOK_MEM_WRITE

BASE = "/home/z/my-project"
MACHO = BASE + "/fn35/extracted/Payload/FortniteClient.app/FortniteClient"
SNAP = BASE + "/fn35/snap2"
LOOP_LO, LOOP_HI = 0x101838ab0, 0x101839660

l = fn35_snap.load_snapshot(SNAP, MACHO, BASE + "/fn35/sandbox",
                            budget=60.0, live_log=False)
uc = l.uc
print("[probe] resumed; watching memory traffic", flush=True)

reads = {}          # 64KB-granule bucket -> count
writes = {}
code_out = {}       # PCs outside the loop (text only) -> count
t0 = [time.time()]

def rd_hook(uc_, access, addr, size, value, user):
    b = addr >> 16
    reads[b] = reads.get(b, 0) + 1

def wr_hook(uc_, access, addr, size, value, user):
    b = addr >> 16
    writes[b] = writes.get(b, 0) + 1

uc.hook_add(UC_HOOK_MEM_READ, rd_hook)
uc.hook_add(UC_HOOK_MEM_WRITE, wr_hook)

l.run()

print("\n[probe] stop=%r fatal=%r after %.1fs"
      % (l.stop_reason, l.fatal_msg, time.time() - t0[0]))
print("\n=== top READ buckets (64KB granule, addr>>16) ===")
for b, c in sorted(reads.items(), key=lambda kv: -kv[1])[:18]:
    print("  [0x%08x0000..] %8d" % (b, c))
print("=== top WRITE buckets ===")
for b, c in sorted(writes.items(), key=lambda kv: -kv[1])[:12]:
    print("  [0x%08x0000..] %8d" % (b, c))

def bucket_desc(b):
    a = b << 16
    if 0x100000000 <= a < 0x1032a0000:
        return "__TEXT (engine code)"
    if 0x1032a0000 <= a < 0x103400000:
        return "__DATA_CONST?"
    if 0x104000000 <= a < 0x105600000:
        return "__DATA"
    if 0x500000000 <= a < 0x600000000:
        return "native-stub region"
    if 0x600000000 <= a < 0x700000000:
        return "guest heap/farm"
    if 0x700000000 <= a < 0x800000000:
        return "thread stacks"
    return "?"

print("\n=== read buckets classified ===")
cls = {}
for b, c in reads.items():
    k = bucket_desc(b)
    cls[k] = cls.get(k, 0) + c
for k, c in sorted(cls.items(), key=lambda kv: -kv[1]):
    print("  %-24s %d" % (k, c))
