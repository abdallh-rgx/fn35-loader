#!/usr/bin/env python3
"""Probe the CURRENT VM loop (pc 0x102c52628): dump candidate
advancing indices from the frame to estimate remaining grind."""
import os, sys
sys.path.insert(0, "/home/z/my-project/scripts")
os.environ["FN35_QUIET"] = "1"

import fn35_snap
from unicorn import Uc, UC_HOOK_BLOCK
from unicorn.arm64_const import UC_ARM64_REG_SP, UC_ARM64_REG_PC

BASE = "/home/z/my-project"
MACHO = BASE + "/fn35/extracted/Payload/FortniteClient.app/FortniteClient"
SNAP = os.environ.get("FN35_SNAPSHOT", BASE + "/fn35/snap")
LO = int(os.environ.get("FN35_PROBE_LO", "0x102c52618"), 0)
HI = int(os.environ.get("FN35_PROBE_HI", "0x102c526a0"), 0)

l = fn35_snap.load_snapshot(SNAP, MACHO, BASE + "/fn35/sandbox",
                            budget=30.0, live_log=False)
uc = l.uc
print("[probe2] watching 0x%x-0x%x" % (LO, HI), flush=True)

hits = [0]
last = {}

def hook(uc_, addr, size, user):
    hits[0] += 1
    if hits[0] % 200_000 == 0:
        sp = uc_.reg_read(UC_ARM64_REG_SP)
        row = []
        for off in range(0, 0x800, 8):
            try:
                v = int.from_bytes(uc_.mem_read(sp + off, 8), "little")
            except Exception:
                continue
            # candidate advancing index: small-ish, changes over time
            if 0 < v < 0x4000000:
                prev = last.get(off)
                last[off] = v
                if prev is not None and v != prev:
                    row.append((off, prev, v))
        if row:
            print("[%3dK blocks] moving: %s"
                  % (hits[0] // 1000,
                     "; ".join("+0x%x: %x->%x" % r
                               for r in row[:10])), flush=True)
        else:
            print("[%3dK blocks] none moving" % (hits[0] // 1000),
                  flush=True)

uc.hook_add(UC_HOOK_BLOCK, hook, begin=LO, end=HI)
l.run()
print("[probe2] done stop=%s fatal=%s" % (l.stop_reason, l.fatal_msg),
      flush=True)
