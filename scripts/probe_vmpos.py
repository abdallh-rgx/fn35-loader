#!/usr/bin/env python3
"""Track the VM interpreter's bytecode position: [sp+0x780]=base,
[sp+0x770]=index. Advancing = real work; oscillating = stuck."""
import os, sys, time
sys.path.insert(0, "/home/z/my-project/scripts")
os.environ["FN35_QUIET"] = "1"
# keep the default sync hook (1 reg read) for faithful segments

import fn35_snap
import fn35_loader as FL
from unicorn import Uc, UC_HOOK_CODE
from unicorn.arm64_const import UC_ARM64_REG_SP, UC_ARM64_REG_PC

BASE = "/home/z/my-project"
MACHO = BASE + "/fn35/extracted/Payload/FortniteClient.app/FortniteClient"
SNAP = BASE + "/fn35/snap2"
LOOP_LO, LOOP_HI = 0x101838ab0, 0x101839660

l = fn35_snap.load_snapshot(SNAP, MACHO, BASE + "/fn35/sandbox",
                            budget=120.0, live_log=False)
uc = l.uc
print("[vm-probe] resumed; watching bytecode position", flush=True)

hits = [0]
hist = []

def hook(uc_, addr, size, user):
    hits[0] += 1
    if hits[0] % 1_000_000 == 0:
        sp = uc_.reg_read(UC_ARM64_REG_SP)
        try:
            base = int.from_bytes(uc_.mem_read(sp + 0x780, 8), "little")
            idx = int.from_bytes(uc_.mem_read(sp + 0x770, 8), "little")
            ptr = int.from_bytes(uc_.mem_read(sp + 0x988, 8), "little")
            hist.append((hits[0], base, idx, ptr, addr))
            print("[%3dM] base=0x%-12x idx=0x%-10x (ptr=0x%x) pc=0x%x"
                  % (hits[0] // 1_000_000, base, idx, ptr, addr),
                  flush=True)
        except Exception as e:
            print("[%3dM] read fail %r" % (hits[0] // 1_000_000, e),
                  flush=True)

uc.hook_add(UC_HOOK_CODE, hook, begin=LOOP_LO, end=LOOP_HI)
l.run()
print("[vm-probe] done stop=%s fatal=%s" % (l.stop_reason, l.fatal_msg),
      flush=True)
if l.fatal_msg:
    print(l.fatal_msg[:300], flush=True)
