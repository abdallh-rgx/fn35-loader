#!/usr/bin/env python3
"""Probe the MainAppThread obfuscated loop: is it progressing or stuck?

Resumes snap2 WITHOUT running the scheduler: hooks the loop region,
samples registers + stack state slots every N hits, runs ~90s.
"""
import os, sys, time
sys.path.insert(0, "/home/z/my-project/scripts")
os.environ["FN35_QUIET"] = "1"
os.environ.setdefault("FN35_NO_SYNC_HOOK", "1")   # raw speed for probing

import fn35_snap
import fn35_loader as FL
from fn35_loader import XREGS
import unicorn.arm64_const as a64
from unicorn import Uc, UC_HOOK_CODE
from unicorn.arm64_const import (
    UC_ARM64_REG_X0, UC_ARM64_REG_X1, UC_ARM64_REG_X2, UC_ARM64_REG_X3,
    UC_ARM64_REG_X4, UC_ARM64_REG_X5, UC_ARM64_REG_X6, UC_ARM64_REG_X7,
    UC_ARM64_REG_X8, UC_ARM64_REG_X9, UC_ARM64_REG_X10, UC_ARM64_REG_X16,
    UC_ARM64_REG_SP, UC_ARM64_REG_PC)

BASE = "/home/z/my-project"
MACHO = BASE + "/fn35/extracted/Payload/FortniteClient.app/FortniteClient"
SNAP = BASE + "/fn35/snap2"
LOOP_LO, LOOP_HI = 0x101838ab0, 0x101839660

l = fn35_snap.load_snapshot(SNAP, MACHO, BASE + "/fn35/sandbox",
                            budget=90.0, live_log=False)
uc = l.uc
print("[probe] resumed; probing loop [0x%x..0x%x]" % (LOOP_LO, LOOP_HI),
      flush=True)

# FULL-COMMIT sync hook: read EVERY register on every instruction inside
# the loop region. If the loop's computed dispatch (br x8/x9) reads stale
# TCG state and jumps wrong, this makes every register authoritative.
ALL_REGS = [XREGS[i] for i in range(29)] + [
    a64.UC_ARM64_REG_X29, a64.UC_ARM64_REG_X30, a64.UC_ARM64_REG_SP,
    a64.UC_ARM64_REG_PC, a64.UC_ARM64_REG_NZCV]

hits = [0]
left = [0]

def full_sync(uc_, addr, size, user):
    hits[0] += 1
    for r in ALL_REGS:
        uc_.reg_read(r)
    if not (LOOP_LO <= addr <= LOOP_HI):
        if not left[0]:
            left[0] = addr
            print("[probe] LEFT THE LOOP at 0x%x after %dM hits!"
                  % (addr, hits[0] // 1_000_000), flush=True)
    if hits[0] % 20_000_000 == 0:
        sp = uc_.reg_read(UC_ARM64_REG_SP)
        s = []
        for so in (0x708, 0x70c, 0x710):
            try:
                v = int.from_bytes(uc_.mem_read(sp + so, 4), "little")
                s.append("%03x=%08x" % (so, v))
            except Exception:
                s.append("%03x=ERR" % so)
        print("[%dM hits] pc=0x%x %s" % (hits[0] // 1_000_000, addr,
                                         " ".join(s)), flush=True)

uc.hook_add(UC_HOOK_CODE, full_sync, begin=LOOP_LO - 0x100,
            end=LOOP_HI + 0x1000)

l.run()
print("[probe] done: stop=%s fatal=%s hits=%dM left_at=%s"
      % (l.stop_reason, l.fatal_msg, hits[0] // 1_000_000, hex(left[0]) if left[0] else "never"),
      flush=True)
if l.fatal_msg:
    print(l.fatal_msg[:400], flush=True)
