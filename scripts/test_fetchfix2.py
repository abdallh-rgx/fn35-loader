#!/usr/bin/env python3
"""test_fetchfix2.py — fetch fault: emu_stop in callback, rewrite PC,
then a SECOND emu_start on the same Uc. Does state stay coherent?"""
import struct
from unicorn import *
from unicorn.arm64_const import *

uc = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
uc.mem_map(0x1000, 0x1000)
uc.mem_map(0x2000, 0x1000)
uc.mem_map(0xF000, 0x1000)

def asm(w, addr):
    uc.mem_write(addr, struct.pack("<I", w))

asm(0xD2800020, 0x1000)              # movz x0, #1
asm(0x97FFFFBF, 0x1004)              # bl #0
asm(0xD2800840, 0x2008)              # movz x0, #0x42  (after svc)
asm(0xD2808400, 0x2000)              # movz x0, #0x42
asm(0xD4000001, 0x2004)              # svc #0

stop_reason = {"n": 0}

def on_invalid(uc_, access, address, size, value, ud):
    if access == UC_MEM_FETCH_UNMAPPED and address == 0:
        stop_reason["n"] += 1
        print("fetch fault at 0 (PC=0x%x) -> emu_stop; will redirect"
              % uc_.reg_read(UC_ARM64_REG_PC))
        uc_.emu_stop()
        return False
    return False

uc.hook_add(UC_HOOK_MEM_INVALID, on_invalid)

def on_intr(uc_, intno, ud):
    print("svc reached: x0=0x%x" % uc_.reg_read(UC_ARM64_REG_X0))
    uc_.emu_stop()

uc.hook_add(UC_HOOK_INTR, on_intr)

try:
    uc.emu_start(0x1000, 0x1008, count=64)
except UcError as e:
    print("first emu_start ended: %s (expected)" % e.errno)

# repair: put PC at the rescue code
uc.reg_write(UC_ARM64_REG_PC, 0x2000)
try:
    uc.emu_start(0x2000, 0x2008, count=64)
except UcError as e:
    print("second emu_start FAILED: %s" % e)
    raise SystemExit(1)
print("second emu_start OK -> PC-redirect repair works")
