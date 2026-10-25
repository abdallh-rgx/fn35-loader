#!/usr/bin/env python3
"""test_fetchfix.py — can we redirect execution from inside the
UC_MEM_FETCH_UNMAPPED callback by rewriting PC and returning True?"""
import struct
import unicorn
from unicorn import *
from unicorn.arm64_const import *

uc = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
uc.mem_map(0x1000, 0x1000)     # code page 1
uc.mem_map(0x2000, 0x1000)     # repair target page
uc.mem_map(0xF000, 0x1000)     # stack

def asm(w, addr):
    uc.mem_write(addr, struct.pack("<I", w))

# at 0x1000: movz x0,#1 ; bl #0 (call to zero -> fetch fault)
asm(0xD2800020, 0x1000)              # movz x0, #1
asm(0x97FFFFBF, 0x1004)              # bl #-0x1004 (target 0x0)
# landed here after repair? put code at 0x2000: movz x0,#0x42 ; svc #0
asm(0xD2808400, 0x2000)              # movz x0, #0x42
asm(0xD4000001, 0x2004)              # svc #0 (we stop here)

repaired = {"n": 0}

def on_invalid(uc_, access, address, size, value, ud):
    if access == UC_MEM_FETCH_UNMAPPED and address == 0:
        repaired["n"] += 1
        print("fetch fault at 0 (PC=0x%x) -> redirect to 0x2000"
              % uc_.reg_read(UC_ARM64_REG_PC))
        uc_.reg_write(UC_ARM64_REG_PC, 0x2000)
        return True
    return False

uc.hook_add(UC_HOOK_MEM_INVALID, on_invalid)

def on_intr(uc_, intno, ud):
    print("svc reached: x0=0x%x (0x42 = repair WORKED, 1 = ignored)"
          % uc_.reg_read(UC_ARM64_REG_X0))
    uc_.emu_stop()

uc.hook_add(UC_HOOK_INTR, on_intr)
uc.emu_start(0x1000, 0x1000 + 8, count=64)
print("done, repairs=%d" % repaired["n"])
