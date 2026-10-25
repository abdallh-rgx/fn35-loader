#!/usr/bin/env python3
"""tb_repro.py — exact reproduction of the loader's patch scenario.

1. map pages, write a LONG function (like the verify loop) + a caller
2. patch the function's first instruction to `ret` + ctl_remove_cache
   (all BEFORE any execution -- exactly like prepare())
3. run the caller: bl -> patched ret -> back -> continue
If this works, the loader's crash must have another cause; if it
reproduces the fetch-at-0, we have the unicorn bug pinned.
"""
import struct
import sys
import unicorn
import unicorn.arm64_const as a64

uc = unicorn.Uc(unicorn.UC_ARCH_ARM64, unicorn.UC_MODE_ARM)
uc.mem_map(0x1000, 0x2000)

def w(a, i):
    uc.mem_write(a, struct.pack("<I", i & 0xFFFFFFFF))

# --- the "verify function" at 0x1000: long multi-instruction body ---
w(0x1000, 0xD10043FF)      # sub  sp, sp, #0x10   (orig prologue)
w(0x1004, 0xA9017BFD)      # stp  x29, x30, [sp, #0x10]
w(0x1008, 0x910043FD)      # add  x29, sp, #0x10
w(0x100C, 0xD2800020)      # mov  x0, #1
w(0x1010, 0xA9417BFD)      # ldp  x29, x30, [sp, #0x10]
w(0x1014, 0x910043FF)      # add  sp, sp, #0x10
w(0x1018, 0xD65F03C0)      # ret

# --- the caller at 0x1800 ---
# prologue + "bl 0x1000" + "mov x0,#0x99" + epilogue + ret
w(0x1800, 0xD10043FF)      # sub sp, sp, #0x10
w(0x1804, 0xF9000FE0)      # str x0, [sp, #0x8]  (something)
w(0x1808, 0x97FFFFFE)      # bl  0x1000   (offset -0x808)
w(0x180C, 0xD2812520)      # mov x0, #0x99
w(0x1810, 0x910043FF)      # add sp, sp, #0x10
w(0x1814, 0xD65F03C0)      # ret

# --- landing pad at 0x1100 (safety) ---
w(0x1100, 0xD65F03C0)      # ret

# ===== THE PATCH (before any execution, like prepare()) =====
uc.mem_write(0x1000, struct.pack("<I", 0xD65F03C0))   # ret
uc.ctl_remove_cache(0x1000, 0x2000)
print("patched 0x1000 -> ret, TB cache invalidated")

# ===== run the caller =====
uc.reg_write(a64.UC_ARM64_REG_SP, 0x1F00)
uc.reg_write(a64.UC_ARM64_REG_X0, 0x42)
uc.emu_start(0x1800, 0, 0, 64)
x0 = uc.reg_read(a64.UC_ARM64_REG_X0)
pc = uc.reg_read(a64.UC_ARM64_REG_PC)
print("after run: x0=0x%x pc=0x%x" % (x0, pc))
print("VERDICT:", "PATCH LIVE (x0=0x99)" if x0 == 0x99 else
      ("STALE (x0=0x42?)" if x0 == 0x42 else "UNEXPECTED"))
