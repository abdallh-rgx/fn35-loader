#!/usr/bin/env python3
"""tb_cache_test.py — does uc.mem_write invalidate translated blocks?

Reproduces the segBM mystery: patching code mid-run via mem_write,
then branching to it. If unicorn serves the STALE translated block,
the patch silently doesn't take effect (or worse).
"""
import struct
import sys
import unicorn
import unicorn.arm64_const as a64

uc = unicorn.Uc(unicorn.UC_ARCH_ARM64, unicorn.UC_MODE_ARM)
uc.mem_map(0x1000, 0x2000)

# target function at 0x1000: "mov x0, #0x11; ret" (original code)
uc.mem_write(0x1000, struct.pack("<I", 0xD2800220))  # mov x0, #0x11
uc.mem_write(0x1004, struct.pack("<I", 0xD65F03C0))  # ret

# caller at 0x1800: "bl 0x1000; mov x0, #0x99; ret"
uc.mem_write(0x1800, struct.pack("<I", 0x97FFFC80))  # bl 0x1000
uc.mem_write(0x1804, struct.pack("<I", 0xD2812520))  # mov x0, #0x99
uc.mem_write(0x1808, struct.pack("<I", 0xD65F03C0))  # ret

# run 1: original -> x0 = 0x11
uc.reg_write(a64.UC_ARM64_REG_LR, 0x1808)
uc.emu_start(0x1000, 0, 0, 10)
print("run1 x0 = 0x%x (expect 0x11)" % uc.reg_read(a64.UC_ARM64_REG_X0))

# PATCH the function mid-run via mem_write: "ret" only
uc.mem_write(0x1000, struct.pack("<I", 0xD65F03C0))  # ret

# run 2: patched -> x0 unchanged (whatever caller had), NOT 0x11
uc.reg_write(a64.UC_ARM64_REG_X0, 0x55)
uc.reg_write(a64.UC_ARM64_REG_LR, 0x1808)
uc.emu_start(0x1000, 0, 0, 10)
x = uc.reg_read(a64.UC_ARM64_REG_X0)
print("run2 x0 = 0x%x (expect 0x55 if patch took effect, "
      "0x11 if STALE TB)" % x)

# run 3: call through bl from another block
uc.reg_write(a64.UC_ARM64_REG_X0, 0xAA)
uc.emu_start(0x1800, 0x1804, 0, 10)
x = uc.reg_read(a64.UC_ARM64_REG_X0)
print("run3 x0 = 0x%x (0xAA if patched-ret ran, 0x11 if stale)" % x)

# run 4: what about a fetch directly at the patched address mid-hook?
print()
print("does mem_write invalidate? ->", "YES" if x == 0xAA else "NO (STALE)")
