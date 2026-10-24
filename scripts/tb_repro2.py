#!/usr/bin/env python3
"""tb_repro2.py — full loader-scenario reproduction:
- instruction hook (records ring)
- long original function, patched to `ret` before any execution
- an svc-based "stub" the caller uses via br x16 (like GOT trampolines)
- emulate the caller via slices like the scheduler, then verify
If this reproduces PC=0/sp=0, we have the unicorn bug pinned.
"""
import struct
import unicorn
import unicorn.arm64_const as a64

uc = unicorn.Uc(unicorn.UC_ARCH_ARM64, unicorn.UC_MODE_ARM)
uc.mem_map(0x1000, 0x4000)

def w(a, i):
    uc.mem_write(a, struct.pack("<I", i & 0xFFFFFFFF))

# ---- stub farm at 0x1400: svc #0x80 then ret ----
w(0x1400, 0xD4000801)      # svc #0x80
w(0x1404, 0xD65F03C0)      # ret

# ---- "GOT" at 0x1300: points at the stub ----
uc.mem_write(0x1300, struct.pack("<Q", 0x1400))

# ---- the original long "verify" function at 0x1000 ----
w(0x1000, 0xD10043FF)      # sub sp, sp, #0x10
w(0x1004, 0xD2800020)      # mov x0, #1
w(0x1008, 0xD65F03C0)      # ret

# ---- the caller at 0x1800 ----
w(0x1800, 0xD10043FF)      # sub sp, sp, #0x10
w(0x1804, 0x18000050)      # ldr w16, [adrp-ish]... (placeholder)
# proper: adrp x16, 0x1000-page? simpler: ldr x16, =0x1300 via literal
# use: ldr x16, [pc-relative]
w(0x1804, 0x580002B0)      # ldr x16, [pc, #0x54]  (0x1858 -> 0x1300? compute below)
w(0x1808, 0xF9400210)      # ldr x16, [x16]
w(0x180C, 0xD61F0200)      # br x16
w(0x1810, 0xD2812520)      # mov x0, #0x99 (after stub returns)
w(0x1814, 0x910043FF)      # add sp, sp, #0x10
w(0x1818, 0xD65F03C0)      # ret
# literal pool at 0x1858: pointer to GOT 0x1300
uc.mem_write(0x1858, struct.pack("<Q", 0x1300))

# landing
w(0x1100, 0xD65F03C0)      # ret

# ---- PATCH the verify function to `ret` (before any execution) ----
uc.mem_write(0x1000, struct.pack("<I", 0xD65F03C0))
uc.ctl_remove_cache(0x1000, 0x2000)

ring = []
def code_hook(uc, addr, size, user):
    ring.append((addr, uc.reg_read(a64.UC_ARM64_REG_SP),
                 uc.reg_read(a64.UC_ARM64_REG_LR)))

stubs = {}
def intr_hook(uc, intno, user):
    # emulate our dispatch_stub: return to LR with x0=0x42
    lr = uc.reg_read(a64.UC_ARM64_REG_LR)
    uc.reg_write(a64.UC_ARM64_REG_X0, 0x42)
    uc.reg_write(a64.UC_ARM64_REG_PC, lr)

uc.hook_add(unicorn.UC_HOOK_CODE, code_hook)
uc.hook_add(unicorn.UC_HOOK_INTR, intr_hook)

# ---- run the caller in slices (like the scheduler) ----
uc.reg_write(a64.UC_ARM64_REG_SP, 0x3F00)
uc.emu_start(0x1800, 1, 2_000_000, 50)   # slice 1: 50 instructions
pc = uc.reg_read(a64.UC_ARM64_REG_PC)
print("after slice 1: pc=0x%x sp=0x%x x0=0x%x"
      % (pc, uc.reg_read(a64.UC_ARM64_REG_SP),
         uc.reg_read(a64.UC_ARM64_REG_X0)))
print("ring size:", len(ring))
for e in ring[-6:]:
    print("  pc=0x%x sp=0x%x lr=0x%x" % e)
