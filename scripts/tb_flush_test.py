#!/usr/bin/env python3
"""Unit test: does ctl_flush_tb() really invalidate stale translation
blocks after mem_write, like ctl_remove_cache(range) does?

Scenario: write code A, execute (translate), overwrite with code B at the
same address, flush via the method under test, execute again.
If the flush is incomplete we still run code A."""
import sys
import unicorn
from unicorn import Uc, UC_ARCH_ARM64, UC_MODE_ARM, UC_HOOK_CODE
import unicorn.arm64_const as a64
import time

CODE_A = bytes.fromhex("200080d2")   # mov x0, #1
CODE_B = bytes.fromhex("400080d2")   # mov x0, #2
BASE = 0x1000

def run_once(uc, trace):
    uc.reg_write(a64.UC_ARM64_REG_X0, 0)
    uc.emu_start(BASE, BASE + 4, count=1)
    return uc.reg_read(a64.UC_ARM64_REG_X0)

def make():
    uc = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
    uc.mem_map(BASE, 0x1000)
    return uc

results = {}

# --- control: no flush ---
uc = make()
uc.mem_write(BASE, CODE_A)
r1 = run_once(uc, None)
uc.mem_write(BASE, CODE_B)           # unicorn 2.1.4: TB cache NOT invalidated
r2 = run_once(uc, None)
results["no-flush"] = (r1, r2)

# --- ctl_flush_tb ---
uc = make()
uc.mem_write(BASE, CODE_A)
r1 = run_once(uc, None)
uc.mem_write(BASE, CODE_B)
try:
    uc.ctl_flush_tb()
    r2 = run_once(uc, None)
    results["ctl_flush_tb"] = (r1, r2)
except Exception as e:
    results["ctl_flush_tb"] = ("ERR", repr(e))

# --- ctl_remove_cache small range ---
uc = make()
uc.mem_write(BASE, CODE_A)
r1 = run_once(uc, None)
uc.mem_write(BASE, CODE_B)
try:
    uc.ctl_remove_cache(BASE, BASE + 4)
    r2 = run_once(uc, None)
    results["remove_cache(small)"] = (r1, r2)
except Exception as e:
    results["remove_cache(small)"] = ("ERR", repr(e))

print("expected after overwrite: x0=2 (fresh translation of code B)")
for k, (r1, r2) in results.items():
    verdict = "STALE (bug!)" if r2 == 1 else "OK (fresh)"
    print("%-20s first=%s second=%s  -> %s" % (k, r1, r2, verdict))

# --- timing: range sweep vs flush_tb on a warm cache ---
uc = make()
prog = bytes.fromhex("200080d2" * 64)          # 64x mov x0,#1
for page in range(8):
    uc.mem_map(BASE + 0x10000 * page, 0x1000)
    uc.mem_write(BASE + 0x10000 * page, prog)
for page in range(8):
    uc.emu_start(BASE + 0x10000 * page, BASE + 0x10000 * page + 0x100, count=16)
t0 = time.time(); uc.ctl_remove_cache(1, 0xFFFFFFF00000); t_range = time.time() - t0
for page in range(8):
    uc.emu_start(BASE + 0x10000 * page, BASE + 0x10000 * page + 0x100, count=16)
t0 = time.time(); uc.ctl_flush_tb(); t_tb = time.time() - t0
print("\ntiming: range sweep %.3fs vs ctl_flush_tb %.6fs" % (t_range, t_tb))
