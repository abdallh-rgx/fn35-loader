#!/usr/bin/env python3
"""Does a flush variant clear STALE SOFTMMU TLB entries after
unmap+remap (what snapshot restore does)?

Map DATA page, translate a load through it, then unmap/remap the DATA
page (host ptr changes), refill, flush, execute: new or stale value?"""
import struct
from unicorn import Uc, UC_ARCH_ARM64, UC_MODE_ARM
import unicorn.arm64_const as a64

CODE = 0x10000
DATA = 0x20000

def build():
    uc = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
    uc.mem_map(CODE, 0x1000)
    uc.mem_map(DATA, 0x1000)
    # ldr w0, [x1]; ret   with x1=DATA
    uc.mem_write(CODE, bytes.fromhex("200040b9") + bytes.fromhex("c0035fd6"))
    uc.reg_write(a64.UC_ARM64_REG_X1, DATA)
    uc.mem_write(DATA, struct.pack("<I", 0x11111111))
    return uc

def run_load(uc):
    uc.reg_write(a64.UC_ARM64_REG_X1, DATA)
    uc.reg_write(a64.UC_ARM64_REG_X0, 0)
    uc.emu_start(CODE, CODE + 4, count=1)
    return uc.reg_read(a64.UC_ARM64_REG_X0)

for variant in ("no-flush", "ctl_flush_tb", "remove_cache(range)",
                "remove_cache(small)"):
    uc = build()
    v1 = run_load(uc)                       # translate + fill TLB
    # restore-like churn: unmap + remap + write new data
    uc.mem_unmap(DATA, 0x1000)
    uc.mem_map(DATA, 0x1000)
    uc.mem_write(DATA, struct.pack("<I", 0x22222222))
    try:
        if variant == "ctl_flush_tb":
            uc.ctl_flush_tb()
        elif variant == "remove_cache(range)":
            uc.ctl_remove_cache(1, 0xFFFFFFF00000)
        elif variant == "remove_cache(small)":
            uc.ctl_remove_cache(CODE, CODE + 0x1000)
    except Exception as e:
        print("%-22s ERR %r" % (variant, e))
        continue
    v2 = run_load(uc)
    ok = "OK (new)" if v2 == 0x22222222 else "STALE (bug!)"
    print("%-22s first=0x%08x second=0x%08x -> %s" % (variant, v1, v2, ok))
