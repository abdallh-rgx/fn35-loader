#!/usr/bin/env python3
"""probe_gotwatch.py — watch GOT slot 0x1037c2700 (___toupper) for the
write that zeroes it; dump PC + backtrace at the moment of the crime."""
import os, sys
os.environ["FN35_BUDGET"] = "360"
os.environ["FN35_SYNC_HOOK"] = "code"
os.environ["FN35_SNAPSHOT"] = "/home/z/my-project/fn35/probe_snap2"
import fn35_loader as L
from unicorn import UC_HOOK_MEM_WRITE as _HW
from unicorn import UcError

SLOT = 0x1037c2700

def patch_after_setup(self):
    # called at the end of install_hooks — add our watcher
    uc = self.uc
    def on_write(uc_, access, addr, size, value, ud):
        if value == 0:
            import unicorn.arm64_const as a64
            pc = uc_.reg_read(a64.UC_ARM64_REG_PC)
            lr = uc_.reg_read(a64.UC_ARM64_REG_LR)
            sp = uc_.reg_read(a64.UC_ARM64_REG_SP)
            print("[gotwatch] ZERO WRITE to 0x%x from pc=0x%x lr=0x%x sp=0x%x"
                  % (addr, pc, lr, sp))
            # quick stack scan for return addresses (code range)
            try:
                stack = uc_.mem_read(sp, 0x200)
                import struct
                rets = []
                for i in range(0, 0x200, 8):
                    v = struct.unpack("<Q", stack[i:i+8])[0]
                    if 0x100000000 <= v < 0x106000000:
                        rets.append(hex(v))
                print("[gotwatch] stack code addrs:", rets[-10:])
            except Exception:
                pass
            uc_.emu_stop()
        else:
            print("[gotwatch] write 0x%x -> 0x%x (nonzero, ignored)"
                  % (value, addr))
    uc.hook_add(_HW, on_write, begin=SLOT, end=SLOT + 8)

orig = L.FNLoader.install_hooks
def patched(self):
    orig(self)
    patch_after_setup(self)
L.FNLoader.install_hooks = patched
sys.argv = [sys.argv[0]]
L.main()
