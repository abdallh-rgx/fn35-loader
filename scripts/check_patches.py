#!/usr/bin/env python3
"""check_patches.py — verify all code patches present in a crash snapshot."""
import sys, os, json, struct
sys.path.insert(0, "/home/z/my-project/scripts")
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
import keystone

SNAP = sys.argv[1] if len(sys.argv) > 1 else "/home/z/my-project/fn35/snap_test_crash"
meta = json.load(open(os.path.join(SNAP, "index.json")))
CHUNK = 1 << 16
regions = meta["regions"]
_files = {}
def rdmem(addr, n):
    for r in regions:
        if r["begin"] <= addr and addr + n <= r["end"]:
            f = _files.get(r["file"])
            if f is None:
                f = open(os.path.join(SNAP, r["file"]), "rb")
                _files[r["file"]] = f
            out = b""
            a = addr; left = n
            while left > 0:
                ci = (a - r["begin"]) // CHUNK
                off_in = (a - r["begin"]) % CHUNK
                if ci not in r["present"]:
                    out += b"\x00" * min(left, CHUNK - off_in)
                    take = min(left, CHUNK - off_in)
                    a += take; left -= take
                    continue
                f.seek(ci * CHUNK + off_in)
                take = min(left, CHUNK - off_in)
                out += f.read(take)
                a += take; left -= take
            return out
    return None

cs = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
ks = keystone.Ks(keystone.KS_ARCH_ARM64, keystone.KS_MODE_LITTLE_ENDIAN)

def show(addr, n=4, note=""):
    d = rdmem(addr, n)
    print("[0x%x] %s %s" % (addr, d.hex() if d else "UNMAPPED", note))
    if d:
        for i in cs.disasm(d, addr):
            print("      %-8s %s" % (i.mnemonic, i.op_str))

# 1. static patches
show(0x1023575d4, 4, "(verify fn: expect ret)")
show(0x10136d094, 4, "(assert helper)")
# 2. weakobj redirects
show(0x102def960, 4, "(IndexToObject ldr1: expect b cave)")
show(0x1028eb2f8, 4, "(twin ldr1: expect b cave)")
# 3. cave body
d = rdmem(0x106000000, 0x40)
print("[cave] %s" % (d.hex() if d else "UNMAPPED"))
if d:
    for i in cs.disasm(d, 0x106000000):
        print("      0x%x %-8s %s" % (i.address, i.mnemonic, i.op_str))
# 4. thread state at crash
from fn35_snap import _load_state
state = _load_state(os.path.join(SNAP, "state.pkl"))
print("\n--- threads with pc=0 or suspicious ---")
for t in state["threads"].values():
    pc = t.regs.get(264, 0)
    sp = t.regs.get(231, 0) if 231 in t.regs else t.regs.get(a64sp, 0)
    lr = t.regs.get(229, 0)
    if pc == 0 or "1bb0" in hex(t.tid):
        print("%r tid=0x%x state=%s pc=0x%x sp=0x%x lr=0x%x" % (
            t.name, t.tid, t.state, pc, sp, lr))
import unicorn.arm64_const as a64
