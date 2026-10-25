#!/usr/bin/env python3
"""disas_sleep.py — disassemble the MainAppThread sleep loop from snapshot."""
import sys, os, json
sys.path.insert(0, "/home/z/my-project/scripts")
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
from fn35_snap import _load_state

BASE = "/home/z/my-project"
snap = os.path.join(BASE, "fn35/snap")
meta = json.load(open(os.path.join(snap, "index.json")))
state = _load_state(os.path.join(snap, "state.pkl"))

# find MainAppThread pc
main_t = None
for t in state["threads"].values():
    if t.name.startswith("of.MainAppThread"):
        main_t = t
        break
pc = main_t.pc if main_t else 0x101b66a64
print("MainAppThread pc = 0x%x  regs[x0..3]=%s" %
      (pc, [hex(v) for v in list(main_t.regs.values())[:4]]))
sp = None
for k, v in main_t.regs.items():
    pass
# grab a few key regs by index (X0=199..)
xr = {}
for k, v in main_t.regs.items():
    xr[k] = v
print("pc-ish regs:", {hex(k): hex(v) for k, v in list(xr.items())[:6]})

CHUNK = 1 << 16
def read_mem(addr, n):
    for r in meta["regions"]:
        b, e = r["begin"], r["end"]
        if b <= addr and addr + n <= e + 1:
            ci = (addr - b) // r["chunksz"]
            off = (addr - b) % r["chunksz"]
            with open(os.path.join(snap, r["file"]), "rb") as f:
                # walk to chunk ci
                for c in r["present"]:
                    if c == ci:
                        f.seek(0)
                        # sequential: read until we reach it
                        f.seek(0)
                        for cc in r["present"]:
                            data = f.read(r["chunksz"])
                            if cc == ci:
                                return data[off:off + n]
                        return None
                    else:
                        pass
            return None
    return None

code = read_mem(pc - 0x100, 0x180)
if code is None:
    print("could not read memory at pc")
    sys.exit(1)

md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
base = pc - 0x100
for ins in md.disasm(code, base):
    mark = " <<< PC" if ins.address == pc else ""
    print("  0x%x  %-10s %s%s" % (ins.address, ins.mnemonic, ins.op_str, mark))
