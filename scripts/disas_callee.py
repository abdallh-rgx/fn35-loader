#!/usr/bin/env python3
"""disas_callee.py — disassemble the blocking callee from snapshot."""
import sys, os, json
sys.path.insert(0, "/home/z/my-project/scripts")
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
from fn35_snap import _load_state

BASE = "/home/z/my-project"
snap = os.path.join(BASE, "fn35/snap")
meta = json.load(open(os.path.join(snap, "index.json")))
state = _load_state(os.path.join(snap, "state.pkl"))

main_t = None
for t in state["threads"].values():
    if t.name.startswith("of.MainAppThread"):
        main_t = t
        break

CHUNK = 1 << 16
_rfiles = {}
def read_mem(addr, n):
    for r in meta["regions"]:
        b, e = r["begin"], r["end"]
        if b <= addr and addr + n <= e + 1:
            if r["file"] is None:
                return b"\x00" * n
            key = r["file"]
            if key not in _rfiles:
                _rfiles[key] = open(os.path.join(snap, r["file"]), "rb")
            f = _rfiles[key]
            ci = (addr - b) // r["chunksz"]
            off = (addr - b) % r["chunksz"]
            # walk present chunks to find file offset of chunk ci
            foff = 0
            for c in r["present"]:
                if c == ci:
                    f.seek(foff + off)
                    return f.read(n)
                foff += r["chunksz"]
            return b"\x00" * n
    return None

target = int(sys.argv[1], 0) if len(sys.argv) > 1 else 0x102018504
back = int(sys.argv[2], 0) if len(sys.argv) > 2 else 0x40
fwd = int(sys.argv[3], 0) if len(sys.argv) > 3 else 0x140

code = read_mem(target - back, back + fwd)
md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
for ins in md.disasm(code, target - back):
    mark = " <<<" if ins.address == target else ""
    print("  0x%x  %-9s %s%s" % (ins.address, ins.mnemonic, ins.op_str, mark))
