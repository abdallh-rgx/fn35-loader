#!/usr/bin/env python3
"""stack_walk2.py — proper FP-chain walk from snapshot."""
import sys, os, json, struct
sys.path.insert(0, "/home/z/my-project/scripts")
from fn35_snap import _load_state
from unicorn import unicorn_py3 as U
from unicorn.arm64_const import (UC_ARM64_REG_X29, UC_ARM64_REG_X30,
                                 UC_ARM64_REG_SP, UC_ARM64_REG_PC)

BASE = "/home/z/my-project"
snap = os.path.join(BASE, "fn35/snap")
meta = json.load(open(os.path.join(snap, "index.json")))
state = _load_state(os.path.join(snap, "state.pkl"))

want = sys.argv[1] if len(sys.argv) > 1 else "of.MainAppThread"
t = None
for tt in state["threads"].values():
    if want in tt.name:
        t = tt
        break
regs = t.regs or {}
sp = regs.get(UC_ARM64_REG_SP)
fp = regs.get(UC_ARM64_REG_X29)
pc = regs.get(UC_ARM64_REG_PC)
lr = regs.get(UC_ARM64_REG_X30)
print("thread=%r pc=0x%x sp=0x%x fp=0x%x lr=0x%x" % (t.name, pc, sp, fp, lr))

_rfiles = {}
def read64(addr):
    for r in meta["regions"]:
        b, e = r["begin"], r["end"]
        if b <= addr and addr + 8 <= e + 1:
            if r["file"] is None:
                return 0
            key = r["file"]
            if key not in _rfiles:
                _rfiles[key] = open(os.path.join(snap, r["file"]), "rb")
            f = _rfiles[key]
            ci = (addr - b) // r["chunksz"]
            off = (addr - b) % r["chunksz"]
            foff = 0
            for c in r["present"]:
                if c == ci:
                    f.seek(foff + off)
                    return struct.unpack("<Q", f.read(8))[0]
                foff += r["chunksz"]
            return 0
    return None

# --- FP chain walk ---
chain = []
cur = fp
for _ in range(40):
    if not cur:
        break
    nxt = read64(cur)
    ret = read64(cur + 8)
    if nxt is None or ret is None:
        break
    chain.append((cur, ret))
    if nxt <= cur or nxt - cur > 0x20000:
        break
    cur = nxt

print("=== FP chain (%d frames) ===" % len(chain))
for i, (fpat, ret) in enumerate(chain):
    print("  #%02d fp=0x%x  ret=0x%x" % (i, fpat, ret))

# also dump raw stack around SP looking for text-range addrs
print("=== raw stack scan (first 40 text addrs above sp) ===")
IMG_LO, IMG_HI = 0x100004000, 0x103100000
found = []
for off in range(0, 0x4000, 8):
    v = read64(sp + off)
    if v is not None and IMG_LO <= v < IMG_HI and (v & 3) == 0:
        found.append((off, v))
    if len(found) >= 40:
        break
for off, v in found:
    print("  sp+0x%03x: 0x%x" % (off, v))
