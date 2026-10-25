#!/usr/bin/env python3
"""Read MainAppThread's VM bytecode position straight from the snapshot."""
import sys, os, json, struct, pickle
sys.path.insert(0, "/home/z/my-project/scripts")

SNAP = "/home/z/my-project/fn35/snap2"
meta = json.load(open(os.path.join(SNAP, "index.json")))

def read_mem(addr, n):
    for r in meta["regions"]:
        b, e = r["begin"], r["end"]
        if b <= addr and addr + n <= e + 1 and r.get("file"):
            path = os.path.join(SNAP, r["file"])
            csz = r["chunksz"]
            out = b""
            off, remaining = addr - b, n
            while remaining > 0:
                ci, co = divmod(off, csz)
                if ci not in r["present"]:
                    return None
                rank = r["present"].index(ci)
                with open(path, "rb") as f:
                    f.seek(rank * csz + co)
                    chunk = f.read(min(remaining, csz - co))
                out += chunk
                remaining -= len(chunk)
                off += len(chunk)
                if not chunk:
                    break
            return out[:n]
    return None

with open(os.path.join(SNAP, "state.pkl"), "rb") as f:
    st = pickle.load(f)

import unicorn.arm64_const as a64
for tid, t in st["threads"].items():
    if not (t.name or "").startswith("of.MainAppThread"):
        continue
    regs = t.regs or {}
    sp = regs.get(a64.UC_ARM64_REG_SP, 0)
    pc = regs.get(a64.UC_ARM64_REG_PC, 0)
    print("MainAppThread pc=0x%x sp=0x%x" % (pc, sp))
    for so, nm in ((0x780, "VM base"), (0x770, "VM idx"),
                   (0x988, "VM ptr"), (0x708, "churn1"),
                   (0x70c, "churn2")):
        b = read_mem(sp + so, 8)
        print("  [sp+0x%03x] %-8s = 0x%s" % (so, nm, b.hex() if b else "?"))

    base_b = read_mem(sp + 0x780, 8)
    idx_b = read_mem(sp + 0x770, 8)
    if base_b and idx_b:
        base = struct.unpack("<Q", base_b)[0]
        idx = struct.unpack("<Q", idx_b)[0]
        print("  -> bytecode at 0x%x + 0x%x (idx %.2f MB)" % (base, idx, idx / 1e6))
        # sample the bytecode around idx
        d = read_mem(base + idx, 32)
        if d:
            print("  -> bytes at ptr: %s" % d.hex())
