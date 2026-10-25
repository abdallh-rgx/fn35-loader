#!/usr/bin/env python3
"""dump_string_work.py — see the string MainAppThread is grinding on."""
import sys, os, json, struct
sys.path.insert(0, "/home/z/my-project/scripts")
from fn35_snap import _load_state
import unicorn.arm64_const as a64

SNAP = "/home/z/my-project/fn35/snap"
meta = json.load(open(os.path.join(SNAP, "index.json")))
CHUNK = 1 << 16
_files, _pmaps = {}, {}
def rdmem(a, n):
    for r in meta["regions"]:
        if r["begin"] <= a and a + n <= r["end"]:
            f = _files.get(r["file"])
            if f is None and r["file"]:
                f = open(os.path.join(SNAP, r["file"]), "rb"); _files[r["file"]] = f
            if f is None:
                return b"\x00" * n
            pmap = _pmaps.setdefault(r["file"], {})
            if not pmap:
                for pos, c in enumerate(r["present"]):
                    pmap[c] = pos * CHUNK
            out = b""
            addr, left = a, n
            while left > 0:
                ci = (addr - r["begin"]) // CHUNK
                off = (addr - r["begin"]) % CHUNK
                if ci not in pmap:
                    take = min(left, CHUNK - off)
                    out += b"\x00" * take; addr += take; left -= take; continue
                f.seek(pmap[ci] + off)
                take = min(left, CHUNK - off)
                out += f.read(take); addr += take; left -= take
            return out
    return None

state = _load_state(os.path.join(SNAP, "state.pkl"))
for t in state["threads"].values():
    if t.approx_instr < 10_000_000_000:
        continue
    regs = t.regs or {}
    pc = regs.get(a64.UC_ARM64_REG_PC, 0)
    print("=== %r tid=0x%x instr=%dB pc=0x%x" % (t.name, t.tid, t.approx_instr, pc))
    for reg in ("X0", "X1", "X19", "X20", "X21"):
        v = regs.get(getattr(a64, "UC_ARM64_REG_" + reg), 0)
        print("   %s = 0x%x" % (reg, v))
        if 0x1000 < v < 0x64000000000000:
            d = rdmem(v, 96)
            if d:
                try:
                    u16 = d.decode("utf-16-le", "replace")
                    print("      str: %r" % u16[:44])
                except Exception:
                    pass
                print("      hex: %s" % d[:24].hex())
