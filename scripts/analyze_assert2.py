#!/usr/bin/env python3
"""analyze_assert2.py — fast offline assert-path analysis from snap_crash.

Reads the error-device vtable + the sink function code + scans the
MainAppThread stack for the wide assert message. Simple & direct:
region lookup is a dict, chunk reads are one-shot.
"""
import json
import os
import sys

sys.path.insert(0, "/home/z/my-project/scripts")
import capstone

BASE = "/home/z/my-project"
BIN = os.path.join(BASE, "fn35/extracted/Payload/FortniteClient.app/"
                        "FortniteClient")
SNAP = os.path.join(BASE, "fn35/snap_crash")

md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
md.skipdata = True

meta = json.load(open(os.path.join(SNAP, "index.json")))
RMAP = {}          # page -> (region info)
for r in meta["regions"]:
    if r["file"]:
        RMAP[(r["begin"] // 0x1000)] = r
        # also register all pages it spans
        for p in range(r["begin"] // 0x1000, r["end"] // 0x1000 + 1):
            RMAP[p] = r


def rd(addr, n):
    out = bytearray()
    while n > 0:
        r = RMAP.get(addr // 0x1000)
        if r is None or not r["file"]:
            out += b"\x00" * n
            return bytes(out)
        b, csz, present = r["begin"], r["chunksz"], r["present"]
        idx = (addr - b) // csz
        if idx not in present:
            out += b"\x00" * n
            return bytes(out)
        with open(os.path.join(SNAP, r["file"]), "rb") as fh:
            fh.seek(present.index(idx) * csz)
            buf = fh.read(csz)
        off = (addr - b) % csz
        take = min(n, csz - off)
        out += buf[off:off + take]
        addr += take
        n -= take
    return bytes(out)


def u64(a):
    return int.from_bytes(rd(a, 8), "little")


print("=== error device @ 0x1055ce990 ===")
vt = u64(0x1055ce990)
print("vtable = 0x%x" % vt)
sink = u64(vt + 0x10)
print("sink (vt+0x10) = 0x%x" % sink)

print("\n=== sink function code ===")
off = sink - 0x100000000
with open(BIN, "rb") as f:
    f.seek(off)
    code = f.read(0x180)
for ins in md.disasm(code, sink):
    print("  0x%x  %-8s %s" % (ins.address, ins.mnemonic, ins.op_str))
    if ins.mnemonic == "ret":
        break

# ---- stack scan for the wide message ----
print("\n=== stack scan (MainAppThread) ===")
from fn35_snap import _load_state
state = _load_state(os.path.join(SNAP, "state.pkl"))
t = next(tt for tt in state["threads"].values()
         if "MainAppThread" in tt.name)
print("thread pc=0x%x" % t.pc)
regs = t.regs or {}
sps = sorted(v for v in regs.values()
             if v and 0x700000000000 <= v < 0x710000000000)
print("stack range: 0x%x..0x%x" % (sps[0], sps[-1]) if sps else "no sp")
if sps:
    raw = rd(sps[0], 0x8000)
    for probe, label in ((b"A\x00s\x00s\x00e\x00r\x00", "assert"),
                         (b"F\x00a\x00i\x00l\x00", "Fail"),
                         (b"S\x00h\x00a\x00d\x00", "Shad")):
        start = 0
        while True:
            i = raw.find(probe, start)
            if i < 0:
                break
            seg = raw[i:i + 600].decode("utf-16-le", "replace")
            seg = seg.split("\x00")[0]
            print("[%s @ +0x%x] %r" % (label, i, seg[:220]))
            start = i + 2
