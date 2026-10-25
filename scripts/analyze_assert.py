#!/usr/bin/env python3
"""analyze_assert.py — offline analysis of the assert/RequestExit path.

From snap_crash (state at abort):
  * read [0x1055ce990] -> vtable -> vtable[+0x10] = error-sink method
  * dump the sink's code (who calls RequestExit / prints the message)
  * scan stacks of MainAppThread for the formatted wide message
"""
import json
import os
import sys

sys.path.insert(0, "/home/z/my-project/scripts")
from fn35_snap import _load_state
import capstone

BASE = "/home/z/my-project"
BIN = os.path.join(BASE, "fn35/extracted/Payload/FortniteClient.app/"
                        "FortniteClient")
SNAP = os.path.join(BASE, "fn35/snap_crash")

md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
md.skipdata = True


def v2o(va):
    """__TEXT is mapped vmaddr-0x100000000 == fileoff."""
    return va - 0x100000000


# ---- build a memory reader from the snapshot regions ----
meta = json.load(open(os.path.join(SNAP, "index.json")))
regions = []
for r in meta["regions"]:
    if r["file"]:
        regions.append((r["begin"], r["end"], r["file"],
                        r["present"], r["chunksz"]))
    else:
        regions.append((r["begin"], r["end"], None, [], 0))
_cache = {}


def rd(addr, n):
    out = b""
    while n > 0:
        for b, e, f, present, csz in regions:
            if b <= addr < e:
                if f is None:
                    return out + b"\x00" * n   # all-zero region
                idx = (addr - b) // csz
                if idx not in present:
                    return out + b"\x00" * n   # zero chunk
                if idx not in _cache:
                    with open(os.path.join(SNAP, f), "rb") as fh:
                        fh.seek(present.index(idx) * csz)
                        _cache[idx] = (b, fh.read(csz))
                base, buf = _cache[idx]
                off = addr - base
                take = min(n, csz - off)
                out += buf[off:off + take]
                addr += take
                n -= take
                break
        else:
            return out + b"\x00" * n
    return out


def u64(a):
    return int.from_bytes(rd(a, 8), "little")


def wstr(a, maxn=200):
    raw = rd(a, maxn * 2)
    try:
        return raw.decode("utf-16-le", "replace").split("\x00")[0]
    except Exception:
        return "?"


print("=== error device object @ 0x1055ce990 ===")
vt = u64(0x1055ce990)
print("vtable = 0x%x" % vt)
for off in (0, 8, 0x10, 0x18, 0x20):
    fn = u64(vt + off)
    print("  vt[+0x%x] = 0x%x" % (off, fn))

sink = u64(vt + 0x10)
print("\n=== sink function @ 0x%x ===" % sink)
off = v2o(sink)
with open(BIN, "rb") as f:
    f.seek(off)
    code = f.read(0x150)
for ins in md.disasm(code, sink):
    print("  0x%x  %-8s %s" % (ins.address, ins.mnemonic, ins.op_str))
    if ins.mnemonic == "ret":
        break

# ---- scan MainAppThread's stack for the wide assert message ----
print("\n=== MainAppThread stack scan (wide strings) ===")
state = _load_state(os.path.join(SNAP, "state.pkl"))
t = None
for tt in state["threads"].values():
    if "MainAppThread" in tt.name:
        t = tt
        break
print("thread pc=0x%x" % t.pc)
regs = t.regs or {}
sp = None
for k, v in regs.items():
    if v and 0x700000000000 <= v < 0x710000000000:
        sp = v if sp is None else min(sp, v)
print("stack pointer guess: 0x%x" % sp)
if sp:
    raw = rd(sp, 0x4000)
    # scan for UTF-16LE "Assertion" or "Failed" patterns
    for probe in (b"A\x00s\x00s\x00e\x00r\x00t\x00i\x00o\x00n\x00",
                  b"a\x00s\x00s\x00e\x00r\x00t\x00",
                  b"F\x00a\x00i\x00l\x00e\x00d\x00",
                  b"S\x00h\x00a\x00d\x00e\x00r\x00"):
        i = raw.find(probe)
        if i >= 0:
            seg = raw[i:i + 400].decode("utf-16-le", "replace")
            print("FOUND @ sp+0x%x: %r" % (i, seg.split("\x00")[0][:200]))
