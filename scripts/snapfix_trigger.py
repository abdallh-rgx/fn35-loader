#!/usr/bin/env python3
"""snapfix_trigger.py — manually Trigger() the FEvents deadlocked
threads are waiting on, directly in the snapshot:
  * state[+0x14] = 1  (FEvent signaled)
  * thread.state  = ready  (wake it)
Use to diagnose 'who should have fired this' deadlocks: if the engine
progresses, the trigger source is a missing completion in our emulation.
"""
import json
import pickle
import struct
import sys

sys.path.insert(0, "/home/z/my-project/scripts")
import fn35_loader                      # noqa: F401 (class defs)
import unicorn.arm64_const as a64

SNAP = "/home/z/my-project/fn35/snap"
X19 = a64.UC_ARM64_REG_X19

meta = json.load(open(SNAP + "/index.json"))
state_path = SNAP + "/" + meta.get("state", "state.pkl")
st = pickle.load(open(state_path, "rb"))

def region_of(addr):
    for r in meta["regions"]:
        if r["begin"] <= addr < r["end"]:
            return r
    return None

def write_mem(addr, data):
    r = region_of(addr)
    assert r, "addr 0x%x not in any region" % addr
    csz = r["chunksz"]
    off = addr - r["begin"]
    ci, co = divmod(off, csz)
    assert ci in r["present"], "chunk %d not present" % ci
    rank = r["present"].index(ci)
    with open(SNAP + "/" + r["file"], "r+b") as f:
        f.seek(rank * csz + co)
        f.write(data)

patched = 0
for t in st["threads"].values():
    w = getattr(t, "wait", None)
    if not w or w[0] != "cond":
        continue
    x19 = t.regs.get(X19, 0) if isinstance(t.regs, dict) else 0
    if not x19:
        continue
    cur = None
    try:
        r = region_of(x19)
        csz = r["chunksz"]
        off = x19 - r["begin"]
        ci, co = divmod(off, csz)
        rank = r["present"].index(ci)
        with open(SNAP + "/" + r["file"], "rb") as f:
            f.seek(rank * csz + co)
            cur = struct.unpack("<I", f.read(4))[0]
    except Exception as e:
        print("read state failed for tid=%x: %r" % (t.tid, e))
        continue
    print("tid=%-8x name=%-24r FEvent=0x%x state[+0x14]=%d -> 1"
          % (t.tid, getattr(t, "name", "?"), x19, cur))
    write_mem(x19 + 0x14, struct.pack("<I", 1))
    t.state = "ready"
    t.wait = None
    t.wake_ns = None
    patched += 1

print("patched %d waiters" % patched)
if patched:
    with open(state_path, "wb") as f:
        pickle.dump(st, f)
    print("snapshot updated:", state_path)
