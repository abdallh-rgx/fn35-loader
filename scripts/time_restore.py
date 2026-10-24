#!/usr/bin/env python3
"""time_restore.py — time each phase of snapshot restore to find the slow one."""
import sys, os, time, json
sys.path.insert(0, "/home/z/my-project/scripts")
os.environ["FN35_QUIET"] = "1"

t0 = time.time()
def mark(s):
    print("[%7.1fs] %s" % (time.time() - t0, s), flush=True)

mark("start")
import fn35_loader as FL
import fn35_snap
mark("imports done")

SNAP = "/home/z/my-project/fn35/snap"
MACHO = "/home/z/my-project/fn35/extracted/Payload/FortniteClient.app/FortniteClient"
SANDBOX = "/home/z/my-project/fn35/sandbox"

l = FL.FNLoader(MACHO, SANDBOX, budget=10, trace_n=0, live_log=False)
mark("FNLoader created")
l.prepare()
mark("prepare() done")

meta = json.load(open(os.path.join(SNAP, "index.json")))
CHUNK = 1 << 16
from fn35_snap import _unmap_intersecting
t_ov = time.time()
written = 0
for i, r in enumerate(meta["regions"]):
    b, e, perms = r["begin"], r["end"], r["perms"]
    _unmap_intersecting(l.uc, b, e)
    l.uc.mem_map(b, e - b + 1, perms)
    if r["file"]:
        with open(os.path.join(SNAP, r["file"]), "rb") as f:
            for ci in r["present"]:
                data = f.read(CHUNK)
                addr = b + ci * CHUNK
                wlen = min(len(data), e + 1 - addr)
                if wlen > 0:
                    l.uc.mem_write(addr, data[:wlen])
                    written += wlen
    if i % 500 == 0:
        mark("overlay %d/%d (%.1fMB)" % (i, len(meta["regions"]), written/1e6))
mark("overlay done: %d bytes" % written)

state = fn35_snap._load_state(os.path.join(SNAP, "state.pkl"))
mark("state.pkl unpickled")
mark("ALL DONE")
