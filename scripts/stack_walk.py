#!/usr/bin/env python3
"""stack_walk.py — extract the call chain of a thread from the snapshot."""
import sys, os, json
sys.path.insert(0, "/home/z/my-project/scripts")
from fn35_snap import _load_state

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
if t is None:
    print("no thread matching %r; have: %s" %
          (want, [tt.name for tt in state["threads"].values()]))
    sys.exit(1)

print("thread %r tid=%x pc=0x%x state=%s" % (t.name, t.tid, t.pc, t.state))
# find SP/X29 from regs. unicorn consts: SP=4? Use position: SAVE_REGS order.
# fallback: scan all regs for stack-range values (stack pools are large
# mappings); print all reg values first.
regs = t.regs or {}
vals = sorted(set(v for v in regs.values() if v))
print("reg range: 0x%x .. 0x%x" % (min(vals), max(vals)))

# stack region = the region containing SP. Identify SP as the reg value
# inside a region that is NOT the image (0x100000000-0x105ac5000).
IMG_LO, IMG_HI = 0x100000000, 0x105ac5000
cands = [v for v in vals if not (IMG_LO <= v < IMG_HI)]
# SP is usually the lowest stack-ish pointer; just try all regions
_rfiles = {}
def read_region(addr, n):
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
            foff = 0
            for c in r["present"]:
                if c == ci:
                    f.seek(foff + off)
                    return f.read(n)
                foff += r["chunksz"]
            return b"\x00" * n
    return None

import struct
# scan every candidate SP-ish value's region for return addresses
for sp in cands[:40]:
    if sp & 7:
        continue
    data = read_region(sp, 0x8000)
    if data is None:
        continue
    rets = []
    for off in range(0, len(data) - 8, 8):
        v, = struct.unpack_from("<Q", data, off)
        if IMG_LO <= v < IMG_HI and (v & 3) == 0:
            rets.append((off, v))
    if len(rets) >= 6:
        print("\n=== candidate SP 0x%x: %d code pointers on stack ==="
              % (sp, len(rets)))
        for off, v in rets[:60]:
            print("  sp+0x%04x: 0x%x" % (off, v))
        break
