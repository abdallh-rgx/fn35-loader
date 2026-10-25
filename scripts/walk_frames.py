#!/usr/bin/env python3
"""walk_frames.py — offline frame-chain walk of all spinning threads from snapshot."""
import sys, os, json, struct
sys.path.insert(0, "/home/z/my-project/scripts")
from fn35_snap import _load_state
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM

SNAP = "/home/z/my-project/fn35/snap"
meta = json.load(open(os.path.join(SNAP, "index.json")))
CHUNK = 1 << 16
_files = {}
_pmaps = {}
def rdmem(addr, n):
    for r in meta["regions"]:
        if r["begin"] <= addr and addr + n <= r["end"]:
            f = _files.get(r["file"])
            if f is None and r["file"]:
                f = open(os.path.join(SNAP, r["file"]), "rb")
                _files[r["file"]] = f
            if f is None:
                return b"\x00" * n
            out = b""
            a = addr; left = n
            # chunks are PACKED in present-order (not at ci*CHUNK)
            pmap = _pmaps.setdefault(r["file"], {})
            if not pmap:
                for pos, c in enumerate(r["present"]):
                    pmap[c] = pos * CHUNK
            while left > 0:
                ci = (a - r["begin"]) // CHUNK
                off_in = (a - r["begin"]) % CHUNK
                if ci not in pmap:
                    take = min(left, CHUNK - off_in)
                    out += b"\x00" * take
                    a += take; left -= take
                    continue
                f.seek(pmap[ci] + off_in)
                take = min(left, CHUNK - off_in)
                out += f.read(take)
                a += take; left -= take
            return out
    return None

def rd64(a):
    d = rdmem(a, 8)
    return struct.unpack("<Q", d)[0] if d else 0

state = _load_state(os.path.join(SNAP, "state.pkl"))
import unicorn.arm64_const as a64

for t in sorted(state["threads"].values(), key=lambda t: -t.approx_instr):
    if t.approx_instr < 100_000_000:
        continue
    regs = t.regs or {}
    pc = regs.get(a64.UC_ARM64_REG_PC, 0)
    fp = regs.get(a64.UC_ARM64_REG_X29, 0) or regs.get(a64.UC_ARM64_REG_FP, 0)
    sp = regs.get(a64.UC_ARM64_REG_SP, 0)
    print("=== %r tid=0x%x instr=%dM pc=0x%x" % (t.name, t.tid, t.approx_instr//1000000, pc))
    seen = set()
    nfr = 0
    while fp and fp not in seen and nfr < 16:
        seen.add(fp)
        nxt = rd64(fp)
        ret = rd64(fp + 8)
        if not ret:
            break
        print("   [bt %2d] 0x%x" % (nfr, ret), end="")
        code = rdmem(ret - 8, 16) if ret else None
        if code:
            try:
                ins = list(Cs(CS_ARCH_ARM64, CS_MODE_ARM).disasm(code, ret - 8))
                if ins:
                    print("  <- called at 0x%x %s %s" % (ins[0].address, ins[0].mnemonic, ins[0].op_str), end="")
            except Exception:
                pass
        print()
        nfr += 1
        if nxt <= fp:
            break
        fp = nxt
