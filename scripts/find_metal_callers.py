#!/usr/bin/env python3
"""find_metal_callers.py — who calls the Metal-die routine at
0x1009c5f08, and what guard precedes each call."""
import sys, struct, bisect
sys.path.insert(0, "/home/z/my-project/scripts")
from fn35_macho import MachO
import capstone

BIN = ("/home/z/my-project/fn35/extracted/Payload/"
       "FortniteClient.app/FortniteClient")
mo = MachO(BIN)
mo.load_symbols()
with open(BIN, "rb") as f:
    blob = f.read()

syms = sorted((s.value, mo.sym_name(i)) for i, s in enumerate(mo.syms)
              if s.value)
addrs = [a for a, _ in syms]


def sym(addr):
    j = bisect.bisect_right(addrs, addr) - 1
    if j < 0:
        return None, 0
    return syms[j][1], syms[j][0]


def va2off(va):
    for s in mo.segments:
        if s.vmaddr <= va < s.vmaddr + s.vmsize:
            return s.fileoff + (va - s.vmaddr)
    return None


DIE = 0x1009c5f08
md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_LITTLE_ENDIAN)
md.skipdata = True
seg = [s for s in mo.segments if s.name == "__TEXT"][0]
text = blob[seg.fileoff:seg.fileoff + seg.filesize]

# scan for bl/b targets == DIE
callers = []
w = 0
n = len(text) - 4
while w < n:
    word = struct.unpack_from("<I", text, w)[0]
    op = word >> 26
    if op in (0x25, 0x05):  # bl / b
        imm = word & 0x3FFFFFF
        if imm & 0x2000000:
            imm -= 0x4000000
        dst = seg.vmaddr + w + (imm << 2)
        if dst == DIE:
            callers.append((seg.vmaddr + w, "bl" if op == 0x25 else "b"))
    w += 4

print("callers of the Metal-die routine:")
for pc, kind in callers:
    n2, a2 = sym(pc)
    print("  0x%x %s from %s+0x%x" % (pc, kind, (n2 or "?")[:60], pc - a2))

# disassemble 30 instructions before each caller to see the guard
for pc, kind in callers[:4]:
    print("\n=== guard before 0x%x ===" % pc)
    lo = pc - 120
    off = va2off(lo)
    code = blob[off:off + 124]
    for ins in md.disasm(code, lo):
        mark = " <<< CALL" if ins.address == pc else ""
        print("   0x%x  %-8s %s%s" % (ins.address, ins.mnemonic,
                                     ins.op_str, mark))
