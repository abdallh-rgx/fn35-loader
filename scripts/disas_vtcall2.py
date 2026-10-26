#!/usr/bin/env python3
"""disas_vtcall2.py — symbolize + xref the null-vtable crash:
- standalone symbolizer over the Mach-O symtab
- find the function start of the crash fn (scan back for prologue)
- xrefs: who calls the crash fn and the caller 0x102b16638's function
- disassemble the immediate callers"""
import sys, struct
sys.path.insert(0, "/home/z/my-project/scripts")
from fn35_macho import MachO
import capstone

BIN = ("/home/z/my-project/fn35/extracted/Payload/"
       "FortniteClient.app/FortniteClient")
mo = MachO(BIN)
with open(BIN, "rb") as f:
    blob = f.read()

syms = []
for i, s in enumerate(mo.syms):
    if s.value:
        syms.append((s.value, mo.sym_name(i)))
syms.sort()
print("symbols:", len(syms))

import bisect
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


def rd(va, n):
    o = va2off(va)
    return blob[o:o + n] if o is not None else b""


md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
md.skipdata = True

for site in (0x102a90c24, 0x102b16638, 0x102a90bf4, 0x102a90c00):
    n, a = sym(site)
    print("0x%x -> %s+0x%x" % (site, (n or "?")[:80], site - a))

# function start of the crash fn: scan back for stp x29/x30 prologue or
# pacibsp (this is arm64e-ish) - look for a sub sp / stp sequence
start = 0x102a90bf4
back = 0x102a90900
code = rd(back, start - back + 4)
ins = list(md.disasm(code, back))
prev = None
for k, i in enumerate(ins):
    if i.address == start:
        # found: the crash fn is standalone at 0x102a90bf4 (prologue seen)
        print("crash fn prologue confirmed at 0x%x" % start)
        break

# xrefs: scan __TEXT for bl/b targets hitting these funcs
targets = {0x102a90bf4: "crashfn", 0x102b16600: "caller-region"}
seg = [s for s in mo.segments if s.name == "__TEXT"][0]
text = blob[seg.fileoff:seg.fileoff + seg.filesize]
hits = []
i = 0
n = len(text) - 4
while i < n:
    w = struct.unpack_from("<I", text, i)[0]
    op = w >> 24
    if op in (0x94, 0x17, 0x14):  # bl, b, b (unconditional)
        if op == 0x94 or op == 0x14 or op == 0x17:
            imm = w & 0x3FFFFFF
            if imm & 0x2000000:
                imm -= 0x4000000
            if op == 0x17 or op == 0x14:
                dst = seg.vmaddr + i + (imm << 2)
            else:
                dst = seg.vmaddr + i + (imm << 2)
            if dst == 0x102a90bf4:
                hits.append((seg.vmaddr + i, "bl" if op == 0x94 else "b"))
    i += 4
print("xrefs to crashfn 0x102a90bf4:", len(hits))
for pc, kind in hits[:12]:
    n, a = sym(pc)
    print("  0x%x %s from %s+0x%x" % (pc, kind, (n or "?")[:60], pc - a))
