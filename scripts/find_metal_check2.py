#!/usr/bin/env python3
"""find_metal_check2.py — precise adrp+add decode to 0x1040a1390
(the 'App requires Metal' cfstring) + xref + full context disasm."""
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


def off2va(off):
    for s in mo.segments:
        if s.fileoff <= off < s.fileoff + s.filesize:
            return s.vmaddr + (off - s.fileoff)
    return None


TARGET = 0x1040a1390  # cfstring const of the Metal message
md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_LITTLE_ENDIAN)
md.skipdata = True
seg = [s for s in mo.segments if s.name == "__TEXT"][0]
text = blob[seg.fileoff:seg.fileoff + seg.filesize]

hits = []
w = 0
n = len(text) - 8
while w < n:
    word = struct.unpack_from("<I", text, w)[0]
    if (word >> 24) == 0x90:  # adrp
        immlo = (word >> 29) & 3
        immhi = (word >> 5) & 0x7FFFF
        imm = (immhi << 2) | immlo
        pc = seg.vmaddr + w
        page = ((pc >> 12) + imm) << 12
        w2 = struct.unpack_from("<I", text, w + 4)[0]
        # add xN, xN, #imm12 (option shift 0)
        if (w2 >> 24) == 0x91 and ((w2 >> 10) & 3) == 0:
            imm12 = (w2 >> 10) >> 2
            imm12 = (w2 >> 10) & 0xFFF  # 12-bit imm at bits 10-21
            dst = page + imm12
            if dst == TARGET:
                hits.append(pc)
        # ldr xN, [xN, #imm] form too
        elif (w2 >> 24) == 0xF9:
            imm12 = ((w2 >> 10) & 0xFFF) << 3
            dst = page + imm12
            if dst in (TARGET, TARGET - 0x10):
                hits.append(pc)
    w += 4

print("exact refs:", [hex(h) for h in hits])
for h in hits[:6]:
    n2, a2 = sym(h)
    print("\n=== ref 0x%x in %s+0x%x ===" % (h, (n2 or "?")[:70], h - a2))
    lo = h - 96
    off = va2off(lo)
    code = blob[off:off + 320]
    for ins in md.disasm(code, lo):
        mark = " <<<" if ins.address == h else ""
        print("   0x%x  %-8s %s%s" % (ins.address, ins.mnemonic,
                                      ins.op_str, mark))
