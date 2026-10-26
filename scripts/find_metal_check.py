#!/usr/bin/env python3
"""find_metal_check.py — locate 'App requires Metal but it doesn't
exist' in the binary, xref the code that logs it, disassemble the
surrounding function to see what gates the abort."""
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


def rd(va, n):
    o = va2off(va)
    return blob[o:o + n] if o is not None else b""


# 1. find the string
needle = b"App requires Metal but it doesn't exist\x00"
i = blob.find(needle)
print("string at file off 0x%x" % i)
sva = off2va(i)
print("string va 0x%x" % sva)
# it might be a __cfstring constant's DATA: find a cfstring whose data
# ptr == sva (search __DATA/__DATA_CONST for the 8-byte LE of sva)
target = struct.pack("<Q", sva)
cf_cands = []
start = 0
while True:
    j = blob.find(target, start)
    if j < 0:
        break
    va = off2va(j - 16)  # cfstring struct starts 16 before the data ptr
    if va:
        cf_cands.append(va)
    start = j + 1
    if len(cf_cands) > 6:
        break
print("cfstring constants referencing it:", [hex(c) for c in cf_cands])

# 2. find adrp/add pairs loading any of those addresses
md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
md.skipdata = True
seg = [s for s in mo.segments if s.name == "__TEXT"][0]
text = blob[seg.fileoff:seg.fileoff + seg.filesize]
hits = []
w = 0
n = len(text) - 4
while w < n:
    word = struct.unpack_from("<I", text, w)[0]
    if (word >> 24) == 0x90:  # adrp
        immlo = (word >> 29) & 3
        immhi = (word >> 5) & 0x7FFFF
        imm = (immhi << 2) | immlo
        page = (seg.vmaddr + (w << 0) + ((imm << 12)
                if (word >> 24) == 0x90 else 0)) & ~0xFFF
        base_pc = seg.vmaddr + w
        page = (base_pc & ~0xFFF) + (imm << 12)
        # next instruction add xN, xN, #imm
        if w + 4 < n:
            w2 = struct.unpack_from("<I", text, w + 4)[0]
            if (w2 >> 24) == 0x91 and ((w2 >> 10) & 3) == 0:
                imm12 = (w2 >> 10) >> 2
                dst = page + imm12
                for c in cf_cands:
                    if dst == c or (dst & ~0xFFF) == (c & ~0xFFF) \
                            and abs(dst - c) < 0x1000:
                        hits.append(base_pc)
    w += 4
print("adrp refs near cfstrings:", len(hits), [hex(h) for h in hits[:8]])
for h in hits[:4]:
    n2, a2 = sym(h)
    print("ref 0x%x in %s+0x%x" % (h, (n2 or "?")[:60], h - a2))
    # disassemble around
    code = rd(h - 48, 160)
    for ins in md.disasm(code, h - 48):
        print("   0x%x  %-8s %s" % (ins.address, ins.mnemonic,
                                    ins.op_str))
    print("   ----")
