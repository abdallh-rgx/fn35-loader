#!/usr/bin/env python3
"""Find code xrefs to the displayLinkWithTarget:selector: selref."""
import struct
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN

EXE = "/home/z/my-project/fn35/extracted/Payload/FortniteClient.app/FortniteClient"
SEL = 0x103096667  # "displayLinkWithTarget:selector:"

with open(EXE, "rb") as f:
    blob = f.read()

segs = []
off = 32
magic, cputype, cpusub, filetype, ncmds, sizeofcmds, flags = \
    struct.unpack_from("<IIIIIII", blob, 0)
sections = []
for _ in range(ncmds):
    cmd, cmdsize = struct.unpack_from("<II", blob, off)
    if cmd == 0x19:
        name = blob[off+8:off+24].split(b"\0")[0].decode()
        vmaddr, vmsize, fileoff, filesize = \
            struct.unpack_from("<QQQQ", blob, off+24)
        segs.append((name, vmaddr, vmsize, fileoff, filesize))
        nsects = struct.unpack_from("<I", blob, off+64)[0]
        so = off + 72
        for si in range(nsects):
            sect = blob[so:so+16].split(b"\0")[0].decode()
            seg2 = blob[so+16:so+32].split(b"\0")[0].decode()
            saddr, ssize = struct.unpack_from("<QQ", blob, so+32)
            sections.append((seg2, sect, saddr, ssize))
            so += 80
    off += cmdsize

def a2f(addr):
    for name, vm, vs, fo, fs in segs:
        if vm <= addr < vm + vs:
            return fo + (addr - vm)
    return None

# 1. find the selref slot whose value == SEL
selrefs = [s for s in sections if s[1] == "__objc_selrefs"]
slot = None
for seg2, sect, saddr, ssize in selrefs:
    fo = a2f(saddr)
    data = blob[fo:fo+ssize]
    for i in range(0, len(data) - 8, 8):
        v = struct.unpack_from("<Q", data, i)[0]
        if v == SEL:
            slot = saddr + i
            print("[selref] slot 0x%x -> 0x%x" % (slot, v))
if slot is None:
    # maybe direct string adrp/add in code instead of selref
    print("[selref] no selref slot; will scan for adrp of string page")

# 2. scan __TEXT for adrp Xn, page(slot) followed by add/ldr using offset
text = [s for s in segs if s[0] == "__TEXT"][0]
n, vm, vs, fo, fs = text
data = blob[fo:fo+fs]
md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
page = slot & ~0xFFF
off12 = slot & 0xFFF
hits = []
i = 0
while i < len(data) - 8:
    w = struct.unpack_from("<I", data, i)[0]
    if (w & 0x9F000000) == 0x90000000:  # ADRP
        rd = w & 0x1F
        immlo = (w >> 29) & 3
        immhi = (w >> 5) & 0x7FFFF
        imm = (immhi << 2) | immlo
        if imm & 0x100000:
            imm -= 0x200000
        pcpage = (vm + i) & ~0xFFF
        target = pcpage + (imm << 12)
        if target == page:
            # check next instr: add Xn, Xn, #off12  or ldr Xn,[Xn,#off12]
            w2 = struct.unpack_from("<I", data, i + 4)[0]
            is_add = (w2 & 0xFFC00000) == 0x91000000 and \
                (w2 & 0x1F) == rd and ((w2 >> 10) & 0xFFF) == off12
            is_ldr = (w2 & 0xFFC00000) == 0xF9400000 and \
                ((w2 >> 5) & 0x1F) == rd and \
                (((w2 >> 10) & 0xFFF) * 8) == off12
            if is_add or is_ldr:
                hits.append(vm + i)
    i += 4
print("[xref] %d code sites reference sel 0x%x" % (len(hits), SEL))
for h in hits[:6]:
    fo2 = a2f(h - 0x30)
    print("\n---- site 0x%x ----" % h)
    for ins in md.disasm(blob[fo2:fo2 + 0x60], h - 0x30):
        mark = "   <<< SEL LOAD" if ins.address == h else ""
        print("0x%x: %-8s %s%s" % (ins.address, ins.mnemonic,
                                    ins.op_str, mark))
