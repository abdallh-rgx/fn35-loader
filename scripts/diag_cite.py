#!/usr/bin/env python3
"""Resolve classrefs/selrefs around the displayLink call site, find the
containing function, and find who calls it."""
import struct
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN

EXE = "/home/z/my-project/fn35/extracted/Payload/FortniteClient.app/FortniteClient"

with open(EXE, "rb") as f:
    blob = f.read()

segs = []
sections = []
off = 32
magic, cputype, cpusub, filetype, ncmds, sizeofcmds, flags = \
    struct.unpack_from("<IIIIIII", blob, 0)
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

def rd64(addr):
    fo = a2f(addr)
    if fo is None:
        return None
    return struct.unpack_from("<Q", blob, fo)[0]

def rd32(addr):
    fo = a2f(addr)
    if fo is None:
        return None
    return struct.unpack_from("<I", blob, fo)[0]

def rd_cstr(addr):
    fo = a2f(addr)
    if fo is None:
        return "?"
    end = blob.find(b"\0", fo)
    return blob[fo:end].decode(errors="replace")

def sect_of(addr):
    for seg2, sect, saddr, ssize in sections:
        if saddr <= addr < saddr + ssize:
            return "%s,%s" % (seg2, sect)
    return "?"

SLOTS = [0x104128318, 0x10411b908, 0x1041296a8, 0x1041276d0,
         0x104126c98, 0x104126ae8, 0x10411b440]
for s in SLOTS:
    v = rd64(s)
    nm = ""
    if v:
        if "methname" in sect_of(v) or "cstring" in sect_of(v):
            nm = rd_cstr(v)
    print("slot 0x%x sect=%s -> 0x%x %r" % (s, sect_of(s), v or 0, nm[:60]))

# find the containing function: scan back from 0x1026b780c for prologue
md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
site = 0x1026b780c
fo = a2f(site - 0x400)
code = blob[fo:fo + 0x400]
starts = []
for ins in md.disasm(code, site - 0x400):
    if ins.mnemonic == "stp" and "x29, x30, [sp, #-" in ins.op_str:
        starts.append(ins.address)
print("\n[func] candidate starts:", [hex(s) for s in starts[-3:]])
fstart = starts[-1] if starts else site - 0x200

# find callers: bl -> fstart
text = [s for s in segs if s[0] == "__TEXT"][0]
tn, tv, tvs, tfo, tfs = text
data = blob[tfo:tfo+tfs]
callers = []
for i in range(0, len(data) - 4, 4):
    w = struct.unpack_from("<I", data, i)[0]
    if (w >> 26) == 0x25:
        imm = w & 0x3FFFFFF
        if imm & 0x2000000:
            imm -= 0x4000000
        if tv + i + (imm << 2) == fstart:
            callers.append(tv + i)
print("[func] start=0x%x callers=%d: %s" %
      (fstart, len(callers), [hex(c) for c in callers[:8]]))
