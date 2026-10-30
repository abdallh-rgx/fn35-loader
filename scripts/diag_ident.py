#!/usr/bin/env python3
"""Identify the spin-loop owner functions by disassembly + string refs."""
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
    return struct.unpack_from("<Q", blob, fo)[0] if fo is not None else 0

def rd_cstr(addr, maxlen=80):
    fo = a2f(addr)
    if fo is None:
        return None
    end = blob.find(b"\0", fo, fo + maxlen * 2)
    if end < 0:
        return None
    s = blob[fo:end]
    try:
        t = s.decode()
    except Exception:
        return None
    if all(32 <= ord(c) < 127 or ord(c) >= 128 for c in t):
        return t
    return None

def sect_of(addr):
    for seg2, sect, saddr, ssize in sections:
        if saddr <= addr < saddr + ssize:
            return "%s,%s" % (seg2, sect)
    return "?"

md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)

def analyze(site, back=0x300):
    """Find function start before site, dump strings it references."""
    fo = a2f(site - back)
    code = blob[fo:fo + back + 0x40]
    starts = []
    for ins in md.disasm(code, site - back):
        if ins.mnemonic == "stp" and "x29, x30, [sp, #-" in ins.op_str:
            starts.append(ins.address)
    fs = starts[-1] if starts else site - back
    print("  function start ~0x%x" % fs)
    # walk from fs to site+0x100, resolve adrp+add string pairs
    fo2 = a2f(fs)
    code2 = blob[fo2:fo2 + (site - fs) + 0x100]
    adrp_val = {}
    strs = set()
    branches = []
    for ins in md.disasm(code2, fs):
        if ins.mnemonic == "adrp":
            try:
                page = int(ins.op_str.split("#")[1], 16)
                rd = ins.op_str.split(",")[0]
                adrp_val[rd] = page
            except Exception:
                pass
        elif ins.mnemonic == "add" and "#" in ins.op_str:
            try:
                rd, rn, imm = ins.op_str.split(", ")
                if rn in adrp_val:
                    v = adrp_val[rn] + int(imm.split("#")[1], 16)
                    sc = sect_of(v)
                    if "cstring" in sc or "methname" in sc or "cfstring" in sc:
                        s = rd_cstr(v)
                        if s:
                            strs.add((hex(v), s[:70], sc))
            except Exception:
                pass
        elif ins.mnemonic in ("b", "bl"):
            try:
                t = int(ins.op_str.split("#")[1], 16)
                branches.append((ins.address, ins.mnemonic, hex(t)))
            except Exception:
                pass
    for a, s, sc in sorted(strs)[:12]:
        print("    str %s %r (%s)" % (a, s, sc))
    return fs

for site in (0x102b16638, 0x102a90c44, 0x101bc5dcc):
    print("== caller site 0x%x ==" % site)
    analyze(site)
    print()
