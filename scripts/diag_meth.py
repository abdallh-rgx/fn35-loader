#!/usr/bin/env python3
"""Find the objc method entry whose IMP == 0x1026b7500, resolve its
selector and owning class."""
import struct

EXE = "/home/z/my-project/fn35/extracted/Payload/FortniteClient.app/FortniteClient"
IMP = 0x1026b7500

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

def rd_cstr(addr):
    fo = a2f(addr)
    if fo is None:
        return "?"
    end = blob.find(b"\0", fo)
    return blob[fo:end].decode(errors="replace")

# scan all of __DATA for pointer == IMP
hits = []
for seg2, sect, saddr, ssize in sections:
    if "cstring" in sect or "methname" in sect:
        continue
    fo = a2f(saddr)
    if fo is None:
        continue
    data = blob[fo:fo+ssize]
    for i in range(0, len(data) - 8, 8):
        v = struct.unpack_from("<Q", data, i)[0]
        if v == IMP:
            hits.append((saddr + i, seg2, sect))
print("[imp] 0x%x referenced at:" % IMP)
for a, sg, sc in hits:
    print("  0x%x (%s,%s)" % (a, sg, sc))

# method_t (relative, arm64e-style) = {int32 sel_rel; int32 types_rel; int64 imp}
# classic 64-bit = {char* name; char* types; IMP imp}
# check both layouts around each hit
for a, sg, sc in hits:
    fo = a2f(a)
    # try classic: imp at +16, name ptr at -16
    nameptr = struct.unpack_from("<Q", blob, fo - 16)[0]
    if 0x100000000 <= nameptr < 0x104000000:
        print("  classic method @0x%x sel=%r" % (a, rd_cstr(nameptr)[:50]))
    # relative method: sel_rel i32 at imp_off-8
    rel = struct.unpack_from("<i", blob, fo - 8)[0]
    s = a - 8 + rel
    if 0x103000000 <= s < 0x104000000:
        print("  relative method @0x%x sel=%r" % (a, rd_cstr(s)[:50]))
