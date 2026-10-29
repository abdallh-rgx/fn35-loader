#!/usr/bin/env python3
"""Search the Mach-O ObjC metadata for frame-pump related selectors."""
import struct

EXE = "/home/z/my-project/fn35/extracted/Payload/FortniteClient.app/FortniteClient"

with open(EXE, "rb") as f:
    blob = f.read()

# parse segments
segs = []
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
    off += cmdsize

def a2f(addr):
    for name, vm, vs, fo, fs in segs:
        if vm <= addr < vm + vs:
            return fo + (addr - vm)
    return None

# find __objc_methname section by walking section headers
off = 32
targets = ("tick", "display", "runloop", "RunLoop", "frame", "render",
           "Timer", "timer", "splash", "Splash", "heartbeat", "HeartBeat")
found = []
for _ in range(ncmds):
    cmd, cmdsize = struct.unpack_from("<II", blob, off)
    if cmd == 0x19:
        nsects = struct.unpack_from("<I", blob, off+64)[0]
        so = off + 72
        for si in range(nsects):
            sect = blob[so:so+16].split(b"\0")[0].decode()
            seg2 = blob[so+16:so+32].split(b"\0")[0].decode()
            saddr, ssize = struct.unpack_from("<QQ", blob, so+32)
            if sect in ("__objc_methname", "__objc_selrefs"):
                fo = a2f(saddr)
                if fo is None:
                    so += 80
                    continue
                data = blob[fo:fo+ssize]
                pos = 0
                while pos < len(data):
                    end = data.find(b"\0", pos)
                    if end < 0:
                        break
                    s = data[pos:end]
                    try:
                        txt = s.decode()
                    except Exception:
                        txt = ""
                    if txt and any(t in txt for t in targets):
                        found.append((hex(saddr + pos), txt))
                    pos = end + 1
            so += 80
    off += cmdsize

print("%d selector hits:" % len(found))
seen = set()
for a, t in found:
    if t in seen:
        continue
    seen.add(t)
    print("  %s %s" % (a, t))
