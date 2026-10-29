#!/usr/bin/env python3
"""Disassemble the innermost spin caller around 0x101bc5dcc and the
middle frame 0x102a90c44 to understand the wait loop."""
import struct
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN

EXE = "/home/z/my-project/fn35/extracted/Payload/FortniteClient.app/FortniteClient"

with open(EXE, "rb") as f:
    blob = f.read()

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

md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)

def dump(lo, hi, marks=()):
    fo = a2f(lo)
    print("==== 0x%x .. 0x%x ====" % (lo, hi))
    for ins in md.disasm(blob[fo:fo + (hi - lo)], lo):
        mark = "   <<<" if ins.address in marks else ""
        print("0x%x: %-8s %s%s" % (ins.address, ins.mnemonic,
                                    ins.op_str, mark))

# innermost caller loop (call site at 0x101bc5dcc)
dump(0x101bc5d60, 0x101bc5e20, marks=(0x101bc5dcc,))
print()
# middle frame: return site 0x102a90c44 (call into 0x101bc5acc fn)
dump(0x102a90c00, 0x102a90c90, marks=(0x102a90c44,))
