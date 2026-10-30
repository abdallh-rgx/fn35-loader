#!/usr/bin/env python3
"""Dump the full spin loop body from 0x102c52694."""
import struct
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN

EXE = "/home/z/my-project/fn35/extracted/Payload/FortniteClient.app/FortniteClient"

def load_text_map(path):
    with open(path, "rb") as f:
        data = f.read(0x8000)
    magic, cputype, cpusub, filetype, ncmds, sizeofcmds, flags = \
        struct.unpack_from("<IIIIIII", data, 0)
    off = 32
    segs = []
    for _ in range(ncmds):
        cmd, cmdsize = struct.unpack_from("<II", data, off)
        if cmd == 0x19:
            name = data[off+8:off+24].split(b"\0")[0].decode()
            vmaddr, vmsize, fileoff, filesize = struct.unpack_from("<QQQQ", data, off+24)
            segs.append((name, vmaddr, vmsize, fileoff, filesize))
        off += cmdsize
    return segs

def addr2file(addr, segs):
    for name, vm, vs, fo, fs in segs:
        if vm <= addr < vm + vs:
            return fo + (addr - vm)
    return None

def dump(md, blob, segs, lo, hi, marks=()):
    fo = addr2file(lo, segs)
    code = blob[fo:fo + (hi - lo)]
    print("==== 0x%x .. 0x%x ====" % (lo, hi))
    for ins in md.disasm(code, lo):
        mark = "   <<<" if ins.address in marks else ""
        print("0x%x: %-8s %s%s" % (ins.address, ins.mnemonic, ins.op_str, mark))

def main():
    segs = load_text_map(EXE)
    with open(EXE, "rb") as f:
        blob = f.read()
    md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
    # full loop: head at 0x102c52694, body until ~0x102c52760
    dump(md, blob, segs, 0x102c525dc, 0x102c52770,
         marks=(0x102c52694,))
    # stub wrappers
    dump(md, blob, segs, 0x10305db1c, 0x10305db30)
    dump(md, blob, segs, 0x10305e074, 0x10305e088)
    dump(md, blob, segs, 0x10305e020, 0x10305e034)
    # what is 0x101d5db00 (called pre-loop)
    dump(md, blob, segs, 0x101d5db00, 0x101d5db40)

if __name__ == "__main__":
    main()
