#!/usr/bin/env python3
"""Disassemble around the spin-loop call sites in FortniteClient (arm64)."""
import sys
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN

EXE = "/home/z/my-project/fn35/extracted/Payload/FortniteClient.app/FortniteClient"

# Parse Mach-O: find __TEXT segment vmaddr + fileoff (and section mapping)
import struct

def load_text_map(path):
    with open(path, "rb") as f:
        data = f.read(0x8000)
    magic, cputype, cpusub, filetype, ncmds, sizeofcmds, flags = \
        struct.unpack_from("<IIIIIII", data, 0)
    off = 32
    segs = []
    for _ in range(ncmds):
        cmd, cmdsize = struct.unpack_from("<II", data, off)
        if cmd == 0x19:  # LC_SEGMENT_64
            name = data[off+8:off+24].split(b"\0")[0].decode()
            vmaddr, vmsize, fileoff, filesize = struct.unpack_from("<QQQQ", data, off+24)
            segs.append((name, vmaddr, vmsize, fileoff, filesize))
        elif cmd == 0x1b:  # LC_SYMTAB
            pass
        off += cmdsize
    return segs

def addr2file(addr, segs):
    for name, vm, vs, fo, fs in segs:
        if vm <= addr < vm + vs:
            return fo + (addr - vm)
    return None

SITES = [
    (0x102c52560, 0x102c525e0),  # mach_abs caller + lock caller
    (0x101f9d5f0, 0x101f9d690),  # getspecific caller
]

def main():
    segs = load_text_map(EXE)
    for n, vm, vs, fo, fs in segs:
        print("[seg] %-16s vm=0x%x size=0x%x fileoff=0x%x" % (n, vm, vs, fo))
    with open(EXE, "rb") as f:
        blob = f.read()
    md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
    for lo, hi in SITES:
        fo = addr2file(lo, segs)
        if fo is None:
            print("!! no mapping for 0x%x" % lo)
            continue
        code = blob[fo:fo + (hi - lo)]
        print("\n==== 0x%x .. 0x%x ====" % (lo, hi))
        for ins in md.disasm(code, lo):
            mark = ""
            if ins.address in (0x102c5259c, 0x102c525c8, 0x101f9d658):
                mark = "   <<< SPIN SITE"
            print("0x%x: %-8s %s%s" % (ins.address, ins.mnemonic,
                                        ins.op_str, mark))

if __name__ == "__main__":
    main()
