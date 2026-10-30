#!/usr/bin/env python3
"""Disassemble the two post-breaker loops:
A) pthread 0x8330: return site 0x102a90c44 (caller of flag-loop)
B) MainAppThread:  return site 0x1029185a4
Find their function starts and full loop bodies."""
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

def func_start(site, back=0x600):
    fo = a2f(site - back)
    code = blob[fo:fo + back]
    starts = []
    for ins in md.disasm(code, site - back):
        if ins.mnemonic == "stp" and "x29, x30, [sp, #-" in ins.op_str:
            starts.append(ins.address)
    return starts[-1] if starts else site - back

def dump(lo, hi, marks=()):
    fo = a2f(lo)
    print("---- 0x%x..0x%x ----" % (lo, hi))
    for ins in md.disasm(blob[fo:fo + (hi - lo)], lo):
        mark = "   <<<" if ins.address in marks else ""
        print("0x%x: %-8s %s%s" % (ins.address, ins.mnemonic,
                                    ins.op_str, mark))

for site in (0x102a90c44, 0x1029185a4):
    fs = func_start(site)
    print("== site 0x%x -> function start 0x%x ==" % (site, fs))
    dump(fs, site + 0x50, marks=(site,))
    print()

# also dump the outer loop around 0x102b16638 (top-most guest frame)
fs = func_start(0x102b16638)
print("== outer site 0x102b16638 -> start 0x%x ==" % fs)
dump(fs, 0x102b16638 + 0x40, marks=(0x102b16638,))
