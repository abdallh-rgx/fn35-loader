#!/usr/bin/env python3
"""Find RHIInit via the 'rhi=' FParse::Value string reference."""
import sys, os, struct

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from fn35_macho import MachO
import capstone

BIN = "/home/z/my-project/fn35/extracted/Payload/FortniteClient.app/FortniteClient"
mo = MachO(BIN)
mo.load_symbols()
CS = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_LITTLE_ENDIAN)

# --- collect __TEXT sections' bytes to find strings + their addresses
strs = {}
for sec in mo.sections:
    if sec.seg != "__TEXT" or not (sec.name.startswith("__cstring") or sec.name.startswith("__const")):
        continue
    blob = mo.buf[sec.offset:sec.offset + sec.size]
    for want in (b"rhi=\x00", b"opengl\x00", b"metal\x00", b"Metal\x00",
                 b"OpenGL\x00", b"bSupportsMetal\x00",
                 b"bSupportsOpenGLES2\x00", b"bForceNonMetal\x00",
                 b"bIsUsingMetal\x00", b"bSupportsMetalMRT\x00"):
        pos = 0
        while True:
            i = blob.find(want, pos)
            if i < 0:
                break
            strs[sec.addr + i] = want[:-1].decode()
            pos = i + 1
print("strings:", {hex(a): s for a, s in strs.items()})

# --- find adrp+add refs into __text
text = next(s for s in mo.sections if s.name == "__text")
tbuf = mo.buf[text.offset:text.offset + text.size]
last_adrp = {}
hits = []
for off in range(0, len(tbuf), 4):
    ins = struct.unpack_from("<I", tbuf, off)[0]
    addr = text.addr + off
    op = ins >> 24
    if op == 0x90 or op == 0xB0 or op == 0x30 or op == 0x10 or op == 0xD0 or op == 0xF0:
        # adrp family: bits 31..24 pattern x1010xxx? actual adrp mask: 1 immlo=2b
        pass
    if (ins & 0x9F000000) == 0x90000000:   # adrp
        rd = ins & 0x1F
        immlo = (ins >> 29) & 3
        immhi = (ins >> 5) & 0x7FFFF
        imm = (immhi << 2) | immlo
        if imm & (1 << 20):
            imm -= 1 << 21
        last_adrp[rd] = (imm << 12) + (addr & ~0xFFF)
    elif (ins & 0xFF800000) == 0x91000000:  # add imm64
        rd = ins & 0x1F
        rn = (ins >> 5) & 0x1F
        imm12 = (ins >> 10) & 0xFFF
        sh = (ins >> 22) & 3
        if sh == 1:
            imm12 <<= 12
        if rn in last_adrp:
            ea = last_adrp[rn] + imm12
            if ea in strs:
                hits.append((addr, strs[ea], ea))
print("\ncode refs (%d):" % len(hits))
for a, s, ea in hits:
    print("  0x%x -> %s" % (a, s))

# --- dump disassembly around each 'rhi=' ref and 'metal'/'opengl' refs
for a, s, ea in hits:
    if s not in ("rhi=", "opengl", "metal", "Metal", "OpenGL"):
        continue
    print("\n===== site 0x%x referencing %r =====" % (a, s))
    start = a - 240
    o = start - text.addr
    code = tbuf[max(0, o):o + 560]
    for ins in CS.disasm(code, start):
        mark = "  <<< REF" if ins.address == a else ""
        print("  %10x: %-8s %s%s" % (ins.address, ins.mnemonic, ins.op_str, mark))
