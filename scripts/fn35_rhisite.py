#!/usr/bin/env python3
"""Locate RHIInit selection logic: find code referencing the module-name
strings "MetalRHI" / "OpenGLDrv" and disassemble around each site."""
import sys, os, struct

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from fn35_macho import MachO
import capstone

BIN = "/home/z/my-project/fn35/extracted/Payload/FortniteClient.app/FortniteClient"
mo = MachO(BIN)
mo.load_symbols()
CS = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_LITTLE_ENDIAN)
CS.detail = False

# --- 1. find target strings
targets = {}
for sec in mo.sections:
    if sec.seg != "__TEXT" or "cstring" not in sec.name and "const" not in sec.name:
        pass
    blob = mo.buf[sec.offset:sec.offset + sec.size]
    for s in (b"MetalRHI\x00", b"OpenGLDrv\x00"):
        pos = 0
        while True:
            i = blob.find(s, pos)
            if i < 0:
                break
            targets[sec.addr + i] = s[:-1].decode()
            pos = i + 1
print("string addresses:", {hex(a): s for a, s in targets.items()})

# --- 2. scan __text for adrp+add pairs computing those addresses
text = next(s for s in mo.sections if s.name == "__text")
tbuf = mo.buf[text.offset:text.offset + text.size]
hits = []
# decode adrp/add streams cheaply with capstone over 4-instr windows
# simpler: iterate instructions once, track last adrp per register
last_adrp = {}
for off in range(0, len(tbuf), 4):
    ins = struct.unpack_from("<I", tbuf, off)[0]
    addr = text.addr + off
    # adrp: 1 xx 10000 immlo(2) immhi(19) Rd(5)
    if (ins >> 24) & 0x9F == 0x90:
        rd = ins & 0x1F
        immlo = (ins >> 29) & 3
        immhi = (ins >> 5) & 0x7FFFF
        imm = (immhi << 2) | immlo
        if imm & (1 << 20):
            imm -= 1 << 21
        last_adrp[rd] = (imm << 12) + (addr & ~0xFFF)
    # add imm: 0x91 (64-bit) or 0x11 (32) — take 64
    elif (ins >> 24) & 0x7F in (0x91,) or ((ins >> 24) == 0x91):
        rd = ins & 0x1F
        rn = (ins >> 5) & 0x1F
        imm12 = (ins >> 10) & 0xFFF
        sh = (ins >> 22) & 1
        if sh:
            imm12 <<= 12
        if rn in last_adrp:
            ea = last_adrp[rn] + imm12
            if ea in targets:
                hits.append((addr, targets[ea], ea))
    # ldr (literal) x_, label — also common for const strings
print("reference sites (%d):" % len(hits))
for a, s, ea in hits:
    print("  0x%x -> %s (0x%x)" % (a, s, ea))
    # disassemble surrounding 30 instructions
    start = a - 80
    o = start - text.addr
    code = tbuf[o:o + 200]
    for ins in CS.disasm(code, start):
        mark = " <<<" if ins.address == a else ""
        print("    %10x: %-8s %s%s" % (ins.address, ins.mnemonic, ins.op_str, mark))
    print()
