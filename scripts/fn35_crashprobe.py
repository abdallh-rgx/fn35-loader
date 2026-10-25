#!/usr/bin/env python3
"""Static analysis of the crash function at 0x102686c74:
find function bounds via LC_FUNCTION_STARTS + identify callers."""
import sys, os, struct
sys.path.insert(0, "/home/z/my-project/scripts")
from fn35_macho import MachO, uleb
import capstone

BIN = "/home/z/my-project/fn35/extracted/Payload/FortniteClient.app/FortniteClient"
mo = MachO(BIN)
mo.load_symbols()
CS = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_LITTLE_ENDIAN)

# --- parse LC_FUNCTION_STARTS (read the load command ourselves)
starts_off = starts_size = 0
p = 32
for _ in range(mo.segments and 54 or 54):
    if p + 8 > len(mo.buf):
        break
    cmd, cmdsize = struct.unpack_from("<II", mo.buf, p)
    if cmd == 0x26:      # LC_FUNCTION_STARTS
        starts_off, starts_size = struct.unpack_from("<II", mo.buf, p + 8)
        break
    if cmd == 0:
        break
    p += cmdsize
print("LC_FUNCTION_STARTS off=0x%x size=0x%x" % (starts_off, starts_size))
fs_data = mo.buf[starts_off:starts_off + starts_size]
fn_addrs = []
acc = 0
i = 0
while i < len(fs_data):
    v, i = uleb(fs_data, i)
    if v == 0 and i >= len(fs_data):
        break
    acc += v
    fn_addrs.append(acc)
text_base = mo.text_vm()
fn_starts = [text_base + a for a in fn_addrs if a]
fn_starts.sort()
CRASH = 0x102686c74
fs = [s for s in fn_starts if s <= CRASH]
fstart = max(fs) if fs else CRASH
fnext = min([s for s in fn_starts if s > CRASH] or [CRASH + 0x400])
print("function: 0x%x .. 0x%x (size 0x%x)" % (fstart, fnext, fnext - fstart))

# --- disassemble the function head to see args
print("\n--- function head ---")
o = fstart - text_base
for ins in CS.disasm(mo.buf[o:o + 160], fstart):
    print("  %10x: %-8s %s" % (ins.address, ins.mnemonic, ins.op_str))
    if ins.address > fstart + 40:
        break

# --- find callers (bl fstart) across __text
text = next(s for s in mo.sections if s.name == "__text")
tbuf = mo.buf[text.offset:text.offset + text.size]
callers = []
for i in range(0, len(tbuf) - 4, 4):
    ins = struct.unpack_from("<I", tbuf, i)[0]
    if (ins & 0xFC000000) == 0x94000000:      # BL
        imm = ins & 0x3FFFFFF
        if imm & (1 << 25):
            imm -= 1 << 26
        tgt = text.addr + i + (imm << 2)
        if tgt == fstart:
            callers.append(text.addr + i)
print("\n--- callers (BL sites): %d ---" % len(callers))
for c in callers[:12]:
    print("  0x%x" % c)
    oo = c - text_base - 32
    for ins in CS.disasm(mo.buf[oo:oo + 72], c - 32):
        mark = "  <<< CALL" if ins.address == c else ""
        print("    %10x: %-8s %s%s" % (ins.address, ins.mnemonic, ins.op_str, mark))
