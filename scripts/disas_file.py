#!/usr/bin/env python3
"""disas_file.py — disassemble from the Mach-O FILE (read-only text)."""
import sys, os, struct
sys.path.insert(0, "/home/z/my-project/scripts")
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
from fn35_macho import MachO

MACHO = "/home/z/my-project/fn35/extracted/Payload/FortniteClient.app/FortniteClient"
mo = MachO(MACHO)
mo.load_symbols()

# build vmaddr -> file offset map for executable segments
segs = []
for seg in mo.segments:
    if seg.name in ("__PAGEZERO",) or seg.filesize == 0:
        continue
    segs.append((seg.vmaddr, seg.vmaddr + seg.filesize, seg.fileoff,
                 4))

def read_file(addr, n):
    for base, end, off, x in segs:
        if base <= addr and addr + n <= end:
            with open(MACHO, "rb") as f:
                f.seek(off + (addr - base))
                return f.read(n)
    return None

target = int(sys.argv[1], 0)
back = int(sys.argv[2], 0) if len(sys.argv) > 2 else 0x40
fwd = int(sys.argv[3], 0) if len(sys.argv) > 3 else 0x80

code = read_file(target - back, back + fwd)
md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)

def cstr_at(a):
    d = read_file(a, 100)
    if d:
        s = d.split(b"\x00")[0]
        try:
            return s.decode("utf8")
        except Exception:
            return None
    return None

# track adrp/add pairs for string refs
pending_adrp = {}
lines = []
for ins in md.disasm(code, target - back):
    mark = " <<<" if ins.address == target else ""
    note = ""
    op = ins.op_str
    if ins.mnemonic == "adrp":
        try:
            pending_adrp[op.split(",")[0].strip()] = int(
                op.split("#")[1].strip(), 0)
        except Exception:
            pass
    elif ins.mnemonic == "add" and "#" in op:
        try:
            parts = op.split(",")
            rd = parts[0].strip()
            if rd in pending_adrp:
                v = pending_adrp[rd] + int(op.split("#")[1].strip(), 0)
                s = cstr_at(v)
                if s and len(s) > 2:
                    note = '   ; "%s"' % s[:60]
        except Exception:
            pass
    lines.append("  0x%x  %-9s %s%s%s" % (ins.address, ins.mnemonic,
                                           op, mark, note))
print("\n".join(lines))
