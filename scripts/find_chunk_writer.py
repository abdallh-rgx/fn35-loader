#!/usr/bin/env python3
"""find_chunk_writer.py — find the code that POPULATES the 24B-entry chunk
table at 0x1056ecfb8 (chunks at +0x108+chunk*8, one chunk = 16384*24 = 0x60000).

Strategy:
 1. Scan __TEXT for functions containing BOTH a reference to the table page
    (adrp 0x1056ec000 with add #0xfb8 OR a register-indirect store with #0x108)
    AND the chunk size 0x60000 / 0xC0000 immediates (0x60000 needs movz+movk).
 2. Print candidates with context.
"""
import sys, struct
sys.path.insert(0, "/home/z/my-project/scripts")
from fn35_macho import MachO
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM

MACHO = "/home/z/my-project/fn35/extracted/Payload/FortniteClient.app/FortniteClient"
mo = MachO(MACHO)
mo.load_symbols()
TEXT = None
for s in mo.segments:
    if s.name == "__TEXT":
        TEXT = (s.vmaddr, s.fileoff, s.filesize)
va, off, size = TEXT
buf = mo.buf[off:off + size]
md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
md.detail = False

PAGE = 0x1056ec000

def is_adrp_to_page(w):
    return (w >> 31) == 1 and ((w >> 24) & 0x1F) == 0x10 and \
           (va + ((w & 0x1F) << 29) + (((w >> 5) & 0x7FFFF) << 12
                if not (w >> 29) & 1 else -(((w >> 5) & 0x7FFFF) << 12)) \
           & ~0xFFF) == 0  # placeholder, fixed below

def adrp_target(pc, w):
    immlo = (w >> 29) & 3
    immhi = (w >> 5) & 0x7FFFF
    imm = (immhi << 2) | immlo
    if imm & 0x100000:
        imm -= 0x200000
    return (pc & ~0xFFF) + (imm << 12)

# pass 1: find all adrp to page 0x1056ec000
adrs = {}
i = 0
hits_page = []
while i + 4 <= len(buf):
    w = struct.unpack_from("<I", buf, i)[0]
    if (w >> 24) == 0x90:  # adrp
        pc = va + i
        if adrp_target(pc, w) == PAGE:
            hits_page.append(pc)
    i += 4

print("adrp->0x1056ec000 sites: %d" % len(hits_page))

# pass 2: for each site, disassemble the surrounding window and check for
# (a) add #0xfb8 (direct table addr)  OR  (b) str [x,#0x108] patterns
cands = []
for pc in hits_page:
    fo = pc - va
    code = buf[max(0, fo - 0x200):fo + 0x200]
    base = pc - (fo - max(0, fo - 0x200))
    for ins in md.disasm(code, base):
        s = "%s %s" % (ins.mnemonic, ins.op_str)
        if ("#0x108]" in s or "#0xfb8" in s) and \
           (ins.mnemonic.startswith("st") or "add" in ins.mnemonic):
            cands.append((pc, ins.address, s))
            break

print("writer candidates (table +0x108/+0xfb8 with store/add):")
for pc, ia, s in cands[:20]:
    print("  adrp@0x%x -> 0x%x: %s" % (pc, ia, s))

# pass 3: find movz/movk pairs producing 0x60000 or 0xC0000 near ANY adrp
# to the page (chunk alloc size = 16384*24)
print("\nsearching 0x60000/0xC0000 immediate constructors near page refs...")
for pc in hits_page:
    fo = pc - va
    code = buf[max(0, fo - 0x100):fo + 0x400]
    base = pc - (fo - max(0, fo - 0x100))
    for ins in md.disasm(code, base):
        if ins.mnemonic in ("mov", "movz", "movk", "orr") and \
           ("#0xc0000" in ins.op_str or "#0x60000" in ins.op_str):
            print("  adrp@0x%x +0x%x: %s %s" % (pc, ins.address - pc,
                                                ins.mnemonic, ins.op_str))
