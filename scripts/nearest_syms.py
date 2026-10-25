#!/usr/bin/env python3
"""Identify functions around the spin-loop call chain via symbols + xrefs."""
import sys, struct
sys.path.insert(0, "/home/z/my-project/scripts")
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN
from fn35_macho import MachO

BIN = "/home/z/my-project/fn35/extracted/Payload/FortniteClient.app/FortniteClient"
mo = MachO(BIN)
mo.load_symbols()

syms = [(s.value, mo.sym_name(i)) for i, s in enumerate(mo.syms)
        if s.value and (s.type & 0x0e) == 0x0e]   # N_SECT defined symbols
syms.sort()

def nearest(addr):
    best = None
    for v, n in syms:
        if v <= addr:
            best = (v, n)
        else:
            break
    return best

for a in (0x101838970, 0x1026e0c04, 0x101885b00, 0x10276b70c,
          0x10305ddd4, 0x10305e578, 0x100e83760):
    v, n = nearest(a)
    print("0x%x -> nearest sym 0x%x %s (+0x%x)" % (a, v, n, a - v))
