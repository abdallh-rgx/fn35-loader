#!/usr/bin/env python3
"""disasm: disassemble a PC window from the FortniteClient binary."""
import sys
sys.path.insert(0, "/home/z/my-project/scripts")
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN

BIN = ("/home/z/my-project/fn35/extracted/Payload/"
       "FortniteClient.app/FortniteClient")
BASE = 0x100000000

lo = int(sys.argv[1], 0)
hi = int(sys.argv[2], 0)
with open(BIN, "rb") as f:
    f.seek(lo - BASE)
    code = f.read(hi - lo)

md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
for i in md.disasm(code, lo):
    print("0x%x:\t%s\t%s" % (i.address, i.mnemonic, i.op_str))
