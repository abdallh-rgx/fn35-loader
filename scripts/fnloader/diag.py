#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""تشخيص ساكن: فك كتل محددة من ثنائي فورتنايت"""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import macho as M
import capstone

BIN="/home/z/my-project/fn35/extracted/Payload/FortniteClient.app/FortniteClient"
mo=M.MachO(BIN)
md=capstone.Cs(capstone.CS_ARCH_ARM64,capstone.CS_MODE_LITTLE_ENDIAN)

def disasm(addr,n=14,label=""):
    print(f"\n===== 0x{addr:X} {label} =====")
    off=addr-mo.text_vm
    code=mo.data[off:off+n*4]
    for ins in md.disasm(code,addr):
        print(f"  0x{ins.address:X}: {ins.mnemonic:10s} {ins.op_str}")

# كتل المستدعي
disasm(0x1015FC54C,10,"[0] كتلة المستدعي العليا")
disasm(0x10154DBEC,12,"[1] كتلة وسطى")
disasm(0x10154DC00,14,"[2] الكتلة التي قبل دخول دالة الذاكرة")
# الدالة المستهدفة نفسها من دخولها
disasm(0x101879BF4,16,"[3] دخول دالة إحصاءات الذاكرة")
# وأيضاً جسم الدالة حول النداءات الثلاثة
disasm(0x101879C00,8,"[6] بعد mach_host_self")
disasm(0x101879C10,8,"[9] بعد host_statistics")
disasm(0x101879C4C,16,"[12] منطقة الحساب قبل الإبيفوق")
