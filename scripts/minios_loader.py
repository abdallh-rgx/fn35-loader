#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
minios_loader.py — نموذج تعليمي مصغّر: لودر "iOS-like" يثبت الفكرة عملياً
=========================================================================
الفكرة المطلوبة: "لودر يقرأ التطبيق ويرد على syscalls" —
وهذه هي نفس الطريقة التي تعمل بها Wine (لنظام Windows) و touchHLE (لنظام iOS).

هذا النموذج:
  1) يبني ملف Mach-O ARM64 صغيراً بأيدينا (برنامج اختبار نظيف نملكه بالكامل)
  2) يقرأ (parse) بنية الملف: الترويسة، المقاطع (__text / __cstring)، نقطة الدخول
  3) ينفّذ تعليمات ARM64 بمعالج تفسيري صغير مكتوب من الصفر
  4) عند تنفيذ "svc #0x80" يقوم اللودر "بالرد" على syscall مثل (write / exit)

لا يستخدم أي ملف من Epic Games إطلاقاً — كل شيء هنا مولّد محلياً.
"""

import struct
import os
import sys

p32 = lambda v: struct.pack("<I", v & 0xFFFFFFFF)
p64 = lambda v: struct.pack("<Q", v & 0xFFFFFFFFFFFFFFFF)

VM_BASE = 0x100000000  # العنوان الافتراضي التقليدي لـ __TEXT في iOS

# ------------------ (أ) ترميز تعليمات ARM64 يدوياً ------------------
def movz(rd, imm16, hw=0):  return 0xD2800000 | (hw << 21) | (imm16 << 5) | rd
def movk(rd, imm16, hw=1):  return 0xF2800000 | (hw << 21) | (imm16 << 5) | rd
def add_reg(rd, rn, rm):    return 0x8B000000 | (rm << 16) | (rn << 5) | rd
def b(off_bytes):           return 0x14000000 | ((off_bytes // 4) & 0x3FFFFFF)
def svc(imm=0x80):          return 0xD4000000 | (imm << 5) | 1  # iOS: svc #0x80

# ------------------ (ب) بناء برنامج الاختبار ------------------
MSG = b"Hello from inside the Mach-O binary! The mini-loader answered my syscalls.\n"
SYS_write, SYS_exit = 4, 1  # أرقام syscalls في نواة XNU (نظام iOS)

def build_program(str_addr):
    code = []
    code.append(movz(0, 21))                       # x0 = 21
    code.append(movz(1, 15))                       # x1 = 15
    code.append(add_reg(3, 0, 1))                  # x3 = x0 + x1 = 36 (نحفظها بعيداً عن سجلات write)
    # --- استدعاء write(1, msg, len) ---
    code.append(movz(16, SYS_write))              # x16 = رقم syscall
    code.append(movz(0, 1))                       # fd = 1 (stdout)
    code.append(movz(1, str_addr & 0xFFFF))       # x1 = عنوان النص
    code.append(movk(1, (str_addr >> 16) & 0xFFFF, hw=1))
    code.append(movk(1, (str_addr >> 32) & 0xFFFF, hw=2))
    code.append(movz(2, len(MSG)))                # x2 = طول النص
    code.append(svc())                            # <<< اللودر يجب أن يرد هنا
    # --- استدعاء exit(36) لنحمل نتيجة الحساب في كود الخروج ---
    code.append(movz(16, SYS_exit))
    code.append(add_reg(0, 3, 31))                # x0 = x3 + xzr = 36 (نتيجة الحساب)
    code.append(svc())                            # <<< والرد هنا بإيقاف التنفيذ
    return b"".join(p32(i) for i in code)

# ------------------ (ج) بناء ملف Mach-O كامل ------------------
MH_MAGIC_64, CPU_ARM64, MH_EXECUTE = 0xFEEDFACF, 0x0100000C, 2
LC_SEGMENT_64, LC_UNIXTHREAD = 0x19, 0x5

def build_macho():
    ncmds = 2
    header_size = 32
    seg_cmdsize = 72 + 2 * 80           # segment_command_64 + قسمان
    thread_cmdsize = 288               # 8 + flavor + count + 68 كلمة حالة
    text_off = header_size + seg_cmdsize + thread_cmdsize
    code_len = 13 * 4
    str_off = (text_off + code_len + 7) & ~7  # محاذاة 8 بايت
    str_addr = VM_BASE + str_off

    code = build_program(str_addr)

    # 1) الترويسة mach_header_64
    out = struct.pack("<IiiIIIII", MH_MAGIC_64, CPU_ARM64, 0, MH_EXECUTE,
                      ncmds, seg_cmdsize + thread_cmdsize, 0, 0)
    # 2) LC_SEGMENT_64 (__TEXT)
    seg = p32(LC_SEGMENT_64) + p32(seg_cmdsize) + b"__TEXT".ljust(16, b"\0")
    total_size = str_off + len(MSG)
    seg += p64(VM_BASE) + p64(total_size) + p64(0) + p64(total_size)
    seg += p32(7) + p32(5) + p32(2) + p32(0)
    # قسم __text
    seg += b"__text".ljust(16, b"\0") + b"__TEXT".ljust(16, b"\0")
    seg += p64(VM_BASE + text_off) + p64(code_len) + p32(text_off)
    seg += p32(2) + p32(0) + p32(0) + p32(0x80000400)
    seg += p32(0) + p32(0) + p32(0)
    # قسم __cstring
    seg += b"__cstring".ljust(16, b"\0") + b"__TEXT".ljust(16, b"\0")
    seg += p64(str_addr) + p64(len(MSG)) + p32(str_off)
    seg += p32(3) + p32(0) + p32(0) + p32(2)
    seg += p32(0) + p32(0) + p32(0)
    out += seg
    # 3) LC_UNIXTHREAD (نفس آلية إدخال النواة الحقيقية xnu)
    th = p32(LC_UNIXTHREAD) + p32(thread_cmdsize) + p32(6) + p32(68)
    state = bytearray(272)
    struct.pack_into("<Q", state, 248, VM_BASE + total_size - len(MSG))  # sp
    struct.pack_into("<Q", state, 256, VM_BASE + text_off)               # pc = الدخول
    th += bytes(state)
    out += th
    # 4) الكود ثم النص (مع حشوة المحاذاة)
    out += code + b"\0" * (str_off - text_off - code_len) + MSG
    return out

# ------------------ (د) اللودر: قراءة Mach-O ------------------
class MachO:
    def __init__(self, data):
        self.mem = data
        (magic, cputype, cpusub, ftype, ncmds, sizeofcmds, flags, _res) = \
            struct.unpack_from("<IiiIIIII", data, 0)
        assert magic == MH_MAGIC_64, "ليس ملف Mach-O 64 صالحاً"
        assert cputype == CPU_ARM64, "ليس بنية ARM64"
        print(f"[MACH-O] magic=0x{magic:X} cputype=ARM64 filetype={ftype} "
              f"ncmds={ncmds} sizeofcmds={sizeofcmds}")
        self.sections, self.entry = {}, None
        off = 32
        for _ in range(ncmds):
            cmd, cmdsize = struct.unpack_from("<II", data, off)
            if cmd == LC_SEGMENT_64:
                name = data[off+8:off+24].rstrip(b"\0").decode()
                vmaddr, vmsize, fileoff, filesize = struct.unpack_from("<QQQQ", data, off+24)
                nsects = struct.unpack_from("<I", data, off+64)[0]
                print(f"[MACH-O] LC_SEGMENT_64 {name} vmaddr=0x{vmaddr:X} "
                      f"vmsize=0x{vmsize:X} filesize={filesize}")
                soff = off + 72
                for s in range(nsects):
                    sname = data[soff:soff+16].rstrip(b"\0").decode()
                    saddr, ssize, soffset = struct.unpack_from("<QQI", data, soff+32)
                    print(f"[MACH-O]   section {sname:10s} addr=0x{saddr:X} "
                          f"size=0x{ssize:X} offset=0x{soffset:X}")
                    self.sections[sname] = (saddr, ssize)
                    soff += 80
            elif cmd == LC_UNIXTHREAD:
                flavor, count = struct.unpack_from("<II", data, off+8)
                self.entry = struct.unpack_from("<Q", data, off+16+256)[0]
                print(f"[MACH-O] LC_UNIXTHREAD flavor={flavor} count={count} "
                      f"-> entry pc=0x{self.entry:X}")
            off += cmdsize

    def read(self, addr, n):
        return self.mem[addr - VM_BASE: addr - VM_BASE + n]

# ------------------ (هـ) المعالج التفسيري ARM64 ------------------
class CPU:
    def __init__(self, macho):
        self.x = [0] * 31            # x0..x30
        self.sp = 0
        self.pc = macho.entry
        self.m = macho
        self.insns = 0
        self.svcs = 0

    def run(self):
        while True:
            (insn,) = struct.unpack_from("<I", self.m.mem, self.pc - VM_BASE)
            self.execute(insn)

    def execute(self, insn):
        self.insns += 1
        rd = insn & 0x1F
        if insn == 0xD503201F:                                   # NOP
            print(f"[cpu] 0x{self.pc:X}: nop")
        elif (insn & 0xFF800000) == 0xD2800000:                  # MOVZ
            imm = (insn >> 5) & 0xFFFF
            hw = (insn >> 21) & 3
            self.x[rd] = imm << (16 * hw)
            print(f"[cpu] 0x{self.pc:X}: movz x{rd}, #{imm}"
                  f"{', lsl #' + str(16*hw) if hw else ''}")
        elif (insn & 0xFF800000) == 0xF2800000:                  # MOVK
            hw = (insn >> 21) & 3
            imm = (insn >> 5) & 0xFFFF
            self.x[rd] = (self.x[rd] & ~(0xFFFF << (16*hw))) | (imm << (16*hw))
            print(f"[cpu] 0x{self.pc:X}: movk x{rd}, #{imm}, lsl #{16*hw}")
        elif (insn & 0xFF200000) == 0x8B000000:                  # ADD (register)
            rn, rm = (insn >> 5) & 0x1F, (insn >> 16) & 0x1F
            # السجل 31 في موضع Rm يعامل كـ xzr (السجل الصفري) — قيمته دائماً 0
            rm_val = self.x[rm] if rm < 31 else 0
            rn_val = self.x[rn] if rn < 31 else 0
            self.x[rd] = rn_val + rm_val
            print(f"[cpu] 0x{self.pc:X}: add x{rd}, x{rn}, " +
                  (f"xzr   ; x{rd} = x{rn} (تمرير النتيجة)" if rm == 31
                   else f"x{rm}"))
        elif (insn >> 26) == 0x05:                               # B
            off26 = insn & 0x3FFFFFF
            if off26 & 0x2000000: off26 -= 0x4000000
            print(f"[cpu] 0x{self.pc:X}: b 0x{self.pc + off26*4:X}")
            self.pc += off26 * 4
            return
        elif (insn & 0xFFE0001F) == 0xD4000001:                  # SVC
            imm = (insn >> 5) & 0xFFFF
            print(f"[cpu] 0x{self.pc:X}: svc #0x{imm:X}"
                  f"   <<< التطبيق يطلب من النظام (x16={self.x[16]})")
            self.svcs += 1
            self.syscall()
        else:
            raise RuntimeError(f"تعليمة غير مدعومة عند 0x{self.pc:X}: "
                              f"0x{insn:08X}")
        self.pc += 4

    # ------------------ اللودر "يرد" هنا ------------------
    def syscall(self):
        num = self.x[16]
        if num == 4:  # write(fd, buf, count)
            fd, buf, count = self.x[0], self.x[1], self.x[2]
            data = self.m.read(buf, count)
            print(f"[loader] >>> SYS_write(fd={fd}, buf=0x{buf:X}, count={count})")
            sys.stdout.write(data.decode())
            self.x[0] = count          # قيمة الإرجاع كما تفعل النواة
            print(f"[loader] >>> رد اللودر: return {count}")
        elif num == 1:  # exit(status)
            print(f"[loader] >>> SYS_exit({self.x[0]}) — إيقاف التنفيذ")
            print(f"\n[stats] تعليمات منفذة: {self.insns} | syscalls تم الرد عليها: "
                  f"{self.svcs} | exit status = {self.x[0]} (= 21 + 15 حساباً داخل التطبيق)")
            raise SystemExit(0)
        else:
            print(f"[loader] >>> syscall غير معروف #{num} — في محاكٍ حقيقي "
                  f"يُضاف إلى الجدول تدريجياً")

# ------------------ التشغيل ------------------
if __name__ == "__main__":
    outdir = "/home/z/my-project/download/minios"
    os.makedirs(outdir, exist_ok=True)
    print("=== (1) بناء برنامج اختبار Mach-O ARM64 بأيدينا ===")
    blob = build_macho()
    path = os.path.join(outdir, "hello.macho")
    with open(path, "wb") as f:
        f.write(blob)
    print(f"[build] كُتب الملف: {path} ({len(blob)} بايت)\n")

    print("=== (2) اللودر يقرأ الملف (parsing) ===")
    mo = MachO(blob)
    print()
    print("=== (3) التنفيذ والرد على syscalls ===")
    CPU(mo).run()
