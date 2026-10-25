#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
fn35_analyze.py — اللودر التحليلي لـ Fortnite iOS 3.5 (الحقيقي!)
================================================================
المرحلة 1: قراءة كاملة لبنية Mach-O الحقيقية (ترويسة، أوامر تحميل، مقاطع، أطر)
المرحلة 2: إحصاءات هندسية (مواقع syscalls، أصناف ObjC، شيدرات Metal)
المرحلة 3: تحميل الثنائي في محاكي CPU (Unicorn/QEMU-core) وتنفيذ نقطة الدخول
            وتوثيق أول جدار يصطدم به اللودر — بأدلة رقمية حقيقية.
"""

import struct, sys, os, re, plistlib
from unicorn import Uc, UcError, UC_ARCH_ARM64, UC_MODE_LITTLE_ENDIAN, UC_PROT_ALL, \
    UC_HOOK_INTR, UC_HOOK_CODE, UC_HOOK_MEM_INVALID, UC_MEM_READ_UNMAPPED, \
    UC_MEM_WRITE_UNMAPPED, UC_MEM_FETCH_UNMAPPED
from unicorn.arm64_const import *
import capstone

BIN = "/home/z/my-project/fn35/extracted/Payload/FortniteClient.app/FortniteClient"
APP = "/home/z/my-project/fn35/extracted/Payload/FortniteClient.app"

p32 = lambda v: struct.pack("<I", v & 0xFFFFFFFF)
p64 = lambda v: struct.pack("<Q", v & 0xFFFFFFFFFFFFFFFF)

LC_NAMES = {
    0x1: "LC_SEGMENT", 0x2: "LC_SYMTAB", 0x3: "LC_SYMSEG", 0x5: "LC_UNIXTHREAD",
    0xB: "LC_DYSYMTAB", 0xC: "LC_LOAD_DYLIB", 0xD: "LC_ID_DYLIB", 0xE: "LC_LOAD_DYLINKER",
    0x1B: "LC_UUID", 0x1C: "LC_RPATH", 0x1D: "LC_CODE_SIGNATURE",
    0x19: "LC_SEGMENT_64", 0x1E: "LC_SEGMENT_SPLIT_INFO",
    0x20: "LC_REEXPORT_DYLIB", 0x22: "LC_DYLD_INFO", 0x80000022: "LC_DYLD_INFO_ONLY",
    0x24: "LC_VERSION_MIN_MACOSX", 0x25: "LC_VERSION_MIN_IPHONEOS", 0x26: "LC_FUNCTION_STARTS",
    0x29: "LC_DATA_IN_CODE", 0x2A: "LC_SOURCE_VERSION", 0x2B: "LC_DYLIB_CODE_SIGN_DRS",
    0x80000028: "LC_MAIN", 0x2C: "LC_ENCRYPTION_INFO_64", 0x2D: "LC_LINKER_OPTION",
    0x2E: "LC_LINKER_OPTIMIZATION_HINT", 0x32: "LC_BUILD_VERSION",
    0x80000034: "LC_DYLD_EXPORTS_TRIE", 0x80000033: "LC_DYLD_CHAINED_FIXUPS",
    0x80000029: "LC_DYLD_EXPORTS_TRIE_DUMMY",
}

def cstr(data, off):
    end = data.index(b"\0", off)
    return data[off:end].decode("utf-8", "replace")

# ======================= المرحلة 1: تحليل Mach-O =======================
class MachO:
    def __init__(self, path):
        self.data = open(path, "rb").read()
        d = self.data
        (magic, cputype, cpusub, ftype, ncmds, sizeofcmds, flags, _res) = \
            struct.unpack_from("<IiiIIIII", d, 0)
        assert magic == 0xFEEDFACF, f"ليس Mach-O 64: 0x{magic:X}"
        self.cputype, self.filetype, self.flags = cputype, ftype, flags
        self.segments, self.dylibs, self.sections = [], [], {}
        self.secinfo, self.symtab, self.indirect = {}, [], []
        self.entry_thread = None      # من LC_UNIXTHREAD
        self.entry_main = None       # من LC_MAIN
        self.encryption = None       # من LC_ENCRYPTION_INFO_64
        self.build_ver = None       # من LC_BUILD_VERSION
        self.uuid = None
        print(f"[T1][Mach-O] magic=0xFEEDFACF (Mach-O 64 LE) | cputype=0x{cputype:X} "
              f"(ARM64) | filetype={ftype} (MH_EXECUTE) | ncmds={ncmds}")
        off = 32
        for _ in range(ncmds):
            cmd, cmdsize = struct.unpack_from("<II", d, off)
            name = LC_NAMES.get(cmd, f"LC_0x{cmd:X}")
            if cmd == 0x19:  # LC_SEGMENT_64
                segname = cstr(d, off + 8)[:16]
                vmaddr, vmsize, fileoff, filesize = struct.unpack_from("<QQQQ", d, off + 24)
                initprot, maxprot = struct.unpack_from("<II", d, off + 56)[:2] if False else (d[off+72-16], 0)
                initprot = struct.unpack_from("<I", d, off + 72 - 16)[0] if False else d[off + 72 - 16]
                nsects = struct.unpack_from("<I", d, off + 64)[0]
                seg = dict(name=segname, vmaddr=vmaddr, vmsize=vmsize,
                           fileoff=fileoff, filesize=filesize, nsects=nsects,
                           initprot=struct.unpack_from("<I", d, off+72-16)[0])
                self.segments.append(seg)
                soff = off + 72
                for s in range(nsects):
                    sname = cstr(d, soff)[:32]
                    saddr, ssize, soffset = struct.unpack_from("<QQI", d, soff + 32)
                    sflags, sres1, sres2 = struct.unpack_from("<III", d, soff + 64)
                    self.sections[sname] = (saddr, ssize)
                    self.secinfo[sname] = dict(addr=saddr, size=ssize, offset=soffset,
                                               flags=sflags, res1=sres1, res2=sres2)
                    soff += 80
            elif cmd == 0x2:  # LC_SYMTAB
                self.symoff, self.nsyms, self.stroff, self.strsize = struct.unpack_from("<IIII", d, off + 8)
            elif cmd == 0xB:  # LC_DYSYMTAB — نقرأ الجدول غير المباشر مباشرة
                self.indirectsymoff = struct.unpack_from("<I", d, off + 56)[0]
                self.nindirectsyms = struct.unpack_from("<I", d, off + 60)[0]
            elif cmd == 0xC:  # LC_LOAD_DYLIB
                nameoff = struct.unpack_from("<I", d, off + 8)[0]
                self.dylibs.append(cstr(d, off + nameoff))
            elif cmd == 0x80000028:  # LC_MAIN
                # البنية: cmd(4) cmdsize(4) entryoff(8) stacksize(8)
                self.entry_main = struct.unpack_from("<Q", d, off + 8)[0]
            elif cmd == 0x5:  # LC_UNIXTHREAD
                flavor, count = struct.unpack_from("<II", d, off + 8)
                if flavor == 6:  # ARM_THREAD_STATE64
                    self.entry_thread = struct.unpack_from("<Q", d, off + 16 + 256)[0]
            elif cmd == 0x2C:  # LC_ENCRYPTION_INFO_64
                cryptoff, cryptsize, cryptid = struct.unpack_from("<III", d, off + 8)
                self.encryption = (cryptoff, cryptsize, cryptid)
            elif cmd == 0x32:  # LC_BUILD_VERSION
                platform, minos, sdk, _ntools = struct.unpack_from("<IIII", d, off + 8)
                self.build_ver = (platform, minos >> 16, (minos >> 8) & 0xFF, minos & 0xFF,
                                   sdk >> 16, (sdk >> 8) & 0xFF)
            elif cmd == 0x1B:  # LC_UUID
                self.uuid = d[off+8:off+24].hex()
            off += cmdsize

    def load_symbols(self):
        """فك جدول الرموز + الجدول غير المباشر لترجمة خانات المؤشرات إلى أسماء رموز"""
        d = self.data
        for i in range(self.nsyms):
            o = self.symoff + i * 16
            n_strx, n_type, n_sect, n_desc, n_value = struct.unpack_from("<IBBHQ", d, o)
            end = d.index(b"\0", self.stroff + n_strx)
            name = d[self.stroff + n_strx:end].decode("utf-8", "replace")
            self.symtab.append((name, n_type, n_value))
        for i in range(self.nindirectsyms):
            (idx,) = struct.unpack_from("<I", d, self.indirectsymoff + i * 4)
            self.indirect.append(idx)
        print(f"[T1] جدول الرموز: {self.nsyms} رمزاً | الجدول غير المباشر: {self.nindirectsyms} خانة")

    def resolve_pointer_slot(self, addr):
        """إذا كان العنوان خانة مؤشر (GOT/la_symbol_ptr/nl) نعيد (اسم الرمز، اسم القسم)"""
        for sname, s in self.secinfo.items():
            if s["flags"] in (0x6, 0x7) or sname in ("__got", "__la_symbol_ptr", "__nl_symbol_ptr"):
                if s["addr"] <= addr < s["addr"] + s["size"]:
                    idx = (addr - s["addr"]) // 8
                    if idx < len(self.indirect):
                        isym = self.indirect[idx]
                        if 0 <= isym < len(self.symtab):
                            return self.symtab[isym][0], sname
                    return None, sname
        return None, None

    def summary(self):
        print("\n[T1] المقاطع (Segments) — خريطة الذاكرة التي يجب أن يرسمها اللودر:")
        for s in self.segments:
            print(f"  {s['name']:16s} vm=0x{s['vmaddr']:X} size=0x{s['vmsize']:X} "
                  f"file=0x{s['fileoff']:X}+0x{s['filesize']:X}")
        print("\n[T1] الأطر والمكتبات المطلوبة (LC_LOAD_DYLIB) — قائمة مهام أي لودر:")
        for i, dy in enumerate(self.dylibs):
            print(f"  {i+1:2d}. {dy}")
        if self.build_ver:
            p, a, b, c, sdkmaj, sdkmin = self.build_ver
            plats = {1: "macOS", 2: "iOS", 5: "iOS-sim", 7: "catalyst"}.get(p, f"platform {p}")
            print(f"\n[T1] بُني لمنصة: {plats} | أدنى نظام: {a}.{b}.{c} | SDK: {sdkmaj}.{sdkmin}")
        if self.encryption:
            cryptoff, cryptsize, cryptid = self.encryption
            state = "مشفَّر بـ FairPlay (cryptid=1)!" if cryptid else "غير مشفَّر (مفكوك — cryptid=0) ✓"
            print(f"[T1] حالة التشفير: {state}  (منطقة مشفرة: 0x{cryptsize:X} بايت عند 0x{cryptoff:X})")
        self.text_vm = next(s["vmaddr"] for s in self.segments if s["name"] == "__TEXT")
        entry = (self.text_vm + self.entry_main) if self.entry_main is not None else self.entry_thread
        if self.entry_main is not None:
            print(f"[T1] نقطة الدخول: LC_MAIN entryoff=0x{self.entry_main:X} → main() عند 0x{entry:X}")
        else:
            print(f"[T1] نقطة الدخول: LC_UNIXTHREAD pc=0x{self.entry_thread:X}")
        return entry

# ======================= المرحلة 2: إحصاءات =======================
def stage2(mo):
    print("\n[T2] إحصاءات هندسية من الثنائي الحقيقي:")
    # مواقع svc (طلبات النظام) داخل __TEXT
    text = mo.sections.get("__text")
    taddr, tsize = text
    tdata = mo.data[taddr - mo.text_vm : taddr - mo.text_vm + tsize]
    svc_sites = sum(1 for i in range(0, len(tdata) - 4, 4)
                    if (struct.unpack_from("<I", tdata, i)[0] & 0xFFE0001F) == 0xD4000001)
    print(f"  مواقع تعليمة svc (نقاط طلب النظام) في __text: {svc_sites}")
    # إحصاءات رموز
    m = re.findall(rb"OBJC_CLASS_\$_[A-Za-z0-9_]+", mo.data)
    print(f"  مراجع أصناف Objective-C: {len(m)} إجمالاً — {len(set(m))} صفاً فريداً مختلفاً")
    mets = re.findall(rb"objc_msgSend|_objc_retain|_objc_release", mo.data)
    print(f"  مراجع دوال ObjC runtime الأساسية: {len(mets)}")
    # شيدرات Metal
    import zipfile
    z = zipfile.ZipFile("/home/z/my-project/fn35/fn35_modded.ipa")
    mets2 = [n for n in z.namelist() if n.endswith(".metallib")]
    print(f"  ملفات شيدرات Metal (كود GPU): {mets2}")
    return svc_sites

# ======================= المرحلة 3: التنفيذ على المحاكي =======================
def stage3(mo, entry):
    print(f"\n[T3] تحميل الثنائي الحقيقي في محاكي CPU (Unicorn/QEMU-core) وتشغيله من 0x{entry:X} ...")

    uc = Uc(UC_ARCH_ARM64, UC_MODE_LITTLE_ENDIAN)
    mapped = []
    for seg in mo.segments:
        if seg["filesize"] == 0 or seg["vmaddr"] == 0:
            continue
        size = (seg["filesize"] + 0xFFF) & ~0xFFF
        if size > 0x10000000:
            size = (min(seg["filesize"], 0x10000000) + 0xFFF) & ~0xFFF
        try:
            uc.mem_map(seg["vmaddr"], size, UC_PROT_ALL)
            uc.mem_write(seg["vmaddr"], mo.data[seg["fileoff"]:seg["fileoff"] + seg["filesize"]])
            mapped.append((seg["vmaddr"], size, seg["name"]))
        except UcError as e:
            print(f"  [تحذير] تعذر رسم مقطع {seg['name']}: {e}")
    for va, sz, nm in mapped:
        print(f"  رسم {nm:16s} @ 0x{va:X} حجم 0x{sz:X}")

    STACK = 0x7F0000000000
    uc.mem_map(STACK - 0x200000, 0x200000, UC_PROT_ALL)  # 2MB مكدس
    sp = STACK - 0x1000
    # نحاكي ما تفعله النواة قبل القفز لـ main: (argc, argv, NULL, envp=NULL, apple=NULL)
    prog_name = b"FortniteClient\0"
    name_slot = STACK - 0x180000  # داخل منطقة المكدس المرسومة
    uc.mem_write(name_slot, prog_name)
    frame = struct.pack("<QQQQQ", 1, name_slot, 0, 0, 0)  # argc=1, argv[0], argv[NULL]
    uc.mem_write(sp, frame)
    uc.reg_write(UC_ARM64_REG_SP, sp)
    uc.reg_write(UC_ARM64_REG_X0, 1)          # argc
    uc.reg_write(UC_ARM64_REG_X1, name_slot)   # argv
    uc.reg_write(UC_ARM64_REG_PC, entry)

    md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_LITTLE_ENDIAN)

    # عرض أول تعليمات main() الحقيقية قبل التشغيل
    print("\n  أول 10 تعليمات حقيقية من فورتنايت 3.5 عند main() (فك Capstone):")
    base = mo.text_vm
    code = mo.data[entry - base: entry - base + 40]
    for ins in md.disasm(code, entry):
        print(f"    0x{ins.address:X}:  {ins.mnemonic:10s} {ins.op_str}")

    stats = {"insns": 0, "svcs": [], "faults": 0}
    SVC_NAMES = {1: "sys_exit", 4: "sys_write", 5: "sys_open", 6: "sys_close",
                 197: "sys_mmap", 199: "sys_munmap", 202: "sys_sysctl",
                 394: "sys_proc_info", 340: "sys_syscall", 486: "sys_thread_selfid"}

    def hook_intr(uc, intno, user):
        x16 = uc.reg_read(UC_ARM64_REG_X16)
        nm = SVC_NAMES.get(x16, f"syscall #{x16}")
        stats["svcs"].append(nm)
        if len(stats["svcs"]) <= 20:
            print(f"  [T3][syscall #{len(stats['svcs'])}] التطبيق طلب: {nm} "
                  f"(x16={x16}) — اللودر يرد بـ ENOSYS (نحاكي الرفض)")
        uc.reg_write(UC_ARM64_REG_X0, 0xFFFFFFFF)  # إرجاع -1/خطأ
        pc = uc.reg_read(UC_ARM64_REG_PC)
        uc.reg_write(UC_ARM64_REG_PC, pc + 4)

    def hook_code(uc, address, size, user):
        stats["insns"] += 1
        if stats["insns"] > 2_000_000:
            uc.emu_stop()

    def hook_mem_invalid(uc, access, address, size, value, user):
        stats["faults"] += 1
        if stats["faults"] > 1:
            return False
        pc = uc.reg_read(UC_ARM64_REG_PC)
        kinds = {UC_MEM_READ_UNMAPPED: "قراءة", UC_MEM_WRITE_UNMAPPED: "كتابة",
                 UC_MEM_FETCH_UNMAPPED: "جلب تعليمة (قفز لتنفيذ)"}.get(access, f"نوع {access}")
        print(f"\n  [T3] *** أول جدار حقيقي ***")
        print(f"  خطأ {kinds} على العنوان 0x{address:X} عند pc=0x{pc:X}")
        # فك تعليمات حول نقطة الانهيار (الإزاحة نسبة إلى بداية __TEXT في الملف)
        base = mo.text_vm
        off = pc - base
        code = mo.data[max(0, off - 16): off + 24]
        start_addr = pc - 16
        print("  التعليمات حول نقطة الانهيار (فك حقيقي بـ Capstone):")
        window = []
        for ins in md.disasm(code, start_addr):
            mark = " <<< هنا الانهيار" if ins.address == pc else ""
            print(f"    0x{ins.address:X}:  {ins.mnemonic:8s} {ins.op_str}{mark}")
            window.append((ins.address, ins.mnemonic, ins.op_str))
        # البحث عن نمط adrp+ldr — أي خانة مؤشر (GOT) استخدمها الكود قبل الانهيار؟
        import re as _re
        adrp_regs = {}
        for addr_i, mn, ops in window:
            m = _re.match(r"adrp x(\d+), #0x([0-9a-f]+)", mn + ", " + ops)
            if mn == "adrp":
                mm = _re.match(r"x(\d+), #0x([0-9a-f]+)", ops)
                if mm:
                    adrp_regs["x" + mm.group(1)] = int(mm.group(2), 16)
            elif mn == "ldr" and adrp_regs:
                mm = _re.match(r"x\d+, \[(x\d+)(?:, #(?:0x([0-9a-f]+)|(\d+)))?\]", ops)
                if mm and mm.group(1) in adrp_regs:
                    disp = int(mm.group(2), 16) if mm.group(2) else int(mm.group(3) or 0)
                    slot = adrp_regs[mm.group(1)] + disp
                    sym, secn = mo.resolve_pointer_slot(slot)
                    if sym:
                        print(f"    >>> الخانة 0x{slot:X} (قسم {secn}) = الرمز المستورد: {sym} "
                              f"— هذا ما كان يجب أن يملأه dyld قبل التشغيل!")
        regs = {f"x{i}": uc.reg_read(globals()[f"UC_ARM64_REG_X{i}"]) for i in range(19)}
        for r, v in regs.items():
            if v:
                print(f"    {r} = 0x{v:X}", end="")
        print()
        for i in range(0, 19, 6):
            line = "  " + "  ".join(f"x{j}=0x{uc.reg_read(globals()[f'UC_ARM64_REG_X{j}']):X}"
                                    for j in range(i, min(i + 6, 19)))
            print(line)
        return False  # أوقف التنفيذ

    uc.hook_add(UC_HOOK_INTR, hook_intr)
    uc.hook_add(UC_HOOK_CODE, hook_code)
    uc.hook_add(UC_HOOK_MEM_INVALID, hook_mem_invalid)

    print("  بدء التنفيذ الفعلي لتعليمات فورتنايت ARM64 ...\n")
    try:
        uc.emu_start(entry, 0x7E0000000000, timeout=90 * 1_000_000, count=300_000)
        print(f"\n  [T3] توقف التنفيذ بعد {stats['insns']} تعليمة")
    except UcError as e:
        print(f"\n  [T3] توقف المحاكي بخطأ: {e} — بعد {stats['insns']} تعليمة منفذة")
    print(f"\n  [T3] الخلاصة: نُفذت {stats['insns']} تعليمة حقيقية من فورتنايت، "
          f"وتم ردّها على {len(stats['svcs'])} syscall: {stats['svcs'][:15]}")

# ======================= main =======================
if __name__ == "__main__":
    print("=" * 72)
    print("التحليل الهندسي لبناء Fortnite 3.5 الحقيقي — CL 3994867 (iOS)")
    print("=" * 72)
    mo = MachO(BIN)
    mo.load_symbols()
    entry = mo.summary()
    stage2(mo)
    # Info.plist
    try:
        pl = plistlib.load(open(os.path.join(APP, "Info.plist"), "rb"))
        print(f"\n[T1] Info.plist: bundle={pl.get('CFBundleIdentifier')} "
              f"الإصدار={pl.get('CFBundleShortVersionString')} "
              f"أدنى iOS={pl.get('MinimumOSVersion')}")
    except Exception as e:
        print("Info.plist:", e)
    stage3(mo, entry)
