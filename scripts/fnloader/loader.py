#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
fnloader/loader.py — المُشغّل الرئيسي المتكامل
=============================================
IPA (.ipa) أو .app → فك → تحليل Mach-O → رسم الذاكرة → ربط dyld كامل
→ تنفيذ ARM64 حقيقي (نواة QEMU عبر Unicorn) مع:
   • ترامبولين لكل رمز مستورد (نداء → تنفيذ Python → عودة)
   • قفزة حقيقية إلى IMP أصناف ObjC الخاصة باللعبة نفسها عند توفرها
   • طبقة syscalls (BSD/Mach) + libc + وقت ObjC/CF
   • تقرير حدود نهائي: أين وصلنا وما الرمز التالي المطلوب
"""
import os, sys, time, struct, zipfile, collections

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import macho as macho_mod
import impls as impls_mod
import objc as objc_mod
from impls import StopRun

from unicorn import Uc, UcError, UC_ARCH_ARM64, UC_MODE_LITTLE_ENDIAN, UC_PROT_ALL, \
    UC_HOOK_INTR, UC_HOOK_CODE, UC_HOOK_MEM_INVALID, UC_HOOK_BLOCK, UC_MEM_READ_UNMAPPED, \
    UC_MEM_WRITE_UNMAPPED, UC_MEM_FETCH_UNMAPPED
from unicorn.arm64_const import *
import capstone

MASK=0xFFFFFFFFFFFFFFFF
HEAP_BASE, HEAP_SIZE = 0x200000000000, 128*1024*1024
FAKES_BASE, FAKES_SIZE = 0x210000000000, 64*1024*1024
STRS_BASE,  STRS_SIZE  = 0x220000000000, 4*1024*1024
DATASYM_BASE          = 0x230000000000
TRAMP_BASE, TRAMP_SIZE= 0x240000000000, 1024*1024
STACK_BASE, STACK_SIZE= 0x7F0000000000, 4*1024*1024
ANON_BASE             = 0x300000000000
RESV_BASE             = 0x400000000000   # حجوزات ضخمة (تُرسم صفحاتها عند اللمس فقط)
ANON_BUDGET           = 1536*1024*1024
UNTIL                 = 0x7E0000000000

class Ctx:
    JUMP=object()
    def __init__(s, uc, mo):
        s.uc=uc; s.mo=mo
        s.heap_ptr=HEAP_BASE; s.fake_ptr=FAKES_BASE
        s.str_ptr=STRS_BASE; s.anon_ptr=ANON_BASE; s.anon_bytes=0
        s.fakes={}; s._interned={}
        s.trace=[]; s.events=0; s.calls=collections.Counter()
        s.svc_pc=collections.Counter(); s.svc_total=0
        s.automap_log=[]; s.cxx_guards=set(); s.resv_cursor=0
        s.file_streams={}
        s.ROOT="/home/z/my-project/fn35/extracted/Payload/FortniteClient.app"
        s.blocks=collections.deque(maxlen=400)
        s.stopped=False; s.stop_reason=None
        s.t0=time.time()
        s.syms=dict(impls_mod.SYMS)
        s.tramp={}
        s.tramp_seq=0
        s.shim=None
    # ---- سجلات ----
    def xr(s,i): return s.uc.reg_read(globals()[f"UC_ARM64_REG_X{i}"])
    def xs(s,i,v): s.uc.reg_write(globals()[f"UC_ARM64_REG_X{i}"], int(v)&MASK)
    def lr(s): return s.uc.reg_read(UC_ARM64_REG_LR)
    def set_pc(s,a): s.uc.reg_write(UC_ARM64_REG_PC,int(a)&MASK)
    # ---- ذاكرة ----
    def rb(s,a,n=16):
        try: return bytes(s.uc.mem_read(a,n))
        except Exception: return None
    def wb(s,a,b):
        try: s.uc.mem_write(a,bytes(b)); return True
        except Exception: return False
    def r64(s,a):
        b=s.rb(a,8)
        return struct.unpack("<Q",b)[0] if b else None
    def r32(s,a):
        b=s.rb(a,4)
        return struct.unpack("<I",b)[0] if b else None
    def w64(s,a,v):
        s.wb(a,struct.pack("<Q",int(v)&MASK))
    def w32(s,a,v):
        s.wb(a,struct.pack("<I",int(v)&0xFFFFFFFF))
    def cstr(s,a,maxlen=1024):
        if not a: return None
        try:
            out=b""; p=a
            for _ in range(maxlen//16+1):
                chunk=s.uc.mem_read(p,16)
                z=chunk.find(b"\0")
                if z>=0: return (out+chunk[:z]).decode("utf-8","replace")
                out+=chunk; p+=16
                if len(out)>=maxlen: return out[:maxlen].decode("utf-8","replace")
        except Exception:
            return None
        return None
    def mem_copy(s,src,dst,n):
        for off in range(0,n,1<<20):
            chunk=s.rb(src+off,min(1<<20,n-off))
            if not chunk: break
            s.wb(dst+off,chunk)
    # ---- مناطق ----
    def bump(s,n):
        if s.heap_ptr+n > HEAP_BASE+HEAP_SIZE: s.stop("نفاد كومة الوهميات"); return HEAP_BASE
        p=s.heap_ptr; s.heap_ptr=(p+n+15)&~15; return p
    def cfstr(s,st):
        p=s.fake("cfstr")
        s.w64(p+16,s.intern(st)); s.w64(p+24,len(st))
        return p
    def fake(s,name):
        if s.fake_ptr+64 > FAKES_BASE+FAKES_SIZE: s.stop("نفاد منطقة الوهميات"); s.fake_ptr=FAKES_BASE
        p=s.fake_ptr; s.fake_ptr+=64; s.fakes[p]=name; return p
    def intern(s,st):
        if st in s._interned: return s._interned[st]
        b=st.encode("utf-8")+b"\0"
        if s.str_ptr+len(b) > STRS_BASE+STRS_SIZE: s.str_ptr=STRS_BASE
        p=s.str_ptr; s.str_ptr+=len(b)
        s.wb(p,b); s._interned[st]=p
        return p
    def reserve(s,n):
        """حجز عنواني ضخم (مثل mmap 4GB لـUnreal) — بلا استهلاك ذاكرة فعلي"""
        n=(n+0xFFFFF)&~0xFFFFF
        if s.resv_cursor==0: s.resv_cursor=RESV_BASE
        p=s.resv_cursor
        s.resv_cursor+=n
        return p
    def map_anon(s,n):
        n=(n+0xFFF)&~0xFFF
        if n>64*1024*1024 and len(s.automap_log)<60:
            s.automap_log.append(f"خريطة كبيرة: {n>>20}MB")
        if s.anon_bytes+n>ANON_BUDGET:
            s.stop(f"تجاوز ميزانية الخرائط ({s.anon_bytes>>20}MB)")
            return ANON_BASE
        p=s.anon_ptr
        try:
            s.uc.mem_map(p,n,UC_PROT_ALL)
        except UcError:
            s.stop("تعذر رسم صفحات مجهولة"); return p
        s.anon_ptr+=n; s.anon_bytes+=n
        return p
    # ---- أدوات عامة ----
    def ticks(s): return int((time.time()-s.t0)*1e9)&MASK
    def log(s,ev):
        s.events+=1
        s.trace.append(ev)
        if len(s.trace)>600: del s.trace[:200]
    def count(s,k): s.calls[k]+=1
    def stop(s,reason):
        if not s.stopped:
            s.stopped=True; s.stop_reason=reason
        try: s.uc.emu_stop()
        except Exception: pass

DATA_SYMS={"__stack_chk_guard":0xE2A7D1B5C0DE5EED,"_vm_page_size":16384}
IVAR_DEFAULT=16

def find_binary(path):
    if os.path.isdir(path):
        for root,_,files in os.walk(path):
            if root.endswith(".app"):
                for f in files:
                    if f.endswith(".plist"): continue
                    fp=os.path.join(root,f)
                    try:
                        with open(fp,"rb") as fh:
                            if fh.read(4)==b"\xcf\xfa\xed\xfe": return fp
                    except Exception: pass
    elif path.endswith(".ipa"):
        with zipfile.ZipFile(path) as z:
            for n in z.namelist():
                if n.startswith("Payload/") and n.endswith(".app/"): continue
                if n.startswith("Payload/") and "/." not in n and not n.endswith("/"):
                    try:
                        with z.open(n) as fh:
                            if fh.read(4)==b"\xcf\xfa\xed\xfe": return (path,n)
                    except Exception: pass
    elif os.path.isfile(path):
        return path
    return None

def load_binary(target):
    if isinstance(target,tuple):
        z=zipfile.ZipFile(target[0])
        data=z.read(target[1])
        import tempfile
        tf=tempfile.NamedTemporaryFile(delete=False,suffix=".macho")
        tf.write(data); tf.close()
        return tf.name
    return target

def main():
    ipa="/home/z/my-project/fn35/fn35_modded.ipa"
    args=[a for a in sys.argv[1:] if not a.startswith("-")]
    if args: ipa=args[0]
    print("="*74)
    print("fnloader — لودر IPA متكامل البنية (Mach-O + dyld + Mach/libc/ObjC)")
    print("="*74)
    t=find_binary(ipa)
    if not t: print("!! لم أجد ثنائياً داخل:",ipa); return 1
    binpath=load_binary(t)
    src=target_desc = t[1] if isinstance(t,tuple) else t
    print(f"[1/6] الهدف: {src}")

    mo=macho_mod.MachO(binpath)
    print(f"[2/6] Mach-O: {len(mo.segments)} مقاطع | {len(mo.dylibs)} إطاراً مطلوباً | "
          f"رموز: {mo.nsyms} | أوامر ربط dyld: {len(mo.bind_records)}")
    print(f"      نقطة الدخول: 0x{mo.entry:X} | التشفير: "
          f"{'مفكوك' if not mo.encryption or mo.encryption[2]==0 else 'مشفّر!'}")

    uc=Uc(UC_ARCH_ARM64,UC_MODE_LITTLE_ENDIAN)
    ctx=Ctx(uc,mo)
    ctx.shim=objc_mod.ObjCShim(mo)
    ctx.syms.update(objc_mod.OBJC_EXPORTS)
    print(f"      أصناف ObjC حقيقية داخل اللعبة: {len(ctx.shim.real)} (قابلة للنداء الحقيقي)")
    print(f"      دوال مُنفَّذة في الطبقات: {len(ctx.syms)}")

    # ---- [3/6] رسم الذاكرة ----
    for g in mo.segments:
        if g.filesize==0 or g.vmaddr==0: continue
        sz=(max(g.filesize,g.vmsize)+0xFFF)&~0xFFF
        uc.mem_map(g.vmaddr,sz,UC_PROT_ALL)
        uc.mem_write(g.vmaddr,mo.data[g.fileoff:g.fileoff+g.filesize])
    for base,size in ((HEAP_BASE,HEAP_SIZE),(FAKES_BASE,FAKES_SIZE),
                      (STRS_BASE,STRS_SIZE),(TRAMP_BASE,TRAMP_SIZE),
                      (STACK_BASE,STACK_SIZE)):
        uc.mem_map(base,size,UC_PROT_ALL)
    uc.mem_map(DATASYM_BASE,0x1000,UC_PROT_ALL)
    # قيم الرموز-البيانات المُهيّأة
    doff=0
    data_slots={}
    for k,v in DATA_SYMS.items():
        uc.mem_write(DATASYM_BASE+doff,struct.pack("<Q",v))
        data_slots[k]=DATASYM_BASE+doff; doff+=8
    env_slot=DATASYM_BASE+doff; doff+=8      # _environ → مؤشر لمصفوفة NULL
    data_slots["_environ"]=env_slot
    stdout_slot=DATASYM_BASE+doff; doff+=8   # FILE* وهمي
    data_slots["_stdout"]=data_slots["__stdoutp"]=stdout_slot
    data_slots["_stderr"]=data_slots["__stderrp"]=stdout_slot
    print(f"[3/6] رُسمت الذاكرة: مقاطع اللعبة + كومة 128MB + وهميات + ترامبولين + مكدس 4MB")

    # ---- [4/6] الربط (دور dyld): تدفق الأوامر + كنس احتياطي عبر جدول indirect ----
    RET=struct.pack("<I",0xD65F03C0)
    dc=collections.Counter()
    def make_trampoline(name):
        taddr=TRAMP_BASE+16*ctx.tramp_seq; ctx.tramp_seq+=1
        uc.mem_write(taddr,RET)
        ctx.tramp[taddr]=(name,ctx.syms.get(name))
        dc["func"]+=1
        return taddr
    def bind_one(addr,name):
        if name in data_slots:
            val=data_slots[name]; dc["data"]+=1
        elif name.startswith("_OBJC_CLASS_$_"):
            val=ctx.fake("class:"+name[15:]); dc["cls"]+=1
        elif name.startswith("_OBJC_METACLASS_$_"):
            val=ctx.fake("meta:"+name[20:]); dc["cls"]+=1
        elif name.startswith(("_OBJC_IVAR_$","_OBJC_SELECTOR_REFERENCES_")):
            uc.mem_write(addr,struct.pack("<Q",IVAR_DEFAULT)); return
        else:
            val=make_trampoline(name)
        uc.mem_write(addr,struct.pack("<Q",val&MASK))
    bound=set()
    for addr,name,addend in mo.bind_records:
        if addr in bound: continue
        bound.add(addr); bind_one(addr,name)
    # كنس احتياطي: كل خانات أقسام المؤشرات عبر جدول indirect (يشمل ما فوّته التدفق)
    extra=0
    LOCAL_SENTINELS={0x80000000,0x40000000}
    for se in mo.sections.values():
        is_ptr=((se.flags&0xFF) in (0x6,0x7) or
                se.name in ("__got","__la_symbol_ptr","__nl_symbol_ptr"))
        if not is_ptr or se.seg!="__DATA": continue
        base=se.res1 if se.res1<len(mo.indirect) else 0
        for i in range(int(se.size//8)):
            slot=se.addr+i*8
            if slot in bound: continue
            idx=base+i
            if idx>=len(mo.indirect): break
            isym=mo.indirect[idx]
            if isym in LOCAL_SENTINELS or isym>=len(mo.symtab): continue
            nm=mo.symtab[isym][0]
            if not nm: continue
            bound.add(slot); bind_one(slot,nm); extra+=1
    n_cls=dc["cls"]; n_data=dc["data"]; n_func=ctx.tramp_seq
    # فحص صلاحية __objc_selrefs (مؤشرات محلية مطلقة — slide=0)
    sel_ok=sel_bad=0
    se=mo.sections.get("__objc_selrefs")
    if se:
        for a in range(se.addr,se.addr+se.size,8):
            v=ctx.r64(a)
            if v and ctx.cstr(v) is not None: sel_ok+=1
            else: sel_bad+=1
    print(f"[4/6] الربط اكتمل: دوال {n_func} | أصناف ObjC خارجية {n_cls} | "
          f"رموز بيانات {n_data} | خانات الكنس الاحتياطي {extra} | "
          f"selrefs صالحة {sel_ok} / تالفة {sel_bad}")

    # مكدس + بيئة main()
    sp=STACK_BASE+STACK_SIZE-0x10000
    name_slot=STACK_BASE+0x1000
    uc.mem_write(name_slot,b"FortniteClient\0")
    frame=struct.pack("<QQQQQ",1,name_slot,0,0,0)
    uc.mem_write(sp,frame)
    uc.reg_write(UC_ARM64_REG_SP,sp)
    uc.reg_write(UC_ARM64_REG_X0,1)
    uc.reg_write(UC_ARM64_REG_X1,name_slot)
    uc.reg_write(UC_ARM64_REG_X18,0)
    # عنوان الخروج sentinel — كما تفعل النواة مع __dyld_start:
    # أي ret في أعلى السلسلة يهبط هنا بدل العنوان 0
    def _on_main_return(c):
        from impls import StopRun
        raise StopRun("عاد main() إلى نقطة الخروج — اكتمال نظيف لمسار التنفيذ!")
    sentinel=TRAMP_BASE+16*(ctx.tramp_seq+1000)
    uc.mem_write(sentinel,RET)
    ctx.tramp[sentinel]=("_start_sentinel",_on_main_return)
    uc.reg_write(UC_ARM64_REG_LR,sentinel)

    md=capstone.Cs(capstone.CS_ARCH_ARM64,capstone.CS_MODE_LITTLE_ENDIAN)
    SVC_NAMES={1:"exit",3:"read",4:"write",5:"open",6:"close",197:"mmap",
               199:"munmap",202:"sysctl",274:"sysctlbyname",394:"proc_info"}

    def hook_intr(uc_,intno,user):
        pc=uc_.reg_read(UC_ARM64_REG_PC)
        if intno!=2:
            ctx.stop(f"تعليمة غير معرّفة (udf) عند 0x{pc:X} — التنفيذ خرج عن الكود")
            return
        num=uc_.reg_read(UC_ARM64_REG_X16)
        ctx.svc_total+=1; ctx.svc_pc[pc]+=1
        if ctx.svc_total>100_000:
            ctx.stop(f"عاصفة svc: {ctx.svc_total} نداء — أشهرها عند 0x{pc:X} "
                     f"(x16=0x{num:X})")
            return
        nm=SVC_NAMES.get(num,f"sys#{num}")
        # إذا كان x16 يشير لترامبولين فنكشف اسم الرمز فوراً — تشخيص ذهبي
        hint=""
        if TRAMP_BASE<=num<TRAMP_BASE+16*max(ctx.tramp_seq,1):
            ent=ctx.tramp.get(num)
            if ent: hint=f" [x16=ترامبولين {ent[0]}]"
        if ctx.svc_total<=60: ctx.log(f"svc {nm} (x16={num}){hint} → ENOSYS عند 0x{pc:X}")
        uc_.reg_write(UC_ARM64_REG_X0,-1 & MASK)
        uc_.reg_write(UC_ARM64_REG_PC,pc+4)

    def hook_code(uc_,address,size,user):
        ent=ctx.tramp.get(address)
        if not ent: return
        name,fn=ent
        ctx.calls[name]+=1
        if not fn:
            if ctx.calls[name]<=3: ctx.log(f"غير مُنفَّذ: {name} → 0")
            uc_.reg_write(UC_ARM64_REG_X0,0)
        else:
            try:
                ret=fn(ctx)
            except StopRun as e:
                ctx.stop(str(e)); return
            except Exception as e:
                ctx.log(f"خطأ تنفيذ {name}: {e!r}")
                ret=0
            if ret is ctx.JUMP: return
            if ret is None: ret=0
            uc_.reg_write(UC_ARM64_REG_X0,int(ret)&MASK)
        uc_.reg_write(UC_ARM64_REG_PC,uc_.reg_read(UC_ARM64_REG_LR))

    def hook_mem(uc_,access,address,size,value,user):
        pc=uc_.reg_read(UC_ARM64_REG_PC)
        kind={UC_MEM_READ_UNMAPPED:"قراءة",UC_MEM_WRITE_UNMAPPED:"كتابة",
              UC_MEM_FETCH_UNMAPPED:"جلب"}.get(access,str(access))
        if address<0x100000:
            ctx.stop(f"إبطال مؤشر NULL ({kind} على 0x{address:X}) عند pc=0x{pc:X}")
            return False
        page=address & ~0xFFF
        if ctx.anon_bytes+0x1000<=ANON_BUDGET:
            try:
                uc_.mem_map(page,0x1000,UC_PROT_ALL)
                ctx.anon_bytes+=0x1000
                ctx.calls["#automap"]+=1
                if len(ctx.automap_log)<60: ctx.automap_log.append(f"0x{address:X} عند pc=0x{pc:X} ({kind})")
                return True
            except UcError:
                pass
        ctx.stop(f"خطأ {kind} على 0x{address:X} عند pc=0x{pc:X}")
        return False

    def hook_block(uc_,addr,size,user):
        ctx.blocks.append(addr)
    uc.hook_add(UC_HOOK_BLOCK,hook_block)
    uc.hook_add(UC_HOOK_INTR,hook_intr)
    uc.hook_add(UC_HOOK_CODE,hook_code,begin=TRAMP_BASE,end=TRAMP_BASE+TRAMP_SIZE)
    uc.hook_add(UC_HOOK_MEM_INVALID,hook_mem)

    # ---- [5/6] التنفيذ المجزأ ----
    print("[5/6] بدء تنفيذ تعليمات فورتنايت الحقيقية (Ctrl+C للإيقاف)...")
    budget=float(os.environ.get("FN_TIME","100"))
    insns=0; CHUNK=1_000_000
    pc=mo.entry
    t0=time.time()
    err=None
    while not ctx.stopped and time.time()-t0<budget and insns<400_000_000:
        if sum(v for k,v in ctx.calls.items() if not k.startswith("#"))>2_500_000:
            ctx.stop("تجاوز سقف نداءات الترامبولين (2.5M)"); break
        try:
            uc.emu_start(pc,UNTIL,timeout=0,count=CHUNK)
        except UcError as e:
            err=e; break
        insns+=CHUNK
        pc=uc.reg_read(UC_ARM64_REG_PC)
    elapsed=time.time()-t0

    # ---- [6/6] تقرير الحدود ----
    print(f"[6/6] اكتملت الجولة — كتابة التقرير")
    L=[]
    L.append("="*74)
    L.append("تقرير تشغيل fnloader — Fortnite 3.5 iOS (حقيقي)")
    L.append("="*74)
    L.append(f"وقت التنفيذ: {elapsed:.1f} ثانية | تعليمات مُنفَّذة: ≥ {insns:,}")
    L.append(f"سبب التوقف: {ctx.stop_reason or err or ('الميزانية الزمنية ' if time.time()-t0>=budget else 'غير معروف')}")
    L.append(f"نداءات إجمالية عبر اللودر: {sum(ctx.calls.values()):,} | أحداث مسجلة: {ctx.events}")
    L.append(f"syscalls مباشرة: {ctx.svc_total} | صفحات رسمها اللودر تلقائياً: {ctx.calls.get('#automap',0)}")
    L.append("")
    L.append("أكثر 25 رمزاً استدعاءً (واجهات iOS تعمل الآن):")
    for k,v in ctx.calls.most_common(25):
        if k.startswith("#"): continue
        L.append(f"   {v:8d}×  {k}")
    L.append("")
    L.append("أشهر مواقع svc (حلقات إعادة المحاولة):")
    for pc,n in ctx.svc_pc.most_common(3):
        L.append(f"   {n:8d}×  0x{pc:X}")
        try:
            off=pc-mo.text_vm
            code=mo.data[max(0,off-16):off+12]
            for ins in md.disasm(code,pc-16):
                mark="  <<<" if ins.address==pc else ""
                L.append(f"      0x{ins.address:X}: {ins.mnemonic} {ins.op_str}{mark}")
        except Exception: pass
    L.append("")
    if ctx.automap_log:
        L.append("أول صفحات رسمها اللودر تلقائياً (عناوين غير متوقعة):")
        for e in ctx.automap_log[:25]:
            L.append("   "+e)
    L.append("")
    L.append("أول 60 حدثاً من بداية التشغيل:")
    for e in ctx.trace[:60]:
        L.append("   "+e)
    L.append("")
    L.append("آخر 40 حدثاً (أقرب جدار):")
    for e in ctx.trace[-40:]:
        L.append("   "+e)
    L.append("")
    if len(ctx.blocks)>0:
        L.append(f"آخر 15 كتلة تنفيذ قبل التوقف (أقدم ← أحدث):")
        tail=list(ctx.blocks)[-15:]
        for i,b in enumerate(tail):
            tname=""
            if TRAMP_BASE<=b<TRAMP_BASE+TRAMP_SIZE:
                ent=ctx.tramp.get(b); tname=f"  ← {ent[0]}" if ent else "  ← ترامبولين؟"
            L.append(f"   [{'%2d'%i}] 0x{b:X}{tname}")
        last_b=tail[-1]
        try:
            off=last_b-mo.text_vm
            code=mo.data[off:off+96]
            L.append(f"فك آخر كتلة (0x{last_b:X}):")
            for ins in md.disasm(code,last_b):
                L.append(f"   0x{ins.address:X}: {ins.mnemonic} {ins.op_str}")
        except Exception as e:
            L.append(f"(تعذر فك الكتلة: {e})")
    L.append("")
    if err or ctx.stop_reason:
        pc_now=uc.reg_read(UC_ARM64_REG_PC)
        lr_now=uc.reg_read(UC_ARM64_REG_LR)
        sp_now=uc.reg_read(UC_ARM64_REG_SP)
        L.append(f"السجلات عند التوقف: PC=0x{pc_now:X} LR=0x{lr_now:X} SP=0x{sp_now:X} "
                 f"X0=0x{uc.reg_read(UC_ARM64_REG_X0):X} X8=0x{uc.reg_read(UC_ARM64_REG_X8):X}")
        if 0<sp_now and (sp_now & (1<<63)):
            try:
                st=uc.mem_read(sp_now,64)
                L.append("محيط SP: "+st.hex())
            except Exception: pass
        L.append(f"آخر PC: 0x{pc_now:X}")
        try:
            off=pc_now-mo.text_vm
            code=mo.data[max(0,off-32):off+16]
            L.append("التعليمات حول نقطة التوقف:")
            for ins in md.disasm(code,pc_now-32):
                mark="  <<< هنا" if ins.address==pc_now else ""
                L.append(f"   0x{ins.address:X}: {ins.mnemonic} {ins.op_str}{mark}")
        except Exception as e:
            L.append(f"(تعذر فك التعليمات: {e})")
    report="\n".join(L)
    outdir="/home/z/my-project/download/fnloader"
    os.makedirs(outdir,exist_ok=True)
    with open(os.path.join(outdir,"run_report.txt"),"w",encoding="utf-8") as f:
        f.write(report)
    print(report[:2600])
    print(f"\n[تم] التقرير الكامل: {outdir}/run_report.txt")
    return 0

if __name__=="__main__":
    sys.exit(main())
