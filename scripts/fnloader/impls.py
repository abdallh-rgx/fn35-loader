#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""fnloader/impls.py — طبقة تنفيذ libc / Mach VM / BSD"""
import struct

MASK=0xFFFFFFFFFFFFFFFF

class StopRun(Exception):
    def __init__(s,reason): s.reason=reason

SYMS={}

def sym(*names):
    def deco(fn):
        for n in names: SYMS[n]=fn
        return fn
    return deco

# ================= Mach VM =================
@sym("_vm_allocate")
def vm_allocate(c):
    addrp,size=c.xr(1),c.xr(2) or 0x4000
    a=c.reserve(size) if size>256*1024*1024 else c.map_anon(max(size,0x4000))
    if addrp: c.w64(addrp,a)
    return 0

@sym("_vm_deallocate","_vm_protect","_vm_msync","_vm_inherit","_mach_port_deallocate",
     "_mach_port_mod_refs","_mach_port_insert_right","_mach_port_allocate")
def ok0(c): return 0

@sym("_vm_map")
def vm_map(c):
    size=c.xr(2) or 0x4000
    return c.reserve(size) if size>256*1024*1024 else c.map_anon(size)

@sym("_mach_absolute_time")
def mach_abs_time(c): return c.ticks()

@sym("_mach_timebase_info")
def mach_tbi(c):
    info=c.xr(0)
    if info: c.wb(info,struct.pack("<II",1,1))
    return 0

@sym("_mach_thread_self","_mach_thread_selfid","_pthread_self","_pthread_mach_thread_np",
     "_mach_host_self","_mach_task_self_")
def self_id(c): return 0x2A

@sym("_mach_msg")
def mach_msg(c):
    c.log("mach_msg (تجاهل)")
    return 0

# ---- معلومات النظام بمعاملات إخراج حقيقية ----
@sym("_host_page_size")
def host_page_size(c):
    p=c.xr(1)
    if p: c.w64(p,16384)
    return 0

@sym("_host_statistics")
def host_statistics(c):
    # سلوك xnu: يقصّ العدد إلى HOST_VM_INFO_COUNT (15 عدداً = 60 بايت)
    # ويكتب العدد الفعلي المُستخدم مرة أخرى في countp
    info,countp=c.xr(2),c.xr(3)
    cnt=min(c.r32(countp) or 1,15)
    if info: c.wb(info,b"\0"*(cnt*4))
    if countp: c.w32(countp,cnt)
    return 0

@sym("_host_statistics64")
def host_statistics64(c):
    info,countp=c.xr(2),c.xr(3)
    cnt=min(c.r32(countp) or 1,20)
    if info: c.wb(info,b"\0"*(cnt*4))
    if countp: c.w32(countp,cnt)
    return 0

@sym("_task_info","_task_info64")
def task_info(c):
    info,countp=c.xr(2),c.xr(3)
    cnt=min(c.r32(countp) or 1,12)
    if info: c.wb(info,b"\0"*(cnt*4))
    if countp: c.w32(countp,cnt)
    return 0

@sym("_mach_vm_region","_mach_vm_region_recurse","_vm_region","_vm_region_recurse_64",
     "_mach_vm_region_64")
def vm_region_unsupported(c): return 1  # KERN_INVALID_ADDRESS

@sym("_vm_read","_mach_vm_read","_vm_read_overwrite","_mach_vm_read_overwrite")
def vm_read_(c):
    data,addr,size=c.xr(3),c.xr(1),c.xr(2)
    if data: c.w64(data,addr)
    return 0

@sym("_thread_info")
def thread_info_(c): return 0

# ================= libc =================
@sym("_malloc","_valloc")
def malloc(c): return c.bump(max(c.xr(0),16))

@sym("_calloc")
def calloc(c):
    n=c.xr(0)*c.xr(1)
    p=c.bump(max(n,16))
    if n: c.wb(p,b"\0"*min(n,4*1024*1024))
    return p

@sym("_realloc")
def realloc(c):
    old,n=c.xr(0),c.xr(1)
    if not old: return c.bump(max(n,16))
    p=c.bump(max(n,16))
    c.mem_copy(old,p,min(n,1024*1024))
    return p

@sym("_free","_malloc_zone_free","_malloc_destroy_zone")
def free(c): return 0

@sym("_malloc_size","_malloc_usable_size")
def malloc_size(c): return max(c.xr(0),16)

@sym("_memcpy","___memcpy_chk","_memmove","___memmove_chk")
def memcpy(c):
    d,s_,n=c.xr(0),c.xr(1),c.xr(2)
    c.mem_copy(s_,d,min(n,16*1024*1024))
    return d

@sym("_memset","___memset_chk")
def memset(c):
    d,v,n=c.xr(0),c.xr(1),c.xr(2)
    if d and n: c.wb(d,bytes([v&0xFF])*min(n,16*1024*1024))
    return d

@sym("_bzero")
def bzero(c):
    d,n=c.xr(0),c.xr(1)
    if d and n: c.wb(d,b"\0"*min(n,16*1024*1024))
    return 0

@sym("_memcmp")
def memcmp(c):
    a,b,n=c.xr(0),c.xr(1),c.xr(2)
    ba,bb=c.rb(a,min(n,1<<20)) or b"",c.rb(b,min(n,1<<20)) or b""
    return (ba>bb)-(ba<bb)

@sym("_strlen")
def strlen(c):
    s_=c.cstr(c.xr(0))
    return len(s_) if s_ is not None else 0

@sym("_strcmp","_strcasecmp")
def strcmp(c):
    a,b=c.cstr(c.xr(0)) or "",c.cstr(c.xr(1)) or ""
    return (a>b)-(a<b)

@sym("_strncmp","_strncasecmp")
def strncmp(c):
    a,b,n=c.cstr(c.xr(0)) or "",c.cstr(c.xr(1)) or "",c.xr(2)
    a,b=a[:n],b[:n]
    return (a>b)-(a<b)

@sym("_strcpy")
def strcpy(c):
    d,s_=c.xr(0),c.cstr(c.xr(1)) or ""
    if d: c.wb(d,s_.encode("utf-8")+b"\0")
    return d

@sym("_strlcpy","_strlcat")
def strlcpy(c): return len(c.cstr(c.xr(1)) or "")

@sym("_strdup","_strdup_if")
def strdup(c):
    s_=c.cstr(c.xr(0)) or ""
    p=c.bump(len(s_)+16)
    c.wb(p,s_.encode("utf-8")+b"\0")
    return p

@sym("_strchr","_strrchr","_strstr","_strtok_r")
def notfound(c): return 0

@sym("_snprintf","_vsnprintf","_asprintf","_vasprintf","_sprintf")
def snprintf(c): return 0

@sym("_strtol","_strtoll","_strtoul","_strtoull","_atoi","_atol","_atoll")
def strtol_(c):
    s_=c.cstr(c.xr(0)) or ""
    s2=s_.lstrip()
    import re as _re
    m=_re.match(r"[+-]?[0-9xXa-fA-F]+",s2)
    try:
        v=int(m.group(0),0) if m else 0
    except ValueError:
        v=0
    endp=c.xr(2)
    if endp: c.w64(endp,c.xr(0)+len(s_)-len(s2)+len(m.group(0)) if m else c.xr(0))
    return v & MASK

@sym("_isdigit")
def isdigit(c):
    ch=c.xr(0)
    return 1 if 48<=ch<=57 else 0

@sym("_tolower")
def tolower(c): return c.xr(0)+32 if 65<=c.xr(0)<=90 else c.xr(0)

@sym("_toupper")
def toupper(c): return c.xr(0)-32 if 97<=c.xr(0)<=122 else c.xr(0)

# ================= pthread =================
@sym("_pthread_mutex_lock","_pthread_mutex_unlock","_pthread_mutex_trylock",
     "_pthread_mutex_init","_pthread_mutex_destroy","_pthread_mutexattr_init",
     "_pthread_mutexattr_destroy","_pthread_mutexattr_settype",
     "_pthread_once","_pthread_attr_init","_pthread_attr_destroy",
     "_pthread_attr_setdetachstate","_pthread_setspecific","_pthread_getspecific",
     "_pthread_cond_wait","_pthread_cond_signal","_pthread_cond_broadcast",
     "_pthread_cond_init","_pthread_cond_destroy","_pthread_detach",
     "_pthread_setname_np","_pthread_join","_pthread_cancel",
     "_pthread_rwlock_rdlock","_pthread_rwlock_wrlock","_pthread_rwlock_unlock")
def pthread_ok(c): return 0

@sym("_pthread_create")
def pthread_create(c):
    c.log("pthread_create (خيط مُتجاهَل)")
    return 0

# ================= sysctl / معلومات النظام =================
SYSCTL_STR={("hw","machine"):"iPhone10,6",("kern","osrelease"):"17.4",
            ("kern","ostype"):"Darwin",("hw","machinearch"):"arm64"}
SYSCTL_INT={("hw","cputype"):0x100000C,("hw","cpusubtype"):0,
            ("hw","memsize"):3221225472,("hw","ncpu"):6,("hw","byteorder"):1234,
            ("hw","pagesize"):16384,("kern","osrev"):17,
            ("hw","cachelinesize"):128,("hw","l1icachesize"):32768,
            ("hw","l1dcachesize"):32768,("hw","l2cachesize"):262144}

def _sysctl_common(c,names,outp,lenp):
    key=tuple(names)
    if key in SYSCTL_STR: val=SYSCTL_STR[key].encode()+b"\0"
    elif key in SYSCTL_INT: val=struct.pack("<Q",SYSCTL_INT[key])
    else: return -1
    if not outp:
        if lenp: c.w64(lenp,len(val))
        return 0
    n=min(c.r64(lenp) or len(val),len(val))
    c.wb(outp,val[:n])
    if lenp: c.w64(lenp,n)
    return 0

@sym("_sysctl")
def sysctl(c):
    nlen,outp,lenp=c.xr(1),c.xr(2),c.xr(3)
    raw=c.rb(c.xr(0),min(nlen*4,128)) or b""
    names=[str(struct.unpack_from("<i",raw,i)[0]) for i in range(0,len(raw),4)][:nlen]
    return _sysctl_common(c,names,outp,lenp)

@sym("_sysctlbyname")
def sysctlbyname(c):
    nm=c.cstr(c.xr(0)) or ""
    return _sysctl_common(c,nm.split("."),c.xr(2),c.xr(3))

@sym("_getpid")
def getpid(c): return 4242
@sym("_getuid","_geteuid","_getgid","_getegid")
def getuid(c): return 501
@sym("_getppid")
def getppid(c): return 1

@sym("_time")
def time_(c):
    import time as _t
    t=int(_t.time())
    if c.xr(0): c.w64(c.xr(0),t)
    return t

@sym("_gettimeofday")
def gettimeofday(c):
    import time as _t
    if c.xr(0): c.wb(c.xr(0),struct.pack("<qq",int(_t.time()),0))
    return 0

@sym("_clock_gettime")
def clock_gettime(c):
    if c.xr(1): c.wb(c.xr(1),struct.pack("<qq",0,0))
    return 0

# ================= نظام ملفات حقيقي =================
import os as _os
ROOT="/home/z/my-project/fn35/extracted/Payload/FortniteClient.app"

def _resolve(path):
    """ترجمة مسار iOS إلى مسار فعلي على هذا الجهاز"""
    if not path: return None
    if "/FortniteClient.app/" in path:
        rel=path.split("/FortniteClient.app/",1)[1]
        return _os.path.join(ROOT,rel)
    if path.rstrip("/").endswith(".app"):
        return ROOT
    if path.startswith("/"):
        if _os.path.exists(path): return path
        return None
    p=_os.path.join(ROOT,path)
    return p if _os.path.exists(p) else None

@sym("_open","_open64")
def open_(c):
    path=c.cstr(c.xr(0)) or ""
    real=_resolve(path)
    if real:
        try:
            fd=_os.open(real,_os.O_RDONLY)
            c.log(f"open({path!r}) ✓ ({_os.path.basename(real)}, {_os.path.getsize(real)}B)")
            return fd
        except OSError as e:
            c.log(f"open({path!r}) خطأ: {e}")
            return -1
    c.log(f"open({path!r}) → ENOENT")
    return -1

@sym("_close")
def close_(c):
    try: _os.close(c.xr(0))
    except Exception: pass
    return 0

@sym("_read","_pread")
def read_(c):
    fd,buf,n=c.xr(0),c.xr(1),c.xr(2)
    if c.xr(0)==0: return 0
    try:
        data=_os.read(fd,n)
    except Exception:
        return 0
    if data: c.wb(buf,data)
    return len(data)

@sym("_lseek","_lseek64")
def lseek_(c):
    try: return _os.lseek(c.xr(0),c.xr(1),c.xr(2))
    except Exception: return 0

@sym("_fstat","_fstat64","_stat","_stat64")
def fstat_(c):
    out=c.xr(1)
    if not out: return -1
    c.wb(out,b"\0"*256)
    try:
        sz=_os.fstat(c.xr(0)).st_size if c.xr(0)>2 else 0
        if c.xr(0)>2 and sz==0:
            p=_resolve(c.cstr(c.xr(0)))
            if p: sz=_os.path.getsize(p)
    except Exception:
        sz=0
    c.w64(out+72,sz); c.w64(out+96,sz)   # st_size (تخطيطان محتملان)
    c.w32(out+8,0o100644)                # S_IFREG|0644
    return 0

@sym("_access")
def access_(c):
    return 0 if _resolve(c.cstr(c.xr(0))) else -1

@sym("_getcwd")
def getcwd_(c):
    c.wb(c.xr(0),ROOT.encode()+b"\0")
    return c.xr(0)

# ---- stdio: FILE* ----
@sym("_fopen","_freopen")
def fopen_(c):
    path=c.cstr(c.xr(0)) or ""
    real=_resolve(path)
    if not real:
        c.log(f"fopen({path!r}) → NULL")
        return 0
    try:
        f=open(real,"rb")
    except Exception:
        return 0
    p=c.bump(64)
    c.file_streams[p]=f
    c.log(f"fopen({path!r}) ✓ ({_os.path.basename(real)})")
    return p

@sym("_fclose")
def fclose_(c):
    f=c.file_streams.pop(c.xr(0),None)
    if f: f.close()
    return 0

@sym("_fread")
def fread_(c):
    size,nm,fp=c.xr(0),c.xr(1),c.xr(2)
    f=c.file_streams.get(fp)
    if not f: return 0
    data=f.read(size*nm)
    c.wb(c.xr(3),data)
    return len(data)//size if size else 0

@sym("_fgets")
def fgets_(c):
    buf,n,fp=c.xr(0),c.xr(1),c.xr(2)
    f=c.file_streams.get(fp)
    if not f: return 0
    line=f.readline(n)
    if not line: return 0
    c.wb(buf,line)
    return buf

@sym("_fseek","_fseeko")
def fseek_(c):
    f=c.file_streams.get(c.xr(0))
    if f:
        try: f.seek(c.xr(1),c.xr(2))
        except Exception: pass
    return 0

@sym("_ftell","_ftello")
def ftell_(c):
    f=c.file_streams.get(c.xr(0))
    return f.tell() if f else 0

@sym("_rewind")
def rewind_(c):
    f=c.file_streams.get(c.xr(0))
    if f: f.seek(0)
    return 0

@sym("_feof")
def feof_(c):
    f=c.file_streams.get(c.xr(0))
    if not f: return 0
    return 1 if (len(f.read(1))==0 and f.seek(-1,1) is None) else 0

@sym("_ferror","_clearerr")
def ferror_(c): return 0

@sym("_fgetc","_getc")
def fgetc_(c):
    f=c.file_streams.get(c.xr(0))
    if not f: return -1
    b=f.read(1)
    return b[0] if b else -1

@sym("_write")
def write_(c):
    data=c.rb(c.xr(1),min(c.xr(2),4096)) or b""
    c.log("write: "+data[:120].decode("utf-8","replace"))
    return c.xr(2)

@sym("_fwrite")
def fwrite_(c):
    return c.xr(1)*c.xr(2)

@sym("_unlink","_mkdir","_rmdir","_chmod")
def fs_nop(c): return 0

@sym("_mmap")
def mmap_(c):
    addr,size,prot,flags=c.xr(0),c.xr(1) or 0x4000,c.xr(2),c.xr(3)
    if size>256*1024*1024 or prot==0:
        p=c.reserve(size)
        if len(c.automap_log)<60:
            c.automap_log.append(f"mmap حجز {size>>20}MB → 0x{p:X}")
        return p
    return c.map_anon(size)

@sym("_munmap","_msync","_mprotect")
def munmap_(c): return 0

@sym("_getenv")
def getenv_(c): return 0

@sym("_setenv","_unsetenv","_putenv")
def setenv_(c): return 0

# ================= dyld / dispatch / خروج =================
@sym("_dyld_image_count")
def img_count(c): return 1

@sym("_dyld_get_image_name")
def img_name(c): return c.intern("/var/containers/Bundle/Application/Fortnite/FortniteClient.app/FortniteClient")

@sym("_dyld_get_image_header")
def img_hdr(c): return c.mo.text_vm

@sym("_dyld_get_image_vmaddr_slide")
def img_slide(c): return 0

@sym("_dyld_register_func_for_add_image","_dyld_register_for_bulk_image_loads")
def dyld_cb(c): return 0

@sym("_dispatch_get_global_queue")
def dgq(c): return c.fake("global_queue")

@sym("_dispatch_queue_create","_dispatch_queue_create_with_target")
def dqc(c): return c.fake("queue:"+(c.cstr(c.xr(0)) or "?"))

@sym("_dispatch_async","_dispatch_async_f","_dispatch_after","_dispatch_sync",
     "_dispatch_group_async","_dispatch_once_f","_dispatch_after_f")
def dispatch_async_(c):
    c.log("dispatch_* (مهمة مؤجلة مُتجاهَلة)")
    return 0

@sym("_dispatch_once")
def dispatch_once_(c):
    p=c.xr(0)
    if p and not c.r64(p): c.w64(p,-1 & MASK)
    return 0

@sym("_dispatch_retain","_dispatch_release","_dispatch_resume","_dispatch_suspend",
     "_dispatch_group_create","_dispatch_semaphore_create","_dispatch_set_target_queue")
def dispatch_misc(c): return 0

@sym("_dispatch_semaphore_signal")
def sem_signal(c): return 1

@sym("_dispatch_semaphore_wait")
def sem_wait(c): return 0

@sym("_os_log","_os_log_info","_os_log_debug","_os_log_error","_os_log_fault","_os_log_create")
def os_log_(c): return c.fake("oslog")

# ---- C++ ABI: حرّاس المُهيّئات الساكنة ----
@sym("___cxa_guard_acquire")
def cxa_guard_acquire(c):
    a=c.xr(0)
    if a in c.cxx_guards: return 0     # سبق تهيئته
    c.cxx_guards.add(a); return 1      # نفّذ المُهيّئ الآن (أول مرة)
@sym("___cxa_guard_release","___cxa_guard_abort")
def cxa_guard_rel(c): return 0
@sym("___cxa_atexit","_atexit","___cxa_finalize","__cxa_atexit")
def cxa_atexit(c): return 0
@sym("___cxa_allocate_exception")
def cxa_alloc_exc(c): return c.bump(128)
@sym("___cxa_throw","___cxa_begin_catch","___cxa_end_catch")
def cxa_throw(c): raise StopRun("C++ exception")

@sym("_exit","__exit")
def do_exit(c): raise StopRun(f"exit({c.xr(0)})")

@sym("_abort","__stack_chk_fail","_abort_with_payload")
def do_abort(c): raise StopRun("abort/stack_chk_fail")

@sym("__assert_rtn")
def assert_rtn(c): raise StopRun("assertion")
