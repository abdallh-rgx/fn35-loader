#!/usr/bin/env python3
"""FN3.5 loader: iOS-side services.

Mach VM, pthread, GCD dispatch, TLS, ObjC/CF stubs, dyld services,
OpenGL ES / Metal trace layer, sysctl tables, and the native-callback
qsort. Registers implementations into fn35_clib.IMPL.
"""
import os
import struct

from fn35_clib import cfunc, IMPL, _to_int

M64 = struct.Struct("<q")

VM_FLAGS_ANYWHERE = 0x1

# ---- data symbols bound as address cells (not function stubs) -------
DATA_SYMS = {
    "_stdout", "_stderr", "_stdin", "_environ", "___stack_chk_guard",
    "_mach_task_self_", "_stderrp", "_stdoutp", "_stdinp", "___progname",
}

# ---- sysctl values (fake iPhone X / iOS 11.3 device) ------------------
SYSCTL_BY_NAME = {
    "hw.machine": b"iPhone10,4\x00",
    "hw.model": b"D221AP\x00",
    "hw.ncpu": 6,
    "hw.physicalcpu": 6,
    "hw.logicalcpu": 6,
    "hw.byteorder": 1234,
    "hw.pagesize": 16384,
    "hw.cachelinesize": 128,
    "hw.l1icachesize": 65536,
    "hw.l1dcachesize": 65536,
    "hw.l2cachesize": 2097152,
    "hw.l3cachesize": 0,
    "hw.memsize": 3221225472,          # 3 GB
    "hw.memsize_usable": 3221225472,
    "hw.cputype": 0x0100000C,          # ARM64
    "hw.cpusubtype": 0,
    "hw.cpusubtype64": 0,
    "hw.cpu64bit_capable": 1,
    "hw.tbfrequency": 24000000,
    "hw.vectorunit": 0,
    "hw.neon": 1,
    "hw.optional.armv8_1_atomics": 1,
    "hw.optional.floatingpoint": 1,
    "hw.optional.neon_fp16": 1,
    "hw.optional.neon_hp_arith": 1,
    "hw.optional.arc4rnd": 1,
    "kern.ostype": b"Darwin\x00",
    "kern.osrelease": b"17.5.0\x00",
    "kern.osversion": b"15E216\x00",
    "kern.osproductversion": b"11.3\x00",
    "kern.version": b"Darwin Kernel Version 17.5.0: Fri Mar 30 2018; fn35 synthetic\x00",
    "kern.bootargs": b"\x00",
    "kern.hostname": b"fn35\x00",
    "kern.maxproc": 1024,
    "kern.safeboot": 0,
    "kern.securelevel": 0,
    "kern.usrstack64": 0,
    "hw.optional.armv8_crc32": 1,
    "hw.optional.armv8_crypto": 1,
}

_SYSCTL_TUPLE_NAMES = {
    (6, 1): "hw.machine", (6, 2): "hw.model", (6, 3): "hw.ncpu",
    (6, 4): "hw.byteorder", (6, 5): "hw.physmem", (6, 6): "hw.usermem",
    (6, 7): "hw.pagesize", (6, 10): "hw.cachelinesize",
    (6, 11): "hw.cachelinesize", (6, 24): "hw.memsize",
    (6, 25): "hw.memsize_usable", (6, 26): "hw.physicalcpu",
    (6, 27): "hw.logicalcpu", (6, 12): "hw.cputype",
    (6, 13): "hw.cpusubtype", (6, 30): "hw.cputype",
    (6, 100): "hw.optional.armv8_1_atomics",
    (1, 1): "kern.ostype", (1, 2): "kern.osrelease", (1, 3): "kern.osrev",
    (1, 4): "kern.version", (1, 65): "kern.osversion",
}


def sysctl_bytes(name):
    v = SYSCTL_BY_NAME.get(name)
    if v is None:
        return None
    if isinstance(v, int):
        if 0 <= v < 0x100000000:
            return struct.pack("<I", v)
        return struct.pack("<q", v)
    return v


# ====================================================================
# Mach VM + task
# ====================================================================

@cfunc("_vm_allocate", "_mach_vm_allocate")
def _vm_allocate(l, task, out_addr, size, flags):
    addr = l.vm_alloc(size)
    if out_addr:
        l.w64(out_addr, addr)
    l.trace_mach("vm_allocate(size=0x%x, anywhere=%d) = 0x%x"
                 % (size, flags & 1, addr))
    return 0


@cfunc("_vm_deallocate", "_mach_vm_deallocate")
def _vm_deallocate(l, task, addr, size):
    l.trace_mach("vm_deallocate(0x%x, 0x%x) [noop]" % (addr, size))
    return 0


@cfunc("_vm_protect", "_mach_vm_protect", "_vm_remap", "_mach_vm_remap")
def _vm_protect(l, a=0, b=0, c=0, d=0, e=0, f=0, g=0):
    return 0


@cfunc("_vm_read", "_vm_read_overwrite", "_mach_vm_read_overwrite")
def _vm_read(l, task, addr, size, out, outcnt):
    l.wrb(out, l.rdb(addr, size))
    if outcnt:
        l.w64(outcnt, size)
    return 0


@cfunc("_vm_write", "_mach_vm_write")
def _vm_write(l, task, addr, data, size):
    l.wrb(addr, l.rdb(data, size))
    return 0


@cfunc("_vm_copy", "_mach_vm_copy")
def _vm_copy(l, task, src, size, dst):
    l.wrb(dst, l.rdb(src, size))
    return 0


@cfunc("_mach_task_self")
def _mach_task_self(l):
    return l.data_cell("_mach_task_self_")


@cfunc("_mach_thread_self")
def _mach_thread_self(l):
    return l.cur.tid


@cfunc("_host_info", "_host_info64")
def _host_info(l, host, flavor, out, count):
    return 0


@cfunc("_host_page_size")
def _host_page_size(l, host, out):
    l.w64(out, 16384)
    return 0


@cfunc("_mach_absolute_time")
def _mach_absolute_time(l):
    return l.vclock & 0xFFFFFFFFFFFFFFFF


@cfunc("_mach_continuous_time")
def _mach_continuous_time(l):
    return l.vclock & 0xFFFFFFFFFFFFFFFF


@cfunc("_mach_timebase_info")
def _mach_timebase_info(l, info):
    if info:
        l.w32(info, 1)
        l.w32(info + 4, 1)
    return 0


@cfunc("_mach_timebase_info_trap")
def _mach_timebase_info_trap(l, info):
    return _mach_timebase_info(l, info)


@cfunc("_mach_wait_until")
def _mach_wait_until(l, deadline):
    l.block_cur("sleep", None, wake_ns=_to_int(deadline), ret=0)
    return 0


# ====================================================================
# Mach semaphores
# ====================================================================

@cfunc("_semaphore_create")
def _semaphore_create(l, task, out_sem, policy, value):
    h = l.data_cell("sem.%d" % (l.sem_seq), 64)
    l.sem_seq += 1
    l.sems[h] = {"count": value & 0xFFFFFFFF}
    if out_sem:
        l.w64(out_sem, h)
    return 0


@cfunc("_semaphore_destroy")
def _semaphore_destroy(l, task, sem):
    return 0


@cfunc("_semaphore_wait", "_semaphore_wait_signal")
def _semaphore_wait(l, sem):
    obj = l.sems.get(sem)
    if obj is None:
        l.warn("semaphore_wait on unknown 0x%x" % sem)
        return 0
    if obj["count"] > 0:
        obj["count"] -= 1
        return 0
    l.block_cur("sem", sem, ret=0)
    return 0


@cfunc("_semaphore_timedwait")
def _semaphore_timedwait(l, sem, deadline):
    obj = l.sems.get(sem)
    if obj and obj["count"] > 0:
        obj["count"] -= 1
        return 0
    l.block_cur("sem", sem, wake_ns=_to_int(deadline), ret=0)
    return 0


@cfunc("_semaphore_signal", "_semaphore_signal_all")
def _semaphore_signal(l, sem, *a):
    obj = l.sems.get(sem)
    if obj is None:
        return 0
    obj["count"] += 1
    l.wake("sem", sem, one=True)
    return 0


# ====================================================================
# pthread
# ====================================================================

@cfunc("_pthread_create")
def _pthread_create(l, out_tid, attr, start, arg):
    if l.thread_count() >= 96:
        l.warn("pthread_create: thread cap hit, dropping thread")
        if out_tid:
            l.w64(out_tid, 0)
        return 0
    t = l.new_thread(start, arg, name="pthread")
    if out_tid:
        l.w64(out_tid, t.tid)
    l.trace_thread("pthread_create(start=0x%x arg=0x%x) tid=%d"
                   % (start, arg, t.tid))
    return 0


@cfunc("_pthread_exit")
def _pthread_exit(l, retval):
    l.cur.retval = retval
    l.thread_done(l.cur)
    return 0


@cfunc("_pthread_join")
def _pthread_join(l, tid, retval_ptr):
    t = l.threads.get(tid)
    if t is None:
        return 0
    if t.state == "done":
        if retval_ptr:
            l.w64(retval_ptr, t.retval or 0)
        return 0
    l.block_cur("join", tid, extra=retval_ptr, ret=0)
    return 0


@cfunc("_pthread_timedjoin_np")
def _pthread_timedjoin(l, tid, retval_ptr, abstime):
    return _pthread_join(l, tid, retval_ptr)


@cfunc("_pthread_detach", "_pthread_attr_init", "_pthread_attr_destroy",
       "_pthread_attr_setdetachstate", "_pthread_attr_setstacksize",
       "_pthread_attr_getstacksize", "_pthread_attr_setschedparam",
       "_pthread_attr_getschedparam", "_pthread_attr_setinheritsched",
       "_pthread_attr_setscope", "_pthread_attr_setguardsize",
       "_pthread_getattr_default_np", "_pthread_setattr_default_np",
       "_pthread_setname_np", "_pthread_cancel", "_pthread_kill",
       "_pthread_cleanup_push", "_pthread_cleanup_pop",
       "_pthread_sigmask", "_pthread_mach_thread_np",
       "_pthread_threadid_np", "_pthread_testcancel")
def _pthread_stub(l, a=0, b=0, c=0, d=0):
    return 0


@cfunc("_pthread_self")
def _pthread_self(l):
    return l.cur.tid


@cfunc("_pthread_is_threaded_np")
def _pthread_is_threaded_np(l):
    return 1


@cfunc("_pthread_main_np")
def _pthread_main_np(l):
    return 1 if l.cur.name == "main" else 0


@cfunc("_pthread_mutex_init", "_pthread_mutexattr_init",
       "_pthread_mutexattr_destroy", "_pthread_mutexattr_settype",
       "_pthread_mutexattr_setpshared", "_pthread_mutexattr_setpolicy")
def _pthread_stub2(l, a=0, b=0, c=0):
    return 0


@cfunc("_pthread_mutex_destroy", "_pthread_cond_destroy")
def _pthread_stub3(l, a=0):
    return 0


def _mutex(l, m):
    st = l.mutexes.get(m)
    if st is None:
        st = l.mutexes[m] = {"owner": None, "count": 0}
    return st


@cfunc("_pthread_mutex_lock", "_pthread_mutex_lock_slow")
def _pthread_mutex_lock(l, m):
    st = _mutex(l, m)
    if st["owner"] is None or st["owner"] == l.cur:
        st["owner"] = l.cur
        st["count"] += 1
        return 0
    l.block_cur("mutex", m, ret=0)
    return 0


@cfunc("_pthread_mutex_unlock", "_pthread_mutex_unlock_slow")
def _pthread_mutex_unlock(l, m):
    st = _mutex(l, m)
    st["count"] -= 1
    if st["count"] <= 0:
        st["count"] = 0
        st["owner"] = None
        l.wake("mutex", m, one=True)
    return 0


@cfunc("_pthread_mutex_trylock")
def _pthread_mutex_trylock(l, m):
    st = _mutex(l, m)
    if st["owner"] is None or st["owner"] == l.cur:
        st["owner"] = l.cur
        st["count"] += 1
        return 0
    return 16  # EBUSY


@cfunc("_pthread_cond_init", "_pthread_condattr_init")
def _cond_stub(l, a=0, b=0):
    return 0


@cfunc("_pthread_cond_wait")
def _pthread_cond_wait(l, cond, m):
    # unlock, sleep on cond, relock on wake
    st = _mutex(l, m)
    st["count"] = 0
    st["owner"] = None
    l.wake("mutex", m, one=True)
    l.block_cur("cond", cond, extra=m, ret=0)
    return 0


@cfunc("_pthread_cond_timedwait")
def _pthread_cond_timedwait(l, cond, m, abstime):
    st = _mutex(l, m)
    st["count"] = 0
    st["owner"] = None
    l.wake("mutex", m, one=True)
    # abstime = timespec{sec, nsec} (absolute, vclock-based epoch)
    wake = None
    if abstime:
        try:
            sec = l.rd64(abstime)
            nsec = l.rd64(abstime + 8)
            wake = (sec & 0x7FFFFFFFFFFFFFFF) * 1000000000 + nsec
        except Exception:
            wake = None
    l.block_cur("cond", cond, extra=m, wake_ns=wake, ret=0)
    return 0


@cfunc("_pthread_cond_signal")
def _pthread_cond_signal(l, cond):
    l.wake("cond", cond, one=True)
    return 0


@cfunc("_pthread_cond_broadcast")
def _pthread_cond_broadcast(l, cond):
    l.wake("cond", cond, one=False)
    return 0


@cfunc("_pthread_once")
def _pthread_once(l, ctrl, routine):
    if l.rd64(ctrl) == 0:
        l.w64(ctrl, 1)
        def drv():
            yield ("call", routine, ())
        l.py_call(drv(), ret=0)
    return 0


@cfunc("_pthread_key_create")
def _pthread_key_create(l, out_key, dtor):
    k = l.tls_seq
    l.tls_seq += 1
    if out_key:
        l.w32(out_key, k)
    return 0


@cfunc("_pthread_key_delete")
def _pthread_key_delete(l, key):
    return 0


@cfunc("_pthread_getspecific")
def _pthread_getspecific(l, key):
    return l.cur.specific.get(key, 0)


@cfunc("_pthread_setspecific")
def _pthread_setspecific(l, key, val):
    l.cur.specific[key] = val
    return 0


# ====================================================================
# GCD dispatch
# ====================================================================

@cfunc("_dispatch_async")
def _dispatch_async(l, q, block):
    invoke = l.rd64(block + 16)
    t = l.new_thread(invoke, block, name="dispatch_async")
    l.trace_thread("dispatch_async(q=0x%x block=0x%x) -> tid %d"
                   % (q, block, t.tid))
    return 0


@cfunc("_dispatch_async_f")
def _dispatch_async_f(l, q, ctx, fn):
    t = l.new_thread(fn, ctx, name="dispatch_async_f")
    return 0


@cfunc("_dispatch_sync_f")
def _dispatch_sync_f(l, q, ctx, fn):
    def drv():
        yield ("call", fn, (ctx,))
    l.py_call(drv(), ret=0)
    return 0


@cfunc("_dispatch_after")
def _dispatch_after(l, when, q, block):
    invoke = l.rd64(block + 16)
    l.new_thread(invoke, block, name="dispatch_after")
    return 0


@cfunc("_dispatch_after_f")
def _dispatch_after_f(l, when, q, ctx, fn):
    l.new_thread(fn, ctx, name="dispatch_after_f")
    return 0


@cfunc("_dispatch_once", "_dispatch_once_f")
def _dispatch_once(l, ptr, a=0):
    if l.rd64(ptr) == 0:
        l.w64(ptr, -1 & 0xFFFFFFFFFFFFFFFF)
        if a:
            def drv():
                yield ("call", a, ())
            l.py_call(drv(), ret=0)
    return 0


@cfunc("_dispatch_get_main_queue")
def _dispatch_get_main_queue(l):
    return l.data_cell("q.main")


@cfunc("_dispatch_get_global_queue")
def _dispatch_get_global_queue(l, prio, flags):
    return l.data_cell("q.global")


@cfunc("_dispatch_queue_create")
def _dispatch_queue_create(l, label, attr):
    return l.data_cell("q.%s" % (l.gcstr(label) if label else "?"))


@cfunc("_dispatch_retain", "_dispatch_release", "_dispatch_suspend",
       "_dispatch_resume", "_dispatch_set_target_queue",
       "_dispatch_set_finalizer_f", "_dispatch_async_and_wait_f",
       "_dispatch_barrier_async_f", "_dispatch_group_async_f")
def _dispatch_stub(l, a=0, b=0, c=0):
    return 0


@cfunc("_dispatch_main")
def _dispatch_main(l):
    l.console("dispatch_main() -- parking main thread")
    l.block_cur("forever", "dispatch_main", ret=0)
    return 0


@cfunc("_dispatch_group_create")
def _dispatch_group_create(l):
    return l.data_cell("group")


@cfunc("_dispatch_group_wait")
def _dispatch_group_wait(l, g, timeout):
    return 0


@cfunc("_dispatch_semaphore_create")
def _dispatch_semaphore_create(l, value):
    h = l.data_cell("dsem.%d" % l.sem_seq, 64)
    l.sem_seq += 1
    l.sems[h] = {"count": value & 0xFFFFFFFF}
    return h


@cfunc("_dispatch_semaphore_wait")
def _dispatch_semaphore_wait(l, sem, timeout):
    return _cfunc_sem_wait(l, sem)


def _cfunc_sem_wait(l, sem):
    obj = l.sems.get(sem)
    if obj and obj["count"] > 0:
        obj["count"] -= 1
        return 0
    l.block_cur("sem", sem, ret=0)
    return 0


@cfunc("_dispatch_semaphore_signal")
def _dispatch_semaphore_signal(l, sem):
    obj = l.sems.get(sem)
    if obj:
        obj["count"] += 1
    l.wake("sem", sem, one=True)
    return 0


# ====================================================================
# TLS (thread-local variables)
# ====================================================================

@cfunc("__tlv_get_addr", "_tlv_bootstrap")
def _tlv_get_addr(l, desc):
    key = l.rd64(desc + 8)
    if key == 0:
        key = desc
        l.w64(desc + 8, key)
    offset = l.rd64(desc + 16)
    t = l.cur
    base = t.tlv_bases.get(key)
    if base is None:
        tlv_base, tlv_size = l.tlv_template
        base = l.heap_alloc(max(tlv_size, 16), zero=True)
        if tlv_base and tlv_size:
            try:
                l.wrb(base, l.rdb(tlv_base, tlv_size))
            except Exception:
                pass
        t.tlv_bases[key] = base
        l.trace_mach("tlv: thread %d new block 0x%x (tmpl 0x%x +0x%x)"
                     % (t.tid, base, tlv_base, tlv_size))
    return base + offset


# ====================================================================
# dyld services
# ====================================================================

@cfunc("_NSGetExecutablePath")
def _nsgetexecpath(l, buf, buflen):
    p = l.exe_path.encode() + b"\x00"
    need = len(p)
    cur = l.rd32(buflen)
    if buf and cur >= need:
        l.wrb(buf, p)
        l.w32(buflen, need)
        return 0
    l.w32(buflen, need)
    return 34  # ERANGE


@cfunc("_dyld_image_count")
def _dyld_image_count(l):
    return 1


@cfunc("_dyld_get_image_name")
def _dyld_get_image_name(l, idx):
    return l.cstring_cell("image.name", l.exe_path) if idx == 0 else 0


@cfunc("_dyld_get_image_header")
def _dyld_get_image_header(l, idx):
    return l.macho.text_vm() if idx == 0 else 0


@cfunc("_dyld_get_image_vmaddr_slide")
def _dyld_get_image_vmaddr_slide(l, idx):
    return 0


@cfunc("_dyld_register_func_add_remove_image", "_dyld_register_func_late",
       "_dyld_register_thread_helpers", "__dyld_register_func_lookup")
def _dyld_stub(l, a=0, b=0):
    return 0


@cfunc("_dlopen")
def _dlopen(l, path, mode):
    return l.data_cell("dl.handle")


@cfunc("_dlsym")
def _dlsym(l, handle, name):
    return l.get_stub(l.gcstr(name))


@cfunc("_dladdr")
def _dladdr(l, addr, info):
    if info:
        l.w64(info + 0, l.macho.text_vm())
        l.w64(info + 8, l.cstring_cell("dl.fname", l.exe_path))
        name, saddr = l.nearest_symbol(addr)
        l.w64(info + 16, l.cstring_cell("dl.sname", name) if name else 0)
        l.w64(info + 24, saddr or 0)
    return 1


@cfunc("_getsectdata", "_getsectiondata", "_getsegmentdata")
def _getsectdata(l, seg, sect, out_size):
    sn = l.gcstr(seg, maxlen=16)
    cn = l.gcstr(sect, maxlen=16)
    for s in l.macho.sections:
        if s.seg == sn and s.name == cn:
            if out_size:
                l.w64(out_size, s.size)
            return s.addr
    if out_size:
        l.w64(out_size, 0)
    return 0


# ====================================================================
# ObjC / CoreFoundation (trace-grade stubs)
# ====================================================================

@cfunc("_objc_msgSend", "_objc_msgSendSuper", "_objc_msgSend_stret")
def _objc_msgsend(l, recv, sel):
    s = l.gcstr(sel) if sel else "?"
    l.trace_objc("%s obj=0x%x sel=%s" % ("msgSend", recv, s))
    return 0


@cfunc("_objc_getClass", "_objc_lookUpClass", "_objc_getRequiredClass",
       "_objc_allocateClassPair")
def _objc_getclass(l, name):
    n = l.gcstr(name) if name else "?"
    l.trace_objc("getClass(%s) -> nil" % n)
    return 0


@cfunc("_objc_registerClassPair", "_objc_disposeClassPair",
       "_objc_setAssociatedObject", "_objc_setProperty",
       "_objc_getProperty", "_objc_copyClassList", "_objc_getClassList",
       "_objc_getMetaClass", "_objc_getProtocol",
       "_objc_copyProtocolList", "_objc_addProtocol",
       "_class_getName", "_class_getInstanceSize", "_class_getSuperclass",
       "_class_respondsToSelector", "_class_createInstance",
       "_class_addMethod", "_class_addIvar", "_class_addProtocol",
       "_object_getClass", "_object_setClass", "_object_getIvar",
       "_object_setIvar", "_method_getName", "_method_getImplementation",
       "_method_setImplementation", "_sel_isEqual", "_sel_getName",
       "_objc_enumerationMutation", "_objc_autorelease",
       "_objc_autoreleasePoolPush", "_objc_autoreleasePoolPop",
       "_objc_retain", "_objc_retainAutorelease",
       "_objc_retainAutoreleasedReturnValue",
       "_objc_storeStrong", "_objc_release", "_objc_terminate",
       "_objc_sync_enter", "_objc_sync_exit", "_objc_copyClassList",
       "_objc_getClassList", "_objc_msgSendSuper2",
       "_objc_beginMessage", "_objc_endMessage")
def _objc_stub(l, a=0, b=0, c=0, d=0):
    return 0


@cfunc("_sel_registerName")
def _sel_registername(l, name):
    return l.cstring_cell("sel." + (l.gcstr(name) if name else ""))


@cfunc("_CFStringCreateWithCString", "_CFStringCreateWithCStringNoCopy",
       "_CFStringCreateMutable", "_CFStringCreateCopy")
def _cf_str_create(l, alloc, *a):
    h = l.data_cell("cfstr.%d" % l.cf_seq, 64)
    l.cf_seq += 1
    return h


@cfunc("_CFStringGetCString")
def _CFStringGetCString(l, s, buf, size, enc):
    return 0


@cfunc("_CFStringGetCStringPtr")
def _CFStringGetCStringPtr(l, s, enc):
    return 0


@cfunc("_CFStringCreateWithFormat")
def _CFStringCreateWithFormat(l, alloc, opts, fmt):
    return l.data_cell("cfstr.%d" % l.cf_seq, 64)


@cfunc("_CFAbsoluteTimeGetCurrent")
def _cfabs_time(l):
    return ("d0", l.vclock / 1e9)


@cfunc("_CFBundleGetMainBundle")
def _cfbundle(l):
    return l.data_cell("cfbundle.main")


@cfunc("_CFBundleCopyBundleURL", "_CFBundleCopyResourcesDirectoryURL",
       "_CFBundleGetValueForInfoDictionaryKey")
def _cfbundle2(l, a=0, b=0):
    return 0


@cfunc("_CFRelease", "_CFRetain", "_CFShow", "_CFAutorelease")
def _cf_stub(l, a=0):
    return 0


@cfunc("_CFUUIDCreate", "_CFUUIDCreateString")
def _cfuuid(l, a=0, b=0):
    return l.data_cell("cfuuid.%d" % l.cf_seq, 64)


@cfunc("_CFNumberCreate")
def _cfnumber(l, alloc, theType, valuePtr):
    return l.data_cell("cfnum.%d" % l.cf_seq, 64)


@cfunc("_CFDictionaryCreate", "_CFDictionaryCreateMutable",
       "_CFDictionaryCreateCopy", "_CFArrayCreateMutable",
       "_CFArrayCreate", "_CFSetCreateMutable")
def _cfcoll(l, *a):
    return l.data_cell("cfcoll.%d" % l.cf_seq, 64)


@cfunc("_CFDictionaryGetValue", "_CFDictionaryAddValue",
       "_CFDictionarySetValue", "_CFArrayGetValueAtIndex",
       "_CFArrayAppendValue", "_CFArrayGetCount", "_CFDictionaryGetCount")
def _cf_value(l, *a):
    return 0


@cfunc("_CFNotificationCenterGetLocalCenter",
       "_CFNotificationCenterGetDistributedCenter")
def _cfnc(l):
    return l.data_cell("cfnc")


# ====================================================================
# OpenGL ES / Metal trace layer
# ====================================================================

def _gl(l, name, x0=0, x1=0, x2=0, x3=0, x4=0, x5=0, x6=0, x7=0):
    l.trace_gl(name, (x0, x1, x2, x3, x4, x5, x6, x7))
    return 0


def _reg_gl():
    names = [
        "glClearColor", "glClear", "glClearDepthf", "glViewport",
        "glCreateShader", "glShaderSource", "glCompileShader",
        "glGetShaderiv", "glGetShaderInfoLog", "glDeleteShader",
        "glCreateProgram", "glAttachShader", "glLinkProgram",
        "glGetProgramiv", "glGetProgramInfoLog", "glDeleteProgram",
        "glUseProgram", "glGenBuffers", "glBindBuffer", "glBufferData",
        "glBufferSubData", "glDeleteBuffers", "glMapBufferRange",
        "glUnmapBuffer", "glGenVertexArrays", "glBindVertexArray",
        "glVertexAttribPointer", "glEnableVertexAttribArray",
        "glDisableVertexAttribArray", "glDrawArrays", "glDrawElements",
        "glEnable", "glDisable", "glBlendFunc", "glDepthFunc",
        "glCullFace", "glFrontFace", "glFinish", "glFlush",
        "glGetString", "glGetIntegerv", "glPixelStorei", "glReadPixels",
        "glGenTextures", "glBindTexture", "glTexImage2D",
        "glTexSubImage2D", "glTexParameteri", "glDeleteTextures",
        "glActiveTexture", "glGenFramebuffers", "glBindFramebuffer",
        "glFramebufferTexture2D", "glCheckFramebufferStatus",
        "glDeleteFramebuffers", "glGenRenderbuffers",
        "glBindRenderbuffer", "glRenderbufferStorage",
        "glFramebufferRenderbuffer", "glDeleteRenderbuffers",
        "glUniform1f", "glUniform2f", "glUniform3f", "glUniform4f",
        "glUniform1i", "glUniformMatrix4fv", "glGetUniformLocation",
        "glGetAttribLocation", "glScissor", "glStencilFunc",
        "glColorMask", "glDepthMask", "glLineWidth", "glPolygonOffset",
        "glGenerateMipmap", "glGetError", "glIsEnabled", "glGetStringi",
        "glInvalidateFramebuffer", "glDispatchCompute",
        "glBindBufferBase", "glUniformBlockBinding", "glFenceSync",
        "glClientWaitSync", "glDeleteSync", "glBlitFramebuffer",
    ]
    for n in names:
        IMPL["_" + n] = (lambda nm: (lambda l, *a: _gl(l, nm, *a)))(n)


_reg_gl()


@cfunc("_glGetError")
def _glGetError(l):
    return 0  # GL_NO_ERROR


@cfunc("_glGetString", "_glGetStringi")
def _glGetString(l, name, index=0):
    vals = {
        0x1F00: "", 0x1F01: "Apple Software Renderer (fn35)",
        0x1F02: "OpenGL ES 3.0 fn35", 0x1F03: "fn35",
        0x8B8C: "OpenGL ES GLSL ES 3.00 fn35",
    }
    return l.cstring_cell("glstr", vals.get(name, ""))


@cfunc("_glGetStringi")
def _glGetStringi(l, name, index):
    return l.cstring_cell("glstr", "")


@cfunc("_MTLCreateSystemDefaultDevice")
def _mtl_device(l):
    l.trace_gl("MTLCreateSystemDefaultDevice", (0,))
    return 0  # nil device -> UE4 logs failure


# ====================================================================
# native-callback qsort
# ====================================================================

def _qsort_native(l, base, n, size, compar):
    def drv():
        arr = [base + i * size for i in range(_to_int(n))]
        for i in range(1, len(arr)):
            j = i
            while j > 0:
                r = yield ("call", compar, (arr[j - 1], arr[j]))
                if r <= 0:
                    break
                a1 = l.rdb(arr[j - 1], size)
                a2 = l.rdb(arr[j], size)
                l.wrb(arr[j - 1], a2)
                l.wrb(arr[j], a1)
                arr[j - 1], arr[j] = base + (j - 1) * size, base + j * size
                j -= 1

    l.py_call(drv(), ret=0)
    return 0


# ====================================================================
# kernel-ish imports discovered during boot (added iteratively)
# ====================================================================

@cfunc("_mach_host_self")
def _mach_host_self(l):
    return l.data_cell("mach.host_self", 64)


@cfunc("_host_statistics", "_host_statistics64", "_host_processor_info")
def _host_statistics(l, host, flavor, info, count):
    # flavor 2 = HOST_BASIC_INFO; fill a real struct (drives UE4's
    # memory model and page-size computations)
    try:
        if flavor == 2 and info:
            # NOTE: UE4's FMallocBinned2 pool sizing derives from
            # max_cpus * PageSize; needs >= 8 MB to build a real hash
            # table. Core counts used by the engine itself come from
            # sysctl(hw.ncpu) instead, so this stays a boot parameter.
            data = struct.pack(
                "<iiIiiiiiiI Q",
                512,            # max_cpus (pool sizing)
                512,            # avail_cpus
                0xC0000000,     # memory_size (3 GB)
                0x0100000C,     # cpu_type (ARM64)
                0,              # cpu_subtype
                0,              # thread_toggle
                6,              # physical_cpu
                6,              # physical_cpu_max
                6,              # logical_cpu
                6,              # logical_cpu_max
                3221225472)     # max_mem
            l.wrb(info, data)
            if count:
                l.w32(count, 11)     # HOST_BASIC_INFO_COUNT
        elif flavor == 1 and info:  # HOST_LOAD_INFO
            data = struct.pack("<iiiiii", 1024, 512, 0, 0, 0, 0)
            l.wrb(info, data)
            if count:
                l.w32(count, 6)
    except Exception:
        pass
    if count and flavor not in (1, 2):
        l.w32(count, 8)
    return 0


@cfunc("_task_info")
def _task_info_fn(l, task, flavor, info, count):
    # flavor 20 = MACH_TASK_BASIC_INFO: virtual/resident sizes drive
    # UE4's FMallocBinned2 configuration
    import os as _os
    if _os.environ.get("FN35_DEBUG_HOOKS"):
        try:
            slot_v = l.rd64(0x1037c1bd8)
            cell_v = l.rd64(slot_v) if slot_v else -1
            l.console("[dbg] task_info(task=0x%x flavor=%d info=0x%x cnt=0x%x "
                      "| GOT[0x1037c1bd8]=0x%x -> [x8]=0x%x)"
                      % (task, flavor, info, count, slot_v, cell_v))
        except Exception as e:
            l.console("[dbg] task_info dbg failed %r" % (e,))
    try:
        if flavor == 20 and info:
            data = struct.pack(
                "<QQii" + "q" * 6,
                0xC0000000,     # virtual_size (3 GB)
                0x28000000,     # resident_size (640 MB)
                0, 0,
                0, 0, 0, 0, 0, 0)
            l.wrb(info, data)
            if count:
                l.w32(count, 12)
        elif flavor == 5 and info:   # TASK_BASIC_INFO
            data = struct.pack("<QQiiiQQi", 0xC0000000, 0x28000000,
                               0, 0, 0, 0, 0, 0)
            l.wrb(info, data)
            if count:
                l.w32(count, 10)
        elif flavor == 22 and info:  # TASK_VM_INFO (subset)
            data = struct.pack("<" + "Q" * 12)
            l.wrb(info, data[:96])
            if count:
                l.w32(count, 24)
    except Exception:
        pass
    return 0


@cfunc("_sysctl")
def _sysctl_fn(l, namep, count, oldp, oldlenp, newp=0, newlen=0):
    return l.sys_sysctl(namep, count, oldp, oldlenp)


@cfunc("_sysctlbyname")
def _sysctlbyname_fn(l, name, oldp, oldlenp, newp=0, newlen=0):
    return l.sys_sysctlbyname(l.gcstr(name), oldp, oldlenp)


@cfunc("_mmap")
def _mmap_fn(l, addr, length, prot, flags, fd, offset):
    p = l.mmap_alloc(length)
    if os.environ.get("FN35_LOG_MMAP"):
        pc = l.reg_lr() if hasattr(l, "reg_lr") else 0
        nm, sa = l.nearest_symbol(pc) if pc else (None, 0)
        l.console("[mmap] len=0x%x -> 0x%x caller=%s+0x%x"
                  % (length, p, (nm or "?")[:50], pc - (sa or 0)))
    return p


@cfunc("_munmap", "_msync", "_madvise", "_mlock", "_munlock", "_mprotect")
def _mm_stub(l, a=0, b=0, c=0, d=0):
    return 0


@cfunc("_wcstombs", "_wcstombs_l", "__wcstombs_l", "_wcstombs_s")
def _wcstombs_fn(l, dst, src, maxn, a=0, b=0):
    if not dst or not maxn:
        return 0
    out = b""
    if src:
        try:
            i = 0
            while i < maxn:
                ch = l.rd16(src + 2 * i)
                if ch == 0:
                    break
                out += chr(ch).encode("utf-8", "replace")
                i += 1
        except Exception:
            pass
    data = out[:maxn - 1] + b"\x00"
    l.wrb(dst, data)
    return len(data) - 1


@cfunc("_wcstold", "_wcstold_l", "_wcstoll", "_wcstoll_l", "_wcstol",
       "_wcstol_l", "_wcstoul", "_wcstoull")
def _wcstoX(l, s, endp, base=10):
    out = ""
    if s:
        try:
            i = 0
            while i < 256:
                ch = l.rd16(s + 2 * i)
                if ch == 0:
                    break
                out += chr(ch)
                i += 1
        except Exception:
            pass
    import re as _re
    m = _re.match(r"\s*[+-]?[0-9a-fA-F]+", out)
    v = int(m.group(0), base if base else 10) if m else 0
    if endp:
        l.w64(endp, s + (2 * len(m.group(0)) if m else 0))
    return v & 0xFFFFFFFFFFFFFFFF


@cfunc("_abort")
def _abort_fn(l):
    lr = l.reg_lr()
    name, saddr = l.nearest_symbol(lr)
    l.console("[abort] caller lr=0x%x (%s+0x%x) -- last stubs:"
               % (lr, name or "?", lr - (saddr or 0)))
    for ent in list(l.stub_ring)[-12:]:
        l.console("   %s" % (ent,))
    l.fatal("abort() called from 0x%x (%s+0x%x)"
            % (lr, name or "?", lr - (saddr or 0)))
    return 0


@cfunc("___assert_rtn", "___assert_fail")
def _assert_rtn(l, func, file, line, expr):
    try:
        fn = l.gcstr(func) if func else "?"
        fl = l.gcstr(file) if file else "?"
        ex = l.gcstr(expr) if expr else "?"
    except Exception:
        fn = fl = ex = "?"
    l.fatal("assert(%s) in %s at %s:%d"
            % (ex, fn, fl, line & 0xFFFFFFFF))
    return 0


@cfunc("___stack_chk_fail")
def _stack_chk_fail(l):
    l.fatal("__stack_chk_fail: stack canary smashed")
    return 0


@cfunc("___cxa_throw", "___cxa_rethrow")
def _cxa_throw(l, obj, typeinfo, dest):
    pc = l.reg_pc()
    name, saddr = l.nearest_symbol(pc)
    l.fatal("C++ exception thrown at %s+0x%x (obj=0x%x)"
            % (name or "?", pc - (saddr or 0), obj))
    return 0


@cfunc("___cxa_allocate_exception")
def _cxa_alloc_exc(l, size):
    return l.heap_alloc(size)


@cfunc("___cxa_free_exception")
def _cxa_free_exc(l, ptr):
    return 0
