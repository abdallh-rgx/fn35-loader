#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""fnloader/objc.py — محاكي وقت Objective-C: بحث طريقة حقيقي + نداء IMP حقيقي"""
import struct
from impls import sym, StopRun

class ObjCShim:
    def __init__(s, mo):
        s.real={}          # عنوان الصف الحقيقي ← اسمه (من __objc_classlist)
        s.by_name={}
        cl=mo.sections.get("__objc_classlist")
        if cl:
            for a in range(cl.addr, cl.addr+cl.size, 8):
                p=mo.read_u64(a)
                if p:
                    nm=s.file_ro_name(mo,p)
                    if nm:
                        s.real[p]=nm; s.by_name[nm]=p
        s.cache={}        # (صف، محدد) ← imp

    @staticmethod
    def file_ro_name(mo,cls):
        try:
            bits=mo.read_u64(cls+0x20)
            if not bits: return None
            ro=bits & ~0x7
            np_=mo.read_u64(ro+24)
            return mo.read_cstr(np_) if np_ else None
        except Exception:
            return None

    def name_of(s,c,ptr):
        if ptr in s.real: return s.real[ptr]
        return c.fakes.get(ptr)

    def lookup_imp(s,c,receiver,sel):
        """بحث طريقة حقيقي عبر سلسلة الوراثة — يرجع عنوان IMP الحقيقي إن وُجد"""
        try:
            start=c.r64(receiver)          # isa (صف الكائن، أو metaclass إن كان المستقبل صفًا)
            cur=start
            for _ in range(8):
                if not cur or cur==receiver: return None
                key=(cur,sel)
                if key in s.cache: return s.cache[key]
                imp=s._method_in(c,cur,sel)
                if imp:
                    s.cache[key]=imp
                    return imp
                cur=c.r64(cur+8)            # superclass
                if not cur: return None
        except Exception:
            return None
        return None

    def _method_in(s,c,cls,sel):
        try:
            bits=c.r64(cls+0x20)
            if not bits: return None
            ro=bits & ~0x7
            ml=c.r64(ro+32)
            if not ml: return None
            hdr=c.rb(ml,8)
            if not hdr or len(hdr)<8: return None
            entsz,count=struct.unpack("<II",hdr)
            es=entsz & 0xFFFF
            if es<24 or es>128 or count>16384: return None
            base=ml+8
            for i in range(count):
                o=base+i*es
                namep=c.r64(o)
                if namep and c.cstr(namep)==sel:
                    return c.r64(o+16)
        except Exception:
            return None
        return None

    def alloc(s,c,cls):
        try:
            bits=c.r64(cls+0x20)
            ro=(bits & ~0x7) if bits else 0
            size=c.r32(ro+8) if ro else 0
            size=max(size,16)
        except Exception:
            size=64
        p=c.bump((size+15)&~15)
        c.w64(p,cls)
        return p

    @staticmethod
    def cfstring(c,ptr):
        try:
            data=c.r64(ptr+16); ln=c.r64(ptr+24)
            if data and 0<ln<8192:
                return c.rb(data,ln).decode("utf-8","replace")
        except Exception:
            return None
        return None

SYMS={}

def _s():
    def deco(fn):
        SYMS[fn.__name__]=fn; return fn
    return deco

# ============ قلب النظام: objc_msgSend ============
def _objc_msgSend(c):
    recv,selp=c.xr(0),c.xr(1)
    sel=c.cstr(selp) if selp else None
    if recv and sel:
        imp=c.shim.lookup_imp(c,recv,sel)
        if imp:
            c.count("objc:"+sel)
            c.set_pc(imp)          # قفزة لتنفيذ كود اللعبة الحقيقي (LR كما هو)
            return c.JUMP
    if sel in ("retain","release","autorelease","self","class","copy",
               "mutableCopy","description","debugDescription","hash"):
        return recv or c.fake("obj")
    if sel in ("alloc","new","allocWithZone:","allocWithZone"):
        if recv in c.shim.real: return c.shim.alloc(c,recv)
        return c.fake("obj")
    if sel=="length":
        st=ObjCShim.cfstring(c,recv) if recv else None
        return len(st) if st is not None else 16
    if sel in ("UTF8String","cString","fileSystemRepresentation"):
        st=ObjCShim.cfstring(c,recv) if recv else None
        return c.intern(st or "") if st is not None else c.fake("cstr")
    if sel in ("bundlePath","resourcePath","executablePath","path"):
        return c.cfstr(c.ROOT)
    if sel in ("integerValue","intValue","uintValue","count"):
        return 1 if sel!="count" else 0
    if sel in ("boolValue","isProxy","isEqual:","respondsToSelector:"):
        return 1
    if sel in ("objectForKey:","valueForKey:","firstObject","lastObject"):
        return 0
    nm=c.shim.name_of(c,recv) if recv else None
    st=ObjCShim.cfstring(c,recv) if (recv and not nm) else None
    who=repr(st) if st else (nm or hex(recv or 0))
    c.count("objc-fake:"+str(sel))
    c.log(f"msgSend({who}, {sel!r}) → كائن وهمي")
    return c.fake("obj")

def _objc_getClass(c):
    nm=c.cstr(c.xr(0)) or "?"
    if nm in c.shim.by_name: return c.shim.by_name[nm]
    p=c.fake("class:"+nm)
    c.shim.by_name.setdefault(nm,p)
    return p

def _class_getName(c):
    nm=c.shim.name_of(c,c.xr(0))
    return c.intern(nm or "<class>") if nm else 0

def _sel_registerName(c):
    return c.intern(c.cstr(c.xr(0)) or "")

def _sel_getName(c): return c.xr(0)
def _object_getClass(c): return c.r64(c.xr(0)) or c.fake("meta")
def _objc_retain(c): return c.xr(0)
def _objc_release(c): return 0
def _objc_autorelease(c): return c.xr(0)
def _objc_autoreleasePoolPush(c): return c.fake("pool")
def _objc_autoreleasePoolPop(c): return 0
def _objc_copyClassList(c):
    if c.xr(1): c.w64(c.xr(1),0)
    return 0
def _objc_allocateClassPair(c): return c.fake("class:new")
def _objc_registerClassPair(c): return 0
def _class_getSuperclass(c): return c.r64(c.xr(0)+8) or 0
def _class_getInstanceMethod(c): return 0
def _class_getClassMethod(c): return 0
def _class_addMethod(c): return 1
def _objc_sync_enter(c): return 0
def _objc_sync_exit(c): return 0
def _objc_setProperty(c): return 0
def _objc_enumerationMutation(c): return 0
def _objc_exception_throw(c):
    raise StopRun("objc_exception_throw")
def _objc_terminate(c):
    raise StopRun("objc_terminate")

# CoreFoundation
def _CFStringCreateWithCString(c):
    st=c.cstr(c.xr(1)) or ""
    p=c.fake("cfstr")
    c.w64(p+16,c.intern(st)); c.w64(p+24,len(st))
    return p
def _CFStringCreateCopy(c): return c.xr(0)
def _CFStringGetCString(c):
    st=ObjCShim.cfstring(c,c.xr(0)) or ""
    buf,maxlen=c.xr(1),c.xr(2)
    if buf:
        b=st.encode("utf-8")[:max(0,maxlen-1)]+b"\0"
        c.wb(buf,b)
    return 1
def _CFStringGetLength(c):
    st=ObjCShim.cfstring(c,c.xr(0))
    return len(st) if st is not None else 0
def _CFStringGetCStringPtr(c):
    st=ObjCShim.cfstring(c,c.xr(0))
    return c.intern(st) if st is not None else 0
def _CFRelease(c): return 0
def _CFRetain(c): return c.xr(0)
def _CFAllocatorGetDefault(c): return c.fake("alloc")
def _CFAutorelease(c): return c.xr(0)
def _CFRunLoopGetCurrent(c): return c.fake("runloop")
def _CFRunLoopGetMain(c): return c.fake("runloop")
def _CFRunLoopRun(c):
    c.log("CFRunLoopRun (توقف اللوب)")
    return 0
def _CFRunLoopRunInMode(c):
    return 0
def _CFRunLoopAddSource(c): return 0
def _CFRunLoopStop(c): return 0
def _CFRunLoopWakeUp(c): return 0
def _CFAbsoluteTimeGetCurrent(c):
    import time as _t
    return int(_t.time())
def _CFBundleGetMainBundle(c): return c.fake("bundle")
def _bundlepath(c):
    return c.cfstr(c.ROOT)
def _CFBundleGetValueForInfoDictionaryKey(c): return c.fake("value")
def _CFBundleCopyBundleURL(c): return c.cfstr(c.ROOT)
def _CFURLCopyFileSystemPath(c): return c.cfstr(c.ROOT)
def _CFStringCreateFromExternalRepresentation(c): return c.fake("cfstr")
def _CFStringConvertEncodingToNSStringEncoding(c): return 4
def _CFDataCreate(c): return c.fake("cfdata")
def _CFDictionaryGetValue(c): return 0
def _CFDictionaryAddValue(c): return 0
def _CFArrayGetCount(c): return 0
def _CGColorSpaceCreateDeviceRGB(c): return c.fake("cgcolorspace")
def _CGColorSpaceCreateWithName(c): return c.fake("cgcolorspace")
def _CGColorSpaceRelease(c): return 0
def _CGBitmapContextCreate(c): return c.fake("cgcontext")
def _CGBitmapContextCreateImage(c): return c.fake("cgimage")
def _CGContextRelease(c): return 0
def _CGImageRelease(c): return 0
def _NSStringFromClass(c):
    nm=c.shim.name_of(c,c.xr(0))
    return c.cfstr(nm or "<class>")

def _NSLog(c):
    # NSLog(تنسيق, ...) — معالجة مبسطة للمتغيرات x2..x7
    st=ObjCShim.cfstring(c,c.xr(0)) or ""
    out=""
    ai=2
    i=0
    while i<len(st) and ai<=7:
        if st[i:i+2]=="%s":
            out+=(c.cstr(c.xr(ai)) or "")[:160]; ai+=1; i+=2
        elif st[i:i+2] in ("%d","%i","%u"):
            v=c.xr(ai); out+=str(v if v<(1<<63) else v-(1<<64)); ai+=1; i+=2
        elif st[i:i+3] in ("%ld","%lu","%zd","%zu"):
            v=c.xr(ai); out+=str(v if v<(1<<63) else v-(1<<64)); ai+=1; i+=3
        elif st[i:i+2] in ("%f","%g"):
            out+="<float>"; ai+=1; i+=2
        elif st[i:i+2]=="%@":
            obj=c.xr(ai)
            s2=ObjCShim.cfstring(c,obj) if obj else None
            out+=(s2 if s2 is not None else "<obj>")[:160]; ai+=1; i+=2
        elif st[i:i+2]=="%%":
            out+="%"; i+=2
        else:
            out+=st[i]; i+=1
    out+=st[i:] if i<=len(st) else ""
    c.log("NSLog: "+out[:200])
    return 0
def _CFLog(c): return 0
def _CFPreferencesCopyAppValue(c): return 0
def _CTFontCreateWithName(c): return c.fake("ctfont")

OBJC_EXPORTS={
    "_objc_msgSend":_objc_msgSend,"_objc_msgSendSuper":_objc_msgSend,
    "_objc_msgSend_stret":_objc_msgSend,"_objc_getClass":_objc_getClass,
    "_objc_lookUpClass":_objc_getClass,"_objc_getRequiredClass":_objc_getClass,
    "_objc_getClass":_objc_getClass,
    "_class_getName":_class_getName,"_class_getSuperclass":_class_getSuperclass,
    "_class_getInstanceMethod":_class_getInstanceMethod,
    "_class_getClassMethod":_class_getClassMethod,"_class_addMethod":_class_addMethod,
    "_sel_registerName":_sel_registerName,"_sel_getUid":_sel_registerName,
    "_sel_getName":_sel_getName,"_object_getClass":_object_getClass,
    "_object_getClassName":_class_getName,
    "_objc_retain":_objc_retain,"_objc_retainAutoreleasedReturnValue":_objc_retain,
    "_objc_retainBlock":_objc_retain,"_objc_retainAutorelease":_objc_retain,
    "_objc_release":_objc_release,"_objc_autorelease":_objc_autorelease,
    "_objc_autoreleasePoolPush":_objc_autoreleasePoolPush,
    "_objc_autoreleasePoolPop":_objc_autoreleasePoolPop,
    "_objc_copyClassList":_objc_copyClassList,"_objc_copyClassNamesForImage":_objc_copyClassList,
    "_objc_allocateClassPair":_objc_allocateClassPair,
    "_objc_registerClassPair":_objc_registerClassPair,
    "_objc_sync_enter":_objc_sync_enter,"_objc_sync_exit":_objc_sync_exit,
    "_objc_setProperty":_objc_setProperty,"_objc_setProperty_atomic":_objc_setProperty,
    "_objc_setProperty_nonatomic":_objc_setProperty,
    "_objc_getProperty":_objc_msgSend,"_objc_getProperty_nonatomic":_objc_msgSend,
    "_objc_enumerationMutation":_objc_enumerationMutation,
    "_objc_exception_throw":_objc_exception_throw,"_objc_terminate":_objc_terminate,
    "_objc_disposeClassPair":_objc_release,"_objc_copyImageList":_objc_copyClassList,
    "_objc_loadWeak":_objc_retain,"_objc_initWeak":_objc_retain,
    "_objc_storeWeak":_objc_retain,"_objc_destroyWeak":_objc_release,
    "_CFStringCreateWithCString":_CFStringCreateWithCString,
    "_CFStringCreateWithCStringNoCopy":_CFStringCreateWithCString,
    "_CFStringCreateCopy":_CFStringCreateCopy,
    "_CFStringGetCString":_CFStringGetCString,
    "_CFStringGetLength":_CFStringGetLength,
    "_CFStringGetCStringPtr":_CFStringGetCStringPtr,
    "_CFStringGetBytes":_CFStringGetCString,
    "_CFRelease":_CFRelease,"_CFRetain":_CFRetain,"_CFAutorelease":_CFAutorelease,
    "_CFAllocatorGetDefault":_CFAllocatorGetDefault,
    "_CFAllocatorCreate":_CFAllocatorGetDefault,
    "_CFRunLoopGetCurrent":_CFRunLoopGetCurrent,
    "_CFRunLoopGetMain":_CFRunLoopGetMain,"_CFRunLoopRun":_CFRunLoopRun,
    "_CFRunLoopRunInMode":_CFRunLoopRunInMode,"_CFRunLoopAddSource":_CFRunLoopAddSource,
    "_CFRunLoopAddTimer":_CFRunLoopAddSource,"_CFRunLoopStop":_CFRunLoopStop,
    "_CFRunLoopWakeUp":_CFRunLoopWakeUp,"_CFRunLoopSourceSignal":_objc_release,
    "_CFAbsoluteTimeGetCurrent":_CFAbsoluteTimeGetCurrent,
    "_CFBundleGetMainBundle":_CFBundleGetMainBundle,
    "_CFBundleGetValueForInfoDictionaryKey":_CFBundleGetValueForInfoDictionaryKey,
    "_CFBundleCopyBundleURL":_CFBundleCopyBundleURL,
    "_CFURLCopyFileSystemPath":_CFURLCopyFileSystemPath,
    "_CFURLCreateFromFileSystemRepresentation":_CFBundleCopyBundleURL,
    "_CFStringCreateFromExternalRepresentation":_CFStringCreateFromExternalRepresentation,
    "_CFStringConvertEncodingToNSStringEncoding":_CFStringConvertEncodingToNSStringEncoding,
    "_CFDataCreate":_CFDataCreate,"_CFDataCreateMutable":_CFDataCreate,
    "_CFDictionaryGetValue":_CFDictionaryGetValue,
    "_CFDictionaryAddValue":_CFDictionaryAddValue,
    "_CFDictionaryCreateMutable":_CFDataCreate,
    "_CFArrayGetCount":_CFArrayGetCount,"_CFArrayCreateMutable":_CFDataCreate,
    "_CGColorSpaceCreateDeviceRGB":_CGColorSpaceCreateDeviceRGB,
    "_CGColorSpaceCreateWithName":_CGColorSpaceCreateWithName,
    "_CGColorSpaceRelease":_CGColorSpaceRelease,
    "_CGBitmapContextCreate":_CGBitmapContextCreate,
    "_CGBitmapContextCreateImage":_CGBitmapContextCreateImage,
    "_CGContextRelease":_CGContextRelease,"_CGImageRelease":_CGImageRelease,
    "_NSLog":_NSLog,"_CFLog":_CFLog,"_NSStringFromClass":_NSStringFromClass,
    "_CFPreferencesCopyAppValue":_CFPreferencesCopyAppValue,
    "_CTFontCreateWithName":_CTFontCreateWithName,
    "_CFNotificationCenterGetLocalCenter":_CFBundleGetMainBundle,
    "_CFUUIDCreate":_CFDataCreate,"_CFUUIDCreateString":_CFStringCreateCopy,
    "_CFTimeZoneCopySystem":_CFBundleGetMainBundle,
    "_CFDateCreate":_CFDataCreate,
}

OBJC_EXPORTS["_CFBundleCopyBundlePath"]=_bundlepath
OBJC_EXPORTS["_CFBundleCopyResourcesDirectoryURL"]=_bundlepath
