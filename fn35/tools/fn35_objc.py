#!/usr/bin/env python3
"""FN3.5 loader: REAL Objective-C runtime.

* Parses the binary's own ObjC metadata (__objc_classlist / class_ro /
  method lists -- absolute-pointer 2017 format) so engine classes and
  their IMPs run as native guest code.
* Ghost classes for UIKit/Foundation, backed by python handlers.
* objc_msgSend resolves: binary IMP -> tail-call; ghost -> python table;
  root NSObject defaults otherwise.
* UIApplicationMain drives the delegate lifecycle.
* EAGLContext/CADisplayLink tie into the fn35_gles bridge for real
  rendering + frame capture.

Registers into fn35_clib.IMPL (import AFTER fn35_ioslib so it wins).
"""
import ctypes
import struct
import sys
import time

from fn35_clib import cfunc, IMPL, RegSrc, _to_int
import fn35_gles
from fn35_gles import GLES, SCREEN_W, SCREEN_H

M64 = (1 << 64) - 1

# ====================================================================


class ObjCClass:
    __slots__ = ("addr", "name", "isa", "super", "ro_addr", "instance_size",
                 "methods", "meta_methods", "ivars")

    def __init__(self, addr):
        self.addr = addr
        self.name = None
        self.isa = 0
        self.super = 0
        self.ro_addr = 0
        self.instance_size = 0
        self.methods = {}         # sel name -> imp
        self.meta_methods = None  # lazy (ObjCClass of metaclass)
        self.ivars = ()


class Ghost:
    __slots__ = ("addr", "cls", "fields")

    def __init__(self, addr, cls, fields=None):
        self.addr = addr
        self.cls = cls            # ghost class name (str)
        self.fields = fields if fields is not None else {}

    def __repr__(self):
        return "<ghost %s @%x %r>" % (self.cls, self.addr,
                                      str(self.fields)[:60])


class ObjCRuntime:
    def __init__(self, l):
        self.l = l
        self.classes = {}          # addr -> ObjCClass (binary classes)
        self.by_name = {}          # name -> addr
        self.meta_of = {}          # class addr -> metaclass ObjCClass
        self.ghost_cells = {}      # name -> ghost class cell addr
        self.ghost_by_addr = {}    # cell addr -> class name
        self.objects = {}           # instance addr -> Ghost
        self.sel_cache = {}        # selname -> guest ptr (canonical)
        self.sel_ptr_cache = {}    # guest sel ptr -> selname (hot path)
        self.find_cache = {}       # (recv, selptr) -> result
        self.nsstring_cache = {}   # str -> ghost addr
        self.singletons = {}       # name -> Ghost
        self.display_links = []     # [(target, sel)]
        self.timers = []           # [dict]
        self.notifs = []           # [(observer, sel, name, obj)]
        self.main_app = None
        self._root = 0

    # ---------------- boot: parse binary metadata -------------------
    def boot(self):
        l = self.l
        mo = l.macho
        cl = mo.sections_in("__DATA", "__objc_classlist")
        n = 0
        for sec in cl:
            for off in range(sec.size // 8):
                addr = l.rd64(sec.addr + 8 * off)
                if addr:
                    self.parse_class(addr)
                    n += 1
        # canonical selectors from __objc_methname via selrefs
        for secname in ("__objc_selrefs",):
            for sec in mo.sections_in("__DATA", secname):
                for off in range(sec.size // 8):
                    p = l.rd64(sec.addr + 8 * off)
                    if p:
                        try:
                            s = l.gcstr(p, maxlen=256)
                            if s and s not in self.sel_cache:
                                self.sel_cache[s] = p
                        except Exception:
                            pass
        # root ghost cell first
        self._root = self.ghost("NSObject")
        l.console("[objc] %d binary classes parsed; root NSObject @0x%x"
                  % (n, self._root))
        return n

    def parse_class(self, addr, _depth=0):
        if addr in self.classes or _depth > 6:
            return self.classes.get(addr)
        l = self.l
        c = ObjCClass(addr)
        try:
            c.isa = l.rd64(addr + 0)
            c.super = l.rd64(addr + 8)
            bits = l.rd64(addr + 0x20)
            ro = bits & ~0x7
            if not ro or not (mo_in(l, ro)):
                return None
            c.ro_addr = ro
            flags = l.rd32(ro)
            c.instance_size = l.rd32(ro + 8)
            namep = l.rd64(ro + 0x18)
            c.name = l.gcstr(namep, maxlen=256) if namep else "?"
            ml = l.rd64(ro + 0x20)     # baseMethodList
            if ml and mo_in(l, ml):
                entsize = l.rd32(ml) & 0xFFFFFFF
                count = l.rd32(ml + 4)
                if 0 < entsize < 64 and 0 < count < 4096:
                    for i in range(count):
                        e = ml + 8 + i * entsize
                        nm = l.rd64(e)
                        imp = l.rd64(e + 16)
                        if nm and imp and mo_in(l, imp):
                            s = l.gcstr(nm, maxlen=256)
                            if s:
                                c.methods[s] = imp
        except Exception as e:
            return None
        self.classes[addr] = c
        self.by_name.setdefault(c.name, addr)
        # also parse the metaclass so class-method dispatch works
        if c.isa and mo_in(l, c.isa) and c.isa not in self.classes:
            mc = self.parse_class(c.isa, _depth + 1)
            if mc:
                self.by_name.setdefault("meta:" + mc.name, c.isa)
        return c

    # ---------------- ghost classes ---------------------------------
    def ghost(self, name, superclass="NSObject"):
        cell = self.ghost_cells.get(name)
        if cell:
            return cell
        l = self.l
        cell = l.data_cell("oc." + name, 96)
        sup = self.ghost_cells.get(superclass) or self._root
        l.w64(cell + 0x00, self._root)     # isa -> root (metaclass trick)
        l.w64(cell + 0x08, sup)             # superclass
        ro = l.data_cell("oc.ro." + name, 64)
        l.w64(cell + 0x20, ro)
        nm = l.cstring_cell("ocn." + name, name)
        l.w64(ro + 0x18, nm)
        l.w64(ro + 0x08, 72)                # instanceSize placeholder
        self.ghost_cells[name] = cell
        self.ghost_by_addr[cell] = name
        return cell

    def ghost_super_of(self, name):
        return GHOST_HIERARCHY.get(name, "NSObject")

    # ---------------- objects ---------------------------------------
    def new_ghost(self, clsname, fields=None, size=96):
        l = self.l
        cell = self.ghost(clsname, self.ghost_super_of(clsname))
        addr = l.heap_alloc(size, zero=True)
        l.w64(addr, cell)
        g = Ghost(addr, clsname, fields)
        self.objects[addr] = g
        return g

    def alloc_instance(self, cls_addr):
        """+alloc on a binary or ghost class -> instance address."""
        l = self.l
        c = self.classes.get(cls_addr)
        if c:
            size = max(c.instance_size, 16)
            obj = l.heap_alloc(size, zero=True)
            l.w64(obj, cls_addr)
            return obj
        name = self.ghost_by_addr.get(cls_addr)
        if name:
            size = GHOST_SIZES.get(name, 96)
            obj = l.heap_alloc(size, zero=True)
            l.w64(obj, cls_addr)
            return obj
        obj = l.heap_alloc(96, zero=True)
        l.w64(obj, self._root)
        return obj

    # ---------------- method resolution ------------------------------
    def resolve(self, recv, selname):
        """Return ("imp", addr) | ("py", fn, owner) | None."""
        l = self.l
        # ghost instance?
        g = self.objects.get(recv)
        start = g.cls if g is not None else None
        if g is not None:
            return self._ghost_lookup(g.cls, selname)
        # class object (binary or ghost)?
        c = self.classes.get(recv)
        if c is not None:
            # class-method lookup through metaclass chain
            cls = self._meta_chain_start(recv)
            if cls and cls not in self.classes:
                self.parse_class(cls)
            while True:
                bc = self.classes.get(cls)
                if bc is None:
                    break
                if selname in bc.methods:
                    return ("imp", bc.methods[selname])
                nxt = bc.super
                if not nxt:
                    break
                if nxt and nxt not in self.classes and mo_in(self.l, nxt):
                    self.parse_class(nxt)
                cls = nxt
            gname = self.ghost_by_addr.get(cls)
            if gname:
                return self._lookup_class_side(gname, selname)
            return self._root_lookup(selname)
        gname = self.ghost_by_addr.get(recv)
        if gname is not None:
            # ghost class object -> class-method tables, then root
            return self._lookup_class_side(gname, selname)
        # plain instance of a binary class?
        try:
            isa = l.rd64(recv)
        except Exception:
            return None
        cls = isa
        depth = 0
        while cls and depth < 16:
            bc = self.classes.get(cls)
            if bc is None:
                gname = self.ghost_by_addr.get(cls)
                if gname:
                    return self._ghost_lookup(gname, selname)
                break
            if selname in bc.methods:
                return ("imp", bc.methods[selname])
            cls = bc.super
            depth += 1
        return None

    def _meta_chain_start(self, class_addr):
        # class-method lookup starts at the metaclass (class->isa)
        l = self.l
        try:
            return l.rd64(class_addr)
        except Exception:
            return 0

    def _lookup_class_side(self, gname, selname):
        if selname in ("class", "self"):
            return ("py", lambda l, r, a: r, "NSObject")
        if selname == "initialize":
            return ("py", lambda l, r, a: 0, "NSObject")
        name = gname
        depth = 0
        while name and depth < 12:
            cm = GHOST_CLASS_METHODS.get(name)
            if cm and selname in cm:
                return ("py", cm[selname], name)
            name = self.ghost_super_of(name)
            depth += 1
        fn = ROOT_TABLE.get(selname)
        if fn is not None:
            return ("py", fn, "NSObject")
        return None

    def _ghost_lookup(self, gname, selname, class_side=False):
        name = gname
        depth = 0
        while name and depth < 12:
            tbl = GHOST_CLASS_TABLE.get(name)
            if tbl and selname in tbl:
                return ("py", tbl[selname], name)
            name = self.ghost_super_of(name)
            depth += 1
        # root NSObject defaults (shared with class side)
        fn = ROOT_TABLE.get(selname)
        if fn is not None:
            return ("py", fn, "NSObject")
        return None

    def _root_lookup(self, selname):
        fn = ROOT_TABLE.get(selname)
        if fn is not None:
            return ("py", fn, "NSObject")
        return None

    # ---------------- string helpers ---------------------------------
    def read_nsstring(self, ptr, maxlen=1 << 22):
        if not ptr:
            return None
        l = self.l
        g = self.objects.get(ptr)
        if g is not None:
            if g.cls == "NSString":
                return g.fields.get("str", "")
            if g.cls == "NSMutableString":
                return g.fields.get("str", "")
            return None
        # binary __cfstring constant?
        for sec in l.macho.sections_in("__DATA", "__cfstring"):
            if sec.addr <= ptr < sec.addr + sec.size:
                data = l.rd64(ptr + 16)
                ln = l.rd64(ptr + 24)
                if data:
                    try:
                        b = l.rdb(data, min(ln, maxlen))
                        return b.decode("utf-8", "replace")
                    except Exception:
                        return None
        return None

    def nsstring(self, s):
        if s in self.nsstring_cache:
            return self.nsstring_cache[s]
        g = self.new_ghost("NSString", {"str": s})
        self.nsstring_cache[s] = g.addr
        return g.addr

    def read_value(self, ptr):
        """Best-effort python value for any guest object pointer."""
        if not ptr:
            return None
        s = self.read_nsstring(ptr)
        if s is not None:
            return s
        g = self.objects.get(ptr)
        if g is not None:
            f = g.fields
            if "str" in f:
                return f["str"]
            if "num" in f:
                return f["num"]
            if "items" in f:
                return f["items"]
            if "map" in f:
                return f["map"]
            return g
        return None

    def sel_for(self, name):
        p = self.sel_cache.get(name)
        if p:
            return p
        p = self.l.cstring_cell("sel." + name, name)
        self.sel_cache[name] = p
        return p

    def sel_name_of(self, selptr, maxlen=200):
        """cached guest selector pointer -> name string (None if bad)."""
        if not selptr:
            return None
        n = self.sel_ptr_cache.get(selptr)
        if n is None:
            try:
                n = self.l.gcstr(selptr, maxlen=maxlen)
            except Exception:
                return None
            if len(self.sel_ptr_cache) > 65536:
                self.sel_ptr_cache.clear()
            self.sel_ptr_cache[selptr] = n
        return n

    # ---------------- timers / display links -------------------------
    def next_deadline(self):
        """Earliest future timer/display-link deadline (for clock jumps)."""
        nxt = None
        for t in self.timers:
            if t.get("done"):
                continue
            d = t.get("next")
            if d is not None and (nxt is None or d < nxt):
                nxt = d
        for dl in self.display_links:
            if dl.get("paused") or dl.get("invalid") or not dl.get("runloop"):
                continue
            d = dl.get("next", 0)
            if nxt is None or d < nxt:
                nxt = d
        return nxt

    def tick(self):
        """Called from scheduler: fire display links + timers."""
        l = self.l
        now = l.vclock
        for t in self.timers:
            if t.get("done"):
                continue
            if now >= t["next"]:
                t["next"] = now + int(t["interval"] * 1e9)
                if not t.get("repeats"):
                    t["done"] = True
                self._fire(t["target"], t["sel"], t.get("timer_obj", 0))
        # display links: fire at ~60Hz -- driven by caller frequency
        for dl in self.display_links:
            if dl.get("paused") or dl.get("invalid") or not dl.get("runloop"):
                continue
            if now >= dl.get("next", 0):
                dl["next"] = now + (1 << 30) // 60   # 1/60s in ns
                self._fire(dl["target"], dl["sel"], dl.get("obj", 0))

    def _fire(self, target, sel, arg):
        _fire_native(self.l, target, sel, arg)


def mo_in(l, addr):
    mo = l.macho
    for seg in mo.segments:
        if seg.name == "__PAGEZERO":
            continue
        if seg.vmaddr <= addr < seg.vmaddr + seg.vmsize:
            return True
    return False


# ====================================================================
# ROOT (NSObject) behaviors -- recv is whatever object got the message
# ====================================================================

def _ns_alloc(l, recv, args, cls=None):
    rt = l.objc
    cls_addr = recv
    obj = rt.alloc_instance(cls_addr)
    return obj


def _ns_new(l, recv, args):
    rt = l.objc
    obj = rt.alloc_instance(recv)
    r = rt.resolve(obj, "init")
    if r and r[0] == "imp":
        def drv():
            rv = yield ("call", r[1], (obj,))
            return rv
        l.py_call(drv(), ret=obj)
        return obj
    return obj


def _ns_init(l, recv, args):
    return recv


def _ns_class(l, recv, args):
    # [obj class] -> isa; [cls class] -> the class itself
    try:
        if recv in l.objc.classes or recv in l.objc.ghost_by_addr:
            return recv
        return l.rd64(recv)
    except Exception:
        return 0


def _ns_retain(l, recv, args):
    return recv


def _ns_copy(l, recv, args):
    return recv


def _ns_responds(l, recv, args):
    sel = args[0] if args else 0
    r = l.objc.resolve(recv, l.gcstr(sel) if sel else "")
    return 1 if r else 0


def _ns_iskind(l, recv, args):
    cls = args[0] if args else 0
    try:
        cur = l.rd64(recv)
    except Exception:
        return 0
    depth = 0
    while cur and depth < 16:
        if cur == cls:
            return 1
        bc = l.objc.classes.get(cur)
        gname = l.objc.ghost_by_addr.get(cur)
        if bc:
            cur = bc.super
        elif gname:
            cur = l.objc.ghost_cells.get(
                l.objc.ghost_super_of(gname), 0)
        else:
            break
        depth += 1
    return 0


def _ns_desc(l, recv, args):
    name = "<unknown>"
    g = l.objc.objects.get(recv)
    if g:
        name = g.cls
    elif recv in l.objc.classes:
        name = l.objc.classes[recv].name
    elif recv in l.objc.ghost_by_addr:
        name = l.objc.ghost_by_addr[recv]
    return l.objc.nsstring("<%s: 0x%x>" % (name, recv))


def _ns_perform(l, recv, args):
    sel = args[0] if args else 0
    if not sel:
        return 0
    selname = l.gcstr(sel)
    a2 = args[1] if len(args) > 1 else 0
    return _dispatch_call(l, recv, selname, [sel, a2])


def _dispatch_call(l, recv, selname, args):
    """Full dispatch with native call support."""
    rt = l.objc
    r = rt.resolve(recv, selname)
    if r is None:
        l.trace_objc("MISSING %s on 0x%x" % (selname, recv))
        return 0
    if r[0] == "imp":
        def drv():
            rv = yield ("call", r[1], [recv] + list(args))
            return rv
        l.py_call(drv(), ret=0)
        return 0
    fn = r[1]
    return fn(l, recv, list(args))


ROOT_TABLE = {
    "alloc": _ns_alloc,
    "allocWithZone:": _ns_alloc,
    "new": _ns_new,
    "init": _ns_init,
    "initWithCoder:": _ns_init,
    "class": _ns_class,
    "self": lambda l, r, a: r,
    "retain": _ns_retain,
    "release": lambda l, r, a: 0,
    "autorelease": _ns_retain,
    "retainCount": lambda l, r, a: 1,
    "copy": _ns_copy,
    "copyWithZone:": _ns_copy,
    "mutableCopy": _ns_copy,
    "mutableCopyWithZone:": _ns_copy,
    "respondsToSelector:": _ns_responds,
    "isKindOfClass:": _ns_iskind,
    "isMemberOfClass:": lambda l, r, a: 1 if l.rd64(r) == (a[0] if a else 0) else 0,
    "isSubclassOfClass:": _ns_iskind,
    "conformsToProtocol:": lambda l, r, a: 1,
    "initialize": lambda l, r, a: 0,
    "description": _ns_desc,
    "debugDescription": _ns_desc,
    "hash": lambda l, r, a: r,
    "isEqual:": lambda l, r, a: 1 if (a[0] if a else 0) == r else 0,
    "doesNotRecognizeSelector:": lambda l, r, a: l.warn(
        "doesNotRecognize %s on 0x%x" % (l.gcstr(a[0]) if a and a[0] else "?", r)) or 0,
    "performSelector:": _ns_perform,
    "performSelector:withObject:": _ns_perform,
    "performSelector:withObject:withObject:": _ns_perform,
    "dealloc": lambda l, r, a: 0,
    "forwardingTargetForSelector:": lambda l, r, a: 0,
    "methodSignatureForSelector:": lambda l, r, a: 0,
    "forwardInvocation:": lambda l, r, a: 0,
    "observeValueForKeyPath:ofObject:change:context:":
        lambda l, r, a: 0,
    "allowsWeakReference": lambda l, r, a: 1,
    "retainWeakReference": lambda l, r, a: 1,
}


# ====================================================================
# Foundation ghost classes
# ====================================================================

def _s_str_helper(l, recv):
    g = l.objc.objects.get(recv)
    return g if (g and "str" in g.fields) else None


def _nsstr(l, s):
    return l.objc.nsstring(s)


def _mk_str_methods():
    T = {}

    def wrap(fn):
        return fn

    @wrap
    def m_length(l, r, a):
        g = _s_str_helper(l, r)
        return len(g.fields["str"].encode("utf-8")) if g else 0
    T["length"] = m_length
    T["lengthOfBytesUsingEncoding:"] = m_length

    @wrap
    def m_utf8(l, r, a):
        g = _s_str_helper(l, r)
        if not g:
            return 0
        s = g.fields["str"].encode()
        if "cptr" not in g.fields:
            p = l.heap_alloc(len(s) + 1, zero=True)
            l.wrb(p, s + b"\x00")
            g.fields["cptr"] = p
        return g.fields["cptr"]
    T["UTF8String"] = m_utf8
    T["cStringUsingEncoding:"] = m_utf8
    T["fileSystemRepresentation"] = m_utf8

    T["isEqualToString:"] = lambda l, r, a: 1 if (
        (l.objc.read_nsstring(a[0]) if a and a[0] else None)
        == (l.objc.read_nsstring(r) or "")) else 0
    T["isEqual:"] = T["isEqualToString:"]
    T["compare:"] = lambda l, r, a: (
        (l.objc.read_nsstring(r) or "") > (l.objc.read_nsstring(a[0]) or "")
        and 1 or -1)

    @wrap
    def m_app(l, r, a, sep=""):
        base = l.objc.read_nsstring(r) or ""
        other = (l.objc.read_nsstring(a[0]) if a and a[0] else "") or ""
        return _nsstr(l, base + other)
    T["stringByAppendingString:"] = m_app
    T["stringByAppendingPathComponent:"] = lambda l, r, a: _nsstr(
        l, ((l.objc.read_nsstring(r) or "").rstrip("/")
            + "/" + (l.objc.read_nsstring(a[0]) or "").lstrip("/")))
    T["stringByAppendingFormat:"] = m_app

    @wrap
    def m_prefix(l, r, a):
        base = l.objc.read_nsstring(r) or ""
        p = l.objc.read_nsstring(a[0]) if a and a[0] else ""
        return 1 if base.startswith(p) else 0
    T["hasPrefix:"] = m_prefix
    T["hasSuffix:"] = lambda l, r, a: 1 if (l.objc.read_nsstring(r) or
                                            "").endswith(
        l.objc.read_nsstring(a[0]) or "") else 0
    T["lowercaseString"] = lambda l, r, a: _nsstr(
        l, (l.objc.read_nsstring(r) or "").lower())
    T["uppercaseString"] = lambda l, r, a: _nsstr(
        l, (l.objc.read_nsstring(r) or "").upper())
    T["capitalizedString"] = lambda l, r, a: _nsstr(
        l, (l.objc.read_nsstring(r) or "").title())
    T["stringByReplacingOccurrencesOfString:withString:"] = \
        lambda l, r, a: _nsstr(l, (l.objc.read_nsstring(r) or "").replace(
            l.objc.read_nsstring(a[0]) or "",
            l.objc.read_nsstring(a[1]) or ""))
    T["stringByDeletingLastPathComponent"] = lambda l, r, a: _nsstr(
        l, "/".join((l.objc.read_nsstring(r) or "").split("/")[:-1]))
    T["lastPathComponent"] = lambda l, r, a: _nsstr(
        l, (l.objc.read_nsstring(r) or "").split("/")[-1])
    T["pathExtension"] = lambda l, r, a: _nsstr(
        l, (l.objc.read_nsstring(r) or "").split(".")[-1])
    T["stringByExpandingTildeInPath"] = lambda l, r, a: r
    T["stringByStandardizingPath"] = lambda l, r, a: r
    T["description"] = lambda l, r, a: r if l.objc.objects.get(r) else _nsstr(
        l, l.objc.read_nsstring(r) or "")
    T["copy"] = lambda l, r, a: r
    T["mutableCopy"] = lambda l, r, a: _nsstr(
        l, l.objc.read_nsstring(r) or "")
    T["copyWithZone:"] = lambda l, r, a: r
    T["characterAtIndex:"] = lambda l, r, a: ord(
        (l.objc.read_nsstring(r) or "?")[a[0] % max(
            1, len(l.objc.read_nsstring(r) or "?"))])
    T["intValue"] = lambda l, r, a: _int_of(l, r)
    T["integerValue"] = lambda l, r, a: _int_of(l, r)
    T["longLongValue"] = lambda l, r, a: _int_of(l, r)
    T["boolValue"] = lambda l, r, a: 1 if _int_of(l, r) else 0
    T["floatValue"] = lambda l, r, a: ("d0", float(_int_of(l, r) or 0.0))
    T["doubleValue"] = lambda l, r, a: ("d0", float(_int_of(l, r) or 0.0))

    @wrap
    def m_comps(l, r, a):
        base = l.objc.read_nsstring(r) or ""
        sep = l.objc.read_nsstring(a[0]) if a and a[0] else " "
        items = [l.objc.nsstring(x) for x in base.split(sep)]
        return l.objc.new_ghost("NSArray", {"items": items}).addr
    T["componentsSeparatedByString:"] = m_comps

    T["writeToFile:atomically:encoding:error:"] = lambda l, r, a: 1
    T["writeToFile:atomically:"] = lambda l, r, a: 1
    T["dataUsingEncoding:"] = lambda l, r, a: 0
    return T


def _int_of(l, r):
    s = l.objc.read_nsstring(r) or ""
    try:
        return int(float(s.strip() or 0))
    except Exception:
        return 0


def _mk_str_class_methods():
    C = {}
    C["stringWithUTF8String:"] = lambda l, r, a: _nsstr(
        l, l.gcstr(a[0]) if a and a[0] else "")
    C["stringWithCString:"] = C["stringWithUTF8String:"]
    C["stringWithCString:encoding:"] = C["stringWithUTF8String:"]
    C["stringWithString:"] = lambda l, r, a: _nsstr(
        l, l.objc.read_nsstring(a[0]) if a and a[0] else "")
    C["string"] = lambda l, r, a: _nsstr(l, "")
    C["localizedStringWithFormat:"] = lambda l, r, a: _nsstr(
        l, l.objc.read_nsstring(a[0]) if a and a[0] else "")
    C["description"] = lambda l, r, a: _nsstr(l, "NSString")
    C["class"] = lambda l, r, a: r

    @wrap_format
    def m_format(l, r, a):
        pass
    C["stringWithFormat:"] = _swf
    C["stringWithFormat:arguments:"] = _swf
    C["initWithFormat:"] = _swf
    return C


def wrap_format(fn):
    return fn


def _swf(l, r, a):
    fmt = l.objc.read_nsstring(a[0]) if a and a[0] else ""
    if not fmt:
        return _nsstr(l, "")
    # pull varargs from x3.. (msgSend: recv,sel,fmt,then...)
    src = RegSrc(l, first_named_x=3)
    try:
        out = _fmt_objc(l, fmt, src)
    except Exception:
        out = fmt
    return _nsstr(l, out)


def _fmt_objc(l, fmt, src):
    out = []
    i = 0
    n = len(fmt)
    while i < n:
        ch = fmt[i]
        if ch == "%" and i + 1 < n:
            j = i + 1
            spec = "%"
            while j < n and fmt[j] not in "diouxXeEfgGcsp@%":
                spec += fmt[j]
                j += 1
            if j < n:
                conv = fmt[j]
                spec += conv
            else:
                out.append(fmt[i:])
                break
            if conv == "%":
                out.append("%")
            elif conv in "dioxX":
                out.append(spec % _to_int(src.next_int()))
            elif conv == "u":
                out.append(spec % (src.next_int() & M64))
            elif conv in "eEfgG":
                out.append(spec % src.next_dbl())
            elif conv == "c":
                out.append(chr(src.next_int() & 0xFF))
            elif conv == "s":
                out.append(l.gcstr(src.next_int()))
            elif conv == "@":
                v = l.objc.read_value(src.next_int())
                out.append(str(v) if not isinstance(v, Ghost) else
                           ("<%s>" % v.cls))
            i = j + 1
            continue
        out.append(ch)
        i += 1
    return "".join(out)


def _mk_array_methods():
    T = {}
    T["count"] = lambda l, r, a: len(_items(l, r))
    T["objectAtIndex:"] = lambda l, r, a: _at(l, r, a[0])
    T["firstObject"] = lambda l, r, a: (_items(l, r) or [0])[0]
    T["lastObject"] = lambda l, r, a: (_items(l, r) or [0])[-1]
    T["addObject:"] = lambda l, r, a: _items(l, r).append(a[0]) or 0
    T["insertObject:atIndex:"] = lambda l, r, a: _items(l, r).insert(
        a[1], a[0]) or 0
    T["removeObjectAtIndex:"] = lambda l, r, a: _items(l, r).pop(
        a[0]) if _items(l, r) else 0
    T["removeObject:"] = lambda l, r, a: _items(l, r).remove(
        a[0]) if a[0] in _items(l, r) else 0
    T["removeAllObjects"] = lambda l, r, a: _items(l, r).clear() or 0
    T["containsObject:"] = lambda l, r, a: 1 if a[0] in _items(l, r) else 0
    T["indexOfObject:"] = lambda l, r, a: (
        _items(l, r).index(a[0]) if a[0] in _items(l, r) else 0)
    T["componentsJoinedByString:"] = lambda l, r, a: _nsstr(l, (
        l.objc.read_nsstring(a[0]) if a and a[0] else "").join(
        str(l.objc.read_value(x) or "") for x in _items(l, r)))
    T["copy"] = lambda l, r, a: l.objc.new_ghost(
        "NSArray", {"items": list(_items(l, r))}).addr
    T["description"] = lambda l, r, a: _nsstr(
        l, str([str(l.objc.read_value(x)) for x in _items(l, r)])[:512])
    T["enumerateObjectsUsingBlock:"] = lambda l, r, a: 0
    T["enumerateObjectsWithOptions:usingBlock:"] = lambda l, r, a: 0
    T["addObjectsFromArray:"] = lambda l, r, a: 0
    T["setArray:"] = lambda l, r, a: 0
    T["writeToFile:atomically:"] = lambda l, r, a: 1
    T["valueForKey:"] = lambda l, r, a: 0
    return T


def _items(l, r):
    g = l.objc.objects.get(r)
    if g and "items" in g.fields:
        return g.fields["items"]
    return []


def _at(l, r, i):
    items = _items(l, r)
    return items[i] if 0 <= i < len(items) else 0


def _mk_array_class_methods():
    C = {}
    C["array"] = lambda l, r, a: l.objc.new_ghost("NSArray", {"items": []}).addr
    C["arrayWithObject:"] = lambda l, r, a: l.objc.new_ghost(
        "NSArray", {"items": [a[0]]}).addr

    @wrap
    def m_objs_count(l, r, a):
        ptrs, count = a[0], a[1]
        items = []
        for i in range(min(count, 4096)):
            items.append(l.rd64(ptrs + 8 * i))
        return l.objc.new_ghost("NSArray", {"items": items}).addr
    C["arrayWithObjects:count:"] = m_objs_count
    return C


def wrap(fn):
    return fn


def _mk_dict_methods():
    T = {}

    def map_of(l, r):
        g = l.objc.objects.get(r)
        if g and "map" in g.fields:
            return g.fields["map"]
        g.fields["map"] = {}
        return g.fields["map"]

    T["objectForKey:"] = lambda l, r, a: map_of(l, r).get(_key(l, a[0]), 0)
    T["valueForKey:"] = lambda l, r, a: map_of(l, r).get(_key(l, a[0]), 0)
    T["setObject:forKey:"] = lambda l, r, a: (
        map_of(l, r).__setitem__(_key(l, a[1]), a[0]), 0)[1]
    T["setValue:forKey:"] = lambda l, r, a: (
        map_of(l, r).__setitem__(_key(l, a[1]), a[0]), 0)[1]
    T["removeObjectForKey:"] = lambda l, r, a: (
        map_of(l, r).pop(_key(l, a[0]), None), 0)[1]
    T["count"] = lambda l, r, a: len(map_of(l, r))
    T["removeAllObjects"] = lambda l, r, a: map_of(l, r).clear() or 0

    @wrap
    def m_allkeys(l, r, a):
        items = [k if isinstance(k, int) else l.objc.nsstring(str(k))
                 for k in map_of(l, r).keys()]
        return l.objc.new_ghost("NSArray", {"items": items}).addr
    T["allKeys"] = m_allkeys
    T["description"] = lambda l, r, a: _nsstr(
        l, str({str(k): str(v) for k, v in list(
            map_of(l, r).items())[:32]})[:512])
    T["copy"] = lambda l, r, a: l.objc.new_ghost(
        "NSDictionary", {"map": dict(map_of(l, r))}).addr
    T["enumerateKeysAndObjectsUsingBlock:"] = lambda l, r, a: 0
    T["allValues"] = lambda l, r, a: l.objc.new_ghost(
        "NSArray", {"items": list(map_of(l, r).values())}).addr
    return T


def _key(l, ptr):
    v = l.objc.read_nsstring(ptr)
    return v if v is not None else ptr


def _mk_dict_class_methods():
    C = {}
    C["dictionary"] = lambda l, r, a: l.objc.new_ghost(
        "NSDictionary", {"map": {}}).addr

    @wrap
    def m_ofk(l, r, a):
        objs, keys, count = a[0], a[1], a[2]
        m = {}
        for i in range(min(count, 4096)):
            k = l.rd64(keys + 8 * i)
            v = l.rd64(objs + 8 * i)
            m[_key(l, k)] = v
        return l.objc.new_ghost("NSDictionary", {"map": m}).addr
    C["dictionaryWithObjects:forKeys:count:"] = m_ofk
    return C


def _mk_number_methods():
    def num_of(l, r):
        g = l.objc.objects.get(r)
        return g.fields.get("num", 0) if g else 0
    T = {}
    T["integerValue"] = lambda l, r, a: int(num_of(l, r))
    T["intValue"] = lambda l, r, a: int(num_of(l, r)) & 0xFFFFFFFF
    T["unsignedIntegerValue"] = lambda l, r, a: int(num_of(l, r))
    T["longLongValue"] = lambda l, r, a: int(num_of(l, r))
    T["boolValue"] = lambda l, r, a: 1 if num_of(l, r) else 0
    T["floatValue"] = lambda l, r, a: ("d0", float(num_of(l, r)))
    T["doubleValue"] = lambda l, r, a: ("d0", float(num_of(l, r)))
    T["charValue"] = lambda l, r, a: int(num_of(l, r)) & 0xFF
    T["stringValue"] = lambda l, r, a: _nsstr(l, str(num_of(l, r)))
    T["description"] = lambda l, r, a: _nsstr(l, str(num_of(l, r)))
    T["descriptionWithLocale:"] = lambda l, r, a: _nsstr(l, str(num_of(l, r)))
    T["isEqualToNumber:"] = lambda l, r, a: 1 if num_of(l, r) == (
        (l.objc.objects.get(a[0]).fields.get("num", 0)
         if a and l.objc.objects.get(a[0]) else 0)) else 0
    T["compare:"] = lambda l, r, a: (1 if num_of(l, r) > 0 else -1)
    T["copy"] = lambda l, r, a: r
    return T


def _mk_number_class_methods():
    def mk(pyval):
        return lambda l, r, a: l.objc.new_ghost(
            "NSNumber", {"num": pyval}).addr
    C = {
        "numberWithInt:": mk(0), "numberWithInteger:": mk(0),
        "numberWithUnsignedInteger:": mk(0), "numberWithLong:": mk(0),
        "numberWithLongLong:": mk(0), "numberWithChar:": mk(0),
        "numberWithShort:": mk(0), "numberWithUnsignedChar:": mk(0),
    }
    C["numberWithInt:"] = lambda l, r, a: l.objc.new_ghost(
        "NSNumber", {"num": _s32(a[0])}).addr
    C["numberWithInteger:"] = C["numberWithInt:"]
    C["numberWithLong:"] = C["numberWithInt:"]
    C["numberWithLongLong:"] = C["numberWithInt:"]
    C["numberWithUnsignedInteger:"] = C["numberWithInt:"]
    C["numberWithChar:"] = C["numberWithInt:"]
    C["numberWithShort:"] = C["numberWithInt:"]
    C["numberWithUnsignedChar:"] = C["numberWithInt:"]
    C["numberWithFloat:"] = lambda l, r, a: l.objc.new_ghost(
        "NSNumber", {"num": _f32(a[0])}).addr
    C["numberWithDouble:"] = lambda l, r, a: l.objc.new_ghost(
        "NSNumber", {"num": _fd(a[0])}).addr
    C["numberWithBool:"] = lambda l, r, a: l.objc.new_ghost(
        "NSNumber", {"num": 1 if a[0] else 0}).addr
    return C


def _s32(v):
    v &= 0xFFFFFFFF
    return v - (1 << 32) if v >= (1 << 31) else v


def _f32(v):
    return struct.unpack("<f", struct.pack("<I", v & 0xFFFFFFFF))[0]


def _fd(v):
    return struct.unpack("<d", struct.pack("<Q", v & M64))[0]




GHOST_SIZES = {
    "NSString": 48, "NSArray": 48, "NSDictionary": 48, "NSNumber": 32,
    "NSValue": 64, "NSBundle": 96, "UIApplication": 128, "UIWindow": 128,
    "UIView": 128, "EAGLContext": 64, "CADisplayLink": 64,
    "CALayer": 128, "CAEAGLLayer": 128, "NSTimer": 64, "NSUUID": 64,
}

GHOST_HIERARCHY = {
    "NSMutableString": "NSString",
    "NSMutableArray": "NSArray",
    "NSMutableDictionary": "NSDictionary",
    "NSMutableAttributedString": "NSString",
    "NSURL": "NSObject",
    "NSUUID": "NSObject",
    "NSError": "NSObject",
    "NSException": "NSObject",
    "NSBundle": "NSObject",
    "NSProcessInfo": "NSObject",
    "NSThread": "NSObject",
    "NSNotificationCenter": "NSObject",
    "NSTimer": "NSObject",
    "NSAutoreleasePool": "NSObject",
    "NSNull": "NSObject",
    "NSValue": "NSObject",
    "NSDate": "NSObject",
    "NSLock": "NSObject",
    "NSRecursiveLock": "NSLock",
    "NSData": "NSObject",
    "NSMutableData": "NSData",
    "NSOperation": "NSObject",
    "NSOperationQueue": "NSObject",
    "NSLocale": "NSObject",
    "NSCalendar": "NSObject",
    "NSTimeZone": "NSObject",
    "NSCharacterSet": "NSObject",
    "NSInputStream": "NSObject",
    "NSOutputStream": "NSObject",
    "NSURLSession": "NSObject",
    "UIDevice": "NSObject",
    "UIScreen": "NSObject",
    "UIApplication": "UIResponder",
    "UIWindow": "UIView",
    "UIView": "UIResponder",
    "UILabel": "UIView",
    "UIImageView": "UIView",
    "UIResponder": "NSObject",
    "UIViewController": "UIResponder",
    "UITouch": "NSObject",
    "UIEvent": "NSObject",
    "UIGestureRecognizer": "NSObject",
    "CALayer": "NSObject",
    "CAEAGLLayer": "CALayer",
    "CAMetalLayer": "CALayer",
    "CADisplayLink": "NSObject",
    "EAGLContext": "NSObject",
    "EAGLSharegroup": "NSObject",
    "CAMetalDrawable": "NSObject",
    "CAMachPort": "NSObject",
    "NSNotificationCenter": "NSObject",
    "CLGeocoder": "NSObject",
    "CMMotionManager": "NSObject",
    "UIPasteboard": "NSObject",
    "UIAlertAction": "NSObject",
    "UIAlertController": "UIViewController",
    "GKLocalPlayer": "NSObject",
    "GKGameCenterViewController": "UIViewController",
    "MPMediaPickerController": "UIViewController",
    "SKProductsRequest": "NSObject",
    "SKPaymentQueue": "NSObject",
    "UITextView": "UIView",
    "UITextField": "UIView",
    "UIButton": "UIView",
    "UIScrollView": "UIView",
    "UIWebView": "UIView",
    "WKWebView": "UIView",
    "UIActivityIndicatorView": "UIView",
}

GHOST_ALLOWED = set(GHOST_HIERARCHY.keys()) | {
    "NSObject", "NSString", "NSArray", "NSDictionary", "NSNumber",
    "NSMutableString", "NSMutableArray", "NSMutableDictionary",
    "NSAttributedString", "NSMutableAttributedString", "NSConstantString",
    "UIResponder", "UIApplicationDelegate", "CAEAGLLayer", "CAMetalLayer",
    "CADisplayLink", "EAGLContext", "EAGLSharegroup", "EAGLDrawable",
    "CAMetalDrawable", "NSNotification", "NSNotificationCenter",
    "NSIndexPath", "NSIndexSet", "NSMutableIndexSet", "NSOperation",
    "NSBlockOperation", "NSInvocation", "NSMethodSignature", "NSRunLoop",
    "NSRunLoopMode", "UIInterfaceOrientation", "NSTextStorage",
    "SKView", "GKPeerPickerController", "SKProductsRequest",
    "SKProduct", "SKPayment", "SKPaymentQueue", "SKStoreProductViewController",
    "AVAudioPlayer", "AVAudioSession", "AVAudioEngine",
    "CIContext", "CIImage", "CIFilter", "CGColorSpaceRef", "CGContext",
    "CVOpenGLESTextureCache", "CVOpenGLESTexture", "CVPixelBuffer",
    "CVPixelBufferPool", "CMClock", "CMSampleBuffer", "CMFormatDescription",
    "MPSImage", "MPSTriangle", "UKSound", "APFuturaServer",
}

GHOST_CLASS_TABLE = {
    "NSString": _mk_str_methods(),
    "NSArray": _mk_array_methods(),
    "NSDictionary": _mk_dict_methods(),
    "NSNumber": _mk_number_methods(),
    "NSMutableString": {},
    "NSMutableArray": {},
    "NSMutableDictionary": {},
}

# class-side method tables (selector -> fn(l, cls_addr, args))
GHOST_CLASS_METHODS = {
    "NSString": _mk_str_class_methods(),
    "NSArray": _mk_array_class_methods(),
    "NSDictionary": _mk_dict_class_methods(),
    "NSNumber": _mk_number_class_methods(),
    "NSObject": {
        "class": lambda l, r, a: r,
        "alloc": _ns_alloc,
        "new": _ns_new,
        "initialize": lambda l, r, a: 0,
        "description": lambda l, r, a: l.objc.nsstring("NSObject"),
    },
}


# ====================================================================
# UIKit / display / EAGL ghost classes
# ====================================================================

def _singleton(l, name, fields=None, cls=None):
    rt = l.objc
    g = rt.singletons.get(name)
    if g is None:
        g = rt.new_ghost(cls or name, fields if fields is not None else {})
        rt.singletons[name] = g
    return g


def _rect_out(l, x8addr, x, y, w, h):
    if x8addr:
        l.wrb(x8addr, struct.pack("<dddd", float(x), float(y),
                                  float(w), float(h)))


def _mk_uikit_tables():
    G = {}
    C = {}

    # ---- UIScreen --------------------------------------------------
    def _screen(l, r, a):
        return _singleton(l, "UIScreen", cls="UIScreen").addr
    C["UIScreen"] = {"mainScreen": _screen, "screens": lambda l, r, a: (
        l.objc.new_ghost("NSArray", {"items": [_screen(l, r, a)]}).addr)}

    def _bounds(l, r, a):
        _rect_out(l, l.reg_x(8), 0, 0, SCREEN_W, SCREEN_H)
        return 0
    def _native_bounds(l, r, a):
        _rect_out(l, l.reg_x(8), 0, 0, SCREEN_W, SCREEN_H)
        return 0
    G["UIScreen"] = {
        "bounds": _bounds,
        "nativeBounds": _native_bounds,
        "applicationFrame": _bounds,
        "scale": lambda l, r, a: ("d0", 1.0),
        "nativeScale": lambda l, r, a: ("d0", 1.0),
        "currentMode": lambda l, r, a: 0,
        "availableModes": lambda l, r, a: l.objc.new_ghost(
            "NSArray", {"items": []}).addr,
    }

    # ---- UIDevice --------------------------------------------------
    def _device(l, r, a):
        return _singleton(l, "UIDevice", cls="UIDevice").addr
    C["UIDevice"] = {"currentDevice": _device}
    G["UIDevice"] = {
        "systemVersion": lambda l, r, a: _nsstr(l, "11.3"),
        "model": lambda l, r, a: _nsstr(l, "iPhone"),
        "localizedModel": lambda l, r, a: _nsstr(l, "iPhone"),
        "name": lambda l, r, a: _nsstr(l, "fn35 Loader"),
        "identifierForVendor": lambda l, r, a: _nsstr(
            l, "1A2B3C4D-5E6F-7A8B-9C0D-1E2F3A4B5C6D"),
        "batteryState": lambda l, r, a: 3,
        "orientation": lambda l, r, a: 4,     # landscape right
        "isBatteryMonitoringEnabled": lambda l, r, a: 0,
        "setBatteryMonitoringEnabled:": lambda l, r, a: 0,
        "proximityState": lambda l, r, a: 0,
        "isMultitaskingSupported": lambda l, r, a: 1,
        "userInterfaceIdiom": lambda l, r, a: 0,   # phone
    }

    # ---- UIApplication --------------------------------------------
    def _app(l, r, a):
        return _singleton(l, "UIApplication", cls="UIApplication").addr
    C["UIApplication"] = {
        "sharedApplication": _app,
        "class": lambda l, r, a: r,
    }
    G["UIApplication"] = {
        "delegate": lambda l, r, a: (
            l.objc.main_app.get("delegate", 0) if l.objc.main_app else 0),
        "setDelegate:": lambda l, r, a: (
            l.objc.main_app or {}).update({"delegate": a[0]}) or 0,
        "windows": lambda l, r, a: l.objc.new_ghost("NSArray", {"items": [
            _singleton(l, "UIWindow", cls="UIWindow").addr]}).addr,
        "keyWindow": lambda l, r, a: _singleton(
            l, "UIWindow", cls="UIWindow").addr,
        "statusBarOrientation": lambda l, r, a: 4,
        "isStatusBarHidden": lambda l, r, a: 1,
        "setStatusBarHidden:withAnimation:": lambda l, r, a: 0,
        "setStatusBarHidden:": lambda l, r, a: 0,
        "isIdleTimerDisabled": lambda l, r, a: (
            1 if _singleton(l, "UIApplication").fields.get("noidle") else 0),
        "setIdleTimerDisabled:": lambda l, r, a: (
            _singleton(l, "UIApplication").fields.update(
                {"noidle": a[0]}) or 0),
        "beginBackgroundTaskWithExpirationHandler:":
            lambda l, r, a: 1,
        "endBackgroundTask:": lambda l, r, a: 0,
        "setNetworkActivityIndicatorVisible:": lambda l, r, a: 0,
        "openURL:": lambda l, r, a: 0,
        "canOpenURL:": lambda l, r, a: 0,
        "applicationIconBadgeNumber": lambda l, r, a: 0,
        "setApplicationIconBadgeNumber:": lambda l, r, a: 0,
        "registerForRemoteNotifications": lambda l, r, a: 0,
        "beginReceivingRemoteControlEvents": lambda l, r, a: 0,
        "supportedInterfaceOrientationsForWindow:":
            lambda l, r, a: (1 << 4) | (1 << 5),  # landscape
    }

    # ---- UIView / UIWindow -----------------------------------------
    def _mk_view(l, addr):
        g = l.objc.objects.get(addr)
        if g is not None and "layer" not in g.fields:
            g.fields["layer"] = 0
        return g

    def _view_layer(l, r, a):
        g = _mk_view(l, r)
        if g is None:
            return 0
        if not g.fields.get("layer"):
            lay = l.objc.new_ghost("CAEAGLLayer", {})
            lay.fields["owner"] = r
            g.fields["layer"] = lay.addr
        return g.fields["layer"]

    viewT = {
        "layer": _view_layer,
        "contentScaleFactor": lambda l, r, a: ("d0", 1.0),
        "setContentScaleFactor:": lambda l, r, a: 0,
        "setClipsToBounds:": lambda l, r, a: 0,
        "setMultipleTouchEnabled:": lambda l, r, a: 0,
        "setUserInteractionEnabled:": lambda l, r, a: 0,
        "setExclusiveTouch:": lambda l, r, a: 0,
        "setAutoresizingMask:": lambda l, r, a: 0,
        "setBackgroundColor:": lambda l, r, a: 0,
        "setOpaque:": lambda l, r, a: 0,
        "setHidden:": lambda l, r, a: 0,
        "isHidden": lambda l, r, a: 0,
        "addSubview:": lambda l, r, a: 0,
        "removeFromSuperview": lambda l, r, a: 0,
        "setNeedsLayout": lambda l, r, a: 0,
        "layoutIfNeeded": lambda l, r, a: 0,
        "setNeedsDisplay": lambda l, r, a: 0,
        "setFrame:": lambda l, r, a: 0,
        "setBounds:": lambda l, r, a: 0,
        "isOpaque": lambda l, r, a: 1,
        "tag": lambda l, r, a: 0,
        "addGestureRecognizer:": lambda l, r, a: 0,
        "removeGestureRecognizer:": lambda l, r, a: 0,
        "window": lambda l, r, a: _singleton(
            l, "UIWindow", cls="UIWindow").addr,
    }

    def _v_bounds(l, r, a):
        _rect_out(l, l.reg_x(8), 0, 0, SCREEN_W, SCREEN_H)
        return 0
    viewT["bounds"] = _v_bounds
    viewT["frame"] = _v_bounds
    G["UIView"] = viewT
    C["UIView"] = {"layerClass": lambda l, r, a: l.objc.ghost(
        "CAEAGLLayer"), "class": lambda l, r, a: r}

    winT = dict(viewT)
    winT["makeKeyAndVisible"] = lambda l, r, a: 0
    winT["makeKeyWindow"] = lambda l, r, a: 0
    winT["rootViewController"] = lambda l, r, a: 0
    winT["setRootViewController:"] = lambda l, r, a: 0
    G["UIWindow"] = winT
    C["UIWindow"] = {"class": lambda l, r, a: r}

    G["UIResponder"] = {}
    vcT = {
        "view": lambda l, r, a: _singleton(
            l, "UIView", cls="UIView").addr,
        "loadView": lambda l, r, a: 0,
        "viewDidLoad": lambda l, r, a: 0,
        "viewWillAppear:": lambda l, r, a: 0,
        "viewDidAppear:": lambda l, r, a: 0,
        "viewDidLayoutSubviews": lambda l, r, a: 0,
        "shouldAutorotate": lambda l, r, a: 1,
        "supportedInterfaceOrientations": lambda l, r, a: (1 << 4) | (1 << 5),
        "preferredInterfaceOrientationForPresentation":
            lambda l, r, a: 4,
        "didReceiveMemoryWarning": lambda l, r, a: 0,
        "setNeedsStatusBarAppearanceUpdate": lambda l, r, a: 0,
        "prefersStatusBarHidden": lambda l, r, a: 1,
        "isViewLoaded": lambda l, r, a: 1,
    }
    G["UIViewController"] = vcT

    # ---- CALayer / CAEAGLLayer --------------------------------------
    layerT = {
        "contents": lambda l, r, a: 0,
        "setContents:": lambda l, r, a: 0,
        "contentsScale": lambda l, r, a: ("d0", 1.0),
        "setContentsScale:": lambda l, r, a: 0,
        "contentsAreFlipped": lambda l, r, a: 1,
        "opaque": lambda l, r, a: 1,
        "setOpaque:": lambda l, r, a: 0,
        "setNeedsDisplay": lambda l, r, a: 0,
        "setNeedsDisplayOnBoundsChange:": lambda l, r, a: 0,
        "display": lambda l, r, a: 0,
        "setDelegate:": lambda l, r, a: 0,
        "removeFromSuperlayer": lambda l, r, a: 0,
    }

    def _l_bounds(l, r, a):
        _rect_out(l, l.reg_x(8), 0, 0, SCREEN_W, SCREEN_H)
        return 0
    layerT["bounds"] = _l_bounds
    layerT["frame"] = _l_bounds
    G["CALayer"] = layerT

    eaglT = dict(layerT)

    def _drawable(l, r, a):
        g = l.objc.objects.get(r)
        if g is None:
            return 0
        return g.fields.get("drawable", 0)
    eaglT["drawableProperties"] = _drawable
    eaglT["setDrawableProperties:"] = lambda l, r, a: (
        (l.objc.objects.get(r) or Ghost(0, "CAEAGLLayer", {})).fields.update(
            {"drawable": a[0]}) or 0)
    G["CAEAGLLayer"] = eaglT

    # ---- EAGLContext ----------------------------------------------
    def _eagl_current(l, r, a):
        t = l.cur
        return getattr(t, "eagl_ctx", 0)

    def _eagl_setcurrent(l, r, a):
        ctx = a[0] if a else 0
        if ctx:
            try:
                fn35_gles._ensure(l)
            except Exception as e:
                l.warn("EAGL makecurrent: %r" % (e,))
        if l.cur is not None:
            l.cur.eagl_ctx = ctx
        return 1

    def _eagl_initapi(l, r, a):
        try:
            fn35_gles._ensure(l)
        except Exception as e:
            l.warn("EAGL init: %r" % (e,))
        g = l.objc.objects.get(r)
        if g is None:
            g = Ghost(r, "EAGLContext", {})
            l.objc.objects[r] = g
        g.fields["api"] = a[0] if a else 3
        return r

    def _eagl_renderbuffer_storage(l, r, a):
        # [ctx renderbufferStorage:GL_RENDERBUFFER fromDrawable:layer]
        try:
            fn35_gles._ensure(l)
            cf = ctypes.CFUNCTYPE(None, ctypes.c_uint, ctypes.c_uint,
                                  ctypes.c_int, ctypes.c_int)(
                GLES.proc("glRenderbufferStorage"))
            # bound renderbuffer of target GL_RENDERBUFFER gets storage
            cf(0x8D41, 0x84ED, SCREEN_W, SCREEN_H)
        except Exception as e:
            l.warn("renderbufferStorage: %r" % (e,))
        return 1

    def _eagl_present(l, r, a):
        # THE FRAME BOUNDARY: capture what was drawn
        try:
            if GLES.ready:
                GLES.capture("frame")
        except Exception as e:
            l.warn("present: %r" % (e,))
        return 1

    G["EAGLContext"] = {
        "initWithAPI:": _eagl_initapi,
        "initWithAPI:sharegroup:": _eagl_initapi,
        "renderbufferStorage:fromDrawable:": _eagl_renderbuffer_storage,
        "presentRenderbuffer:": _eagl_present,
        "setMultiThreaded": lambda l, r, a: 1,
        "getRenderbufferParameteriv": lambda l, r, a: 0,
        "sharegroup": lambda l, r, a: l.objc.ghost("EAGLSharegroup"),
    }
    C["EAGLContext"] = {
        "setCurrentContext:": _eagl_setcurrent,
        "currentContext": _eagl_current,
        "contextWithAPI:": lambda l, r, a: l.objc.new_ghost(
            "EAGLContext", {"api": a[0]}).addr,
    }
    G["EAGLSharegroup"] = {}

    # ---- CADisplayLink ----------------------------------------------
    def _dl_create(l, r, a):
        g = l.objc.new_ghost("CADisplayLink", {})
        g.fields["target"] = a[0]
        g.fields["sel"] = l.gcstr(a[1]) if a[1] else ""
        g.fields["obj"] = g.addr
        g.fields["runloop"] = 0
        g.fields["paused"] = 0
        g.fields["invalid"] = 0
        l.objc.display_links.append(g.fields)
        l.console("[CADisplayLink] created target=0x%x sel=%s" % (a[0], g.fields["sel"]))
        return g.addr

    C["CADisplayLink"] = {"displayLinkWithTarget:selector:": _dl_create}
    G["CADisplayLink"] = {
        "addToRunLoop:forMode:": lambda l, r, a: (
            l.objc.objects.get(r).fields.update({"runloop": 1}) or 0),
        "removeFromRunLoop:forMode:": lambda l, r, a: (
            l.objc.objects.get(r).fields.update({"runloop": 0}) or 0),
        "invalidate": lambda l, r, a: (
            l.objc.objects.get(r).fields.update({"invalid": 1}) or 0),
        "setPaused:": lambda l, r, a: (
            l.objc.objects.get(r).fields.update({"paused": a[0]}) or 0),
        "isPaused": lambda l, r, a: (1 if l.objc.objects.get(r).fields.get(
            "paused") else 0),
        "frameInterval": lambda l, r, a: 1,
        "timestamp": lambda l, r, a: ("d0", l.vclock / 1e9),
        "duration": lambda l, r, a: ("d0", 1.0 / 60.0),
    }

    # ---- NSBundle ----------------------------------------------------
    def _bundle_main(l, r, a):
        return _singleton(l, "NSBundle", cls="NSBundle").addr

    def _bundle_path(l, r, a):
        from fn35_loader import GUEST_BUNDLE
        return _nsstr(l, GUEST_BUNDLE)

    def _info_dict(l, r, a):
        g = _singleton(l, "NSBundle")
        if "info" not in g.fields:
            import plistlib
            try:
                from fn35_loader import GUEST_BUNDLE
                host = l.translate_path(GUEST_BUNDLE + "/Info.plist")
                with open(host, "rb") as f:
                    pl = plistlib.load(f)
            except Exception:
                pl = {}
            m = {}
            for k, v in pl.items():
                m[k] = _nsstr(l, str(v))
            g.fields["info"] = l.objc.new_ghost(
                "NSDictionary", {"map": m}).addr
        return g.fields["info"]

    def _info_key(l, r, a):
        key = l.objc.read_nsstring(a[0]) if a and a[0] else ""
        g = _singleton(l, "NSBundle")
        if "infolist" not in g.fields:
            import plistlib
            try:
                from fn35_loader import GUEST_BUNDLE
                host = l.translate_path(GUEST_BUNDLE + "/Info.plist")
                with open(host, "rb") as f:
                    pl = plistlib.load(f)
            except Exception:
                pl = {}
            g.fields["infolist"] = pl
        v = g.fields["infolist"].get(key)
        if v is None:
            return 0
        if isinstance(v, bool):
            return l.objc.new_ghost("NSNumber", {"num": 1 if v else 0}).addr
        if isinstance(v, (int, float)):
            return l.objc.new_ghost("NSNumber", {"num": v}).addr
        return _nsstr(l, str(v))

    def _path_res(l, r, a):
        from fn35_loader import GUEST_BUNDLE
        name = l.objc.read_nsstring(a[0]) if a and a[0] else ""
        typ = l.objc.read_nsstring(a[1]) if len(a) > 1 and a[1] else ""
        if not name:
            return 0
        cand = name if name.endswith(typ) and typ else (
            name + ("." + typ if typ else ""))
        host = l.translate_path(GUEST_BUNDLE + "/" + cand)
        import os as _os
        if _os.path.isfile(host):
            return _nsstr(l, GUEST_BUNDLE + "/" + cand)
        return 0

    C["NSBundle"] = {"mainBundle": _bundle_main}
    G["NSBundle"] = {
        "bundlePath": _bundle_path,
        "resourcePath": lambda l, r, a: _bundle_path(l, r, a),
        "bundleIdentifier": lambda l, r, a: _nsstr(
            l, "com.chairentertainment.Fortnite"),
        "infoDictionary": _info_dict,
        "objectForInfoDictionaryKey:": _info_key,
        "pathForResource:ofType:": _path_res,
        "load": lambda l, r, a: 1,
        "isLoaded": lambda l, r, a: 1,
    }

    # ---- NSProcessInfo / NSThread / etc -----------------------------
    def _pinfo(l, r, a):
        return _singleton(l, "NSProcessInfo", cls="NSProcessInfo").addr
    C["NSProcessInfo"] = {"processInfo": _pinfo}
    G["NSProcessInfo"] = {
        "processName": lambda l, r, a: _nsstr(l, "FortniteClient"),
        "globallyUniqueString": lambda l, r, a: _nsstr(
            l, "FN35-%08X" % (l.vclock & 0xFFFFFFFF)),
        "operatingSystemVersion": lambda l, r, a: _nsstr(l, "11.3"),
        "systemUptime": lambda l, r, a: ("d0", l.vclock / 1e9),
        "physicalMemory": lambda l, r, a: 3221225472,
        "environment": lambda l, r, a: l.objc.new_ghost(
            "NSDictionary", {"map": {}}).addr,
        "hostName": lambda l, r, a: _nsstr(l, "localhost"),
        "processorCount": lambda l, r, a: 6,
        "activeProcessorCount": lambda l, r, a: 6,
    }

    def _cur_thread(l, r, a):
        return _singleton(l, "NSThread." + l.cur.name,
                          cls="NSThread").addr
    G["NSThread"] = {
        "isMainThread": lambda l, r, a: (
            1 if l.cur.name == "main" else 0),
        "name": lambda l, r, a: _nsstr(l, l.cur.name),
        "setName:": lambda l, r, a: 0,
        "isFinished": lambda l, r, a: 0,
        "isExecuting": lambda l, r, a: 1,
        "threadPriority": lambda l, r, a: ("d0", 0.5),
    }

    def _nc_center(l, r, a):
        return _singleton(l, "NSNotificationCenter",
                          cls="NSNotificationCenter").addr
    C["NSNotificationCenter"] = {"defaultCenter": _nc_center}
    G["NSNotificationCenter"] = {
        "addObserver:selector:name:object:": lambda l, r, a: (
            l.objc.notifs.append((a[0], l.gcstr(a[1]) if a[1] else "",
                                  l.objc.read_nsstring(a[2])
                                  if a[2] else None, a[3])) or 0),
        "removeObserver:": lambda l, r, a: 0,
        "removeObserver:name:object:": lambda l, r, a: 0,
        "postNotificationName:object:": lambda l, r, a: (
            _nc_post(l, l.objc.read_nsstring(a[0]) or "",
                     a[1], None, None)),
        "postNotificationName:object:userInfo:": lambda l, r, a: (
            _nc_post(l, l.objc.read_nsstring(a[0]) or "",
                     a[1], None, a[2])),
    }

    G["NSAutoreleasePool"] = {}
    C["NSAutoreleasePool"] = {
        "new": lambda l, r, a: l.objc.new_ghost(
            "NSAutoreleasePool", {}).addr,
    }

    def _nsv_rect(l, r, a):
        return _singleton(l, "NSValue.rect", cls="NSValue").addr
    C["NSValue"] = {}
    G["NSValue"] = {}

    G["NSDate"] = {
        "timeIntervalSince1970": lambda l, r, a: ("d0", time.time()),
        "timeIntervalSinceReferenceDate": lambda l, r, a: (
            "d0", time.time() - 978307200.0),
    }
    C["NSDate"] = {"date": lambda l, r, a: l.objc.new_ghost(
        "NSDate", {}).addr}

    G["NSLock"] = {
        "lock": lambda l, r, a: 0,
        "unlock": lambda l, r, a: 0,
        "tryLock": lambda l, r, a: 1,
        "name": lambda l, r, a: 0,
        "setName:": lambda l, r, a: 0,
    }

    G["NSNull"] = {}
    C["NSNull"] = {"null": lambda l, r, a: _singleton(
        l, "NSNull", cls="NSNull").addr}

    def _url_file(l, r, a):
        g = l.objc.new_ghost("NSURL", {})
        g.fields["str"] = l.objc.read_nsstring(a[0]) if a and a[0] else ""
        return g.addr
    C["NSURL"] = {"fileURLWithPath:": _url_file,
                  "URLWithString:": _url_file}
    G["NSURL"] = {
        "path": lambda l, r, a: _nsstr(
            l, l.objc.objects.get(a and 0 or 0) is not None and "" or ""),
        "absoluteString": lambda l, r, a: _nsstr(
            l, (l.objc.objects.get(r).fields.get("str", "")
                if l.objc.objects.get(r) else "")),
        "description": lambda l, r, a: _nsstr(
            l, (l.objc.objects.get(r).fields.get("str", "")
                if l.objc.objects.get(r) else "")),
    }

    def _uuid_str(l, r, a):
        import uuid as _u
        return _nsstr(l, str(_u.uuid4()).upper())
    C["NSUUID"] = {"UUID": _uuid_str}
    G["NSUUID"] = {"UUIDString": _uuid_str}

    G["NSError"] = {
        "code": lambda l, r, a: 0,
        "domain": lambda l, r, a: 0,
        "localizedDescription": lambda l, r, a: _nsstr(l, ""),
    }
    G["NSData"] = {"length": lambda l, r, a: 0, "bytes": lambda l, r, a: 0}
    G["NSError"] = G["NSError"]

    return G, C


def _nc_post(l, name, obj, userinfo):
    rt = l.objc
    for (obs, sel, nm, _) in list(rt.notifs):
        if nm is None or nm == name:
            _fire_native(l, obs, sel, obj, name)
    return 0


def _fire_native(l, target, sel, arg, note_name=None):
    """Invoke [target sel:arg] on a fresh native thread."""
    rt = l.objc
    r = rt.resolve(target, sel)
    if not (r and r[0] == "imp"):
        l.trace_objc("fire %s on 0x%x (no imp)" % (sel, target))
        return
    t = l.new_thread(r[1], 0, name="of.%s" % sel[:24], stack_size=0x40000)
    selreg = rt.sel_for(sel)
    from fn35_loader import XREGS
    t.regs[XREGS[0]] = target & M64
    t.regs[XREGS[1]] = selreg & M64
    t.regs[XREGS[2]] = (arg or 0) & M64
    t.regs[XREGS[3]] = 0
    l.trace_thread("objc-fire %s on 0x%x -> tid %x" % (sel, target, t.tid))


GHOST_UKIT, GHOST_UKIT_CLASS = _mk_uikit_tables()
for _k, _v in GHOST_UKIT.items():
    GHOST_CLASS_TABLE.setdefault(_k, {}).update(_v)
for _k, _v in GHOST_UKIT_CLASS.items():
    GHOST_CLASS_METHODS.setdefault(_k, {}).update(_v)
# ---- late additions: mutable strings, NSTimer, NSThread, UIImage ----

_mut_str = {
    "setString:": lambda l, r, a: (
        (l.objc.objects.get(r) or Ghost(0, "NSMutableString", {})).fields
        .__setitem__("str", l.objc.read_nsstring(a[0]) or ""), 0)[1],
    "appendString:": lambda l, r, a: (
        (l.objc.objects.get(r) or Ghost(0, "NSMutableString", {})).fields
        .__setitem__(
            "str",
            (l.objc.read_nsstring(r) or "")
            + (l.objc.read_nsstring(a[0]) or "")), 0)[1],
    "appendFormat:": lambda l, r, a: (
        (l.objc.objects.get(r) or Ghost(0, "NSMutableString", {})).fields
        .__setitem__(
            "str",
            (l.objc.read_nsstring(r) or "")
            + (l.objc.read_nsstring(a[0]) if a and a[0] else "")), 0)[1],
    "initWithString:": lambda l, r, a: (
        (l.objc.objects.get(r) or Ghost(0, "NSMutableString", {})).fields
        .__setitem__("str", l.objc.read_nsstring(a[0]) or ""), r)[1],
    "initWithFormat:": lambda l, r, a: (
        (l.objc.objects.get(r) or Ghost(0, "NSMutableString", {})).fields
        .__setitem__("str", ""), r)[1],
}


def _read_file_str(l, r, a, cls="NSString"):
    g = l.objc.objects.get(r)
    if g is None:
        g = Ghost(r, cls, {})
        l.objc.objects[r] = g
    path = l.objc.read_nsstring(a[0]) if a and a[0] else ""
    content = ""
    if path:
        host = l.translate_path(path)
        import os as _os
        if host and _os.path.isfile(host):
            try:
                with open(host, "rb") as f:
                    content = f.read(1 << 22).decode("utf-8", "replace")
            except Exception as e:
                l.warn("initWithContentsOfFile %s: %r" % (path, e))
        else:
            l.console("[objc] file not found: %s" % path)
    g.fields["str"] = content
    g.cls = cls
    return r


def _ns_getchars(l, r, a):
    # getCharacters:(unichar*)buffer range:(NSRange){loc,len}
    # ABI: x2 = buffer, x3 = (loc | len<<32) as packed NSRange
    buf = a[0] if a else 0
    packed = a[1] if len(a) > 1 else 0
    loc = packed & 0xFFFFFFFF
    length = (packed >> 32) & 0xFFFFFFFF
    g = _s_str_helper(l, r)
    s = g.fields.get("str", "") if g else ""
    if buf and length:
        chunk = s[loc:loc + length]
        l.wrb(buf, chunk.encode("utf-16-le", "replace")
              + b"\x00" * max(0, 2 * (length - len(chunk))))
    return 0


def _ns_getcstring(l, r, a):
    # getCString:(char*)buffer maxLength:(NSUInteger)max encoding
    buf = a[0] if a else 0
    mx = a[1] if len(a) > 1 else 1024
    g = _s_str_helper(l, r)
    s = (g.fields.get("str", "") if g else "").encode("utf-8") + b"\x00"
    if buf and mx:
        l.wrb(buf, s[:mx])
    return 1


_ns_more = {
    "getCharacters:range:": _ns_getchars,
    "getCString:maxLength:encoding:": _ns_getcstring,
    "getCString:": _ns_getcstring,
    "lengthOfBytesUsingEncoding:": lambda l, r, a: len(
        (l.objc.read_nsstring(r) or "").encode("utf-8")),
    "canBeConvertedToEncoding:": lambda l, r, a: 1,
    "stringByAddingPercentEscapesUsingEncoding:": lambda l, r, a: r,
    "fastestEncoding": lambda l, r, a: 4,
    "smallestEncoding": lambda l, r, a: 4,
    "dataUsingEncoding:": lambda l, r, a: 0,
    "getLineStart:end:contentsEnd:forRange:": lambda l, r, a: 0,
    "enumerateSubstringsInRange:options:usingBlock:": lambda l, r, a: 0,
    "containsString:": lambda l, r, a: 1 if (l.objc.read_nsstring(
        a[0]) if a and a[0] else "") in (l.objc.read_nsstring(r) or "")
        else 0,
}
GHOST_CLASS_TABLE.setdefault("NSString", {}).update(_ns_more)
GHOST_CLASS_TABLE.setdefault("NSMutableString", {}).update(_mut_str)
GHOST_CLASS_TABLE["NSString"]["initWithContentsOfFile:"] =     lambda l, r, a: _read_file_str(l, r, a, "NSString")
GHOST_CLASS_TABLE["NSString"]["initWithContentsOfFile:encoding:error:"] = \
    lambda l, r, a: _read_file_str(l, r, a, "NSString")
GHOST_CLASS_TABLE["NSString"]["stringWithContentsOfFile:encoding:error:"] = \
    lambda l, r, a: _file_content_str(l, a)

def _file_content_str(l, a):
    path = l.objc.read_nsstring(a[0]) if a and a[0] else ""
    content = ""
    if path:
        host = l.translate_path(path)
        import os as _os
        if host and _os.path.isfile(host):
            try:
                with open(host, "rb") as f:
                    content = f.read(1 << 22).decode("utf-8", "replace")
            except Exception:
                pass
        else:
            l.console("[objc] file not found: %s" % path)
    return _nsstr(l, content)

# NSTimer: scheduledTimer... (interval in d0!)
def _timer_sched(l, r, a):
    interval = l.reg_d(0)
    target = a[0] if a else 0
    sel = l.gcstr(a[1]) if a and len(a) > 1 and a[1] else ""
    userinfo = a[2] if len(a) > 2 else 0
    repeats = a[3] if len(a) > 3 else 0
    g = l.objc.new_ghost("NSTimer", {})
    l.objc.timers.append({
        "interval": max(interval, 0.001) if interval else 1.0,
        "target": target, "sel": sel, "repeats": 1 if repeats else 0,
        "next": l.vclock + int(max(interval, 0.001) * 1e9) if interval
        else l.vclock + 1000000,
        "done": 0, "timer_obj": g.addr,
    })
    l.console("[NSTimer] +%ss target=0x%x sel=%s repeats=%d"
              % (interval, target, sel, 1 if repeats else 0))
    return g.addr


GHOST_CLASS_METHODS.setdefault("NSTimer", {}).update({
    "scheduledTimerWithTimeInterval:target:selector:userInfo:repeats:":
        _timer_sched,
    "timerWithTimeInterval:invocation:repeats:": lambda l, r, a:
        l.objc.new_ghost("NSTimer", {}).addr,
})
GHOST_CLASS_TABLE["NSTimer"] = {
    "invalidate": lambda l, r, a: 0,
    "isValid": lambda l, r, a: 1,
    "fireDate": lambda l, r, a: 0,
    "setFireDate:": lambda l, r, a: 0,
    "userInfo": lambda l, r, a: 0,
}

# NSThread: initWithTarget:selector:object: + start
def _nsthread_init(l, r, a):
    g = l.objc.objects.get(r)
    if g is None:
        g = Ghost(r, "NSThread", {})
        l.objc.objects[r] = g
    g.fields["target"] = a[0] if a else 0
    g.fields["sel"] = l.gcstr(a[1]) if a and len(a) > 1 and a[1] else ""
    g.fields["obj"] = a[2] if len(a) > 2 else 0
    return r


def _nsthread_start(l, r, a):
    g = l.objc.objects.get(r)
    if g and g.fields.get("target"):
        _fire_native(l, g.fields["target"], g.fields["sel"],
                     g.fields.get("obj", 0))
        g.fields["started"] = 1
    return 0


GHOST_CLASS_TABLE["NSThread"].update({
    "initWithTarget:selector:object:": _nsthread_init,
    "start": _nsthread_start,
    "isFinished": lambda l, r, a: 0,
    "isCancelled": lambda l, r, a: 0,
    "cancel": lambda l, r, a: 0,
    "setName:": lambda l, r, a: 0,
})

# UIImage
GHOST_CLASS_METHODS.setdefault("UIImage", {}).update({
    "imageWithCGImage:scale:orientation:": lambda l, r, a: (
        l.objc.new_ghost("UIImage", {})).addr,
    "imageNamed:": lambda l, r, a: (l.objc.new_ghost("UIImage", {})).addr,
    "imageWithContentsOfFile:": lambda l, r, a: (
        l.objc.new_ghost("UIImage", {})).addr,
})
GHOST_CLASS_TABLE["UIImage"] = {
    "size": lambda l, r, a: ("d0", 0.0),
    "scale": lambda l, r, a: ("d0", 1.0),
    "CGImage": lambda l, r, a: 0,
}
GHOST_HIERARCHY["UIImage"] = "NSObject"
GHOST_HIERARCHY["UIImageView"] = "UIView"
GHOST_CLASS_TABLE.setdefault("UIImageView", {})["initWithImage:"] = \
    lambda l, r, a: r

# generic sharedInstance on any ghost class
def _shared_instance(l, r, a):
    name = l.objc.ghost_by_addr.get(r, "NSObject")
    return _singleton(l, "shared." + name, cls=name).addr


def _perform_on_main(l, r, a):
    # [obj performSelectorOnMainThread:sel withObject:arg waitUntilDone:w]
    sel = a[0] if a else 0
    arg = a[1] if len(a) > 1 else 0
    if sel:
        _fire_native(l, r, l.gcstr(sel), arg)
    return 0


ROOT_TABLE["performSelectorOnMainThread:withObject:waitUntilDone:"] = \
    _perform_on_main
ROOT_TABLE["performSelectorOnMainThread:withObject:waitUntilDone:modes:"] = \
    _perform_on_main
ROOT_TABLE["performSelectorInBackground:withObject:"] = _perform_on_main
ROOT_TABLE["performSelector:afterDelay:"] = lambda l, r, a: 0
ROOT_TABLE["performSelectorOnMainThread"] = _shared_instance

ROOT_TABLE["sharedInstance"] = _shared_instance
ROOT_TABLE["sharedManager"] = _shared_instance
ROOT_TABLE["defaultManager"] = _shared_instance

GHOST_CLASS_TABLE["NSNotification"] = {
    "name": lambda l, r, a: _nsstr(
        l, (l.objc.objects.get(r).fields.get("name", "")
            if l.objc.objects.get(r) else "")),
    "object": lambda l, r, a: (
        l.objc.objects.get(r).fields.get("obj", 0)
        if l.objc.objects.get(r) else 0),
    "userInfo": lambda l, r, a: 0,
}


# ====================================================================
# C-function layer (imports from libobjc / Foundation / UIKit)
# ====================================================================

@cfunc("_objc_msgSend", "_objc_msgSendSuper", "_objc_msgSend_stret",
       "_objc_msgSend_fpret", "_objc_msgSend_fp2ret")
def _objc_msgsend(l, recv, sel, *rest):
    rt = l.objc
    if not recv:
        return 0
    name = rt.sel_name_of(sel)
    if name is None:
        return 0
    if rt is None:
        return 0
    # auto-answer modal dialogs: nobody is tapping an iOS alert in here
    if name == "AlertResponse" and rt.main_app \
            and recv == rt.main_app.get("delegate"):
        return 1        # "user tapped the default button"
    r = rt.resolve(recv, name)
    import os as _o
    if _o.environ.get("FN35_TRACE_MSG"):
        l.trace_objc("[%s @0x%x]" % (name, recv))
    if r is None:
        l.trace_objc("?? [0x%x %s]" % (recv, name))
        return 0
    if r[0] == "imp":
        return ("pc", r[1])
    try:
        return r[1](l, recv, list(rest))
    except Exception as e:
        l.warn("objc [%s @%s]: %r" % (name, r[2], e))
        return 0


@cfunc("_objc_msgSendSuper2", "_objc_msgSendSuper_stret")
def _objc_msgsend_super(l, sup, sel, *rest):
    rt = l.objc
    recv = l.rd64(sup) if sup else 0
    if not recv:
        return 0
    return _objc_msgsend(l, recv, sel, *rest)


@cfunc("_objc_getClass", "_objc_lookUpClass", "_objc_getRequiredClass")
def _objc_getclass(l, name):
    if not name:
        return 0
    n = l.gcstr(name, maxlen=256)
    rt = l.objc
    a = rt.by_name.get(n)
    if a:
        return a
    if n in GHOST_ALLOWED:
        return rt.ghost(n, rt.ghost_super_of(n))
    return 0


@cfunc("_objc_getMetaClass")
def _objc_getmetaclass(l, name):
    n = l.gcstr(name, maxlen=256) if name else ""
    a = l.objc.by_name.get(n)
    if a:
        try:
            return l.rd64(a)
        except Exception:
            pass
    return l.objc.ghost("NSObject")


@cfunc("_class_getName")
def _class_getname(l, cls):
    c = l.objc.classes.get(cls)
    if c:
        return l.cstring_cell("cn." + c.name, c.name)
    g = l.objc.ghost_by_addr.get(cls)
    if g:
        return l.cstring_cell("cn." + g, g)
    return l.cstring_cell("cn.?", "?")


@cfunc("_class_getSuperclass")
def _class_getsuper(l, cls):
    c = l.objc.classes.get(cls)
    if c and c.super:
        return c.super
    g = l.objc.ghost_by_addr.get(cls)
    if g:
        sup = l.objc.ghost_super_of(g)
        return l.objc.ghost_cells.get(sup, l.objc.ghost("NSObject"))
    return 0


@cfunc("_class_getInstanceSize")
def _class_getsize(l, cls):
    c = l.objc.classes.get(cls)
    if c:
        return c.instance_size
    return GHOST_SIZES.get(l.objc.ghost_by_addr.get(cls, ""), 64)


@cfunc("_object_getClass", "_object_getClassName")
def _object_getclass(l, obj):
    try:
        return l.rd64(obj)
    except Exception:
        return 0


@cfunc("_object_setClass")
def _object_setclass(l, obj, cls):
    try:
        l.w64(obj, cls)
    except Exception:
        pass
    return cls


@cfunc("_sel_getName")
def _sel_getname(l, sel):
    return sel


@cfunc("_sel_isEqual")
def _sel_isequal(l, a, b):
    if a == b:
        return 1
    return 1 if l.gcstr(a) == l.gcstr(b) else 0


@cfunc("_sel_registerName")
def _sel_register(l, name):
    if not name:
        return 0
    return l.objc.sel_for(l.gcstr(name, maxlen=256))


@cfunc("_NSStringFromClass")
def _nsstringfromclass(l, cls):
    import os as _o
    if _o.environ.get("FN35_DBG_OBJC"):
        nm, sa = l.nearest_symbol(cls)
        c0 = l.objc.classes.get(cls)
        print("[dbg NSStringFromClass] cls=0x%x nearest=%s parsed=%s "
              "ghost=%s" % (cls, nm, c0 and c0.name,
                            l.objc.ghost_by_addr.get(cls)), flush=True)
    c = l.objc.classes.get(cls)
    if c:
        return l.objc.nsstring(c.name)
    g = l.objc.ghost_by_addr.get(cls)
    if g:
        return l.objc.nsstring(g)
    return l.objc.nsstring("?")


@cfunc("_NSStringFromSelector")
def _nsstringfromsel(l, sel):
    return l.objc.nsstring(l.gcstr(sel) if sel else "")


@cfunc("_NSSelectorFromString")
def _nsselfromstring(l, s):
    v = l.objc.read_nsstring(s) if s else ""
    return l.objc.sel_for(v) if v else 0


@cfunc("_NSClassFromString")
def _nsclassfromstring(l, s):
    v = l.objc.read_nsstring(s) if s else ""
    if not v:
        return 0
    a = l.objc.by_name.get(v)
    if a:
        return a
    if v in GHOST_ALLOWED:
        return l.objc.ghost(v, l.objc.ghost_super_of(v))
    return 0


@cfunc("_objc_retain", "_objc_retainAutorelease",
       "_objc_retainAutoreleasedReturnValue",
       "_objc_retainBlock", "_objc_retainAutoreleaseReturnValue")
def _objc_retain(l, obj):
    return obj


@cfunc("_objc_release", "_objc_destroy")
def _objc_release(l, obj):
    return 0


@cfunc("_objc_autorelease")
def _objc_autorelease(l, obj):
    return obj


@cfunc("_objc_storeStrong", "_objc_copyStruct")
def _objc_storestrong(l, addr, val):
    if addr:
        try:
            l.w64(addr, val or 0)
        except Exception:
            pass
    return 0


@cfunc("_objc_autoreleasePoolPush")
def _pool_push(l):
    return l.data_cell("pool.%d" % l.cf_seq, 16)


@cfunc("_objc_autoreleasePoolPop")
def _pool_pop(l, token):
    return 0


@cfunc("_objc_enumerationMutation", "_objc_sync_enter",
       "_objc_sync_exit", "_objc_setAssociatedObject",
       "_objc_getAssociatedObject", "_objc_removeAssociatedObjects")
def _objc_stub2(l, a=0, b=0, c=0):
    return 0


@cfunc("_objc_copyClassList", "_objc_getClassList")
def _objc_classlist(l, out, count):
    if out is not None and count is not None and count > 0:
        return 0
    return len(l.objc.classes)


@cfunc("_class_respondsToSelector")
def _class_responds(l, cls, sel):
    r = l.objc.resolve(cls, l.gcstr(sel) if sel else "")
    return 1 if r else 0


@cfunc("_class_getInstanceMethod", "_class_getClassMethod",
       "_method_getImplementation", "_method_getName")
def _class_method_stub(l, a=0, b=0):
    return 0


@cfunc("_class_addMethod", "_class_addIvar", "_class_addProtocol",
       "_objc_allocateClassPair", "_objc_registerClassPair")
def _class_mutate_stub(l, a=0, b=0, c=0):
    return 1


@cfunc("_objc_getProtocol", "_objc_copyProtocolList",
       "_objc_getVersion", "_class_setVersion")
def _proto_stub(l, a=0, b=0):
    return 0


@cfunc("_objc_allocateProtocol")
def _objc_allocateprotocol(l, name):
    return 0


# ---- NSLog: real formatter with %@ support ---------------------------

@cfunc("_NSLog", "_NSLogv")
def _nslog(l, fmt, *va):
    s = l.objc.read_nsstring(fmt) if fmt else None
    if s is None:
        s = l.gcstr(fmt) if fmt else ""
    src = RegSrc(l, first_named_x=2)
    try:
        out = _fmt_objc(l, s, src)
    except Exception:
        out = s
    l.console("[NSLog] %s" % out)
    return 0


# ---- UIApplicationMain: the app lifecycle driver ----------------------

@cfunc("_UIApplicationMain")
def _uiapplicationmain(l, argc, argv, principal, delegate):
    rt = l.objc
    rt.main_app = {"delegate": 0}
    app = _singleton(l, "UIApplication", cls="UIApplication")

    del_name = l.objc.read_nsstring(delegate) if delegate else None
    if not del_name and principal:
        del_name = l.objc.read_nsstring(principal)

    cls = 0
    if del_name:
        cls = rt.by_name.get(del_name)
        if not cls:
            l.console("[uikit] delegate class %r not in binary -- ghosting"
                      % del_name)
            cls = rt.ghost(del_name if del_name in GHOST_ALLOWED
                           else "NSObject")
    l.console("[uikit] UIApplicationMain(delegate=%r) cls=0x%x"
              % (del_name, cls))

    sel_init = rt.sel_for("init")
    sel_launch = rt.sel_for("application:didFinishLaunchingWithOptions:")

    def drv():
        if not cls:
            l.console("[uikit] no delegate class; parking")
            l.block_cur("forever", "uikit_runloop", ret=0)
            return 0
        delobj = rt.alloc_instance(cls)
        r = rt.resolve(delobj, "init")
        if r and r[0] == "imp":
            rv = yield ("call", r[1], (delobj, sel_init))
            l.console("[uikit] delegate init -> 0x%x" % rv)
        else:
            delobj = _ns_init(l, delobj, [])
        rt.main_app["delegate"] = delobj
        r = rt.resolve(delobj, "application:didFinishLaunchingWithOptions:")
        if r and r[0] == "imp":
            opts = rt.new_ghost("NSDictionary", {"map": {}}).addr
            rv = yield ("call", r[1], (delobj, sel_launch, app.addr, opts))
            l.console("[uikit] didFinishLaunching -> 0x%x" % rv)
        else:
            l.console("[uikit] delegate has no didFinishLaunching IMP")
        l.console("[uikit] main thread parks in run loop")
        l.block_cur("forever", "uikit_runloop", ret=0)
        return 0
    l.py_call(drv(), ret=0)
    return 0


# ====================================================================
# CFString bridge (real implementations -- many were trace stubs)
# ====================================================================

def _cfs_value(l, s):
    """python string behind a CFString/NSString guest pointer"""
    v = l.objc.read_nsstring(s)
    if v is not None:
        return v
    if s:
        try:
            return l.gcstr(s)
        except Exception:
            return None
    return None


@cfunc("_CFStringGetLength")
def _CFStringGetLength(l, s):
    v = _cfs_value(l, s)
    return len(v.encode("utf-8")) if v else 0


@cfunc("_CFStringGetCString")
def _CFStringGetCString(l, s, buf, size, encoding):
    v = _cfs_value(l, s) or ""
    b = v.encode("utf-8") + b"\x00"
    if not buf or size <= 0:
        return 0
    if len(b) > size:
        b = b[:size - 1] + b"\x00"
    l.wrb(buf, b)
    return 1


@cfunc("_CFStringGetCStringPtr")
def _CFStringGetCStringPtr(l, s, encoding):
    g = l.objc.objects.get(s) if s else None
    if g and "cptr" in g.fields:
        return g.fields["cptr"]
    v = _cfs_value(l, s)
    if v is None and s:
        try:
            # raw C string already? treat as-is
            _ = l.rdb(s, 1)
            return s
        except Exception:
            return 0
    if not v:
        return 0
    return l.cstring_cell("cfs.%x" % (hash(v) & 0xFFFFFFFF), v)


@cfunc("_CFStringGetBytes")
def _CFStringGetBytes(l, s, rng_loc, rng_len, encoding, lossByte,
                      isExternal, buf, maxBytes, usedBytes):
    """9-arg API: (string, range{loc,len}, enc, lossByte, isExternal,
    buffer, maxBufLen, *usedBufLen-on-stack)."""
    v = _cfs_value(l, s) or ""
    enc = encoding & 0xFFFFFFFF
    if enc == 0x14000100:
        b = v.encode("utf-16-le")
    elif enc == 0x10000100:
        b = v.encode("utf-16-be")
    elif enc == 0x0100:
        b = v.encode("utf-16-le")
    else:
        b = v.encode("utf-8")
    if rng_loc and rng_len:
        # copy only the requested sub-range (character-based)
        v2 = v[rng_loc:rng_loc + rng_len]
        if enc == 0x14000100 or enc == 0x0100:
            b = v2.encode("utf-16-le")
        elif enc == 0x10000100:
            b = v2.encode("utf-16-be")
        else:
            b = v2.encode("utf-8")
    if buf and maxBytes:
        n = min(len(b), maxBytes)
        l.wrb(buf, b[:n])
        if usedBytes:
            l.w64(usedBytes, n)
        return n
    # size-query call (buffer NULL): report the bytes that WOULD be used
    if usedBytes:
        l.w64(usedBytes, len(b))
    return len(b)


@cfunc("_CFStringCreateWithCString", "_CFStringCreateWithCStringNoCopy",
       "_CFStringCreateMutable", "_CFStringCreateCopy")
def _cf_str_create2(l, alloc, *a):
    if a and a[0]:
        try:
            s = l.gcstr(a[0], maxlen=1 << 20)
        except Exception:
            s = ""
    else:
        s = ""
    g = l.objc.new_ghost("NSString", {"str": s})
    return g.addr


@cfunc("_CFStringCreateWithBytes")
def _cf_str_create_bytes(l, alloc, bytes_ptr, len_, encoding, is_ext):
    b = l.rdb(bytes_ptr, len_) if bytes_ptr and len_ > 0 else b""
    g = l.objc.new_ghost("NSString", {"str": b.decode("utf-8", "replace")})
    return g.addr


@cfunc("_CFStringGetCharacters")
def _cf_str_getchars(l, s, rng, buf):
    v = _cfs_value(l, s) or ""
    if buf and v:
        l.wrb(buf, v.encode("utf-16-le"))
    return 0


@cfunc("_CFStringGetCharacterAtIndex")
def _cf_str_getchar(l, s, idx):
    v = _cfs_value(l, s) or ""
    return ord(v[idx]) if 0 <= idx < len(v) else 0


@cfunc("_CFStringIsEqualToCString")
def _cf_str_iscstr(l, s, cstr):
    v = _cfs_value(l, s) or ""
    return 1 if v == (l.gcstr(cstr) if cstr else "") else 0


@cfunc("_CFStringAppendCString")
def _cf_str_appendcstr(l, ms, cstr):
    g = l.objc.objects.get(ms) if ms else None
    if g is not None:
        g.fields["str"] = (g.fields.get("str") or "") + (
            l.gcstr(cstr) if cstr else "")
        g.fields.pop("cptr", None)
    return 0


@cfunc("_CFStringSetCString")
def _cf_str_setcstr(l, ms, cstr):
    g = l.objc.objects.get(ms) if ms else None
    if g is not None:
        g.fields["str"] = l.gcstr(cstr) if cstr else ""
        g.fields.pop("cptr", None)
    return 0


@cfunc("_CFStringCreateMutableCopy", "_CFStringCreateCopy0")
def _cf_str_mcopy(l, alloc, s):
    v = _cfs_value(l, s) or ""
    g = l.objc.new_ghost("NSMutableString", {"str": v})
    return g.addr


@cfunc("_CFStringGetTypeID")
def _cf_str_typeid(l):
    return 0x1001
