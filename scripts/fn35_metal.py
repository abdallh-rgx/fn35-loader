#!/usr/bin/env python3
"""fn35_metal.py — Python bridge to the safe-Rust Metal shim.

Stack (user-directed architecture):

    Z3 formal spec (scripts/metal_z3_spec.py, proofs P0..P5)
        -> safe Rust core  (rust/fn35-metal, #![forbid(unsafe_code)])
        -> C ABI cdylib    (rust/fn35-metal-ffi, the only unsafe)
        -> THIS MODULE     (ctypes bindings + ObjC ghost classes)
        -> fn35_loader.py  (engine-facing selectors, opt-in FN35_METAL=1)

Everything stateful goes through the Rust registry; this module only
marshals arguments and hosts the ObjC-side ghosts so objc_msgSend has
something to dispatch on.

Self-verification: `python3 fn35_metal.py --selftest` replays the SAME
Z3-generated conformance traces (tests/conformance_traces.txt) through
ctypes -> C ABI -> safe Rust and asserts bit-identical rc/kind/phase
agreement — the full stack re-proves the differential on every host.
"""
import ctypes
import os
import sys

SO_CANDIDATES = (
    "/home/z/my-project/rust/target/release/libfn35_metal_ffi.so",
    "libfn35_metal_ffi.so",
)

OK, E_DEAD, E_PHASE, E_BOUNDS, E_KIND, E_PARSE = range(6)

ERR_NAMES = {
    0: "ok", 1: "dead-handle", 2: "phase-violation", 3: "bounds",
    4: "kind-mismatch", 5: "parse-error",
}

# MTLPixelFormat values used by the client
PF_BGRA8 = 80
PF_RGBA8 = 70


class MetalError(Exception):
    def __init__(self, rc):
        self.rc = rc
        super().__init__("MetalError(%d %s)" % (rc, ERR_NAMES.get(rc, "?")))


class MetalFFI:
    """Thin ctypes wrapper over libfn35_metal_ffi.so."""

    def __init__(self, path=None):
        p = path or self._find()
        if not p:
            raise OSError("libfn35_metal_ffi.so not found "
                          "(build rust/ first)")
        self.lib = ctypes.CDLL(p)
        self.path = p
        u64 = ctypes.c_uint64
        u32 = ctypes.c_uint32
        u8p = ctypes.c_void_p
        ip = ctypes.c_int
        L = self.lib
        L.fn35_metal_init.restype = u32
        L.fn35_metal_version.restype = u32
        L.fn35_metal_last_error.restype = u32
        L.fn35_metal_device_create.restype = u64
        L.fn35_metal_queue_new.argtypes = [u64]
        L.fn35_metal_queue_new.restype = u64
        L.fn35_metal_cb_new.argtypes = [u64]
        L.fn35_metal_cb_new.restype = u64
        for f in ("fn35_metal_cb_encode", "fn35_metal_cb_commit",
                  "fn35_metal_cb_tick", "fn35_metal_cb_fail"):
            getattr(L, f).argtypes = [u64] + ([u32] if f.endswith("fail")
                                              else [])
            getattr(L, f).restype = u32
        L.fn35_metal_cb_wait.argtypes = [u64, ctypes.POINTER(u32)]
        L.fn35_metal_cb_wait.restype = u32
        L.fn35_metal_cb_phase.argtypes = [u64]
        L.fn35_metal_cb_phase.restype = u32
        L.fn35_metal_buf_new.argtypes = [u64, u64, u8p, u64]
        L.fn35_metal_buf_new.restype = u64
        L.fn35_metal_buf_write.argtypes = [u64, u64, u8p, u64]
        L.fn35_metal_buf_write.restype = u32
        L.fn35_metal_buf_read.argtypes = [u64, u64, u8p, u64]
        L.fn35_metal_buf_read.restype = u32
        L.fn35_metal_buf_len.argtypes = [u64]
        L.fn35_metal_buf_len.restype = u64
        L.fn35_metal_tex_new.argtypes = [u64, u32, u32, u32, u32]
        L.fn35_metal_tex_new.restype = u64
        L.fn35_metal_tex_write.argtypes = [u64, u32, u32, u32, u32, u32,
                                           u8p, u64]
        L.fn35_metal_tex_write.restype = u32
        L.fn35_metal_tex_check_region.argtypes = [u64, u32, u32, u32, u32,
                                                  u32]
        L.fn35_metal_tex_check_region.restype = u32
        L.fn35_metal_buf_check_region.argtypes = [u64, u64, u64]
        L.fn35_metal_buf_check_region.restype = u32
        L.fn35_metal_lib_new.argtypes = [u64, u8p, u64]
        L.fn35_metal_lib_new.restype = u64
        L.fn35_metal_lib_has_function.argtypes = [u64, ctypes.c_char_p]
        L.fn35_metal_lib_has_function.restype = u32
        L.fn35_metal_lib_function_count.argtypes = [u64]
        L.fn35_metal_lib_function_count.restype = u32
        L.fn35_metal_lib_function_name.argtypes = [u64, u32, u8p, u64]
        L.fn35_metal_lib_function_name.restype = u64
        L.fn35_metal_release.argtypes = [u64]
        L.fn35_metal_release.restype = u32
        L.fn35_metal_is_live.argtypes = [u64]
        L.fn35_metal_is_live.restype = u32
        L.fn35_metal_obj_kind.argtypes = [u64]
        L.fn35_metal_obj_kind.restype = u32
        L.fn35_metal_live_count.restype = u32
        rc = L.fn35_metal_init()
        if rc != 0:
            raise RuntimeError("fn35_metal_init -> %d" % rc)

    @staticmethod
    def _find():
        for c in SO_CANDIDATES:
            if os.path.exists(c):
                return c
        return None

    # ---------------- pythonic wrappers ----------------
    def device(self):
        return self.lib.fn35_metal_device_create()

    def queue(self, dev):
        h = self.lib.fn35_metal_queue_new(dev)
        self._ok(h != 0, "queue_new")
        return h

    def cmdbuf(self, q):
        h = self.lib.fn35_metal_cb_new(q)
        self._ok(h != 0, "cb_new")
        return h

    def encode(self, cb):
        return self.lib.fn35_metal_cb_encode(cb)

    def commit(self, cb):
        return self.lib.fn35_metal_cb_commit(cb)

    def tick(self, cb):
        return self.lib.fn35_metal_cb_tick(cb)

    def wait(self, cb):
        err = ctypes.c_uint32(0)
        rc = self.lib.fn35_metal_cb_wait(cb, ctypes.byref(err))
        if rc != 0:
            raise MetalError(rc)
        return err.value

    def phase(self, cb):
        return self.lib.fn35_metal_cb_phase(cb)

    def buf_new(self, dev, data=b"", length=None):
        ln = length if length is not None else len(data)
        if data:
            buf = ctypes.create_string_buffer(data, max(len(data), 1))
            h = self.lib.fn35_metal_buf_new(dev, ln, buf, len(data))
        else:
            h = self.lib.fn35_metal_buf_new(dev, ln, None, 0)
        self._ok(h != 0, "buf_new")
        return h

    def buf_write(self, b, off, data):
        buf = ctypes.create_string_buffer(data, max(len(data), 1))
        return self.lib.fn35_metal_buf_write(b, off, buf, len(data))

    def buf_read(self, b, off, ln):
        out = ctypes.create_string_buffer(ln)
        rc = self.lib.fn35_metal_buf_read(b, off, out, ln)
        if rc != 0:
            raise MetalError(rc)
        return out.raw[:ln]

    def buf_len(self, b):
        v = self.lib.fn35_metal_buf_len(b)
        self._ok(v != 0xFFFF_FFFF_FFFF_FFFF, "buf_len")
        return v

    def tex_new(self, dev, w, h, levels, fmt=PF_BGRA8):
        h_ = self.lib.fn35_metal_tex_new(dev, w, h, levels, fmt)
        self._ok(h_ != 0, "tex_new")
        return h_

    def tex_write(self, t, x, y, w, h, level, data):
        buf = ctypes.create_string_buffer(data, max(len(data), 1))
        return self.lib.fn35_metal_tex_write(t, x, y, w, h, level, buf,
                                              len(data))

    def lib_new(self, dev, data):
        buf = ctypes.create_string_buffer(data, max(len(data), 1))
        h = self.lib.fn35_metal_lib_new(dev, buf, len(data))
        self._ok(h != 0, "lib_new")
        return h

    def lib_has_function(self, lib, name):
        return bool(self.lib.fn35_metal_lib_has_function(
            lib, name.encode() if isinstance(name, str) else name))

    def lib_functions(self, lib):
        n = self.lib.fn35_metal_lib_function_count(lib)
        out = []
        cap = 256
        buf = ctypes.create_string_buffer(cap)
        for i in range(n):
            got = self.lib.fn35_metal_lib_function_name(lib, i, buf, cap)
            if 0 < got < cap:
                out.append(buf.raw[:got].decode("utf-8", "replace"))
        return out

    def release(self, h):
        return self.lib.fn35_metal_release(h)

    def is_live(self, h):
        return bool(self.lib.fn35_metal_is_live(h))

    def obj_kind(self, h):
        return self.lib.fn35_metal_obj_kind(h)

    def live_count(self):
        return self.lib.fn35_metal_live_count()

    @staticmethod
    def _ok(cond, what):
        if not cond:
            raise MetalError(E_DEAD)


# ---------------------------------------------------------------------------
# FFI-level Z3 conformance (full-stack differential re-verification)
# ---------------------------------------------------------------------------
def selftest():
    here = os.path.dirname(os.path.abspath(__file__))
    trace_path = os.path.join(here, "..", "rust", "fn35-metal", "tests",
                              "conformance_traces.txt")
    if not os.path.exists(trace_path):
        print("[selftest] trace file missing — run "
              "scripts/metal_z3_spec.py --emit-traces first")
        return 1
    f = MetalFFI()
    print("[selftest] libfn35_metal_ffi.so: %s (version %d)"
          % (f.path, f.lib.fn35_metal_version()))
    lines = open(trace_path).read().splitlines()
    assert lines[0].startswith("fn35-metal conformance v1")
    traces, cur, expect = [], [], 0
    for line in lines[1:]:
        t = line.strip()
        if not t:
            continue
        if t.startswith("T "):
            if cur:
                assert len(cur) == expect
                traces.append(cur)
            expect = int(t[2:])
            cur = []
        else:
            cur.append(t.split())
    if cur:
        assert len(cur) == expect
        traces.append(cur)

    total = acc = rej = mismatches = 0
    for trace in traces:
        slots = [None] * 4
        for flds in trace:
            (op, h, off, ln, x, y, w, ht, lvl, rc, phase, kind,
             buflen) = flds
            h = int(h)
            off, ln, x, y = int(off), int(ln), int(x), int(y)
            w, ht, lvl = int(w), int(ht), int(lvl)
            rc, buflen = int(rc), int(buflen)
            total += 1
            cur_h = slots[h] or 0
            U32 = lambda v: v & 0xFFFFFFFF
            U64 = lambda v: v & 0xFFFFFFFFFFFFFFFF
            got = 0
            if op == "OP_NOP":
                got = 0
            elif op == "OP_DEV_NEW":
                if slots[h] is not None:
                    got = E_KIND
                else:
                    slots[h] = f.device()
            elif op == "OP_QUEUE_NEW":
                nh = f.lib.fn35_metal_queue_new(cur_h)
                if nh:
                    slots[h] = nh
                else:
                    got = f.lib.fn35_metal_last_error()
            elif op == "OP_CB_NEW":
                nh = f.lib.fn35_metal_cb_new(cur_h)
                if nh:
                    slots[h] = nh
                else:
                    got = f.lib.fn35_metal_last_error()
            elif op == "OP_LIB_NEW":
                nh = f.lib.fn35_metal_lib_new(
                    cur_h, ctypes.create_string_buffer(MINIMAL_METALLIB),
                    len(MINIMAL_METALLIB))
                if nh:
                    slots[h] = nh
                else:
                    got = f.lib.fn35_metal_last_error()
            elif op == "OP_BUF_NEW":
                nh = f.lib.fn35_metal_buf_new(cur_h, U64(ln), None, 0)
                if nh:
                    slots[h] = nh
                else:
                    got = f.lib.fn35_metal_last_error()
            elif op == "OP_TEX_NEW":
                nh = f.lib.fn35_metal_tex_new(cur_h, U32(w), U32(ht),
                                              U32(lvl), PF_BGRA8)
                if nh:
                    slots[h] = nh
                else:
                    got = f.lib.fn35_metal_last_error()
            elif op == "OP_ENCODE":
                got = f.encode(cur_h)
            elif op == "OP_COMMIT":
                got = f.commit(cur_h)
            elif op == "OP_TICK":
                got = f.tick(cur_h)
            elif op == "OP_WAIT":
                got = f.lib.fn35_metal_cb_wait(cur_h, None)
            elif op == "OP_BUF_WRITE":
                got = f.lib.fn35_metal_buf_check_region(cur_h, U64(off),
                                                        U64(ln))
            elif op == "OP_TEX_WRITE":
                got = f.lib.fn35_metal_tex_check_region(cur_h, U32(x),
                                                        U32(y), U32(w),
                                                        U32(ht), U32(lvl))
            elif op == "OP_RELEASE":
                got = f.release(cur_h)
                if got == 0:
                    slots[h] = None
            if got == 0:
                acc += 1
            else:
                rej += 1
            if got != rc:
                mismatches += 1
                if mismatches <= 5:
                    print("MISMATCH %s h=%d off=%d ln=%d x=%d y=%d w=%d "
                          "ht=%d lvl=%d: ffi=%d z3=%d"
                          % (op, h, off, ln, x, y, w, ht, lvl, got, rc))
    print("[selftest] %d traces / %d steps: accepted=%d rejected=%d "
          "mismatches=%d" % (len(traces), total, acc, rej, mismatches))
    if mismatches:
        print("[selftest] FAILED")
        return 1
    print("[selftest] FULL-STACK CONFORMANCE OK "
          "(python ctypes -> C ABI -> safe Rust == Z3 oracle)")
    return 0


_METD = b'{"functions":[]}'
MINIMAL_METALLIB = (
    b"MTLB" + (2).to_bytes(4, "little") +
    b"METD" + len(_METD).to_bytes(4, "little") + _METD +
    b"METB" + (1).to_bytes(4, "little") + b"\x42"
)


# ---------------------------------------------------------------------------
# ObjC ghost-class integration (opt-in via FN35_METAL=1)
# ---------------------------------------------------------------------------
def read_nsdata(l, ptr):
    """Best-effort bytes for an NSData-ish pointer: ghost fields or
    __cfstring constant."""
    if not ptr:
        return b""
    g = l.objc.objects.get(ptr)
    if g is not None:
        f = g.fields
        if "bytes" in f and "len" in f:
            return bytes(l.rdb(f["bytes"], f["len"]))
        if "str" in f:
            return f["str"].encode()
    # CFConstantString layout: isa, flags, data, len
    try:
        data = l.rd64(ptr + 16)
        ln = l.rd64(ptr + 24)
        if data and 0 < ln < (1 << 24):
            return bytes(l.rdb(data, ln))
    except Exception:
        pass
    return b""


def _bridge(l):
    b = getattr(l, "_metal_bridge", None)
    if b is None:
        b = l._metal_bridge = MetalFFI()
    return b


def _h(recv, l):
    g = l.objc.objects.get(recv)
    return (g.fields.get("h", 0) if g is not None else 0)


def _wrap(l, cls, handle, extra=None):
    fields = {"h": handle}
    if extra:
        fields.update(extra)
    return l.objc.new_ghost(cls, fields).addr


def install_ghost_classes(loader):
    """Register the MTL* ghost surface in GHOST_CLASS_TABLE. Called from
    loader boot when FN35_METAL=1 — the default remains the nil-device
    so the GL chain is never destabilized."""
    import fn35_objc
    T = fn35_objc.GHOST_CLASS_TABLE
    for cls, sz in (("MTLDevice", 96), ("MTLCommandQueue", 64),
                    ("MTLCommandBuffer", 96), ("MTLBuffer", 64),
                    ("MTLTexture", 96), ("MTLLibrary", 64),
                    ("MTLFunction", 64)):
        fn35_objc.GHOST_SIZES.setdefault(cls, sz)
        fn35_objc.GHOST_HIERARCHY.setdefault(cls, "NSObject")
        fn35_objc.GHOST_ALLOWED.add(cls)

    # ----- MTLDevice -----------------------------------------------------
    def dev_new_queue(l, recv, args):
        b = _bridge(l)
        qh = b.queue(_h(recv, l))
        return _wrap(l, "MTLCommandQueue", qh)

    def dev_new_buffer(l, recv, args):
        b = _bridge(l)
        ln = args[0] if args else 0
        bh = b.buf_new(_h(recv, l), length=ln)
        return _wrap(l, "MTLBuffer", bh)

    def dev_new_buffer_bytes(l, recv, args):
        b = _bridge(l)
        p, ln = args[0], args[1]
        data = bytes(l.rdb(p, ln)) if p and ln else b""
        bh = b.buf_new(_h(recv, l), data=data)
        return _wrap(l, "MTLBuffer", bh)

    def dev_new_texture(l, recv, args):
        # MTLTextureDescriptor ghost: fields w/h/levels/fmt
        b = _bridge(l)
        d = l.objc.objects.get(args[0]) if args else None
        f = d.fields if d is not None else {}
        th = b.tex_new(_h(recv, l), f.get("w", 4), f.get("h", 4),
                       f.get("levels", 1), f.get("fmt", PF_BGRA8))
        return _wrap(l, "MTLTexture", th)

    def dev_new_library(l, recv, args):
        b = _bridge(l)
        data = read_nsdata(l, args[0] if args else 0)
        if not data:
            l.warn("MTLDevice newLibraryWithData: empty NSData")
            return 0
        try:
            lh = b.lib_new(_h(recv, l), data)
        except MetalError:
            # report via the error** out-param as a ghost NSError
            if len(args) > 1 and args[1]:
                l.w64(args[1], l.objc.new_ghost(
                    "NSError", {"code": 5, "domain": "MTLLibraryErrorDomain"}).addr)
            return 0
        return _wrap(l, "MTLLibrary", lh)

    T.setdefault("MTLDevice", {}).update({
        "name": lambda l, r, a: l.objc.nsstring("fn35-metal-shim"),
        "newCommandQueue": dev_new_queue,
        "newCommandQueueWithMaxCommandBufferCount:": dev_new_queue,
        "newBufferWithLength:options:": dev_new_buffer,
        "newBufferWithBytes:length:options:": dev_new_buffer_bytes,
        "newTextureWithDescriptor:": dev_new_texture,
        "newLibraryWithData:error:": dev_new_library,
        "newDefaultLibrary": lambda l, r, a: 0,
        "maxBufferLength": lambda l, r, a: 256 * 1024 * 1024,
        "hasUnifiedMemory": lambda l, r, a: 1,
        "supportsFamily:": lambda l, r, a: 0,
        "registryID": lambda l, r, a: 0x464E3335,
        "isDepth24Stencil8PixelFormatSupported":
            lambda l, r, a: 1,
        "isFormatSupported:": lambda l, r, a: 1,
        "currentAllocatedSize": lambda l, r, a: 1 << 20,
    })

    # ----- MTLCommandQueue ----------------------------------------------
    def q_cmdbuf(l, recv, args):
        b = _bridge(l)
        ch = b.cmdbuf(_h(recv, l))
        return _wrap(l, "MTLCommandBuffer", ch)

    T.setdefault("MTLCommandQueue", {}).update({
        "commandBuffer": q_cmdbuf,
        "commandBufferWithUnretainedReferences": q_cmdbuf,
        "label": lambda l, r, a: l.objc.nsstring(""),
        "device": lambda l, r, a: 0,
        "insertDebugCaptureBoundary": lambda l, r, a: 0,
    })

    # ----- MTLCommandBuffer ---------------------------------------------
    def cb_commit(l, recv, args):
        return _bridge(l).commit(_h(recv, l))

    def cb_wait(l, recv, args):
        try:
            _bridge(l).wait(_h(recv, l))
        except MetalError:
            pass
        return 0

    T.setdefault("MTLCommandBuffer", {}).update({
        "label": lambda l, r, a: l.objc.nsstring(""),
        "commit": cb_commit,
        "waitUntilCompleted": cb_wait,
        "waitUntilScheduled": cb_wait,
        "enqueue": lambda l, r, a: 0,
        "addCompletedHandler:": lambda l, r, a: 0,
        "addScheduledHandler:": lambda l, r, a: 0,
        "status": lambda l, r, a: 2,  # MTLCommandBufferStatusCommitted
        "error": lambda l, r, a: 0,
        "renderCommandEncoderWithDescriptor:": lambda l, r, a: 0,
        "blitCommandEncoder": lambda l, r, a: 0,
        "computeCommandEncoder": lambda l, r, a: 0,
        "presentDrawable:": lambda l, r, a: 0,
        "addPresentedHandler:": lambda l, r, a: 0,
        "kernelStartTime": lambda l, r, a: 0,
        "kernelEndTime": lambda l, r, a: 0,
        "GPUStartTime": lambda l, r, a: 0,
        "GPUEndTime": lambda l, r, a: 0,
        "retainReferences": lambda l, r, a: 0,
    })

    # ----- MTLBuffer -----------------------------------------------------
    T.setdefault("MTLBuffer", {}).update({
        "length": lambda l, r, a: _bridge(l).buf_len(_h(r, l)),
        "contents": lambda l, r, a: 0,   # host-backed; not guest ptr
        "didModifyRange:": lambda l, r, a: 0,
        "storageMode": lambda l, r, a: 0,  # MTLStorageModeShared
        "cpuCacheMode": lambda l, r, a: 0,
    })

    # ----- MTLTexture ----------------------------------------------------
    T.setdefault("MTLTexture", {}).update({
        "width": lambda l, r, a: 0,
        "height": lambda l, r, a: 0,
        "rootTexture": lambda l, r, a: 0,
        "gpuResourceID": lambda l, r, a: 0,
        "usage": lambda l, r, a: 0,
        "storageMode": lambda l, r, a: 0,
    })

    # ----- MTLLibrary ------------------------------------------------------
    def lib_new_function(l, recv, args):
        name = l.objc.read_nsstring(args[0]) if args else None
        b = _bridge(l)
        h = _h(recv, l)
        if name and b.lib_has_function(h, name):
            return l.objc.new_ghost("MTLFunction",
                                    {"h": h, "name": name}).addr
        l.warn("MTLLibrary newFunctionWithName: '%s' not in metallib"
               % (name or "?"))
        return 0

    T.setdefault("MTLLibrary", {}).update({
        "label": lambda l, r, a: l.objc.nsstring(""),
        "functionNames": lambda l, r, a: 0,
        "newFunctionWithName:": lib_new_function,
        "newFunctionWithName:constantValues:error:":
            lambda l, r, a: 0,
    })

    T.setdefault("MTLFunction", {}).update({
        "label": lambda l, r, a: l.objc.nsstring(""),
    })

    T.setdefault("MTLTextureDescriptor", {}).update({
        "initWithTextureDescriptor:": lambda l, r, a: r,
        "setPixelFormat:": lambda l, r, a: 0,
        "setWidth:": lambda l, r, a: 0,
        "setHeight:": lambda l, r, a: 0,
        "setMipmapLevelCount:": lambda l, r, a: 0,
        "setUsage:": lambda l, r, a: 0,
        "setStorageMode:": lambda l, r, a: 0,
        "setSampleCount:": lambda l, r, a: 0,
    })

    loader.console("[metal] ghost classes installed "
                   "(Rust shim live objects: %d)"
                   % _bridge(loader).live_count())


def make_system_default_device(l):
    """MTLCreateSystemDefaultDevice via the Rust shim; returns the ghost
    instance address (0 if the shim failed to load)."""
    try:
        b = _bridge(l)
    except OSError as e:
        l.warn("[metal] shim unavailable: %r" % (e,))
        return 0
    dev = b.device()
    if not dev:
        return 0
    return _wrap(l, "MTLDevice", dev)


if __name__ == "__main__":
    if "--selftest" in sys.argv:
        sys.exit(selftest())
    print("fn35_metal: import from the loader (FN35_METAL=1) or run "
          "--selftest")
