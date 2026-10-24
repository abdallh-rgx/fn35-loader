#!/usr/bin/env python3
"""FN3.5 loader: real OpenGL ES via Mesa/llvmpipe (offscreen, no GPU).

Bridges the 95 OpenGL ES imports of the Fortnite binary to a real
software-rendered EGL context (surfaceless platform + pbuffer), so the
game's own GL ES RHI renders actual pixels. Every call reads/writes guest
memory transparently. presentRenderbuffer captures the frame to PNG.

Registers implementations into fn35_clib.IMPL (loaded after fn35_ioslib
so it replaces the GL trace stubs).
"""
import ctypes
import os
import struct
import sys

from fn35_clib import cfunc, IMPL

_TRACE_GL = bool(os.environ.get("FN35_TRACE_GL"))
SCREEN_W = 1280
SCREEN_H = 720

GLES = None          # module singleton state
CAPTURE_DIR = "/home/z/my-project/download/fn35/screenshots"
MAX_SHOTS = int(os.environ.get("FN35_MAX_SHOTS", "400"))


def _setup_env():
    os.environ.setdefault("EGL_PLATFORM", "surfaceless")
    os.environ.setdefault("LIBGL_ALWAYS_SOFTWARE", "1")
    os.environ.setdefault("GALLIUM_DRIVER", "llvmpipe")
    os.environ.setdefault("MESA_DEBUG", "silent")
    os.environ.setdefault("__EGL_VENDOR_LIBRARY_FILENAMES",
                          "/home/z/mesa-debs/glvnd/50_mesa.json")


class GLState:
    def __init__(self):
        _setup_env()
        self.lib = None
        self.display = None
        self.context = None
        self.surface = None
        self.fn = {}
        self._proc_cache = {}
        self.ready = False
        self.shots = 0
        self.present_count = 0
        self.mapped = {}        # guest buffer -> host ctypes buffer info
        self.sync_id = 0
        self.sync_map = {}       # guest id -> host sync ptr
        self.query_map = {}
        self.fbo_stack = []
        self.gl_errors = []

    # ---------------- context ----------------
    def init(self):
        if self.ready:
            return True
        try:
            from PIL import Image  # noqa: F401
            self._pil = Image
        except Exception:
            self._pil = None
        try:
            lib = ctypes.CDLL("libEGL.so.1")
        except OSError:
            # local deb extraction (no root in this sandbox)
            lib = ctypes.CDLL(
                "/home/z/mesa-debs/root/usr/lib/x86_64-linux-gnu/"
                "libEGL.so.1")
        self.lib = lib
        c_vp = ctypes.c_void_p
        i32 = ctypes.c_int32
        u32 = ctypes.c_uint32

        lib.eglGetPlatformDisplay.restype = c_vp
        lib.eglGetPlatformDisplay.argtypes = [u32, c_vp, c_vp]
        lib.eglInitialize.restype = u32
        lib.eglInitialize.argtypes = [c_vp, ctypes.POINTER(i32), ctypes.POINTER(i32)]
        lib.eglQueryString.restype = ctypes.c_char_p
        lib.eglQueryString.argtypes = [c_vp, u32]
        lib.eglChooseConfig.restype = u32
        lib.eglChooseConfig.argtypes = [c_vp, ctypes.POINTER(i32),
                                        ctypes.POINTER(c_vp), i32,
                                        ctypes.POINTER(i32)]
        lib.eglBindAPI.restype = u32
        lib.eglBindAPI.argtypes = [u32]
        lib.eglCreateContext.restype = c_vp
        lib.eglCreateContext.argtypes = [c_vp, c_vp, c_vp, ctypes.POINTER(i32)]
        lib.eglCreatePbufferSurface.restype = c_vp
        lib.eglCreatePbufferSurface.argtypes = [c_vp, c_vp, ctypes.POINTER(i32)]
        lib.eglMakeCurrent.restype = u32
        lib.eglMakeCurrent.argtypes = [c_vp, c_vp, c_vp, c_vp]
        lib.eglGetProcAddress.restype = c_vp
        lib.eglGetProcAddress.argtypes = [ctypes.c_char_p]
        lib.eglSwapBuffers.restype = u32
        lib.eglSwapBuffers.argtypes = [c_vp, c_vp]

        d = lib.eglGetPlatformDisplay(0x31DD, None, None)   # surfaceless
        if not d:
            raise RuntimeError("no EGL display (surfaceless)")
        self.display = d
        if not lib.eglInitialize(d, None, None):
            raise RuntimeError("eglInitialize failed")
        attribs = (i32 * 20)(
            0x3033, 0x0001,          # EGL_SURFACE_TYPE = PBUFFER
            0x3040, 0x0040,          # EGL_RENDERABLE_TYPE = ES3
            0x3024, 8, 0x3023, 8, 0x3022, 8, 0x3021, 8,
            0x3025, 24, 0x3026, 8,
            0x3038)
        cfgs = (c_vp * 8)()
        n = i32(0)
        if not lib.eglChooseConfig(d, attribs, cfgs, 8, ctypes.byref(n)) \
                or n.value == 0:
            raise RuntimeError("eglChooseConfig failed")
        pattr = (i32 * 5)(0x3056, SCREEN_W, 0x3057, SCREEN_H, 0x3038)
        self.surface = lib.eglCreatePbufferSurface(d, cfgs[0], pattr)
        cattr = (i32 * 3)(0x3098, 3, 0x3038)              # ES3 context
        self.context = lib.eglCreateContext(d, cfgs[0], None, cattr)
        if not self.surface or not self.context:
            raise RuntimeError("context/surface creation failed")
        lib.eglBindAPI(0x30A0)
        if not lib.eglMakeCurrent(d, self.surface, self.surface, self.context):
            raise RuntimeError("eglMakeCurrent failed")
        self.ready = True
        self.gstr(0x1F01) and None
        print("[gl] Mesa context ready: %s | %s" % (
            self.gstr(0x1F01), self.gstr(0x1F02)), file=sys.stderr, flush=True)
        return True

    def proc(self, name):
        """RAW eglGetProcAddress address (int) for a GL entry point.
        Callers wrap it ONCE with CFUNCTYPE. (Returning a pre-wrapped
        CFunctionType here used to cause double-wrapping at call sites
        -- a guaranteed host segfault.)"""
        a = self._proc_cache.get(name)
        if a is None:
            a = self.lib.eglGetProcAddress(name.encode())
            if not a:
                raise AttributeError("gl proc missing: " + name)
            self._proc_cache[name] = a
        return a

    def gstr(self, enum):
        f = self.fn.get("glGetString")
        if f is None:
            a = self.lib.eglGetProcAddress(b"glGetString")
            f = ctypes.CFUNCTYPE(ctypes.c_char_p, ctypes.c_uint)(a)
            self.fn["glGetString"] = f
        return f(enum)

    # ---------------- capture ----------------
    def capture(self, tag="frame"):
        if not self.ready:
            return
        self.present_count += 1
        try:
            W, H = SCREEN_W, SCREEN_H
            buf = ctypes.create_string_buffer(W * H * 4)
            self.read_pixels(0, 0, W, H, 0x1908, 0x1401, buf)
            raw = buf.raw
            # alpha channel from pbuffer may be 0; force opaque
            b = bytearray(raw)
            b[3::4] = b"\xff" * (W * H)
            if self._pil is None:
                return
            img = self._pil.frombytes("RGBA", (W, H), bytes(b), "raw",
                                      "RGBA", 0, 1)
            os.makedirs(CAPTURE_DIR, exist_ok=True)
            path = os.path.join(CAPTURE_DIR,
                                "%04d_%s.png" % (self.shots, tag))
            img.save(path)
            self.shots += 1
            print("[gl] captured %s -> %s" % (tag, path),
                  file=sys.stderr, flush=True)
        except Exception as e:
            print("[gl] capture failed: %r" % (e,), file=sys.stderr,
                  flush=True)

    def read_pixels(self, x, y, w, h, fmt, typ, out):
        f = self.proc("glReadPixels")
        f.argtypes = [ctypes.c_int, ctypes.c_int, ctypes.c_int,
                      ctypes.c_int, ctypes.c_uint, ctypes.c_uint, c_void_p_t]
        f(x, y, w, h, fmt, typ, ctypes.cast(out, c_void_p_t) if not isinstance(
            out, c_void_p_t) else out)


c_void_p_t = ctypes.c_void_p
GLES = GLState()


def _ensure(l):
    if not GLES.ready:
        try:
            GLES.init()
            l.console("[gl] llvmpipe context online (%s)" %
                      GLES.gstr(0x1F01).decode())
        except Exception as e:
            l.warn("GL init failed: %r" % (e,))
            return False
    return True


# ====================================================================
# helpers: guest memory <-> host
# ====================================================================

def gbuf(l, addr, size):
    if not addr or size <= 0:
        return None
    try:
        return l.rdb(addr, size)
    except Exception:
        return None


def gw32(l, addr, val):
    try:
        l.w32(addr, val & 0xFFFFFFFF)
    except Exception:
        pass


def argtypes_for(name):
    """Signature table for the GL calls we forward (GLES C ABI)."""
    c = ctypes
    I = c.c_int
    U = c.c_uint
    F = c.c_float
    P = c.c_void_p
    S = {
        # state
        "glClearColor": ([F, F, F, F], None),
        "glClearDepthf": ([F], None),
        "glClearStencil": ([I], None),
        "glClear": ([U], None),
        "glEnable": ([U], None),
        "glDisable": ([U], None),
        "glEnableVertexAttribArray": ([U], None),
        "glDisableVertexAttribArray": ([U], None),
        "glViewport": ([I, I, I, I], None),
        "glScissor": ([I, I, I, I], None),
        "glCullFace": ([U], None),
        "glFrontFace": ([U], None),
        "glBlendFunc": ([U, U], None),
        "glBlendFuncSeparate": ([U, U, U, U], None),
        "glBlendEquation": ([U], None),
        "glBlendEquationSeparate": ([U, U], None),
        "glDepthFunc": ([U], None),
        "glDepthMask": ([U], None),
        "glDepthRangef": ([F, F], None),
        "glColorMask": ([U, U, U, U], None),
        "glStencilFunc": ([U, I, U], None),
        "glStencilFuncSeparate": ([U, U, I, U], None),
        "glStencilOp": ([U, U, U], None),
        "glStencilOpSeparate": ([U, U, U, U], None),
        "glStencilMask": ([U], None),
        "glLineWidth": ([F], None),
        "glPolygonOffset": ([F, F], None),
        "glPixelStorei": ([U, I], None),
        "glFinish": ([], None),
        "glFlush": ([], None),
        "glActiveTexture": ([U], None),
        # shader / program
        "glCreateShader": ([U], U),
        "glCreateProgram": ([], U),
        "glDeleteShader": ([U], None),
        "glDeleteProgram": ([U], None),
        "glCompileShader": ([U], None),
        "glLinkProgram": ([U], None),
        "glUseProgram": ([U], None),
        "glAttachShader": ([U, U], None),
        "glGetShaderiv": ([U, U, P], None),
        "glGetProgramiv": ([U, U, P], None),
        "glGetUniformLocation": ([U, P], I),
        "glGetAttribLocation": ([U, P], I),
        "glBindAttribLocation": ([U, I, P], None),
        "glGetError": ([], U),
        "glIsEnabled": ([U], U),
        "glGetBooleanv": ([U, P], None),
        "glGetIntegerv": ([U, P], None),
        "glGetFloatv": ([U, P], None),
        # buffers
        "glGenBuffers": ([I, P], None),
        "glDeleteBuffers": ([I, P], None),
        "glBindBuffer": ([U, U], None),
        "glBufferData": ([U, U, P, U], None),   # (target, size, data, usage)
        "glBufferSubData": ([U, U, U, P], None),  # (target, offset, size, data)
        "glVertexAttribPointer": ([U, I, U, U, I, P], None),
        "glVertexAttrib4fv": ([U, P], None),
        "glVertexAttribDivisor": ([U, U], None),
        # textures
        "glGenTextures": ([I, P], None),
        "glDeleteTextures": ([I, P], None),
        "glBindTexture": ([U, U], None),
        "glTexParameteri": ([U, U, I], None),
        "glTexParameterf": ([U, U, F], None),
        "glTexImage2D": ([U, I, I, I, I, I, U, U, P], None),
        "glTexSubImage2D": ([U, I, I, I, I, I, U, U, P], None),
        "glCompressedTexImage2D": ([U, I, I, I, I, I, I, P], None),
        "glCompressedTexSubImage2D": ([U, I, I, I, I, I, I, I, P], None),
        "glCopyTextureLevels": ([U, U, I, I], None),
        "glGenerateMipmap": ([U], None),
        "glTexStorage2D": ([U, I, I, I, I], None),
        # draw
        "glDrawArrays": ([U, I, I], None),
        "glDrawElements": ([U, I, U, P], None),
        "glDrawArraysInstanced": ([U, I, I, I], None),
        "glDrawElementsInstanced": ([U, I, U, P, I], None),
        # uniforms
        "glUniform1i": ([I, I], None),
        "glUniform1f": ([I, F], None),
        "glUniform4fv": ([I, I, P], None),
        "glUniform4iv": ([I, I, P], None),
        "glUniformMatrix4fv": ([I, I, U, P], None),
        "glUniform2fv": ([I, I, P], None),
        "glUniform3fv": ([I, I, P], None),
        # framebuffers / renderbuffers
        "glGenFramebuffers": ([I, P], None),
        "glDeleteFramebuffers": ([I, P], None),
        "glBindFramebuffer": ([U, U], None),
        "glFramebufferTexture2D": ([U, U, U, U, I], None),
        "glCheckFramebufferStatus": ([U], U),
        "glGenRenderbuffers": ([I, P], None),
        "glDeleteRenderbuffers": ([I, P], None),
        "glBindRenderbuffer": ([U, U], None),
        "glRenderbufferStorage": ([U, U, I, I], None),
        "glFramebufferRenderbuffer": ([U, U, U, U], None),
        "glGetRenderbufferParameteriv": ([U, U, P], None),
        "glBlitFramebuffer": ([I, I, I, I, I, I, I, I, U], None),
        "glInvalidateFramebuffer": ([I, P], None),
        # queries / sync
        "glGenQueries": ([I, P], None),
        "glDeleteQueries": ([I, P], None),
        "glBeginQuery": ([U, U], None),
        "glEndQuery": ([U], None),
        "glGetQueryObjectuiv": ([U, U, P], None),
        "glFenceSync": ([U, U], P),
        "glDeleteSync": ([P], None),
        "glClientWaitSync": ([P, U, c.c_uint64], U),
        # mapping
        "glMapBufferRange": ([U, U, U, U], P),  # ints! (special-handled)
        "glUnmapBuffer": ([U], U),
        "glFlushMappedBufferRange": ([U, U, U], None),
    }
    return S.get(name)


_P_T = ctypes.c_void_p

_P_OUT = {          # out-params: {name: (arg_idx, nbytes_to_copy_back)}
    "glGetRenderbufferParameteriv": (2, 4),
    "glGetFramebufferAttachmentParameteriv": (2, 4),
    "glGetShaderiv": (2, 4),
    "glGetProgramiv": (2, 4),
    "glGetBufferParameteriv": (2, 4),
    "glGetIntegerv": (1, 64),
    "glGetBooleanv": (1, 64),
    "glGetFloatv": (1, 64),
    "glGetProgramInfoLog": (2, 4),
    "glGetShaderInfoLog": (2, 4),
}

# in-pointers: {name: (arg_idx, size_fn(args) -> bytes)}; guest data is
# copied to a host buffer before handing it to Mesa
def _tex_bpp(fmt, typ):
    if typ == 0x1401:                       # GL_UNSIGNED_BYTE
        if fmt == 0x1908:                   # RGBA
            return 4
        if fmt == 0x1907:                   # RGB
            return 3
        if fmt in (0x1903, 0x6403):         # RED / LUMINANCE
            return 1
        if fmt in (0x190A, 0x8005):         # BGRA / COMPRESSED
            return 4
        if fmt in (0x1906, 0x1909, 0x190A):  # ALPHA, LUMINANCE_ALPHA
            return 2
        return 4
    if typ == 0x1403:                       # GL_UNSIGNED_SHORT
        return 2
    if typ == 0x1405:                       # GL_UNSIGNED_INT
        return 4
    if typ == 0x8C3B or typ == 0x8C3A:      # INT_2_10_10_10_REV etc
        return 4
    if typ == 0x140B or typ == 0x140C:      # HALF_FLOAT
        return 2
    if typ == 0x1406:                       # FLOAT
        return 4
    return 4


_P_IN = {
    "glBufferData": (2, lambda a: a[1]),
    "glBufferSubData": (3, lambda a: a[2]),
    "glUniform4fv": (2, lambda a: a[1] * 16),
    "glUniform3fv": (2, lambda a: a[1] * 12),
    "glUniform2fv": (2, lambda a: a[1] * 8),
    "glUniform1fv": (2, lambda a: a[1] * 4),
    "glUniform4iv": (2, lambda a: a[1] * 16),
    "glUniform4iv".replace("4", "2"): (2, lambda a: a[1] * 8),
    "glUniform1iv": (2, lambda a: a[1] * 4),
    "glUniformMatrix4fv": (3, lambda a: a[1] * 64),
    "glUniformMatrix3fv": (3, lambda a: a[1] * 36),
    "glVertexAttrib4fv": (1, lambda a: 16),
    "glCompressedTexImage2D": (7, lambda a: a[6]),
    "glCompressedTexSubImage2D": (8, lambda a: a[7]),
    "glTexImage2D": (8, lambda a: max(a[3] * max(a[4], 1)
                                      * _tex_bpp(a[6], a[7]), 4)),
    "glTexSubImage2D": (8, lambda a: max(a[3] * max(a[4], 1)
                                         * _tex_bpp(a[6], a[7]), 4)),
}

# pointer args that are VBO byte-offsets (integers), not host pointers:
# they must pass through unchanged
_P_PASSTHRU = {
    "glDrawElements": (3,),
    "glDrawElementsInstanced": (3,),
    "glVertexAttribPointer": (5,),
    "glCopyTextureLevels": (),
}


class GLCall:
    """Adapted forwarding for one GL call with guest pointer handling."""
    __slots__ = ("name", "cf", "sig")

    def __init__(self, name):
        self.name = name
        self.cf = None
        self.sig = argtypes_for(name)

    def call(self, l, args):
        name = self.name
        # special cases first
        h = _SPECIAL.get(name)
        if h is not None:
            if _TRACE_GL:
                print("[glcall] %s*" % name, flush=True)
            global _CURRENT_GL
            _CURRENT_GL = name
            return h(l, args)
        if self.sig is None:
            l.trace_gl("%s ???" % name)
            return 0
        if _TRACE_GL:
            print("[glcall] %s(%s)" % (name, ",".join(
                hex(a & 0xFFFFFFFFFFFFFFFF)[:12] for a in args[:8])),
                flush=True)
        ins, outs = self.sig
        cvals = []
        host_out = None                      # (guest_ptr, c_buffer, n)
        for i, t in enumerate(ins):
            a = args[i] if i < len(args) else 0
            if t is None:
                cvals.append(a)
                continue
            # pointer safety: never hand a GUEST address to Mesa
            if t is _P_T:
                if a == 0:
                    cvals.append(None)
                    continue
                pt = _P_PASSTHRU.get(name)
                if pt and i in pt:
                    cvals.append(a & 0xFFFFFFFFFFFFFFFF)   # VBO offset
                    continue
                po = _P_OUT.get(name)
                if po and i == po[0]:
                    host_out = (a, ctypes.create_string_buffer(po[1]),
                                po[1])
                    cvals.append(host_out[1])
                    continue
                pin = _P_IN.get(name)
                if pin is not None and i == pin[0]:
                    try:
                        n = max(0, min(pin[1](args), 1 << 26))
                    except Exception:
                        n = 0
                    if n:
                        data = bytes(l.rdb(a, n))
                        cvals.append(ctypes.create_string_buffer(data, n))
                    else:
                        cvals.append(None)
                    continue
                # default: small bounded copy (pointer-shaped scalar or
                # short data we cannot size -- never the raw guest addr)
                try:
                    data = bytes(l.rdb(a, 64))
                    cvals.append(ctypes.create_string_buffer(data, 64))
                except Exception:
                    cvals.append(None)
                continue
            cvals.append(t(a & 0xFFFFFFFFFFFFFFFF))
        rv = self.fwd(cvals, l, args)
        if host_out is not None:
            try:
                l.wrb(host_out[0], host_out[1].raw[:host_out[2]])
            except Exception:
                pass
        return rv

    def fwd(self, cvals, l, args):
        if self.cf is None:
            f = GLES.proc(self.name)
            ins, outs = self.sig
            at = [t for t in ins if t is not None]
            # NB: CFUNCTYPE(...) is a TYPE -- instantiate it with the
            # resolved proc address, otherwise every call raises
            # "takes exactly 1 argument (N given)".
            self.cf = ctypes.CFUNCTYPE(outs or None, *at)(f)
        return self.cf(*cvals)


def _rd_ptrs(l, args, i_guest, count, fmts):
    return [args[i] if i < len(args) else 0 for i in fmts]


# ---- special handlers (pointer-rich / ES-specific) -------------------

def _sp_maprange(l, args):
    """glMapBufferRange(target, offset, length, access) -> GUEST ptr.
    Mesa returns a HOST pointer; handing it to the engine would make the
    guest write straight into host memory. We mirror the mapping in a
    guest vm buffer instead and sync on unmap/flush."""
    target = args[0] & 0xFFFFFFFF
    offset = args[1] & 0xFFFFFFFFFFFFFFFF
    length = args[2] & 0xFFFFFFFFFFFFFFFF
    access = args[3] & 0xFFFFFFFF
    if not _ensure(l):
        return 0
    try:
        cf = ctypes.CFUNCTYPE(ctypes.c_void_p, ctypes.c_uint,
                              ctypes.c_uint64, ctypes.c_uint64,
                              ctypes.c_uint)(GLES.proc("glMapBufferRange"))
        host = cf(target, offset, min(length, 1 << 30), access)
    except Exception as e:
        l.warn("glMapBufferRange: %r" % (e,))
        return 0
    if not host:
        return 0
    n = min(length, 1 << 30)
    gbuf = l.vm_alloc(max(n, 16))
    if access & 0x1:                       # GL_MAP_READ_BIT: host -> guest
        try:
            l.wrb(gbuf, ctypes.string_at(host, n))
        except Exception:
            pass
    GLES.mapped[target] = (gbuf, host, n, access)
    return gbuf


def _sp_unmap(l, args):
    """glUnmapBuffer(target): flush guest mirror to the host mapping,
    then unmap for real."""
    target = args[0] & 0xFFFFFFFF
    m = GLES.mapped.pop(target, None)
    if m is None:
        try:
            cf = ctypes.CFUNCTYPE(ctypes.c_uint, ctypes.c_uint)(
                GLES.proc("glUnmapBuffer"))
            return cf(target)
        except Exception:
            return 1
    gbuf, host, n, access = m
    if access & 0x2:                       # GL_MAP_WRITE_BIT: guest -> host
        try:
            ctypes.memmove(host, l.rdb(gbuf, n), n) if False else None
            data = bytes(l.rdb(gbuf, n))
            ctypes.memmove(host, data, n)
        except Exception as e:
            l.warn("unmap flush: %r" % (e,))
    try:
        cf = ctypes.CFUNCTYPE(ctypes.c_uint, ctypes.c_uint)(
            GLES.proc("glUnmapBuffer"))
        return cf(target)
    except Exception:
        return 1


def _sp_flushmapped(l, args):
    """glFlushMappedBufferRange(target, offset, length)"""
    target = args[0] & 0xFFFFFFFF
    m = GLES.mapped.get(target)
    if m is None:
        return 0
    gbuf, host, n, access = m
    off = args[1] & 0xFFFFFFFFFFFFFFFF
    ln = min(args[2] & 0xFFFFFFFFFFFFFFFF, max(n - off, 0))
    if ln > 0 and (access & 0x2):
        try:
            data = bytes(l.rdb(gbuf + off, ln))
            ctypes.memmove(host + off, data, ln)
        except Exception as e:
            l.warn("flushmapped: %r" % (e,))
    return 0


def _sp_getstring(l, args):
    """glGetString(name) -> const GLubyte*"""
    enum = args[0] & 0xFFFFFFFF
    vals = {
        0x1F00: b"", 0x1F01: GLES.gstr(0x1F01),
        0x1F02: GLES.gstr(0x1F02), 0x1F03: GLES.gstr(0x1F03),
        0x8B8C: GLES.gstr(0x8B8C),
    }
    v = vals.get(enum, GLES.gstr(enum) or b"")
    # NB: cstring_cell caches BY NAME -- one shared name would return
    # the first string forever (vendor == renderer == version ...).
    # Unique per-enum names keep every GL string distinct.
    return l.cstring_cell("glstr.%x" % enum, v.decode("utf-8", "replace"))


def _sp_getstringi(l, args):
    """glGetStringi(GL_EXTENSIONS, i): the engine indexes extensions
    one by one; returning the whole list as one "name" overflows
    fixed-size name buffers in the RHI's extension parser."""
    idx = (args[1] if len(args) > 1 else 0) & 0xFFFFFFFF
    try:
        exts = (GLES.gstr(0x8B8C) or b"").decode("utf-8", "replace") \
            .split()
    except Exception:
        exts = []
    v = exts[idx] if idx < len(exts) else ""
    return l.cstring_cell("glstri.%d" % idx, v)


def _sp_getshaderprecision(l, args):
    # ES-only: (shaderType, precisionType, range[2], *precision)
    sh, prec, rng, pout = args[0], args[1], args[2], args[3]
    vals = {0: (127, 127, 23), 1: (127, 127, 23),   # float/vec
            2: (14, 14, 10), 3: (14, 14, 10),       # int/ivec (low)
            4: (24, 24, 8), 5: (24, 24, 8)}          # sampler idx base
    r0, r1, p = vals.get(prec, (127, 127, 23))
    if rng:
        l.w32(rng, r0)
        l.w32(rng + 4, r1)
    if pout:
        l.w32(pout, p)
    return 0


def _sp_shadersource(l, args):
    # glShaderSource(shader, count, const GLchar** string, const GLint* len)
    shader, count, strs, lens = args[0], args[1], args[2], args[3]
    if not strs or not count:
        return 0
    host = []
    total = []
    for i in range(count):
        p = l.rd64(strs + 8 * i)
        ln = -1
        if lens:
            ln = l.rd64(lens + 8 * i)  # len array is GLint* (4 bytes)
        if ln is None or ln == 0 or ln == -1:
            s = l.gcstr(p, maxlen=1 << 22)
            b = s.encode()
        else:
            b = l.rdb(p, ln)
        total.append(b)
    # hand to real glShaderSource with host buffers
    arr = (ctypes.c_char_p * count)(*[ctypes.c_char_p(b) for b in total])
    f = GLES.proc("glShaderSource")
    cf = ctypes.CFUNCTYPE(None, ctypes.c_uint, ctypes.c_int,
                          ctypes.POINTER(ctypes.c_char_p),
                          ctypes.POINTER(ctypes.c_int))
    lens_c = (ctypes.c_int * count)([-1] * count)
    cf(shader, count, arr, lens_c)
    l.trace_gl("glShaderSource(%d, %d strings, %d bytes total)"
               % (shader, count, sum(len(b) for b in total)))
    return 0


def _sp_getshaderinfolog(l, args):
    # glGetShaderInfoLog(shader, bufSize, length*, infoLog*)
    shader, bufsz, lp, out = args
    f = GLES.proc("glGetShaderInfoLog")
    cf = ctypes.CFUNCTYPE(None, ctypes.c_uint, ctypes.c_int,
                          ctypes.POINTER(ctypes.c_int),
                          ctypes.c_void_p)
    host = ctypes.create_string_buffer(max(bufsz, 1))
    n = ctypes.c_int(0)
    cf(shader, bufsz, ctypes.byref(n), host)
    data = host.raw[:max(n.value, 0)]
    if out and data:
        l.wrb(out, data[:bufsz])
    if lp:
        l.w32(lp, n.value)
    if data.strip():
        l.console("[gl] shader log: %s" %
                  data.decode("utf-8", "replace")[:400])
    return 0


def _sp_getprograminfolog(l, args):
    return _sp_getshaderinfolog(l, args)


def _sp_glreadpixels(l, args):
    # glReadPixels(x,y,w,h,format,type,pixels)
    x, y, w, h, fmt, typ, ptr = args
    if not ptr or not w or not h:
        return 0
    cf = ctypes.CFUNCTYPE(None, ctypes.c_int, ctypes.c_int, ctypes.c_int,
                         ctypes.c_int, ctypes.c_uint, ctypes.c_uint,
                         ctypes.c_void_p)(GLES.proc("glReadPixels"))
    host = ctypes.create_string_buffer(w * h * 4)
    cf(x, y, w, h, fmt & 0xFFFFFFFF, typ & 0xFFFFFFFF, host)
    l.wrb(ptr, host.raw[:w * h * 4])
    return 0


_CURRENT_GL = "glGenRenderbuffers"     # set by GLCall before dispatch


def _sp_gen(l, args):
    # glGen*(n, ptr)
    name = _CURRENT_GL
    n, ptr = args[0], args[1]
    if not ptr or n <= 0 or n > 4096:
        return 0
    try:
        cf = ctypes.CFUNCTYPE(None, ctypes.c_int,
                              ctypes.c_void_p)(GLES.proc(name))
    except Exception as e:
        l.warn("glGen %r: %r" % (name, e))
        return 0
    host = (ctypes.c_uint * n)()
    cf(n, host)
    for i in range(n):
        l.w32(ptr + 4 * i, host[i])
    return 0


def _sp_bindattrib(l, args):
    # direct (GLuint program, GLuint index, const GLchar* name)
    prog, idx, namep = args
    cf = ctypes.CFUNCTYPE(None, ctypes.c_uint, ctypes.c_int,
                          ctypes.c_char_p)(GLES.proc("glBindAttribLocation"))
    cf(prog, idx, l.gcstr(namep).encode())
    return 0


def _sp_getuniformlocation(l, args):
    prog, namep = args
    cf = ctypes.CFUNCTYPE(ctypes.c_int, ctypes.c_uint,
                          ctypes.c_char_p)(GLES.proc("glGetUniformLocation"))
    return cf(prog, l.gcstr(namep).encode())


def _sp_getattriblocation(l, args):
    prog, namep = args
    cf = ctypes.CFUNCTYPE(ctypes.c_int, ctypes.c_uint,
                          ctypes.c_char_p)(GLES.proc("glGetAttribLocation"))
    return cf(prog, l.gcstr(namep).encode())


_SPECIAL = {
    "glMapBufferRange": _sp_maprange,
    "glUnmapBuffer": _sp_unmap,
    "glFlushMappedBufferRange": _sp_flushmapped,
    "glGetString": _sp_getstring,
    "glGetStringi": _sp_getstringi,
    "glGetShaderPrecisionFormat": _sp_getshaderprecision,
    "glShaderSource": _sp_shadersource,
    "glGetShaderInfoLog": _sp_getshaderinfolog,
    "glGetProgramInfoLog": _sp_getprograminfolog,
    "glReadPixels": _sp_glreadpixels,
    "glGenBuffers": _sp_gen,
    "glGenTextures": _sp_gen,
    "glGenFramebuffers": _sp_gen,
    "glGenRenderbuffers": _sp_gen,
    "glGenVertexArrays": _sp_gen,
    "glGenQueries": _sp_gen,
    "glBindAttribLocation": _sp_bindattrib,
    "glGetUniformLocation": _sp_getuniformlocation,
    "glGetAttribLocation": _sp_getattriblocation,
}


# ====================================================================
# name mapping: iOS extension names -> core names
# ====================================================================

NAME_MAP = {
    "glMapBufferRangeEXT": ("glMapBufferRange", None),
    "glUnmapBufferOES": ("glUnmapBuffer", None),
    "glFlushMappedBufferRangeEXT": ("glFlushMappedBufferRange", None),
    "glFenceSyncAPPLE": ("glFenceSync", None),
    "glClientWaitSyncAPPLE": ("glClientWaitSync", None),
    "glDeleteSyncAPPLE": ("glDeleteSync", None),
    "glDrawArraysInstancedEXT": ("glDrawArraysInstanced", None),
    "glDrawElementsInstancedEXT": ("glDrawElementsInstanced", None),
    "glVertexAttribDivisorEXT": ("glVertexAttribDivisor", None),
    "glTexStorage2DEXT": ("glTexStorage2D", None),
    "glBeginQueryEXT": ("glBeginQuery", None),
    "glEndQueryEXT": ("glEndQuery", None),
    "glGetQueryObjectuivEXT": ("glGetQueryObjectuiv", None),
    "glDiscardFramebufferEXT": ("glInvalidateFramebuffer", None),
    "glCopyTextureLevelsAPPLE": ("glCopyTextureLevels", None),
    # trace-only (no host equivalent needed)
    "glLabelObjectEXT": (None, "noop"),
    "glGetObjectLabelEXT": (None, "zero"),
    "glPushGroupMarkerEXT": (None, "noop"),
    "glPopGroupMarkerEXT": (None, "noop"),
}


def register_gl():
    """Register every GL import name into IMPL with adapters."""
    import fn35_macho
    mo = fn35_macho.MachO(
        "/home/z/my-project/fn35/extracted/Payload/"
        "FortniteClient.app/FortniteClient")
    mo.load_symbols()
    imports = set()
    for rec in mo.parse_binds():
        if rec.symbol:
            imports.add(rec.symbol.lstrip("_"))
    for slot, symidx in mo.iter_pointer_slots():
        if symidx is None or symidx & 0xC0000000:
            continue
        nm = mo.sym_name(symidx)
        if nm:
            imports.add(nm.lstrip("_"))
    n_reg = 0
    for name in sorted(imports):
        if not (name.startswith("gl") and len(name) > 3):
            continue
        # names we implement by hand below stay untouched
        if name in IMPL:
            continue
        if name in NAME_MAP:
            core, mode = NAME_MAP[name]
            if mode == "noop":
                IMPL["_" + name] = (lambda nm: lambda l, *a: 0)(name)
                n_reg += 1
            elif mode == "zero":
                IMPL["_" + name] = (lambda nm: lambda l, *a: 0)(name)
                n_reg += 1
            elif core:
                IMPL["_" + name] = _mk(core)
                n_reg += 1
            continue
        if name == "glGetError":
            continue
        # NB: _SPECIAL names MUST also be registered -- GLCall.call()
        # routes them into their hand-written handler. Skipping them
        # here left _glGetString/_glShaderSource/... unimplemented!
        IMPL["_" + name] = _mk(name)
        n_reg += 1
    return n_reg


def _mk(core_name):
    gc = GLCall(core_name)

    def h(l, *args):
        if not _ensure(l):
            return 0
        try:
            return gc.call(l, list(args))
        except Exception as e:
            l.warn("gl %s: %r" % (core_name, e))
            return 0
    return h


# ---- plain forwarding of state getters ------------------------------

@cfunc("_glGetError")
def _glGetError(l):
    if not _ensure(l):
        return 0
    return 0          # report GL_NO_ERROR always (keep engine happy)


@cfunc("_glGetIntegerv")
def _glGetIntegerv(l, pname, ptr):
    if not _ensure(l):
        return 0
    vals = {
        0x0D33: [SCREEN_W],        # GL_MAX_VIEWPORT_DIMS (first)
        0x8872: [16],              # GL_MAX_TEXTURE_IMAGE_UNITS
        0x8B4C: [16],              # GL_MAX_VERTEX_TEXTURE_IMAGE_UNITS
        0x8DFB: [16],              # GL_MAX_COMBINED_TEXTURE_IMAGE_UNITS
        0x8B4D: [16],              # GL_MAX_VERTEX_ATTRIBS
        0x8869: [8],                # GL_MAX_VERTEX_UNIFORM_VECTORS
        0x8DFB + 0: [16],
    }
    try:
        cf = ctypes.CFUNCTYPE(None, ctypes.c_uint,
                              ctypes.c_void_p)(GLES.proc("glGetIntegerv"))
        host = (ctypes.c_int * 4)()
        cf(pname & 0xFFFFFFFF, host)
        if ptr:
            for i in range(4):
                l.w32(ptr + 4 * i, host[i])
    except Exception as e:
        l.warn("glGetIntegerv %r" % (e,))
    return 0


@cfunc("_glFlush", "_glFinish")
def _gl_flushfinish(l):
    if GLES.ready:
        try:
            GLES.capture("flush") if False else None
        except Exception:
            pass
    return 0
