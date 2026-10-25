#!/usr/bin/env python3
"""Test: real offscreen OpenGL ES context via Mesa/llvmpipe (EGL surfaceless)."""
import ctypes, os, sys

os.environ.setdefault("EGL_PLATFORM", "surfaceless")
os.environ.setdefault("LIBGL_ALWAYS_SOFTWARE", "1")
os.environ.setdefault("GALLIUM_DRIVER", "llvmpipe")
os.environ.setdefault("MESA_DEBUG", "silent")
os.environ.setdefault("__EGL_VENDOR_LIBRARY_FILENAMES",
                      "/home/z/mesa-debs/glvnd/50_mesa.json")

EGL = ctypes.CDLL("libEGL.so.1")
EGLenum = ctypes.c_uint32
EGLDisplay = ctypes.c_void_p
EGLContext = ctypes.c_void_p
EGLSurface = ctypes.c_void_p
EGLConfig = ctypes.c_void_p
EGLint = ctypes.c_int32
EGLsizei = ctypes.c_size_t
EGLBoolean = ctypes.c_uint
EGL_TRUE, EGL_FALSE = 1, 0
EGL_DEFAULT_DISPLAY = 0
EGL_NO_CONTEXT = EGLSurface(None)
EGL_NO_SURFACE = EGLSurface(None)
EGL_SURFACE_TYPE, EGL_PBUFFER_BIT = 0x3033, 0x0001
EGL_BLUE_SIZE, EGL_GREEN_SIZE, EGL_RED_SIZE, EGL_ALPHA_SIZE = 0x3022, 0x3023, 0x3024, 0x3021
EGL_DEPTH_SIZE = 0x3025
EGL_STENCIL_SIZE = 0x3026
EGL_RENDERABLE_TYPE, EGL_OPENGL_ES3_BIT = 0x3040, 0x0040
EGL_OPENGL_ES2_BIT = 0x0004
EGL_NONE = 0x3038
EGL_CLIENT_APIS = 0x308D
EGL_VENDOR, EGL_VERSION, EGL_EXTENSIONS = 0x3053, 0x3054, 0x3055
EGL_CONTEXT_CLIENT_VERSION = 0x3098
EGL_WIDTH, EGL_HEIGHT = 0x3056, 0x3057

EGL.eglGetDisplay.restype = EGLDisplay
EGL.eglGetDisplay.argtypes = [ctypes.c_void_p]
EGL.eglInitialize.restype = EGLBoolean
EGL.eglInitialize.argtypes = [EGLDisplay, ctypes.POINTER(EGLint), ctypes.POINTER(EGLint)]
EGL.eglQueryString.restype = ctypes.c_char_p
EGL.eglQueryString.argtypes = [EGLDisplay, EGLenum]
EGL.eglChooseConfig.restype = EGLBoolean
EGL.eglChooseConfig.argtypes = [EGLDisplay, ctypes.POINTER(EGLint), ctypes.POINTER(EGLConfig), EGLint, ctypes.POINTER(EGLint)]
EGL.eglBindAPI.restype = EGLBoolean
EGL.eglBindAPI.argtypes = [EGLenum]
EGL_OPENGL_ES_API = 0x30A0
EGL.eglCreateContext.restype = EGLContext
EGL.eglCreateContext.argtypes = [EGLDisplay, EGLConfig, EGLContext, ctypes.POINTER(EGLint)]
EGL.eglCreatePbufferSurface.restype = EGLSurface
EGL.eglCreatePbufferSurface.argtypes = [EGLDisplay, EGLConfig, ctypes.POINTER(EGLint)]
EGL.eglMakeCurrent.restype = EGLBoolean
EGL.eglMakeCurrent.argtypes = [EGLDisplay, EGLSurface, EGLSurface, EGLContext]
EGL.eglGetProcAddress.restype = ctypes.c_void_p
EGL.eglGetProcAddress.argtypes = [ctypes.c_char_p]

EGL.eglGetPlatformDisplay = getattr(EGL, "eglGetPlatformDisplay", None)
if EGL.eglGetPlatformDisplay:
    EGL.eglGetPlatformDisplay.restype = EGLDisplay
    EGL.eglGetPlatformDisplay.argtypes = [EGLenum, ctypes.c_void_p, ctypes.POINTER(EGLint)]
EGL_PLATFORM_SURFACELESS_MESA = 0x31DD
d = None
for getter, plat in ((EGL.eglGetPlatformDisplay, EGL_PLATFORM_SURFACELESS_MESA),):
    if getter:
        d = getter(plat, None, None)
        if d:
            print("got surfaceless display via", getter.__name__)
            break
if not d:
    d = EGL.eglGetDisplay(ctypes.c_void_p(EGL_DEFAULT_DISPLAY))
print("display =", d)
maj, mn = EGLint(0), EGLint(0)
if not EGL.eglInitialize(d, ctypes.byref(maj), ctypes.byref(mn)):
    print("eglInitialize FAILED")
    sys.exit(1)
print("EGL %d.%d" % (maj.value, mn.value))
print("vendor :", EGL.eglQueryString(d, EGL_VENDOR))
print("version:", EGL.eglQueryString(d, EGL_VERSION))
print("apis   :", EGL.eglQueryString(d, EGL_CLIENT_APIS))

attribs = (EGLint * 20)(
    EGL_SURFACE_TYPE, EGL_PBUFFER_BIT,
    EGL_RENDERABLE_TYPE, EGL_OPENGL_ES3_BIT,
    EGL_RED_SIZE, 8, EGL_GREEN_SIZE, 8, EGL_BLUE_SIZE, 8, EGL_ALPHA_SIZE, 8,
    EGL_DEPTH_SIZE, 24, EGL_STENCIL_SIZE, 8,
    EGL_NONE)
cfgs = (EGLConfig * 8)()
n = EGLint(0)
ok = EGL.eglChooseConfig(d, attribs, cfgs, 8, ctypes.byref(n))
print("chooseConfig ok=%s n=%d" % (bool(ok), n.value))
assert n.value > 0, "no config"

pbuf_attribs = (EGLint * 5)(EGL_WIDTH, 640, EGL_HEIGHT, 360, EGL_NONE)
surf = EGL.eglCreatePbufferSurface(d, cfgs[0], pbuf_attribs)
print("pbuffer =", surf)
ctx_attribs = (EGLint * 3)(EGL_CONTEXT_CLIENT_VERSION, 3, EGL_NONE)
ctx = EGL.eglCreateContext(d, cfgs[0], EGL_NO_CONTEXT, ctx_attribs)
print("context =", ctx)
assert ctx, "no context"

EGL.eglBindAPI(EGL_OPENGL_ES_API)
assert EGL.eglMakeCurrent(d, surf, surf, ctx)
print("makeCurrent OK")

gl = EGL.eglGetProcAddress
def fn(name):
    a = gl(name.encode())
    return ctypes.CFUNCTYPE(ctypes.c_uint, ctypes.c_uint)(a) if name in ("glGetString",) else a

GL_VENDOR, GL_RENDERER, GL_VERSION, GL_SHADING_LANGUAGE_VERSION = 0x1F00, 0x1F01, 0x1F02, 0x8B8C
gs = ctypes.CFUNCTYPE(ctypes.c_char_p, ctypes.c_uint)(gl(b"glGetString"))
print("GL_RENDERER:", gs(GL_RENDERER))
print("GL_VERSION :", gs(GL_VERSION))
print("GLSL ver   :", gs(GL_SHADING_LANGUAGE_VERSION))

# quick draw test: clear to orange, read pixels, save PNG-ish
glClearColor = ctypes.CFUNCTYPE(None, ctypes.c_float, ctypes.c_float, ctypes.c_float, ctypes.c_float)(gl(b"glClearColor"))
glClear = ctypes.CFUNCTYPE(None, ctypes.c_uint)(gl(b"glClear"))
glReadPixels = ctypes.CFUNCTYPE(None, ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_uint, ctypes.c_uint, ctypes.c_void_p)(gl(b"glReadPixels"))
GL_COLOR_BUFFER_BIT = 0x4000
GL_RGBA, GL_UNSIGNED_BYTE = 0x1908, 0x1401
glClearColor(1.0, 0.55, 0.1, 1.0)
glClear(GL_COLOR_BUFFER_BIT)
buf = ctypes.create_string_buffer(640 * 360 * 4)
glReadPixels(0, 0, 640, 360, GL_RGBA, GL_UNSIGNED_BYTE, buf)
raw = buf.raw
print("readback %d bytes, first pixel = %s" % (len(raw), raw[:4].hex()))
assert raw[0] == 0xFF and raw[3] == 0xFF, "expected orange"
print("SOFTWARE GL RENDERING WORKS: llvmpipe cleared + readback OK")
