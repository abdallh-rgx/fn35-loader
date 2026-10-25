#!/usr/bin/env python3
"""Diagnose EGL glvnd vendor discovery."""
import ctypes, os, sys

ROOT = "/home/z/mesa-debs/root/usr/lib/x86_64-linux-gnu"

# 1) can we dlopen the mesa vendor directly?
try:
    lib = ctypes.CDLL(os.path.join(ROOT, "libEGL_mesa.so.0"))
    print("direct dlopen libEGL_mesa.so.0: OK")
except OSError as e:
    print("direct dlopen FAILED:", e)

# 2) glvnd libEGL
EGL = ctypes.CDLL("libEGL.so.1")
EGL.eglGetError.restype = ctypes.c_int
EGL.eglGetDisplay.argtypes = [ctypes.c_void_p]
EGL.eglGetDisplay.restype = ctypes.c_void_p
EGL.eglInitialize.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_int32), ctypes.POINTER(ctypes.c_int32)]
EGL.eglInitialize.restype = ctypes.c_uint

for envname in ("__EGL_VENDOR_LIBRARY_DIRS", "EGL_VENDOR_LIBRARY_DIRS",
                "__EGL_VENDOR_LIBRARY_FILENAMES"):
    os.environ[envname] = "/home/z/mesa-debs/glvnd"
os.environ["EGL_PLATFORM"] = "surfaceless"
os.environ["LIBGL_ALWAYS_SOFTWARE"] = "1"

d = EGL.eglGetDisplay(None)
print("eglGetDisplay(NULL) with EGL_PLATFORM=surfaceless ->", d, "err=0x%x" % EGL.eglGetError())
if d:
    ma, mi = ctypes.c_int32(0), ctypes.c_int32(0)
    ok = EGL.eglInitialize(d, ctypes.byref(ma), ctypes.byref(mi))
    print("  eglInitialize ->", ok, ma.value, mi.value, "err=0x%x" % EGL.eglGetError())

# 3) eglGetPlatformDisplay surfaceless via glvnd core
try:
    g = EGL.eglGetPlatformDisplay
except AttributeError:
    g = ctypes.CFUNCTYPE(ctypes.c_void_p, ctypes.c_uint32, ctypes.c_void_p,
                         ctypes.c_void_p)(ctypes.cast(EGL.eglGetProcAddress(b"eglGetPlatformDisplay"), ctypes.c_void_p).value) \
        if hasattr(EGL, "eglGetProcAddress") else None
    print("(eglGetPlatformDisplay via getProcAddress)")
if g:
    try:
        g.restype = ctypes.c_void_p
        g.argtypes = [ctypes.c_uint32, ctypes.c_void_p, ctypes.c_void_p]
        d2 = g(0x31DD, None, None)
        print("eglGetPlatformDisplay(SURFACELESS) ->", d2, "err=0x%x" % EGL.eglGetError())
        if d2:
            ma, mi = ctypes.c_int32(0), ctypes.c_int32(0)
            ok = EGL.eglInitialize(d2, ctypes.byref(ma), ctypes.byref(mi))
            print("  eglInitialize ->", ok, ma.value, mi.value, "err=0x%x" % EGL.eglGetError())
    except Exception as e:
        print("platdisplay raised:", e)
