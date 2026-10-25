import ctypes, os
os.environ["LIBGL_ALWAYS_SOFTWARE"] = "1"
os.environ["GALLIUM_DRIVER"] = "llvmpipe"
os.environ["EGL_PLATFORM"] = "surfaceless"

# bypass glvnd: load Mesa's own EGL vendor directly
M = ctypes.CDLL("/home/z/mesa-debs/root/usr/lib/x86_64-linux-gnu/libEGL_mesa.so.0")
M.eglGetDisplay.restype = ctypes.c_void_p
M.eglGetDisplay.argtypes = [ctypes.c_void_p]
M.eglInitialize.restype = ctypes.c_uint
M.eglInitialize.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_int32), ctypes.POINTER(ctypes.c_int32)]
M.eglGetError.restype = ctypes.c_int

d = M.eglGetDisplay(None)
print("mesa eglGetDisplay(NULL) ->", hex(d or 0), "err=0x%x" % M.eglGetError())
if not d:
    raise SystemExit(1)
ma, mi = ctypes.c_int32(0), ctypes.c_int32(0)
ok = M.eglInitialize(d, ctypes.byref(ma), ctypes.byref(mi))
print("eglInitialize ->", ok, ma.value, mi.value, "err=0x%x" % M.eglGetError())
if not ok:
    raise SystemExit(1)
M.eglQueryString.restype = ctypes.c_char_p
M.eglQueryString.argtypes = [ctypes.c_void_p, ctypes.c_uint32]
print("vendor:", M.eglQueryString(d, 0x3053))
print("apis  :", M.eglQueryString(d, 0x308D))
print("exts  :", M.eglQueryString(d, 0x3055)[:200])
