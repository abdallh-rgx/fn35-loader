#!/usr/bin/env python3
"""Detect the render path available in the Fortnite 3.5 binary.

Enumerates imported symbols, class references and strings that indicate:
  * OpenGL ES RHI (gl* imports, EAGL classes)
  * Metal RHI (MTL* classes, MTLCreateSystemDefaultDevice)
  * RHI selection command line switches compiled in
"""
import sys, os, re, struct

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from fn35_macho import MachO

BIN = "/home/z/my-project/fn35/extracted/Payload/FortniteClient.app/FortniteClient"

mo = MachO(BIN)
mo.load_symbols()

# ---- collect every imported symbol name (bind table + GOT slots)
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

gl_imports = sorted(n for n in imports if n.startswith("gl") or n.startswith("egl"))
mtl_fn = sorted(n for n in imports if "MTL" in n or "Metal" in n)
print("== GL/EGL function imports: %d" % len(gl_imports))
for n in gl_imports:
    print("   ", n)
print("== Metal function imports: %d" % len(mtl_fn))
for n in mtl_fn:
    print("   ", n)

# ---- ObjC class references (from __objc_classlist + class name strings)
data = mo.buf
classes = set(m.group(1).decode() for m in
              re.finditer(rb"OBJC_CLASS_\$_([A-Za-z0-9_]+)", data))
objc_cls = sorted(c for c in classes if any(
    k in c for k in ("MTL", "Metal", "CAEAGL", "EAGL", "CAMetal",
                     "GLK", "UIWindow", "UIView", "CADisplay",
                     "UIScreen", "UIApplication", "UIViewController")))
print("\n== render/UIApplication-related ObjC classes referenced: %d" % len(objc_cls))
for c in objc_cls:
    print("   ", c)

# ---- raw strings that steer RHI selection
pats = [
    rb"-rhi=[a-z0-9]{1,20}", rb"-opengl[0-9a-z]*", rb"-metal[a-z0-9]*",
    rb"OpenGL ES [0-9.]{0,6}", rb"MetalSM[0-9]", rb"SP_METAL[A-Z_0-9]*",
    rb"SP_OPENGL[A-Z_0-9]*", rb"GLSL_[0-9]{3,4}", rb"SF_METAL[A-Z_0-9]*",
    rb"SF_OPENGL[A-Z_0-9]*", rb"kEAGL[A-Za-z0-9]*",
    rb"OpenGLRHI", rb"MetalRHI", rb"FMetalDynamicRHI", rb"FOpenGLDynamicRHI",
    rb"ShaderFormatMetal", rb"ShaderFormatGLSL",
    rb"metallib", rb"global_sf_metal",
]
print("\n== RHI-selection strings found in binary:")
found = {}
for p in pats:
    for m in set(re.findall(p, data)):
        found[m.decode("utf-8", "replace")] = found.get(m, 0) + 1
for s in sorted(found):
    print("   ", s)
