#!/usr/bin/env python3
"""Find RHI selection logic strings: how does this UE4 build pick Metal vs GL?"""
import sys, os, re

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from fn35_macho import MachO

BIN = "/home/z/my-project/fn35/extracted/Payload/FortniteClient.app/FortniteClient"
mo = MachO(BIN)
mo.load_symbols()
data = mo.buf

# All printable strings >= 4 chars (scan whole image; UE4 cstrings live in __TEXT __cstring)
strings = set()
for m in re.finditer(rb"[\x20-\x7e]{6,}", data):
    strings.add(m.group().decode())

keys = ("rhi", "RHI", "Metal", "OpenGL", "GLSL", "OpenGLShaderPlatform",
        "ES2", "ES3", "EAGL", "MetalSM", "SM5", "SM4", "fallback",
        "Fallback", "bUseMetal", "GraphicsRHI", "PreferredRHI")
hits = set()
for s in strings:
    if any(k in s for k in ("Metal", "OpenGL", "GLSL", "EAGL", "rhi=",
                            "RHI")):
        hits.add(s)

print("== %d candidate strings ==" % len(hits))
for s in sorted(hits):
    # skip obvious shader-source noise
    if len(s) > 130:
        continue
    print("   ", s)
