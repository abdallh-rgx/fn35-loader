#!/usr/bin/env python3
"""Test ObjC selector resolution for the three app-delegate timers."""
import os, sys
sys.path.insert(0, "/home/z/my-project/scripts")
os.environ["FN35_QUIET"] = "1"

import fn35_loader as FL

BIN = "/home/z/my-project/fn35/extracted/Payload/FortniteClient.app/FortniteClient"
# build a minimal loader just for the objc runtime (prepare is heavy; the
# objc table parse happens inside prepare -> use a cheaper path: the same
# code path the loader uses, via FNLoader.__init__ + objc boot only)
l = object.__new__(FL.FNLoader)   # skip __init__ machinery
l.macho = FL.MachO(BIN)
l.console = lambda *a, **k: print(*a)
l.warn = lambda *a, **k: print("[warn]", *a)

# the objc boot from the loader's prepare: find how it's invoked
import inspect
src = inspect.getsource(FL.FNLoader.objc_boot) if hasattr(
    FL.FNLoader, "objc_boot") else None
print("objc_boot exists:", src is not None)
if src:
    print(src[:600])
