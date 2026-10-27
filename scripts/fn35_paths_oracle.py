#!/usr/bin/env python3
"""fn35_paths_oracle.py - dump (guest path -> host path) pairs from the
REAL FNLoader.translate_path for the Rust differential test.

Uses the loader's constants and roots without booting the emulator
(translate_path only needs self.sandbox).
"""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import fn35_loader as FL  # noqa: E402

SB = "/home/z/my-project/fn35/sandbox"

# minimal stand-in object with just .sandbox (translate_path only
# touches self.sandbox)
class _T:
    sandbox = SB

GUEST_PATHS = [
    None,
    "",
    "file:///var/mobile/foo.txt",
    FL.GUEST_BUNDLE + "/Info.plist",
    FL.GUEST_BUNDLE + "/cookeddata/fortnitegame/Content/Paks/pak.pak",
    FL.GUEST_BUNDLE.replace("/private/", "/", 1) + "/FortniteClient",
    FL.GUEST_DATA + "/Documents/save.dat",
    FL.GUEST_DATA + "/Library/Preferences/x.plist",
    "/var/mobile/anything",
    "/var/tmp/cache.bin",
    "/tmp/x",
    "/private/tmp/y",
    "/var/db/z",
    "/System/Library/Fonts/xx.ttc",
    "/usr/lib/system/libsystem_c.dylib",
    "/Developer/usr/bin/llvm",
    "/Library/Preferences/global.plist",
    "/etc/hosts",
    "/not/a/known/root",
    "relative/path.txt",
    FL.GUEST_BUNDLE + "//double//slash",
    "//var//mobile//a",
    "file://" + FL.GUEST_BUNDLE + "/f",
]

out = []
for g in GUEST_PATHS:
    try:
        host = FL.FNLoader.translate_path(_T(), g) if g is not None else None
    except Exception as e:
        host = "ERR:" + repr(e)[:50]
    out.append({"guest": g, "host": host})

print(json.dumps(out, indent=1))
