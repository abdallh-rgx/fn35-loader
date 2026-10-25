#!/usr/bin/env python3
"""Parse __objc_classlist from the raw Mach-O; find the delegate class and
check which of the three timer selectors have IMPs."""
import sys, struct
sys.path.insert(0, "/home/z/my-project/scripts")
from fn35_macho import MachO

BIN = "/home/z/my-project/fn35/extracted/Payload/FortniteClient.app/FortniteClient"
mo = MachO(BIN)

# file-backed readers
def rd(va, n):
    for seg in mo.segments:
        if seg.vmaddr <= va < seg.vmaddr + seg.vmsize and seg.filesize:
            if va - seg.vmaddr < seg.filesize:
                return mo.buf[seg.fileoff + va - seg.vmaddr:
                              seg.fileoff + va - seg.vmaddr + n]
    return None

def rd64(va):
    b = rd(va, 8)
    return struct.unpack("<Q", b)[0] if b else 0

def rd32(va):
    b = rd(va, 4)
    return struct.unpack("<I", b)[0] if b else 0

def cstr(va):
    b = rd(va, 256)
    return b.split(b"\0")[0].decode(errors="replace") if b else "?"

WANT = ("NoUrlCommandLine", "RecordPeakMemory", "timerForSplashScreen")

cl = mo.sections_in("__DATA", "__objc_classlist")
n_classes = 0
found = {}
for sec in cl:
    for i in range(sec.size // 8):
        cls = struct.unpack("<Q", mo.buf[sec.offset + 8 * i:
                                         sec.offset + 8 * i + 8])[0]
        data = rd64(cls + 32) & ~7          # class_t.data -> class_ro_t
        name_p = rd64(data + 24)             # ro.name (after 4x u32 + u64 ivarLayout)
        name = cstr(name_p)
        n_classes += 1
        if "AppDelegate" in name or "Application" == name:
            print("class %s @ 0x%x" % (name, cls))
        # scan baseMethods
        mlist = rd64(data + 32)
        if mlist:
            entsize, count = rd32(mlist), rd32(mlist + 4)
            if entsize >= 24 and count < 4096:
                for m in range(count):
                    nm = rd64(mlist + 8 + m * 24)
                    imp = rd64(mlist + 8 + m * 24 + 16)
                    s = cstr(nm)
                    if s in WANT:
                        found.setdefault(s, []).append((name, cls, imp))

print("parsed %d classes" % n_classes)
for s in WANT:
    for name, cls, imp in found.get(s, []):
        print("FOUND %-22s on class %-28s imp=0x%x" % (s, name, imp))
    if s not in found:
        print("MISSING %s  <-- !!!" % s)
