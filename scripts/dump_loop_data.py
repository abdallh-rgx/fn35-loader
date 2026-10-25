#!/usr/bin/env python3
"""Dump the wide string at x1 + neighbor cstrings of bCommandLineReady."""
import sys, os, json, struct
sys.path.insert(0, "/home/z/my-project/scripts")

SNAP = "/home/z/my-project/fn35/snap2"
meta = json.load(open(os.path.join(SNAP, "index.json")))

def read_mem(addr, n):
    for r in meta["regions"]:
        b, e = r["begin"], r["end"]
        if b <= addr and addr + n <= e + 1 and r.get("file"):
            path = os.path.join(SNAP, r["file"])
            csz = r["chunksz"]
            out = b""
            off = addr - b
            remaining = n
            while remaining > 0:
                ci, co = divmod(off, csz)
                if ci not in r["present"]:
                    return None
                rank = r["present"].index(ci)
                with open(path, "rb") as f:
                    f.seek(rank * csz + co)
                    chunk = f.read(min(remaining, csz - co))
                out += chunk
                remaining -= len(chunk)
                off += len(chunk)
                if not chunk:
                    break
            return out[:n]
    return None

# 1. the wide string at x1 (from MainAppThread saved regs)
ws = read_mem(0x1056a5138, 512)
if ws:
    s = ws.decode("utf-16-le", errors="replace").split("\x00")[0]
    print("WIDE STRING at 0x1056a5138: %r" % s)
    print("raw hex head:", ws[:48].hex())

# 2. the obj at x0
o = read_mem(0x105890110, 64)
if o:
    print("OBJ at 0x105890110:", o.hex())

# 3. cstrings around bCommandLineReady (0x103096f54) - read from BINARY
BIN = "/home/z/my-project/fn35/extracted/Payload/FortniteClient.app/FortniteClient"
from fn35_macho import MachO
mo = MachO(BIN)
def read_bin(va, n):
    for seg in mo.segments:
        if seg.vmaddr <= va < seg.vmaddr + seg.vmsize:
            with open(BIN, "rb") as f:
                f.seek(seg.fileoff + (va - seg.vmaddr))
                return f.read(n)
    return None

d = read_bin(0x103096e00, 0x400)
if d:
    cur, start = None, 0
    for i, b in enumerate(d):
        if b == 0:
            if cur is not None and 3 < (i - start) < 64:
                try:
                    s = d[start:i].decode()
                    print("str @0x%x: %r" % (0x103096e00 + start, s))
                except Exception:
                    pass
            cur = None
        elif cur is None:
            cur = b
            start = i
