#!/usr/bin/env python3
"""test_png_read.py — read Slate PNGs through PakFS and verify PNG structure."""
import sys, json, zlib, struct
sys.path.insert(0, "/home/z/my-project/scripts")
from fn35_pakfs import PakFS

PAK = "/home/z/my-project/fn35/extracted/Payload/FortniteClient.app/cookeddata/fortnitegame/content/paks/pakchunkearly-iosclient.pak"
fs = PakFS(PAK, "/home/z/my-project/fn35/pakcache")
idx = json.load(open("/home/z/my-project/fn35/pak_index.json"))
names = [e["name"] for e in idx["entries"] if e["name"].endswith(".png")]

def png_check(data):
    if len(data) < 40:
        return "too short (%d)" % len(data)
    if data[:8] != b"\x89PNG\r\n\x1a\n":
        return "BAD SIGNATURE: %s" % data[:8].hex()
    # IHDR chunk
    ln = struct.unpack(">I", data[8:12])[0]
    if data[12:16] != b"IHDR":
        return "no IHDR (got %s)" % data[12:16]
    ihdr = data[16:16+ln]
    crc_exp = struct.unpack(">I", data[16+ln:20+ln])[0]
    crc_real = zlib.crc32(data[12:16+ln]) & 0xFFFFFFFF
    if crc_exp != crc_real:
        return "IHDR CRC MISMATCH exp=0x%x real=0x%x" % (crc_exp, crc_real)
    w, h, bd, ct = struct.unpack(">IIBB", ihdr[:10])
    return "OK %dx%d bd=%d ct=%d" % (w, h, bd, ct)

bad = ok = 0
for n in names[:30]:
    e = fs.entries.get(n)
    if not e:
        print("MISSING:", n); bad += 1; continue
    try:
        data = fs.read_entry(e)
        r = png_check(data)
        flag = "OK " if r.startswith("OK") else "BAD"
        if flag == "OK ": ok += 1
        else: bad += 1
        print("%s %-55s %s" % (flag, n.split("/")[-1], r))
    except Exception as ex:
        bad += 1
        print("EXC %-55s %r" % (n.split("/")[-1], ex))
print("ok=%d bad=%d" % (ok, bad))
