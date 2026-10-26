#!/usr/bin/env python3
"""pak_strip_uproject.py — rebuild the pak with the uproject entry
REMOVED from the index (entry data offsets are absolute and untouched).

Why: the engine mounts this pak itself (it has the AES key), sees
'FortniteGame/FortniteGame.uproject' in the entry list, then tries to
read it through its own pak layer -- whose serve path dies in our
emulation before touching I/O. With the entry gone: pak mounts fine,
the uproject scan finds nothing (physical tree has none either) -> the
engine's command line stays EMPTY -> the project-file check is SKIPPED
entirely (the run49 recipe) -> boot proceeds engine-content-only.

Usage: python3 pak_strip_uproject.py [in.pak] [out.pak]
"""
import hashlib
import struct
import sys

sys.path.insert(0, "/home/z/my-project/scripts")
from fn35_pakfs import AES_KEY, COMPRESSION_NONE, FOOTER_SIZE, PAK_MAGIC
import zlib

try:
    from Crypto.Cipher import AES
except ImportError:
    from Cryptodome.Cipher import AES


def fstr_write(out, s):
    b = s.encode("utf-8") + b"\x00"
    out += struct.pack("<i", len(b))
    out += b
    return out


def main(src, dst):
    data = open(src, "rb").read()
    # footer: last 44 bytes: magic u32, version u32, idx_off i64,
    # idx_size i64, sha1[20]
    f = data[-FOOTER_SIZE:]
    magic, version = struct.unpack_from("<II", f, 0)
    idx_off, idx_size = struct.unpack_from("<qq", f, 8)
    sha1_old = f[24:44]
    assert magic == PAK_MAGIC, hex(magic)
    print("footer: version=%d idx_off=%d idx_size=%d" %
          (version, idx_off, idx_size))

    aes = AES.new(AES_KEY, AES.MODE_ECB)
    dec = aes.decrypt(data[idx_off:idx_off + idx_size])

    # ---- parse (mirror of fn35_pakfs._load_index) --------------------
    class R:
        def __init__(s, b):
            s.b, s.o = b, 0
        def rd(s, n):
            v = s.b[s.o:s.o + n]; s.o += n; return v
        def i32(s):
            return struct.unpack("<i", s.rd(4))[0]
        def i64(s):
            return struct.unpack("<q", s.rd(8))[0]
        def u8(s):
            return s.rd(1)[0]
        def fstr(s):
            n = s.i32()
            return s.rd(n)[:-1].decode("utf-8", "replace") if n > 0 else ""

    r = R(dec)
    mount = r.fstr()
    n = r.i32()
    entries = []
    for _ in range(n):
        name = r.fstr()
        off, size, usize = r.i64(), r.i64(), r.i64()
        comp = r.i32()
        sha1e = r.rd(20)
        if comp != COMPRESSION_NONE:
            nb = r.i32()
            blocks = [(r.i64(), r.i64()) for _ in range(nb)]
            enc = r.u8()
            cbs = r.i32()
        else:
            enc_raw = r.i32()
            pad = r.u8()
            enc = 1 if enc_raw else 0
            blocks = []
            cbs = 0
        entries.append((name, off, size, usize, comp, sha1e,
                        blocks, enc, cbs))
    print("parsed %d entries, mount=%r" % (len(entries), mount))

    drop = [e for e in entries
            if e[0].lower().endswith("fortnitegame.uproject")]
    kept = [e for e in entries if e not in drop]
    print("dropping: %s" % [e[0] for e in drop])

    # ---- rebuild the index -------------------------------------------
    out = b""
    out = fstr_write(out, mount)
    out += struct.pack("<i", len(kept))
    for (name, off, size, usize, comp, sha1e, blocks, enc, cbs) in kept:
        out = fstr_write(out, name)
        out += struct.pack("<qqq", off, size, usize)
        out += struct.pack("<i", comp)
        out += sha1e
        if comp != COMPRESSION_NONE:
            out += struct.pack("<i", len(blocks))
            for (bo, bs) in blocks:
                out += struct.pack("<qq", bo, bs)
            out += bytes([enc])
            out += struct.pack("<i", cbs)
        else:
            out += struct.pack("<i", 1 if enc else 0)
            out += b"\x00"  # pad
    # AES-ECB pad to 16 (decrypted tail slack is never parsed)
    padlen = (-len(out)) % 16
    out += b"\x00" * padlen
    enc_idx = aes.encrypt(out)

    new = bytearray(data[:idx_off])
    new += enc_idx
    idx_sha1 = hashlib.sha1(out).digest()   # convention: hash of DECRYPTED index
    idx_sha1_dec = hashlib.sha1(out).digest()
    footer = struct.pack("<IIqq", PAK_MAGIC, version, idx_off,
                         len(enc_idx)) + idx_sha1
    new += footer
    open(dst, "wb").write(bytes(new))
    print("wrote %s: %d bytes (idx %d -> %d encrypted)" %
          (dst, len(new), idx_size, len(enc_idx)))
    print("sha1(enc)=%s  sha1(dec)=%s  old=%s" %
          (idx_sha1.hex(), idx_sha1_dec.hex(), sha1_old.hex()))


if __name__ == "__main__":
    src = sys.argv[1] if len(sys.argv) > 1 else (
        "/home/z/my-project/fn35/extracted/Payload/FortniteClient.app/"
        "cookeddata/fortnitegame/content/paks/pakchunkearly-iosclient.pak")
    dst = sys.argv[2] if len(sys.argv) > 2 else (
        "/home/z/my-project/fn35/pakcache/pak-stripped.pak")
    main(src, dst)
