#!/usr/bin/env python3
"""FN3.5 loader: pak filesystem overlay (UE4 pak v4, AES-256 + zlib).

Fortnite 3.5 stores the whole project tree inside
cookeddata/fortnitegame/content/paks/pakchunkearly-iosclient.pak.
The engine resolves paths relative to the app bundle ("../../../FortniteGame/..").
This module serves those paths by extracting pak entries on demand into a
host cache directory, so the existing sandbox file layer keeps working
unchanged (open/stat/read/opendir all hit real files).

Pak format notes (v4, empirically verified):
  footer (last 44 bytes): magic 0x5A6F12E1, version=4, index_offset,
      index_size, sha1[20]
  index: AES-256-ECB encrypted with the build key, then:
      FString mount_point, i32 count, then per entry:
        FString name; i64 off; i64 size; i64 usize; i32 comp;
        20B sha1; then
        comp != 0: i32 nblocks, blocks{i64,i64}[], u8 enc, i32 cbs
        comp == 0: i32 enc, u8 pad
      entry data at 'off' repeats the same header (minus name) before data;
      blocks are absolute offsets pointing past that header.
"""
import json
import os
import struct
import zlib

AES_KEY = bytes.fromhex("A3278BA7DDD751A75456415A36C3559138E99134D08958C44C2FD29E4BBF342B")
PAK_MAGIC = 0x5A6F12E1
FOOTER_SIZE = 44

COMPRESSION_NONE = 0


def _find_footer(f):
    f.seek(0, 2)
    size = f.tell()
    f.seek(size - FOOTER_SIZE)
    magic, version, idx_off, idx_size = struct.unpack("<Iiqq", f.read(24))
    if magic != PAK_MAGIC:
        raise ValueError("pak footer magic mismatch: 0x%08X" % magic)
    return version, idx_off, idx_size


class PakFS:
    """Read-only overlay for one .pak with on-disk extraction cache."""

    def __init__(self, pak_path, cache_dir, loader_console=None):
        self.pak_path = pak_path
        self.cache_dir = cache_dir
        self.console = loader_console or (lambda msg: None)
        self.f = open(pak_path, "rb")
        self.aes = None
        self.entries = {}
        self.dirs = set()
        self.lc_entries = {}                 # lowercase name -> entry
        self.lc_dirs = {}                    # lowercase dir -> real dir
        self.stats = {"resolve": 0, "extract": 0, "bytes": 0}
        os.makedirs(cache_dir, exist_ok=True)
        self._load_index()

    # ------------------------------------------------------------- parse
    def _aes(self):
        if self.aes is None:
            from Crypto.Cipher import AES
            self.aes = AES.new(AES_KEY, AES.MODE_ECB)
        return self.aes

    def _load_index(self):
        version, idx_off, idx_size = _find_footer(self.f)
        if version != 4:
            self.console("[pakfs] warning: pak version %d (expected 4)"
                         % version)
        self.f.seek(idx_off)
        raw = self.f.read(idx_size)
        dec = self._aes().decrypt(raw)

        class R:
            def __init__(s, b):
                s.b, s.o = b, 0

            def rd(s, n):
                v = s.b[s.o:s.o + n]
                s.o += n
                return v

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
        self.mount = mount
        n = r.i32()
        for _ in range(n):
            name = r.fstr()
            off = r.i64()
            size = r.i64()
            usize = r.i64()
            comp = r.i32()
            r.rd(20)                       # sha1
            if comp != COMPRESSION_NONE:
                nb = r.i32()
                blocks = [(r.i64(), r.i64()) for _ in range(nb)]
                enc = r.u8()
                cbs = r.i32()
                hdr = 8 + 8 + 8 + 4 + 20 + 4 + 16 * nb + 1 + 4
            else:
                enc = 1 if r.i32() else 0
                r.u8()
                nb = 0
                blocks = []
                cbs = 0
                hdr = 8 + 8 + 8 + 4 + 20 + 5
            self.entries[name] = {
                "name": name, "off": off, "size": size, "usize": usize,
                "comp": comp, "enc": enc, "blocks": blocks, "cbs": cbs,
                "hdr": hdr,
            }
            # register all parent dirs
            parts = name.split("/")
            for k in range(1, len(parts)):
                self.dirs.add("/".join(parts[:k]))
        for name, e in self.entries.items():
            self.lc_entries[name.lower()] = e
        for d in self.dirs:
            self.lc_dirs[d.lower()] = d
        self.console("[pakfs] %d entries, mount %r, %d dirs"
                     % (len(self.entries), mount, len(self.dirs)))

    # ------------------------------------------------------------- read
    def read_entry(self, e):
        if e["comp"] == COMPRESSION_NONE:
            self.f.seek(e["off"] + e["hdr"])
            raw = self.f.read((e["size"] + 15) & ~15)
            if e["enc"]:
                raw = self._aes().decrypt(raw)[:e["size"]]
            return raw
        out = []
        for (s, en) in e["blocks"]:
            self.f.seek(s)
            chunk = self.f.read(en - s)
            if e["enc"]:
                chunk = self._aes().decrypt(chunk[:len(chunk) // 16 * 16])[:en - s]
            out.append(zlib.decompressobj().decompress(chunk))
        return b"".join(out)

    # ------------------------------------------------------------- paths
    @staticmethod
    def _components(gpath):
        """Split a guest path, collapsing '.' and '..' lexically."""
        if not gpath:
            return []
        p = gpath.replace("\\", "/")
        if p.startswith("file://"):
            p = p[7:]
        out = []
        for c in p.split("/"):
            if c in ("", "."):
                continue
            if c == "..":
                if out:
                    out.pop()
                continue
            out.append(c)
        return out

    def resolve(self, gpath):
        """Map a guest path onto a pak entry name (or None).

        Matching is suffix-based on path components AND case-insensitive
        (UE4 file layer is case-insensitive), so
          '../../../FortniteGame/FortniteGame.uproject',
          '<app>/cookeddata/fortnitegame/fortnitegame.uproject'
        and plain 'FortniteGame/FortniteGame.uproject' all resolve.
        Longest (earliest component) match wins.
        """
        comps = self._components(gpath)
        for i in range(len(comps)):
            cand = "/".join(comps[i:]).lower()
            if cand in self.lc_entries:
                return self.lc_entries[cand]
        return None

    def resolve_dir(self, gpath):
        comps = self._components(gpath)
        for i in range(len(comps)):
            cand = "/".join(comps[i:]).lower()
            if cand in self.lc_dirs:
                return self.lc_dirs[cand]
        return None

    def list_dir(self, pak_dir):
        """Immediate children names of a pak directory."""
        prefix = pak_dir + "/"
        out = []
        seen = set()
        for name in self.entries:
            if name.startswith(prefix):
                rest = name[len(prefix):]
                if "/" in rest:
                    child = rest.split("/", 1)[0]
                    if child not in seen:
                        seen.add(child)
                        out.append(child)
                else:
                    out.append(rest)
        # plus nested dir names recorded in self.dirs
        for d in self.dirs:
            if d.startswith(prefix) and "/" not in d[len(prefix):]:
                if d[len(prefix):] not in seen:
                    seen.add(d[len(prefix):])
                    out.append(d[len(prefix):])
        return out

    # -------------------------------------------------------- materialize
    def _cache_path(self, entry_name):
        return os.path.join(self.cache_dir, *entry_name.split("/"))

    def materialize(self, gpath, want_dir=False):
        """Extract the pak object for gpath into the cache and return the
        host path (file or directory). Returns None when not in the pak."""
        if want_dir:
            pak_dir = self.resolve_dir(gpath)
            if pak_dir is None:
                return None
            return self.materialize_dir(pak_dir)
        e = self.resolve(gpath)
        if e is not None:
            return self.materialize_file(e)
        d = self.resolve_dir(gpath)
        if d is not None:
            return self.materialize_dir(d)
        return None

    def materialize_file(self, e):
        host = self._cache_path(e["name"])
        if os.path.isfile(host):
            return host
        os.makedirs(os.path.dirname(host), exist_ok=True)
        data = self.read_entry(e)
        tmp = host + ".tmp%d" % (os.getpid(),)
        with open(tmp, "wb") as f:
            f.write(data)
        os.replace(tmp, host)
        self.stats["extract"] += 1
        self.stats["bytes"] += len(data)
        return host

    def materialize_dir(self, pak_dir, depth=0):
        host = os.path.join(self.cache_dir, *pak_dir.split("/"))
        if os.path.isdir(host):
            return host
        os.makedirs(host, exist_ok=True)
        # make children visible (dirs really, files as empty placeholders
        # that get filled on first open)
        for child in self.list_dir(pak_dir):
            child_pak = pak_dir + "/" + child
            if child_pak in self.dirs:
                continue                      # handled when enumerated
            ch = os.path.join(self.cache_dir, *child_pak.split("/"))
            if not os.path.exists(ch):
                e = self.entries.get(child_pak)
                if e is not None and e["size"] <= (1 << 20):
                    self.materialize_file(e)
                else:
                    open(ch, "wb").close()     # placeholder
        return host

    # placeholder files are zero-length; this grows them on demand
    def hydrate(self, host_path):
        """If host_path is an empty placeholder (or missing) but known to
        the pak, extract the real content. Returns final host path."""
        rel = os.path.relpath(host_path, self.cache_dir).replace(os.sep, "/")
        if rel.startswith(".."):
            return host_path
        e = self.entries.get(rel)
        if e is None:
            return host_path
        if os.path.isfile(host_path) and os.path.getsize(host_path) > 0:
            return host_path
        return self.materialize_file(e)

    def in_cache(self, host_path):
        try:
            rel = os.path.relpath(host_path, self.cache_dir)
        except ValueError:
            return False
        return not rel.startswith("..")

    def note_stats(self):
        return self.stats
