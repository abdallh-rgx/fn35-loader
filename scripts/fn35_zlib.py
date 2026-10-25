#!/usr/bin/env python3
"""fn35_zlib.py — zlib (libz) user-space implementation for the guest.

The engine links zlib dynamically (inflateInit2_, inflate, deflate, ...).
The stub farm auto-returning 0 made every decompression a silent no-op,
which is why the pak-index decode ground for billions of instructions on
empty buffers and the project file "failed to read".

z_stream layout (64-bit, zlib 1.2.x):
  +0x00 next_in(ptr) +0x08 avail_in(u32) +0x10 total_in(u64)
  +0x18 next_out(ptr) +0x20 avail_out(u32) +0x28 total_out(u64)
  +0x30 msg(ptr) +0x38 state(ptr) +0x40 zalloc +0x48 zfree +0x50 opaque
  +0x58 data_type(i32) +0x60 adler(u64) +0x68 reserved
Total: 0x70 bytes.

The Python zlib objects (decompressobj/compressobj) live host-side,
keyed by the guest z_stream address (the guest never dereferences
->state itself; it only passes the struct back to us).
"""
import zlib as _z

IMPL = {}


def cfunc(*names):
    def deco(fn):
        for n in names:
            IMPL[n] = fn
        return fn
    return deco


Z_OK = 0
Z_STREAM_END = 1
Z_NEED_DICT = 2
Z_STREAM_ERROR = -2
Z_DATA_ERROR = -3
Z_MEM_ERROR = -4
Z_BUF_ERROR = -5
Z_VERSION_ERROR = -6

Z_NO_FLUSH = 0
Z_SYNC_FLUSH = 2
Z_FINISH = 4


class _ZStreams:
    """Host-side registry of live z_stream objects."""
    def __init__(self):
        self.by_addr = {}

    def get(self, addr):
        return self.by_addr.get(addr)

    def put(self, addr, obj):
        self.by_addr[addr] = obj

    def drop(self, addr):
        return self.by_addr.pop(addr, None)


def _streams(l):
    st = getattr(l, "_zlib_streams", None)
    if st is None:
        st = _ZStreams()
        l._zlib_streams = st
    return st


def _rd(l, a, n):
    return l.rdb(a, n) if a else b""


def _wr(l, a, data):
    if a and data:
        l.wrb(a, data)


# ---------------- inflate family ----------------

@cfunc("_inflateInit_")
def _inflate_init1(l, strm, version, stream_size):
    # windowBits fixed at 15 for plain zlib streams
    return _init_inflate(l, strm, 15, version, stream_size)


@cfunc("_inflateInit2_")
def _inflate_init2(l, strm, window_bits, version, stream_size):
    return _init_inflate(l, strm, window_bits, version, stream_size)


def _init_inflate(l, strm, wbits, version, stream_size):
    if not strm:
        return Z_STREAM_ERROR
    try:
        ver = l.gcstr(version) if version else ""
    except Exception:
        ver = ""
    if ver and not ver.startswith("1."):
        return Z_VERSION_ERROR
    if wbits == 0:
        wbits = 15
    # python wbits semantics match zlib: >9 zlib header, <0 raw, +32 gzip,
    # +16 gzip-only. Clamp the 8..15 window-size range like zlib does.
    if 9 <= wbits <= 15 or wbits < 0 or wbits in (31, 32, 47, 48):
        pybits = wbits
    elif 8 == wbits:
        pybits = 9
    else:
        return Z_STREAM_ERROR
    try:
        obj = _z.decompressobj(pybits)
    except Exception:
        return Z_STREAM_ERROR
    _streams(l).put(strm, ("inf", obj, {"wbits": pybits}))
    # zero total counters
    try:
        l.w64(strm + 0x10, 0)
        l.w64(strm + 0x28, 0)
    except Exception:
        pass
    return Z_OK


@cfunc("_inflate")
def _inflate(l, strm, flush):
    if not strm:
        return Z_STREAM_ERROR
    ent = _streams(l).get(strm)
    if not ent or ent[0] != "inf":
        return Z_STREAM_ERROR
    _, obj, st = ent
    try:
        next_in = l.rd64(strm + 0x00)
        avail_in = l.rd32(strm + 0x08)
        next_out = l.rd64(strm + 0x18)
        avail_out = l.rd32(strm + 0x20)
    except Exception:
        return Z_STREAM_ERROR
    if avail_out == 0 and avail_in == 0:
        return Z_BUF_ERROR
    data = _rd(l, next_in, avail_in) if avail_in else b""
    out = b""
    err = Z_OK
    try:
        if avail_out:
            out = obj.decompress(data, avail_out)
        else:
            out = b""
    except _z.error:
        err = Z_DATA_ERROR
    consumed = len(data) - len(obj.unconsumed_tail)
    # update the guest stream fields
    try:
        if consumed:
            l.w64(strm + 0x00, next_in + consumed)
            l.w32(strm + 0x08, avail_in - consumed)
        if out:
            l.w64(strm + 0x18, next_out + len(out))
            l.w32(strm + 0x20, avail_out - len(out))
            l.w64(strm + 0x28,
                  l.rd64(strm + 0x28) + len(out))
        l.w64(strm + 0x10,
              l.rd64(strm + 0x10) + consumed)
    except Exception:
        pass
    if err != Z_OK:
        st["last_err"] = err
        return err
    if obj.eof:
        return Z_STREAM_END
    if not out and avail_out == 0:
        return Z_BUF_ERROR
    return Z_OK


@cfunc("_inflateEnd")
def _inflate_end(l, strm):
    if not strm:
        return Z_STREAM_ERROR
    if _streams(l).drop(strm) is None:
        return Z_STREAM_ERROR
    return Z_OK


@cfunc("_inflateReset")
def _inflate_reset(l, strm):
    if not strm:
        return Z_STREAM_ERROR
    ent = _streams(l).get(strm)
    if not ent or ent[0] != "inf":
        return Z_STREAM_ERROR
    _, obj, st = ent
    # recreate the decompressobj with the same wbits
    wb = st.get("wbits", 15)
    _streams(l).put(strm, ("inf", _z.decompressobj(wb), {}))
    try:
        l.w64(strm + 0x10, 0)
        l.w64(strm + 0x28, 0)
    except Exception:
        pass
    return Z_OK


@cfunc("_uncompress", "_uncompress2")
def _uncompress(l, dest, dest_len_p, src, src_len):
    try:
        dlen = l.rd64(dest_len_p) if dest_len_p else 0
    except Exception:
        dlen = 0
    raw = _rd(l, src, src_len) if src and src_len else b""
    try:
        out = _z.decompress(raw)
    except _z.error:
        return Z_DATA_ERROR
    n = min(len(out), dlen if dest_len_p else len(out))
    if dest and n:
        _wr(l, dest, out[:n])
        if dest_len_p:
            l.w64(dest_len_p, n)
    elif dest_len_p:
        l.w64(dest_len_p, 0)
    return Z_OK


# ---------------- deflate family ----------------

@cfunc("_deflateInit_")
def _deflate_init1(l, strm, level, version, stream_size):
    # plain zlib header: windowBits 15, memLevel 8, strategy 0
    return _init_deflate(l, strm, level, 15, 8, 0,
                          version, stream_size)


@cfunc("_deflateInit2_")
def _deflate_init2(l, strm, level, method, window_bits, mem_level,
                   strategy, version, stream_size):
    return _init_deflate(l, strm, level, window_bits, mem_level,
                         strategy, version, stream_size, raw=True)


def _init_deflate(l, strm, level, wbits, mem_level, strategy,
                  version, stream_size, raw=False):
    if not strm:
        return Z_STREAM_ERROR
    if not raw:
        wbits = 15
    try:
        obj = _z.compressobj(level if 0 <= level <= 9 else 6, _z.DEFLATED,
                             wbits)
    except Exception:
        return Z_STREAM_ERROR
    _streams(l).put(strm, ("def", obj, {"wbits": wbits}))
    try:
        l.w64(strm + 0x10, 0)
        l.w64(strm + 0x28, 0)
    except Exception:
        pass
    return Z_OK


@cfunc("_deflate")
def _deflate(l, strm, flush):
    if not strm:
        return Z_STREAM_ERROR
    ent = _streams(l).get(strm)
    if not ent or ent[0] != "def":
        return Z_STREAM_ERROR
    _, obj, st = ent
    try:
        next_in = l.rd64(strm + 0x00)
        avail_in = l.rd32(strm + 0x08)
        next_out = l.rd64(strm + 0x18)
        avail_out = l.rd32(strm + 0x20)
    except Exception:
        return Z_STREAM_ERROR
    data = _rd(l, next_in, avail_in) if avail_in else b""
    try:
        if flush == Z_FINISH:
            out = obj.compress(data) + obj.flush()
        elif flush == Z_SYNC_FLUSH:
            out = obj.compress(data) + obj.flush(_z.Z_SYNC_FLUSH)
        else:
            out = obj.compress(data)
    except _z.error:
        return Z_DATA_ERROR
    if len(out) > avail_out:
        # keep what fits, buffer the rest host-side
        st.setdefault("pend", b"")
        st["pend"] += out
        out, st["pend"] = out[:avail_out], st["pend"][avail_out:]
    try:
        consumed = len(data)
        l.w64(strm + 0x00, next_in + consumed)
        l.w32(strm + 0x08, 0)
        if out:
            l.w64(strm + 0x18, next_out + len(out))
            l.w32(strm + 0x20, avail_out - len(out))
        l.w64(strm + 0x10, l.rd64(strm + 0x10) + consumed)
        l.w64(strm + 0x28, l.rd64(strm + 0x28) + len(out))
    except Exception:
        pass
    if flush == Z_FINISH and not st.get("pend"):
        return Z_STREAM_END
    return Z_OK


@cfunc("_deflateEnd")
def _deflate_end(l, strm):
    if not strm:
        return Z_STREAM_ERROR
    if _streams(l).drop(strm) is None:
        return Z_STREAM_ERROR
    return Z_OK


@cfunc("_deflateReset")
def _deflate_reset(l, strm):
    if not strm:
        return Z_STREAM_ERROR
    ent = _streams(l).get(strm)
    if not ent or ent[0] != "def":
        return Z_STREAM_ERROR
    _, obj, st = ent
    _streams(l).put(strm, ("def", _z.compressobj(6, _z.DEFLATED,
                                                  st.get("wbits", 15)), {}))
    try:
        l.w64(strm + 0x10, 0)
        l.w64(strm + 0x28, 0)
    except Exception:
        pass
    return Z_OK


# ---------------- one-shot helpers ----------------

@cfunc("_compress")
def _compress(l, dest, dest_len_p, src, src_len):
    try:
        dlen = l.rd64(dest_len_p) if dest_len_p else 0
    except Exception:
        dlen = 0
    raw = _rd(l, src, src_len) if src and src_len else b""
    out = _z.compress(raw)
    if dest and len(out) <= dlen:
        _wr(l, dest, out)
        if dest_len_p:
            l.w64(dest_len_p, len(out))
        return Z_OK
    if dest_len_p:
        l.w64(dest_len_p, len(out))
    return Z_BUF_ERROR


@cfunc("_compress2")
def _compress2(l, dest, dest_len_p, src, src_len, level):
    return _compress(l, dest, dest_len_p, src, src_len)


@cfunc("_compressBound")
def _compress_bound(l, src_len):
    return src_len + (src_len >> 12) + (src_len >> 14) + (src_len >> 25) + 13


# ---------------- checksums ----------------

@cfunc("_crc32")
def _crc32(l, crc, buf, len_):
    if buf and len_:
        data = _rd(l, buf, len_)
        c = crc & 0xFFFFFFFF
        if c == 0 and crc != 0:
            c = 0xFFFFFFFF  # caller passed -1 style init? normalize below
        # zlib crc32 semantics: crc=0xFFFFFFFF start, result inverted.
        # Most callers pass a previous return value; python does the same
        # inversion internally, so pass through directly.
        try:
            return _z.crc32(data, crc)
        except Exception:
            return _z.crc32(data)
    return crc if crc else 0


@cfunc("_adler32")
def _adler32(l, adler, buf, len_):
    if buf and len_:
        data = _rd(l, buf, len_)
        try:
            return _z.adler32(data, adler)
        except Exception:
            return _z.adler32(data)
    return adler if adler else 1


def register(loader_impl):
    """Merge our IMPL table into the loader's cfunc registry."""
    for k, v in IMPL.items():
        loader_impl.setdefault(k, v)
