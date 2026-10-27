#!/usr/bin/env python3
"""FN3.5 loader: replacement C library (memory/string/printf/stdio/stdlib).

Every entry here replaces a libSystem import. Implementations receive the
loader (l) plus guest x0..x7 and return the value for x0 (or ("d0", float)).
"""
import struct

IMPL = {}


def cfunc(*names):
    def deco(fn):
        for n in names:
            IMPL[n] = fn
        return fn
    return deco


F64 = struct.Struct("<d")
U64 = struct.Struct("<Q")
I64 = struct.Struct("<q")


# ====================================================================
# format engine (printf family, incl. arm64 va_list decoding)
# ====================================================================

class RegSrc:
    """Variadic args straight from registers (x-named, d-named) + stack."""
    def __init__(self, l, first_named_x=3):
        self.l = l
        self.xi = first_named_x
        self.di = 0
        self.stack_i = 0

    def next_int(self):
        if self.xi <= 7:
            v = self.l.reg_x(self.xi)
            self.xi += 1
            return v
        sp = self.l.reg_sp()
        v = self.l.rd64(sp + 8 * self.stack_i)
        self.stack_i += 1
        return v

    def next_dbl(self):
        if self.di <= 7:
            v = self.l.reg_d(self.di)
            self.di += 1
            return v
        sp = self.l.reg_sp()
        v = self.l.rd64(sp + 8 * self.stack_i)
        self.stack_i += 1
        return v


class VaSrc:
    """Decode a guest arm64 va_list structure."""
    def __init__(self, l, va):
        self.l = l
        self.va = va
        self.stack = l.rd64(va + 0)
        self.gr_top = l.rd64(va + 8)
        self.vr_top = l.rd64(va + 16)
        self.gr_offs = struct.unpack("<i", l.rdb(va + 24, 4))[0]
        self.vr_offs = struct.unpack("<i", l.rdb(va + 28, 4))[0]

    def _flush(self):
        b = struct.pack("<QQQiI", self.stack, self.gr_top, self.vr_top,
                        self.gr_offs, self.vr_offs & 0xFFFFFFFF)
        self.l.wrb(self.va, b)

    def next_int(self):
        if self.gr_offs < 0:
            v = self.l.rd64(self.gr_top + self.gr_offs)
            self.gr_offs += 8
        else:
            v = self.l.rd64(self.stack)
            self.stack += 8
        self._flush()
        return v

    def next_dbl(self):
        if self.vr_offs < 0:
            v = self.l.rd64(self.vr_top + self.vr_offs)
            self.vr_offs += 16
        else:
            v = self.l.rd64(self.stack)
            self.stack += 8
        self._flush()
        return v


def _to_int(v):
    if v >= 1 << 63:
        v -= 1 << 64
    return v


def fmt_engine(fmt, src):
    out = []
    i = 0
    n = len(fmt)

    def emit(s):
        out.append(s)

    while i < n:
        c = fmt[i]
        if c != "%":
            emit(c)
            i += 1
            continue
        i += 1
        if i >= n:
            break
        if fmt[i] == "%":
            emit("%")
            i += 1
            continue
        # flags
        left = plus = space = zero = alt = False
        while i < n and fmt[i] in "-+ #0":
            ch = fmt[i]
            if ch == "-":
                left = True
            elif ch == "+":
                plus = True
            elif ch == " ":
                space = True
            elif ch == "0":
                zero = True
            elif ch == "#":
                alt = True
            i += 1
        width = None
        if i < n and fmt[i] == "*":
            width = _to_int(src.next_int())
            i += 1
        else:
            w = 0
            got = False
            while i < n and fmt[i].isdigit():
                w = w * 10 + int(fmt[i])
                i += 1
                got = True
            if got:
                width = w
        prec = None
        if i < n and fmt[i] == ".":
            i += 1
            if i < n and fmt[i] == "*":
                prec = _to_int(src.next_int())
                i += 1
            else:
                p = 0
                while i < n and fmt[i].isdigit():
                    p = p * 10 + int(fmt[i])
                    i += 1
                prec = p
        while i < n and fmt[i] in "hlqjztL":
            i += 1
        if i >= n:
            break
        conv = fmt[i]
        i += 1

        def pad(s, w):
            if w is None or len(s) >= w:
                return s
            fillc = "0" if (zero and not left) else " "
            if left:
                return s + " " * (w - len(s))
            return fillc * (w - len(s)) + s

        try:
            if conv in "di":
                v = _to_int(src.next_int())
                s = str(abs(v))
                if prec is not None:
                    s = s.rjust(prec, "0")
                sign = "-" if v < 0 else ("+" if plus else (" " if space else ""))
                emit(pad(sign + s, width))
            elif conv in "uU":
                v = src.next_int() & 0xFFFFFFFFFFFFFFFF
                s = str(v)
                if prec is not None:
                    s = s.rjust(prec, "0")
                emit(pad(s, width))
            elif conv in "oxX":
                v = src.next_int() & 0xFFFFFFFFFFFFFFFF
                if conv == "o":
                    s = oct(v)[2:]
                    if alt and not s.startswith("0"):
                        s = "0" + s
                elif conv == "x":
                    s = "%x" % v
                    if alt and v:
                        s = "0x" + s
                else:
                    s = "%X" % v
                    if alt and v:
                        s = "0X" + s
                if prec is not None:
                    s = s.rjust(prec, "0")
                emit(pad(s, width))
            elif conv == "p":
                v = src.next_int() & 0xFFFFFFFFFFFFFFFF
                emit(pad("0x%x" % v, width))
            elif conv == "c":
                v = src.next_int() & 0xFF
                emit(chr(v))
            elif conv == "s":
                p = src.next_int()
                s = "(null)" if not p else l_cstr_safe(p)
                if prec is not None:
                    s = s[:prec]
                emit(pad(s, width))
            elif conv in "fFeEgG":
                # next_dbl() returns the DOUBLE VALUE (reg_d), not bits -
                # the old `& mask` was an int-path leftover and raised
                # TypeError("unsupported operand") on every %f
                d = src.next_dbl()
                if not isinstance(d, float):
                    d = F64.unpack(U64.pack(int(d) & 0xFFFFFFFFFFFFFFFF))[0]
                if prec is None:
                    prec = 6
                s = "%.*f" % (prec, d) if conv in "fF" else \
                    ("%.*e" % (prec, d) if conv in "eE" else
                     ("%.*g" % (prec, d)))
                if conv in "FEG" and conv != conv.lower():
                    s = s.upper()
                if plus and not s.startswith("-"):
                    s = "+" + s
                emit(pad(s, width))
            elif conv == "@":
                p = src.next_int()
                emit("<objc %x>" % p)
            else:
                emit("%" + conv)
        except Exception as e:
            emit("<fmt-err %s>" % e)
    return "".join(out)


_CSTR_CACHE = {}


def l_cstr_safe(p):
    return _CSTR_CACHE.get(p) or _read_cstr_global(p)


def _read_cstr_global(p):
    # set at import time by loader (liveness): see set_cstr_reader
    s = _READER(p)
    _CSTR_CACHE[p] = s
    return s


_READER = lambda p: "??"


def set_cstr_reader(fn):
    global _READER
    _READER = fn


def out_str(l, dst, size, text):
    """snprintf-style store; returns full (untruncated) length."""
    if dst == 0:
        return len(text)
    if size == 0:
        return len(text)
    data = text.encode("utf-8", "replace")[: size - 1] + b"\x00"
    l.wrb(dst, data)
    return len(text)


# ====================================================================
# memory
# ====================================================================

@cfunc("_malloc")
def _malloc(l, size):
    if size >= 4096:
        import os
        if os.environ.get("FN35_LOG_ALLOC"):
            pc = l.reg_lr() if hasattr(l, "reg_lr") else 0
            nm, sa = l.nearest_symbol(pc) if pc else (None, 0)
            l.console("[alloc] malloc(0x%x) caller=%s+0x%x"
                      % (size, (nm or "?")[:50], pc - (sa or 0)))
    return l.heap_alloc(size)


@cfunc("_calloc")
def _calloc(l, count, size):
    return l.heap_alloc(count * size)


@cfunc("_realloc")
def _realloc(l, ptr, newsize):
    if ptr == 0:
        return l.heap_alloc(newsize)
    old = l.heap_size_of(ptr)
    if newsize == 0:
        return 0
    p = l.heap_alloc(newsize)
    if old:
        l.wrb(p, l.rdb(ptr, min(old, newsize)))
    return p


@cfunc("_free", "_malloc_free")
def _free(l, ptr):
    import os as _os
    if _os.environ.get("FN35_LOG_FREE") and l:
        try:
            pc = l.reg_lr() if hasattr(l, "reg_lr") else 0
            nm, sa = l.nearest_symbol(pc) if pc else (None, 0)
            l.console("[free] ptr=0x%x caller=%s+0x%x"
                      % (ptr, (nm or "?")[:60], pc - (sa or 0)))
        except Exception:
            pass
    return 0                    # bump allocator: no-op


@cfunc("_valloc", "_aligned_alloc")
def _valloc(l, size):
    return l.heap_alloc(size)


@cfunc("_posix_memalign")
def _posix_memalign(l, outptr, align, size):
    p = l.heap_alloc(size)
    if outptr:
        l.w64(outptr, p)
    return 0


@cfunc("_memalign")
def _memalign(l, align, size):
    return l.heap_alloc(size)


@cfunc("_malloc_zone_malloc", "_malloc_zone_alloc")
def _zone_malloc(l, zone, size):
    return l.heap_alloc(size)


@cfunc("_malloc_zone_calloc")
def _zone_calloc(l, zone, count, size):
    return l.heap_alloc(count * size)


@cfunc("_malloc_zone_realloc")
def _zone_realloc(l, zone, ptr, newsize):
    return _realloc(l, ptr, newsize)


@cfunc("_malloc_zone_free")
def _zone_free(l, zone, ptr):
    return 0


@cfunc("_malloc_zone_memalign")
def _zone_memalign(l, zone, align, size):
    return l.heap_alloc(size)


@cfunc("_malloc_zone_valloc")
def _zone_valloc(l, zone, size):
    return l.heap_alloc(size)


@cfunc("_malloc_default_zone", "_malloc_create_zone")
def _malloc_zone(l, a=0, b=0):
    return l.data_cell("malloc.zone", 64)


@cfunc("_malloc_set_zone_name", "_malloc_zone_print",
       "_malloc_zone_statistics", "_malloc_get_zone_name")
def _malloc_zone_stub(l, a=0, b=0):
    return 0


@cfunc("_malloc_size", "_malloc_good_size")
def _malloc_size(l, ptr):
    return l.heap_size_of(ptr)


# ---- C++ new / delete

@cfunc("_Znwm", "_ZnwmStandalone", "__Znwm")
def _op_new(l, size):
    return l.heap_alloc(size)


@cfunc("_Znam", "_ZnamStandalone", "__Znam")
def _op_new_array(l, size):
    return l.heap_alloc(size)


@cfunc("_ZnwmRKSt9nothrow_t", "_ZnamRKSt9nothrow_t")
def _op_new_nothrow(l, size, nt):
    return l.heap_alloc(size)


@cfunc("_ZdlPv", "_ZdlPvStandalone", "__ZdlPv",
       "_ZdaPv", "_ZdaPvStandalone", "__ZdaPv")
def _op_delete(l, ptr, a=0):
    return 0


@cfunc("_ZdlPvm", "_ZdlPvRKSt9nothrow_t", "_ZdaPvm",
       "_ZdaPvRKSt9nothrow_t")
def _op_delete2(l, ptr, size):
    return 0


@cfunc("_memcpy", "_memmove")
def _memcpy(l, dst, src, n):
    if dst and src and n:
        l.wrb(dst, l.rdb(src, n))
    return dst


@cfunc("_memset")
def _memset(l, dst, c, n):
    if dst and n:
        l.wrb(dst, bytes([c & 0xFF]) * n)
    return dst


@cfunc("_bzero", "__bzero")
def _bzero(l, dst, n):
    if dst and n:
        l.wrb(dst, b"\x00" * n)
    return 0


@cfunc("_memcmp", "_bcmp")
def _memcmp(l, a, b, n):
    if not n:
        return 0
    ba = l.rdb(a, n)
    bb = l.rdb(b, n)
    return -1 if ba < bb else (1 if ba > bb else 0)


@cfunc("__memcmpv2", "_memcmpv2")
def _memcmp2(l, a, b, n):
    return _memcmp(l, a, b, n)


# ====================================================================
# strings
# ====================================================================

@cfunc("_strlen")
def _strlen(l, s):
    return len(l.gcstr(s))


@cfunc("_strnlen")
def _strnlen(l, s, n):
    return len(l.gcstr(s, maxlen=n))


@cfunc("_strcmp")
def _strcmp(l, a, b):
    sa = l.gcstr(a)
    sb = l.gcstr(b)
    return -1 if sa < sb else (1 if sa > sb else 0)


@cfunc("_strncmp")
def _strncmp(l, a, b, n):
    sa = l.gcstr(a, maxlen=max(n, 1)).encode()[:n]
    sb = l.gcstr(b, maxlen=max(n, 1)).encode()[:n]
    return -1 if sa < sb else (1 if sa > sb else 0)


@cfunc("_strcasecmp", "_strncasecmp")
def _strcasecmp(l, a, b, n=None):
    sa = l.gcstr(a).lower()
    sb = l.gcstr(b).lower()
    if n is not None:
        sa = sa[:n]
        sb = sb[:n]
    return -1 if sa < sb else (1 if sa > sb else 0)


@cfunc("_strcpy")
def _strcpy(l, dst, src):
    s = l.gcstr(src)
    l.wrb(dst, s.encode() + b"\x00")
    return dst


@cfunc("_strncpy")
def _strncpy(l, dst, src, n):
    s = l.gcstr(src).encode()
    l.wrb(dst, (s[:n] + b"\x00" * n)[:n])
    return dst


@cfunc("_strlcpy")
def _strlcpy(l, dst, src, size):
    s = l.gcstr(src).encode()
    if size:
        l.wrb(dst, (s[: size - 1] + b"\x00"))
    return len(s)


@cfunc("_strlcat")
def _strlcat(l, dst, src, size):
    cur = l.gcstr(dst).encode()
    s = l.gcstr(src).encode()
    if size and len(cur) < size - 1:
        room = size - 1 - len(cur)
        l.wrb(dst, s[:room])
    return len(cur) + len(s)


@cfunc("_strcat")
def _strcat(l, dst, src):
    cur = l.gcstr(dst)
    s = l.gcstr(src)
    l.wrb(dst, (cur + s).encode() + b"\x00")
    return dst


@cfunc("_strstr")
def _strstr(l, hay, needle):
    sh = l.gcstr(hay)
    sn = l.gcstr(needle)
    if not sn:
        return hay
    idx = sh.find(sn)
    return hay + idx if idx >= 0 else 0


@cfunc("_strchr")
def _strchr(l, s, c):
    st = l.gcstr(s)
    ch = chr(c & 0xFF) if c else "\x00"
    idx = st.find(ch)
    if c == 0:
        return s + len(st)
    return s + idx if idx >= 0 else 0


@cfunc("_strrchr")
def _strrchr(l, s, c):
    st = l.gcstr(s)
    ch = chr(c & 0xFF)
    idx = st.rfind(ch)
    return s + idx if idx >= 0 else (s + len(st) if c == 0 else 0)


@cfunc("_strdup")
def _strdup(l, s):
    b = l.gcstr(s).encode() + b"\x00"
    p = l.heap_alloc(len(b), zero=False)
    l.wrb(p, b)
    return p


@cfunc("_strndup")
def _strndup(l, s, n):
    b = l.gcstr(s, maxlen=n).encode()[:n] + b"\x00"
    p = l.heap_alloc(len(b), zero=False)
    l.wrb(p, b)
    return p


@cfunc("_strchrnul")
def _strchrnul(l, s, c):
    st = l.gcstr(s)
    ch = chr(c & 0xFF)
    idx = st.find(ch)
    return s + (idx if idx >= 0 else len(st))


@cfunc("_strtod")
def _strtod(l, s, endp):
    st = l.gcstr(s)
    try:
        val = float(st.split()[0]) if st.split() else 0.0
        used = len(str(val))
    except ValueError:
        val = 0.0
        used = 0
    if endp:
        l.w64(endp, s + used)
    return ("d0", val)


def _digit_val(c):
    if "0" <= c <= "9":
        return ord(c) - 48
    if "a" <= c <= "z":
        return ord(c) - 87
    if "A" <= c <= "Z":
        return ord(c) - 55
    return 99


@cfunc("_strtol", "_strtoll", "_strtoul", "_strtoull")
def _strtol(l, s, endp, base):
    """True strtol semantics: parse the longest valid numeric prefix,
    stop at the first invalid char (a comma in '10,4' stops after 10)."""
    st = l.gcstr(s)
    i, n = 0, len(st)
    while i < n and st[i] in " \t\n\r\f\v":
        i += 1
    sign = 1
    if i < n and st[i] in "+-":
        if st[i] == "-":
            sign = -1
        i += 1
    b = base & 0xFF
    if b == 0:
        b = 10
        if i + 1 < n and st[i] == "0" and st[i + 1] in "xX" \
                and i + 2 < n and _digit_val(st[i + 2]) < 16:
            b = 16
        elif i < n and st[i] == "0":
            b = 8
    if b == 16 and i + 1 < n and st[i] == "0" and st[i + 1] in "xX":
        i += 2
    start = i
    val = 0
    while i < n:
        d = _digit_val(st[i])
        if d >= b:
            break
        val = val * b + d
        i += 1
    if i == start and not (start > 0 and st[start - 1:start] == "0"
                           and b == 16):
        # no digits consumed
        if endp:
            l.w64(endp, s)
        return 0
    if endp:
        l.w64(endp, s + i)
    v = sign * val
    return v & 0xFFFFFFFFFFFFFFFF


@cfunc("_atoi", "_atol")
def _atoi(l, s):
    try:
        return int(l.gcstr(s).strip() or "0")
    except ValueError:
        return 0


@cfunc("_atof")
def _atof(l, s):
    try:
        return ("d0", float(l.gcstr(s).strip() or "0"))
    except ValueError:
        return ("d0", 0.0)


# ====================================================================
# printf family
# ====================================================================

@cfunc("_snprintf")
def _snprintf(l, dst, size, fmt, *rest):
    txt = fmt_engine(l.gcstr(fmt), RegSrc(l, first_named_x=3))
    return out_str(l, dst, size, txt)


@cfunc("__snprintf_chk")
def __snprintf_chk(l, dst, flag, size, fmt, *rest):
    txt = fmt_engine(l.gcstr(fmt), RegSrc(l, first_named_x=4))
    return out_str(l, dst, size, txt)


@cfunc("_sprintf")
def _sprintf(l, dst, fmt):
    txt = fmt_engine(l.gcstr(fmt), RegSrc(l, 2))
    return out_str(l, dst, 1 << 30, txt)


@cfunc("_vsnprintf")
def _vsnprintf(l, dst, size, fmt, va):
    txt = fmt_engine(l.gcstr(fmt), VaSrc(l, va))
    return out_str(l, dst, size, txt)


@cfunc("__vsnprintf_chk")
def __vsnprintf_chk(l, dst, flag, size, fmt, va):
    txt = fmt_engine(l.gcstr(fmt), VaSrc(l, va))
    return out_str(l, dst, size, txt)


@cfunc("_vsprintf")
def _vsprintf(l, dst, fmt, va):
    txt = fmt_engine(l.gcstr(fmt), VaSrc(l, va))
    return out_str(l, dst, 1 << 30, txt)


@cfunc("_printf")
def _printf(l, fmt):
    lr = l.reg_lr()
    nm, sa = l.nearest_symbol(lr)
    l.console("[pr] lr=0x%x (%s+0x%x)" % (lr, (nm or "?")[:48],
                                          lr - (sa or 0)))
    try:
        raw = l.rdb(fmt, 256) if fmt else b""
    except Exception:
        raw = b""
    # UE4's iOS log device may pass UTF-16 text to printf
    if raw[:1] and raw[0] and (raw[1] == 0 if len(raw) > 1 else True) \
            and b"\x00" in raw[:4] and raw[:2] != b"\x00\x00":
        # looks like UTF-16LE: decode
        try:
            end = raw.find(b"\x00\x00")
            if end % 2:
                end += 1
            txt = raw[:end + 1].decode("utf-16-le", "replace")
        except Exception:
            txt = raw.split(b"\x00")[0].decode("utf-8", "replace")
    else:
        txt = raw.split(b"\x00")[0].decode("utf-8", "replace")
    txt2 = fmt_engine(txt, RegSrc(l, 1)) if "%" in txt else txt
    if not txt2.strip() and "%s" not in txt and "Failed" in txt:
        l.console("[PROJ-EARLY] txt=%r txt2=%r x1=%x" % (txt[:60], txt2[:60], l.reg_x(1)))
    if not txt2.strip() and "%s" in txt:
        # the engine sometimes passes the first vararg on the stack
        # (stack vararg slot = [sp]); retry with that
        try:
            sp = l.reg_sp()
            alt = l.rd64(sp)
            save = [l.reg_x(i) for i in range(1, 8)]

            class StackSrc:
                def __init__(self):
                    self.stack_i = 1

                def next_int(self):
                    if self.stack_i == 1:
                        self.stack_i = 2
                        return alt
                    return l.rd64(sp + 8 * (self.stack_i - 2))

                def next_dbl(self):
                    return 0.0

            retry = fmt_engine(txt, StackSrc())
            if retry.strip():
                txt2 = retry
        except Exception:
            pass
    if txt2 == txt and "%" in txt:
        # substitution failed? dump arg bytes for diagnosis
        try:
            a1 = l.reg_x(1)
            raw1 = l.rdb(a1, 96) if a1 else b""
            l.console("printf: [RAW] %r" % (raw1,))
        except Exception:
            pass
    if "didn't allocate" in txt2 or "we didn" in txt2:
        # walk the guest FP chain to expose the recursion source
        try:
            chain = []
            fp = l.reg_x(29)
            for _ in range(48):
                if not fp or fp < 0x1000:
                    break
                nxt = l.rd64(fp)
                ret = l.rd64(fp + 8)
                if nxt <= fp or nxt - fp > 0x100000:
                    break
                nm, sa = l.nearest_symbol(ret)
                chain.append("0x%x (%s+0x%x)" % (ret, (nm or "?")[:44],
                                                  ret - (sa or 0)))
                fp = nxt
            l.console("[freewarn-stack] %s" % " <- ".join(chain[:16]))
        except Exception as e:
            l.console("[freewarn-stack] walk failed %r" % (e,))
    if "CRC error" in txt2 and getattr(l, "_crc_bt_done", 0) < 3:
        l._crc_bt_done = getattr(l, "_crc_bt_done", 0) + 1
        try:
            chain = []
            fp = l.reg_x(29)
            for _ in range(40):
                if not fp or fp < 0x1000:
                    break
                nxt = l.rd64(fp)
                ret = l.rd64(fp + 8)
                if nxt <= fp or nxt - fp > 0x100000:
                    break
                nm, sa = l.nearest_symbol(ret)
                chain.append("0x%x (%s+0x%x)" % (ret, (nm or "?")[:44],
                                                  ret - (sa or 0)))
                fp = nxt
            l.console("[crc-stack] %s" % " <- ".join(chain[:14]))
        except Exception as e:
            l.console("[crc-stack] walk failed %r" % (e,))
    if "Failed to read file" in (txt2 or "") and \
            not getattr(l, "_uproj_dumped", False):
        l._uproj_dumped = True
        try:
            ring = getattr(l, "_lm_ring", None)
            if ring:
                l.console("[proj-lm] last 45 instructions:")
                import capstone as _cs
                _md = _cs.Cs(_cs.CS_ARCH_ARM64, _cs.CS_MODE_ARM)
                for pc, sp, lr in list(ring)[-45:]:
                    nm2, sa2 = l.nearest_symbol(pc)
                    try:
                        _d = next(_md.disasm(
                            bytes(l.rdb(pc, 4)), pc), None)
                        ins = ("%s %s" % (_d.mnemonic, _d.op_str)
                               if _d else "?")
                    except Exception:
                        ins = "?"
                    l.console("  [plm] 0x%x %-22s %s+0x%x%s"
                              % (pc, ins[:22],
                                 (nm2 or "?")[:34], pc - (sa2 or 0),
                                 "  SP0!" if sp == 0 else ""))
            l.console("[PROJ-FAIL] stack scan:")
            sp = l.reg_sp()
            for off in range(0, 0x300, 8):
                v = l.rd64(sp + off)
                if 0x100000000 <= v < 0x106000000:
                    nm2, sa2 = l.nearest_symbol(v)
                    l.console("  [pf +0x%03x] 0x%x %s+0x%x"
                               % (off, v, (nm2 or "?")[:52], v - (sa2 or 0)))
            l.console("[PROJ-FAIL] recent file stubs:")
            for e in list(l.stub_ring)[-400:]:
                s = str(e[0])
                if any(f in s for f in ("open", "stat", "access", "read",
                                        "getcwd", "realpath", "dirent",
                                        "NSGet", "proc")):
                    l.console("   %s" % (e,))
        except Exception as _e:
            l.console("[PROJ-FAIL] dump err %r" % _e)
    l.console("printf: " + (txt2 or txt))
    return len(txt2 or txt)


@cfunc("_fprintf")
def _fprintf(l, fp, fmt):
    txt = fmt_engine(l.gcstr(fmt), RegSrc(l, 2))
    l.console("fprintf[%x]: %s" % (fp, txt))
    return len(txt)


@cfunc("___fprintf_chk")
def ___fprintf_chk(l, fp, flag, fmt):
    txt = fmt_engine(l.gcstr(fmt), RegSrc(l, 3))
    l.console("fprintf[%x]: %s" % (fp, txt))
    return len(txt)


@cfunc("_vprintf")
def _vprintf(l, fmt, va):
    txt = fmt_engine(l.gcstr(fmt), VaSrc(l, va))
    l.console("vprintf: " + txt)
    return len(txt)


@cfunc("_vfprintf")
def _vfprintf(l, fp, fmt, va):
    txt = fmt_engine(l.gcstr(fmt), VaSrc(l, va))
    l.console("vfprintf[%x]: %s" % (fp, txt))
    return len(txt)


@cfunc("_asprintf")
def _asprintf(l, outp, fmt):
    txt = fmt_engine(l.gcstr(fmt), RegSrc(l, 2))
    b = txt.encode() + b"\x00"
    p = l.heap_alloc(len(b), zero=False)
    l.wrb(p, b)
    l.w64(outp, p)
    return len(txt)


@cfunc("_vasprintf")
def _vasprintf(l, outp, fmt, va):
    txt = fmt_engine(l.gcstr(fmt), VaSrc(l, va))
    b = txt.encode() + b"\x00"
    p = l.heap_alloc(len(b), zero=False)
    l.wrb(p, b)
    l.w64(outp, p)
    return len(txt)


@cfunc("_puts")
def _puts(l, s):
    l.console("puts: " + l.gcstr(s))
    return 0


@cfunc("_fputs")
def _fputs(l, s, fp):
    l.console("fputs[%x]: %s" % (fp, l.gcstr(s)))
    return 0


@cfunc("_fputc", "_putc")
def _fputc(l, c, fp):
    return c


@cfunc("_fgetc", "_getc")
def _fgetc(l, fp):
    """int fgetc(FILE*) -- one byte or EOF. The engine parses text
    files (ue4commandline.txt!) byte-wise."""
    fd = (fp - 0x1000) if fp and fp > 0x1000 else 0
    ent = l.fds.get(fd) if fd else None
    if not ent or ent[0] != "file":
        return -1
    try:
        c = ent[1].read(1)
    except Exception:
        return -1
    return c[0] if c else -1


@cfunc("_getchar")
def _getchar(l):
    return -1


def _stdio_line(l, fp, n):
    """shared fgets core: read up to n-1 bytes stopping after newline"""
    if n <= 0 or not fp:
        return None
    fd = (fp - 0x1000) if fp > 0x1000 else 0
    ent = l.fds.get(fd) if fd else None
    if not ent or ent[0] != "file":
        return None
    try:
        line = ent[1].readline(n - 1)
    except Exception:
        return None
    return line if line else None


@cfunc("_fgets")
def _fgets(l, buf, n, fp):
    line = _stdio_line(l, fp, n)
    if line is None:
        return 0
    l.wrb(buf, line[:n - 1] + b"\x00")
    return buf


@cfunc("_NSLog", "__NSLog", "_CFLog")
def _nslog(l, fmt):
    txt = fmt_engine(l.gcstr(fmt), RegSrc(l, 1))
    l.console("NSLog: " + txt)
    # ---- trigger the last-mile instruction trace -----------------
    # the PC=0/sp=0 null-call happens shortly after the pipeline-cache
    # warning; switch on a bounded instruction ring right here so the
    # fault dump shows the exact branch that went to NULL.
    try:
        if "Failed to open default shader pipeline cache" in txt \
                and not getattr(l, "_trace_armed", False):
            l._trace_armed = True
            l.arm_lastmile_trace(1_500_000)
    except Exception:
        pass
    return 0


# ====================================================================
# stdlib
# ====================================================================

@cfunc("_atoi")
def _atoi2(l, s):
    try:
        return int(l.gcstr(s).strip() or "0")
    except ValueError:
        return 0


@cfunc("_abs", "_labs", "_llabs")
def _abs(l, v):
    v = _to_int(v)
    return abs(v) & 0xFFFFFFFFFFFFFFFF


@cfunc("_getenv")
def _getenv(l, name):
    s = l.gcstr(name)
    val = l.env_get(s)
    if val is None:
        return 0
    return l.cstring_cell("env." + s, val)


@cfunc("_setenv")
def _setenv(l, name, val, overwrite):
    l.env_set(l.gcstr(name), l.gcstr(val))
    return 0


@cfunc("_unsetenv")
def _unsetenv(l, name):
    l.env_unset(l.gcstr(name))
    return 0


@cfunc("_putenv")
def _putenv(l, s):
    kv = l.gcstr(s)
    if "=" in kv:
        k, v = kv.split("=", 1)
        l.env_set(k, v)
    return 0


@cfunc("_arc4random")
def _arc4random(l):
    import random
    return random.randrange(1 << 32)


@cfunc("_arc4random_uniform")
def _arc4random_uniform(l, bound):
    import random
    return random.randrange(bound) if bound else 0


@cfunc("_arc4random_buf")
def _arc4random_buf(l, buf, n):
    import random
    l.wrb(buf, random.randbytes(n))
    return 0


@cfunc("_random")
def _random(l):
    import random
    return random.randrange(1 << 31)


@cfunc("_rand")
def _rand(l):
    import random
    return random.randrange(1 << 31)


@cfunc("_srand", "_srandom")
def _srand(l, seed):
    return 0


@cfunc("_getentropy")
def _getentropy(l, buf, n):
    import random
    l.wrb(buf, random.randbytes(n))
    return 0


@cfunc("_atexit", "___cxa_atexit")
def _atexit(l, fn, arg, dso):
    l.atexit_list.append((fn, arg))
    return 0


@cfunc("___cxa_guard_acquire")
def _cxa_guard_acquire(l, guard):
    # must return 1 = "you own the guard, run the initializer"
    return 1


@cfunc("___cxa_guard_release")
def _cxa_guard_release(l, guard):
    try:
        l.w8(guard, 1)          # mark initialized (guard byte bit 0)
    except Exception:
        pass
    return 0


@cfunc("___cxa_guard_abort")
def _cxa_guard_abort(l, guard):
    return 0


@cfunc("__error", "___error", "_error")
def _error(l):
    # per-thread errno cell
    if l.cur is not None and l.cur.errno_cell:
        return l.cur.errno_cell
    return l.data_cell("errno.main", 16)


@cfunc("___cxa_begin_catch", "___cxa_end_catch")
def _cxa1(l, a=0):
    return 0


@cfunc("_signal", "_sigaction", "_sigprocmask", "_sigemptyset", "_sigaddset",
       "_sigaltstack", "_sigwait", "_sigpending", "_signal", "__sigaction")
def _sig_stub(l, a=0, b=0, c=0, d=0):
    return 0


@cfunc("_getpagesize")
def _getpagesize(l):
    return 16384


@cfunc("_localeconv")
def _localeconv(l):
    return l.data_cell("localeconv", 128)


@cfunc("_qsort_b", "_qsort_r")
def _qsort_stub(l, base, n, size, compar):
    # real qsort with native comparator lives in ioslib (needs py_call)
    from fn35_ioslib import _qsort_native
    return _qsort_native(l, base, n, size, compar)


@cfunc("_bsearch")
def _bsearch(l, key, base, n, size, compar):
    def drv():
        lo, hi = 0, _to_int(n)
        while lo < hi:
            mid = (lo + hi) // 2
            r = yield ("call", compar, (key, base + mid * size))
            if r == 0:
                return base + mid * size
            if r < 0:
                hi = mid
            else:
                lo = mid + 1
        return 0
    # py_call: StopIteration.value becomes x0 on return
    l.py_call(drv(), ret=0)
    return 0


# ====================================================================
# ctype family (tolower/toupper/isdigit...) -- discovered via stub ring
# ====================================================================

import string as _string


def _mk_ctype():
    lower_map = {}
    for i in range(256):
        c = chr(i)
        lower_map[i] = ord(c.lower()) if c.isupper() else i
    return lower_map


_LOWER = _mk_ctype()


@cfunc("___tolower", "_tolower")
def ___tolower(l, c):
    return _LOWER.get(c & 0xFF, c & 0xFF)


@cfunc("___toupper", "_toupper")
def ___toupper(l, c):
    ch = chr(c & 0xFF)
    return ord(ch.upper()) if ch.islower() else c & 0xFF


@cfunc("___isalpha", "_isalpha")
def _isalpha(l, c):
    return 1 if chr(c & 0xFF).isalpha() else 0


@cfunc("___isdigit", "_isdigit")
def _isdigit(l, c):
    return 1 if chr(c & 0xFF).isdigit() else 0


@cfunc("___isspace", "_isspace")
def _isspace(l, c):
    return 1 if chr(c & 0xFF).isspace() else 0


@cfunc("___isupper", "_isupper")
def _isupper(l, c):
    return 1 if chr(c & 0xFF).isupper() else 0


@cfunc("___islower", "_islower")
def _islower(l, c):
    return 1 if chr(c & 0xFF).islower() else 0


@cfunc("___isalnum", "_isalnum")
def _isalnum(l, c):
    return 1 if chr(c & 0xFF).isalnum() else 0


@cfunc("___ispunct", "_ispunct")
def _ispunct(l, c):
    ch = chr(c & 0xFF)
    return 1 if (ch.isprintable() and not ch.isalnum() and not ch.isspace()) else 0


@cfunc("___isprint", "_isprint")
def _isprint(l, c):
    return 1 if chr(c & 0xFF).isprintable() else 0


@cfunc("___iscntrl", "_iscntrl")
def _iscntrl(l, c):
    return 1 if (c & 0xFF) < 32 or (c & 0xFF) == 127 else 0


@cfunc("___isxdigit", "_isxdigit")
def _isxdigit(l, c):
    return 1 if chr(c & 0xFF) in "0123456789abcdefABCDEF" else 0


@cfunc("___isblank", "_isblank")
def _isblank(l, c):
    return 1 if chr(c & 0xFF) in " \t" else 0


@cfunc("___isascii", "_isascii")
def _isascii(l, c):
    return 1 if (c & 0xFF) < 128 else 0


@cfunc("___toupper_l", "___tolower_l")
def _ctype_l(l, c, loc):
    return _LOWER.get(c & 0xFF, c & 0xFF)


@cfunc("_setlocale")
def _setlocale(l, category, locale):
    if locale:
        return l.cstring_cell("locale.C", "C")
    return l.cstring_cell("locale.cur", "C")
