#!/usr/bin/env python3
"""FN3.5 loader: guest-native hot stubs.

The Python stub farm costs ~75us per imported call (dispatch + unicorn
reg_read overhead). Pure functions like toupper/tolower/strlen/memcpy are
called MILLIONS of times during engine boot, so we assemble tiny ARM64
implementations with keystone, place them in the (RWX) stub farm window
and point the GOT slots at them. They then run at full emulation speed
with zero Python involvement.

Semantics mirror fn35_clib's versions (ASCII-only fast paths).
"""
import capstone
import struct

try:
    from keystone import Ks, KS_ARCH_ARM64, KS_MODE_LITTLE_ENDIAN
    _KS = Ks(KS_ARCH_ARM64, KS_MODE_LITTLE_ENDIAN)
except Exception:                                    # pragma: no cover
    _KS = None

CS = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_LITTLE_ENDIAN)

# lives inside the mapped 16 MB stub-farm window, past the svc slots
NATIVE_BASE = 0x0000500000000000 + 0x00F00000

NATIVES = {
    # ASCII toupper: 'a'-'z' -> -32
    "___toupper": """
        cmp   w0, #97
        b.lo  La
        cmp   w0, #122
        b.hi  La
        sub   w0, w0, #32
    La: ret
    """,
    # ASCII tolower: 'A'-'Z' -> +32
    "___tolower": """
        cmp   w0, #65
        b.lo  La
        cmp   w0, #90
        b.hi  La
        add   w0, w0, #32
    La: ret
    """,
    # size_t strlen(const char* s)
    "_strlen": """
        mov   x10, #0x10000
        cmp   x0, x10
        b.lo  Lb
        mov   x9, x0
        mov   x8, #0
    Ll: ldrb  w10, [x9]
        cbz   w10, Le
        add   x9, x9, #1
        add   x8, x8, #1
        b     Ll
    Le: mov   x0, x8
        ret
    Lb: mov   x0, #0
        ret
    """,
    # void* memcpy(dst, src, n) -- returns dst; no-op on bad pointers
    # (mirrors the Python stub's silent-failure behaviour)
    "_memcpy": """
        mov   x10, #0x10000
        cmp   x0, x10
        b.lo  Ld2
        cmp   x1, x10
        b.lo  Ld2
        mov   x8, x0
        cbz   x2, Ld1
    Lm: ldrb  w9, [x1]
        strb  w9, [x0]
        add   x0, x0, #1
        add   x1, x1, #1
        subs  x2, x2, #1
        b.ne  Lm
    Ld1: mov   x0, x8
        ret
    Ld2: ret
    """,
    # int memcmp(a, b, n)
    "_memcmp": """
        mov   x10, #0x10000
        cmp   x0, x10
        b.lo  Lz
        cmp   x1, x10
        b.lo  Lz
        cbz   x2, Lz
    Lm: ldrb  w8, [x0]
        ldrb  w9, [x1]
        subs  w11, w8, w9
        cbnz  w11, Lx
        add   x0, x0, #1
        add   x1, x1, #1
        subs  x2, x2, #1
        b.ne  Lm
    Lz: mov   w11, #0
    Lx: mov   w0, w11
        ret
    """,
    # int strcmp(a, b)
    "_strcmp": """
        mov   x10, #0x10000
        cmp   x0, x10
        b.lo  Lb
        cmp   x1, x10
        b.lo  Lb
    Ls: ldrb  w8, [x0]
        ldrb  w9, [x1]
        subs  w11, w8, w9
        cbnz  w11, Ld
        cbz   w8, Ld
        add   x0, x0, #1
        add   x1, x1, #1
        b     Ls
    Ld: mov   w0, w11
        ret
    Lb: mov   w0, #0
        ret
    """,
    # int strncmp(a, b, n)
    "_strncmp": """
        mov   x10, #0x10000
        cmp   x0, x10
        b.lo  Lz
        cmp   x1, x10
        b.lo  Lz
        cbz   x2, Lz
    Ls: ldrb  w8, [x0]
        ldrb  w9, [x1]
        subs  w11, w8, w9
        cbnz  w11, Lx
        cbz   w8, Lz
        add   x0, x0, #1
        add   x1, x1, #1
        subs  x2, x2, #1
        b.ne  Ls
    Lz: mov   w11, #0
    Lx: mov   w0, w11
        ret
    """,
    # char* strchr(s, c)  -- c in w1
    "_strchr": """
        mov   x10, #0x10000
        cmp   x0, x10
        b.lo  Ln
        mov   x8, x0
    Lc: ldrb  w9, [x8]
        cmp   w9, w1
        b.eq  Lf
        cbz   w9, Ln
        add   x8, x8, #1
        b     Lc
    Lf: mov   x0, x8
        ret
    Ln: mov   x0, #0
        ret
    """,
}


def build_native_stubs(loader):
    """Assemble + install the native routines; returns {name: addr}."""
    if _KS is None:
        loader.console("[native] keystone unavailable; skipping")
        return {}
    import os as _os
    disabled = set(x.strip().lstrip("_")
                   for x in _os.environ.get("FN35_NO_NATIVE", "").split(",")
                   if x.strip())
    out = {}
    code = bytearray()

    def place(name, src):
        addr = NATIVE_BASE + len(code)
        ks = Ks(KS_ARCH_ARM64, KS_MODE_LITTLE_ENDIAN)
        blob = bytes(ks.asm(src)[0])
        txt = "; ".join("%s %s" % (i.mnemonic, i.op_str)
                        for i in CS.disasm(blob, addr))
        loader.console("[native] %-12s 0x%x %s" % (name, addr, txt[:100]))
        out[name] = addr
        code.extend(blob)
        while len(code) % 16:
            code.extend(b"\x1f\x20\x03\xd5")      # nop
        return addr

    # --- hybrid toupper/tolower: ASCII fast path, unicode via Python ---
    # The engine uses UTF-16 TCHARs, so non-ASCII input must fall back to
    # the Python stub (which does proper unicode case mapping).
    for name, py_name, lo, hi, delta in (
            ("___toupper", "___toupper_py", 97, 122, -32),
            ("___tolower", "___tolower_py", 65, 90, 32)):
        if name.lstrip("_") in disabled:
            continue
        svc = loader.make_svc_stub(py_name)
        sub = "sub   w0, w0, #32" if delta < 0 else "add   w0, w0, #32"
        # trampoline: ASCII? -> native path : svc back to Python
        loader.native_trampolines = getattr(loader, "native_trampolines", {})
        # register the python fallback name so dispatch_stub resolves it
        loader.addr2stub[svc] = py_name
        # KEYSTONE FAR-BRANCH BUG: place() assembles with ks.asm(src)
        # WITHOUT addr= (PC=0), so `b 0x500000000000` truncates to 32
        # bits and became `b block_start` -- every non-ASCII char spun
        # the native block forever (the 2026-10-30 MainAppThread CRC
        # stall). Assemble the body with a nop at Lpy, then hand-encode
        # the far branch to the farm svc stub (imm26 fits: 3.9M instrs
        # < 33.5M range).
        addr = NATIVE_BASE + len(code)
        body = """
            cmp   w0, #127
            b.hi  Lpy
            cmp   w0, #%d
            b.lo  Lret
            cmp   w0, #%d
            b.hi  Lret
            %s
        Lret: ret
        Lpy:  nop
        """ % (lo, hi, sub)
        blob = bytearray(bytes(_KS.asm(body)[0]))
        lpy_off = len(blob) - 4
        off_i = (svc - (addr + lpy_off)) >> 2
        if not (-(1 << 25) <= off_i < (1 << 25)):
            raise RuntimeError("hybrid %s Lpy branch out of range: %d"
                               % (name, off_i))
        b_ins = 0x14000000 | (off_i & 0x3FFFFFF)
        blob[lpy_off:lpy_off + 4] = struct.pack("<I", b_ins)
        txt = "; ".join("%s %s" % (i.mnemonic, i.op_str)
                        for i in CS.disasm(bytes(blob), addr))
        loader.console("[native] %-12s 0x%x %s" % (name, addr, txt[:100]))
        out[name] = addr
        code.extend(blob)
        while len(code) % 16:
            code.extend(b"\x1f\x20\x03\xd5")      # nop

    for name, src in NATIVES.items():
        if name in out or name.lstrip("_") in disabled:
            continue
        place(name, src)

    if code:
        loader.wrb(NATIVE_BASE, bytes(code))
    return out
