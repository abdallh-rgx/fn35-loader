#!/usr/bin/env python3
"""fn35_printf_oracle.py - dump (fmt, args) -> string pairs for the Rust
differential test of the printf engine.

Uses the REAL fmt_engine from fn35_clib.py with a sequence source, so the
oracle exercises exactly the production code path.
"""
import json
import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import fn35_clib as CL  # noqa: E402


class SeqSrc:
    """Deterministic varargs source: ints, dbls, strs in order."""

    def __init__(self, ints, dbls, strs):
        self.ints = ints
        self.dbls = dbls
        self.strs = strs
        self.xi = 0
        self.di = 0
        self.si = 0

    def next_int(self):
        v = self.ints[min(self.xi, len(self.ints) - 1)] if self.ints else 0
        self.xi += 1
        return v

    def next_dbl(self):
        v = self.dbls[min(self.di, len(self.dbls) - 1)] if self.dbls else 0.0
        self.di += 1
        return v

    def reg_d(self, i):
        return self.next_dbl()


class PtrSrc(SeqSrc):
    """%s consumes a pointer via next_int then a string from strs."""

    def __init__(self, ints, dbls, strs):
        super().__init__(ints, dbls, strs)
        self._orig = None

    def install(self):
        # fmt_engine calls the MODULE-LEVEL l_cstr_safe(p); monkeypatch
        # it to serve our strs sequence
        self._orig = CL.l_cstr_safe
        state = {"i": 0}
        strs = self.strs

        def fake_cstr(p):
            if p == 0 or not strs:
                return "(null)"
            s = strs[min(state["i"], len(strs) - 1)]
            state["i"] += 1
            return s

        CL.l_cstr_safe = fake_cstr

    def restore(self):
        if self._orig is not None:
            CL.l_cstr_safe = self._orig
            self._orig = None


CASES = [
    # (fmt, ints, dbls, strs)
    ("hello world", [], [], []),
    ("100%% done", [], [], []),
    ("%d %i %d", [42, -7, 0], [], []),
    ("%5d|%-5d|%05d|", [42, 42, 42], [], []),
    ("%+d % d", [42, 42], [], []),
    ("%u %u", [42, 0xFFFFFFFFFFFFFFFF], [], []),
    ("%x %X %#x %#X", [255, 255, 255, 255], [], []),
    ("%o %#o", [8, 8], [], []),
    ("%p", [0x1055d64e0], [], []),
    ("%c%c%c", [65, 66, 67], [], []),
    ("%s and %s", [1, 2], [], ["left", "right"]),
    ("%10s|%-10s|", [1, 2], [], ["pad", "pad"]),
    ("%.3s", [1], [], ["truncated"]),
    ("%s null", [0], [], ["never-read"]),
    ("%f", [], [3.14159], []),
    ("%f", [], [-0.5], []),
    ("%.0f|%.1f|%.10f", [0, 0, 0], [2.5, 2.25, 1.0 / 3.0], []),
    ("%e %E", [0, 0], [1234.5, 0.00001234], []),
    ("%g %G %g", [0, 0, 0], [0.0001, 123456789.0, 100.0], []),
    ("%g %g", [0, 0], [0.000123456, 1e-5], []),
    ("%*d|%.*d|", [6, 42, 5, 42], [], []),
    ("%.*f", [3, 0], [3.14159265], []),
    ("%08.3f", [], [-3.14159], []),
    ("%-+8.2f|", [], [3.14159], []),
    ("%lld %zu %hx", [1234567890123, 77, 5], [], []),
    ("mixed %d %s %f %x", [7, 1, 0, 48879], [2.75], ["str"]),
    ("@@%d@@", [5], [], []),
    ("", [9], [1.0], ["never"]),
    ("%d trailing", [1], [], []),
    ("%f", [], [1e300], []),
    ("%f", [], [1e-300], []),
    ("%e", [], [0.0], []),
    ("%g", [], [0.0], []),
    ("%f", [], [float("inf")], []),
    ("%s|%d", [3, 4], [], ["chain"]),
]

def _enc_dbl(x):
    # json.dumps writes Infinity/NaN as bare literals that serde_json
    # rejects; encode non-finite as strings instead
    if x != x:
        return "nan"
    if x == float("inf"):
        return "inf"
    if x == float("-inf"):
        return "-inf"
    return x


out = []
for (fmt, ints, dbls, strs) in CASES:
    src = PtrSrc(ints, dbls, strs or ["(null)"])
    src.install()
    try:
        got = CL.fmt_engine(fmt, src)
        if "<fmt-err" in got:
            got = "FMTERR"
    except Exception as e:
        got = "FMTERR:" + repr(e)[:60]
    finally:
        src.restore()
    out.append({
        "fmt": fmt,
        "ints": [v & 0xFFFFFFFFFFFFFFFF for v in ints],
        "dbls": [_enc_dbl(v) for v in dbls],
        "strs": strs,
        "out": got,
    })

print(json.dumps(out, indent=1))
