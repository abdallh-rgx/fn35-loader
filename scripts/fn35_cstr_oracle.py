#!/usr/bin/env python3
"""fn35_cstr_oracle.py - dump string/memory/conv vectors from the REAL
fn35_clib implementations for the Rust differential test.

Faithful mini-guest: one flat byte buffer; oracle strings placed at
0x10000; scratch at 0x80000; heap bump at 0x90000. The clib functions
only need l.gcstr / l.rdb / l.wrb / l.w64 / l.heap_alloc - provided here
against the flat buffer.
"""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import fn35_clib as CL  # noqa: E402

BUF = bytearray(0x100000)  # 1MB flat guest


class Mem:
    def rdb(self, addr, n):
        assert 0 <= addr and addr + n <= len(BUF), "oracle rdb OOB"
        return bytes(BUF[addr:addr + n])

    def wrb(self, addr, b):
        assert 0 <= addr and addr + len(b) <= len(BUF), "oracle wrb OOB"
        BUF[addr:addr + len(b)] = b

    def w64(self, addr, v):
        self.wrb(addr, int(v & 0xFFFFFFFFFFFFFFFF).to_bytes(8, "little"))

    def gcstr(self, addr, maxlen=1 << 20):
        if not addr:
            return ""
        out = b""
        while len(out) < maxlen:
            chunk = self.rdb(addr + len(out), 256)
            z = chunk.find(b"\x00")
            if z >= 0:
                out += chunk[:z]
                break
            out += chunk
        return out.decode("utf-8", "replace")

    def heap_alloc(self, size, zero=True):
        return 0x90000  # oracle: single-shot bump, contents captured


STR = 0x10000
SCR = 0x80000


def place(s):
    """Place a C string (utf-8 encoded, NUL terminated) in the buffer,
    return its address. Returns contents to reset between cases."""
    b = s.encode("utf-8") + b"\x00"
    global STR
    STR += (-(STR & 0xFF)) % 256  # keep 256-align so chunk reads see it
    addr = STR
    BUF[addr:addr + len(b)] = b
    STR += len(b) + 8
    return addr


def clear_scratch():
    for i in range(SCR, SCR + 0x100):
        BUF[i] = 0xAA  # poison so unwritten bytes differ from written


def read_back(addr, n):
    return BUF[addr:addr + n]


L = Mem()
VEC = []


def norm_ptr(ret, base):
    if ret == 0:
        return None
    return ret - base


# ---------------- vectors ----------------
# ---- strlen / strnlen ----
for s in ["", "a", "hello", "UE4-Fortnite!!", "12ab" * 20]:
    a = place(s)
    VEC.append({"fn": "strlen", "s": s, "ret": CL._strlen(L, a)})
    VEC.append({"fn": "strnlen", "s": s, "n": 3, "ret": CL._strnlen(L, a, 3)})
    VEC.append({"fn": "strnlen", "s": s, "n": 0, "ret": CL._strnlen(L, a, 0)})

# ---- strcmp family ----
pairs = [("abc", "abc"), ("abc", "abd"), ("b", "a"), ("a", "b"),
         ("", ""), ("", "a"), ("a", ""), ("ABC", "abc"), ("abc", "ABC"),
         ("Fortnite", "fortnite"), ("\u00c9", "\u00e9")]
for a_, b_ in pairs:
    aa, ab = place(a_), place(b_)
    VEC.append({"fn": "strcmp", "a": a_, "b": b_, "ret": CL._strcmp(L, aa, ab)})
    VEC.append({"fn": "strncmp", "a": a_, "b": b_, "n": 2,
                "ret": CL._strncmp(L, aa, ab, 2)})
    VEC.append({"fn": "strncmp", "a": a_, "b": b_, "n": 0,
                "ret": CL._strncmp(L, aa, ab, 0)})
    VEC.append({"fn": "strcasecmp", "a": a_, "b": b_,
                "ret": CL._strcasecmp(L, aa, ab)})
    VEC.append({"fn": "strncasecmp", "a": a_, "b": b_, "n": 3,
                "ret": CL._strcasecmp(L, aa, ab, 3)})

# ---- memcpy / memset / bzero / memcmp ----
memcases = [
    (b"\x00" * 8, b"\x11" * 8, 8),
    (b"abcdef", b"ABCDEF", 3),
    (b"", b"", 0),
    (bytes(range(16)), b"\xff" * 16, 16),
]
for dstb, srcb, n in memcases:
    d = SCR
    BUF[d:d + len(dstb)] = dstb
    s_ = place(srcb.decode("latin-1"))  # place via utf-8 of latin-1? use bytes
    # place raw bytes directly
    BUF[s_:s_ + len(srcb)] = srcb + b"\x00"
    VEC.append({"fn": "memcpy", "dst": dstb.hex(), "src": srcb.hex(), "n": n,
                "out": read_back(d, n).hex(), "n_actual": n})
for fill in [0, 0x41, 0xFF]:
    for n in [0, 1, 5, 16]:
        clear_scratch()
        d = SCR
        CL._memset(L, d, fill, n)
        VEC.append({"fn": "memset", "c": fill, "n": n,
                    "out": read_back(d, n).hex()})
        clear_scratch()
        CL._bzero(L, d, n)
        VEC.append({"fn": "bzero", "n": n,
                    "out": read_back(d, n).hex()})
for a_, b_, n in [(b"abc", b"abc", 3), (b"abc", b"abd", 3), (b"ab", b"ac", 1),
                  (b"a", b"b", 0), (b"\x00a", b"\x01a", 2), (b"zz", b"za", 2)]:
    aa, ab = SCR, SCR + 0x40
    BUF[aa:aa + len(a_)] = a_
    BUF[ab:ab + len(b_)] = b_
    VEC.append({"fn": "memcmp", "a": a_.hex(), "b": b_.hex(), "n": n,
                "ret": CL._memcmp(L, aa, ab, n)})

# ---- strcpy / strncpy / strlcpy / strlcat / strcat ----
for src in ["", "a", "engine.ini", "x" * 40]:
    for n in [0, 1, 3, 100]:
        clear_scratch()
        s_ = place(src)
        CL._strncpy(L, SCR, s_, n)
        VEC.append({"fn": "strncpy", "src": src, "n": n,
                    "out": read_back(SCR, n).hex()})
    for size in [0, 1, 3, 100]:
        clear_scratch()
        s_ = place(src)
        r = CL._strlcpy(L, SCR, s_, size)
        span = min(len(src.encode()), size - 1) + 1 if size else 0
        VEC.append({"fn": "strlcpy", "src": src, "size": size, "ret": r,
                    "out": read_back(SCR, span).hex() if span else ""})
for cur, src, size in [("abc", "def", 10), ("abc", "def", 4),
                       ("abc", "def", 3), ("abc", "def", 0),
                       ("", "hello", 6), ("longdst", "s", 100)]:
    clear_scratch()
    da, sa = place(cur), place(src)
    BUF[SCR:SCR + len(cur)] = cur.encode()
    r = CL._strlcat(L, SCR, sa, size)
    room = size - 1 - len(cur.encode())
    span = min(len(src.encode()), room) if (size and room > 0) else 0
    VEC.append({"fn": "strlcat", "dst": cur, "src": src, "size": size,
                "ret": r, "at": len(cur.encode()),
                "out": read_back(SCR + len(cur.encode()), span).hex() if span else ""})
for cur, src in [("abc", "def"), ("", "x"), ("end", "")]:
    clear_scratch()
    sa = place(src)
    BUF[SCR:SCR + len(cur)] = cur.encode()
    CL._strcat(L, SCR, sa)
    VEC.append({"fn": "strcat", "dst": cur, "src": src,
                "out": read_back(SCR, len(cur) + len(src) + 1).hex()})

# ---- strstr / strchr / strrchr / strchrnul ----
for hay, ndl in [("abcdef", "cd"), ("abcdef", ""), ("abcdef", "z"),
                 ("aXbXc", "X"), ("aaa", "aa")]:
    ha, na = place(hay), place(ndl)
    VEC.append({"fn": "strstr", "hay": hay, "needle": ndl,
                "ret": norm_ptr(CL._strstr(L, ha, na), ha)})
for s, c in [("hello", ord("l")), ("hello", 0), ("hello", ord("z")),
             ("", 0), ("", ord("a")), ("caf\xe9", 0xe9),
             ("hello", 0x6c + 0x100)]:
    a = place(s)
    VEC.append({"fn": "strchr", "s": s, "c": c,
                "ret": norm_ptr(CL._strchr(L, a, c), a)})
    VEC.append({"fn": "strrchr", "s": s, "c": c,
                "ret": norm_ptr(CL._strrchr(L, a, c), a)})
    VEC.append({"fn": "strchrnul", "s": s, "c": c,
                "ret": norm_ptr(CL._strchrnul(L, a, c), a)})

# ---- digit_val ----
for ch in ["0", "9", "a", "f", "z", "A", "F", "Z", " ", "/"]:
    VEC.append({"fn": "digit_val", "c": ch, "ret": CL._digit_val(ch)})

# ---- strtol ----
strol_cases = [
    ("10", 10), ("10", 0), ("-42", 10), ("+7", 10), ("0x1F", 16),
    ("0X1f", 0), ("0xg", 0), ("0x", 16), ("0x", 0), ("17", 8),
    ("777", 8), ("z", 36), ("10,4", 10), ("  12", 10), ("\t\n 3", 10),
    ("", 10), ("abc", 10), ("-0x10", 16), ("ffff", 16), ("FFFF", 16),
    ("0", 16), ("0", 0), ("1", 0), ("8", 8), ("9", 8),
]
for s, base in strol_cases:
    a = place(s)
    ep = SCR + 0x200
    BUF[ep:ep + 8] = b"\x00" * 8
    ret = CL._strtol(L, a, ep, base)
    consumed = int.from_bytes(read_back(ep, 8), "little") - a
    VEC.append({"fn": "strtol", "s": s, "base": base,
                "ret": ret, "consumed": consumed})

# ---- strtod ----
strtod_cases = ["3.14", "-2.5e3", "1e3", "0.0001", "abc", "", "  ",
                "42abc", "inf", "-inf", "nan", "1e999", "0.5 7.9",
                "1_0.5", ".5"]
for s in strtod_cases:
    a = place(s)
    ep = SCR + 0x200
    BUF[ep:ep + 8] = b"\x00" * 8
    tag, val = CL._strtod(L, a, ep)
    consumed = int.from_bytes(read_back(ep, 8), "little") - a
    VEC.append({"fn": "strtod", "s": s, "val": repr(val),
                "consumed": consumed})

# ---- atoi / atof ----
for s in ["12", "  -7  ", "", "abc", "+5", "1_0", "0x10", "-"]:
    VEC.append({"fn": "atoi", "s": s, "ret": CL._atoi(L, place(s))})
    tag, v = CL._atof(L, place(s))
    VEC.append({"fn": "atof", "s": s, "val": repr(v)})

out_path = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                        "..", "rust", "fn35-cstr", "tests", "oracle.json")
os.makedirs(os.path.dirname(out_path), exist_ok=True)
with open(out_path, "w") as f:
    json.dump(VEC, f, indent=1)
print("oracle:", len(VEC), "vectors ->", out_path)
