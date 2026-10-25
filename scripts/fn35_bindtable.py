#!/usr/bin/env python3
"""Empirically determine the bind opcode table used by this Mach-O.

Tries candidate (DO_BIND, ADD_ADDR_ULEB, SCALED, ULEB_TIMES) placements
and scores each decode: reaches DONE exactly at stream end, symbol names
sane, segment offsets in range, types in {0,1,2}.
"""
import sys
sys.path.insert(0, "/home/z/my-project/scripts")
from fn35_macho import MachO, uleb, sleb

MO = MachO("/home/z/my-project/fn35/extracted/Payload/"
           "FortniteClient.app/FortniteClient")
BUF = MO.buf


def decode(off, size, table, weak):
    DO_BIND, ADD_ULEB, SCALED, ULEB_TIMES = table
    p = off
    end = off + size
    seg_index = 0
    seg_offset = 0
    btype = 1
    name = None
    score = 0
    recs = 0
    names = []
    while p < end:
        b = BUF[p]
        p += 1
        op = b & 0xF0
        imm = b & 0x0F
        if op == 0x00:
            score += 10  # DONE
            break
        if op == 0x10 or op == 0x20:
            if op == 0x20:
                _, p = uleb(BUF, p)
        elif op == 0x30:
            pass
        elif op == 0x40:
            e = BUF.find(b"\x00", p, p + 4096)
            if e < 0:
                return score - 1000, recs
            name = BUF[p:e].decode("utf-8", "replace")
            names.append(name)
            p = e + 1
        elif op == 0x50:
            if imm > 2:
                score -= 5          # implausible type
            btype = imm
        elif op == 0x60:
            _, p = sleb(BUF, p)
        elif op == 0x70:
            seg_index = imm
            seg_offset, p = uleb(BUF, p)
            seg = MO.seg_by_index(seg_index)
            if seg is None or seg_offset >= seg.vmsize:
                score -= 3
        elif op == DO_BIND:
            recs += 1
            seg_offset += 8
        elif op == ADD_ULEB:
            skip, p = uleb(BUF, p)
            recs += 1
            seg_offset += 8 + skip
        elif op == SCALED:
            recs += 1
            seg_offset += 8 + imm * 8
        elif op == ULEB_TIMES:
            count, p = uleb(BUF, p)
            skip, p = uleb(BUF, p)
            recs += min(count, 1 << 20)
            seg_offset += count * (8 + skip)
        else:
            score -= 50             # invalid opcode nibble
            if score < -200:
                break
    else:
        score -= 20                  # no DONE at end
    # name plausibility
    if names:
        with_us = sum(1 for n in names if n.startswith("_"))
        score += 5 * with_us - 3 * (len(names) - with_us)
    score += min(recs, 50)
    return score, recs


CANDS = {
    "A (0x80/0x90/0xA0/0xB0)": (0x80, 0x90, 0xA0, 0xB0),
    "B (0x90/0xA0/0xB0/0xC0)": (0x90, 0xA0, 0xB0, 0xC0),
    "C (0x80/0xA0/0xB0/0xC0)": (0x80, 0xA0, 0xB0, 0xC0),
    "D (0x90/0x80/0xA0/0xB0)": (0x90, 0x80, 0xA0, 0xB0),
}

for label, table in CANDS.items():
    s1, r1 = decode(MO.bind_off, MO.bind_size, table, False)
    s2, r2 = decode(MO.weak_off, MO.weak_size, table, True)
    print("%-28s bind: score=%5d recs=%5d | weak: score=%5d recs=%5d"
          % (label, s1, r1, s2, r2))
