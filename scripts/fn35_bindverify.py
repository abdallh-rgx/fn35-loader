#!/usr/bin/env python3
"""Cross-validate bind decode against the indirect symbol table.

For every candidate opcode table, decode the bind stream and check that
records targeting known GOT/la_symbol_ptr slots carry the SAME symbol
name that the indirect symbol table says lives at that slot.
"""
import sys
sys.path.insert(0, "/home/z/my-project/scripts")
from fn35_macho import MachO, uleb, sleb, S_NON_LAZY_SYMBOL_POINTERS, \
    S_LAZY_SYMBOL_POINTERS

MO = MachO("/home/z/my-project/fn35/extracted/Payload/"
           "FortniteClient.app/FortniteClient")
MO.load_symbols()
BUF = MO.buf

# ---- ground truth: slot address -> symbol name (indirect table)
truth = {}
for sec in MO.sections:
    if sec.flags not in (S_NON_LAZY_SYMBOL_POINTERS,
                         S_LAZY_SYMBOL_POINTERS):
        continue
    base = sec.reserved1 or 0
    for i in range(sec.size // 8):
        idx = base + i
        if idx >= len(MO.indirect):
            continue
        v = MO.indirect[idx]
        if v & 0x80000000 or v & 0x40000000:
            continue
        nm = MO.sym_name(v)
        if nm:
            truth[sec.addr + 8 * i] = nm
print("ground-truth slots: %d (e.g. %s)"
      % (len(truth), list(truth.items())[:2]))


def decode(off, size, table):
    DO_BIND, ADD_ULEB, SCALED, ULEB_TIMES = table
    p = off
    end = off + size
    seg_index = 0
    seg_offset = 0
    btype = 1
    name = None
    recs = []
    desync = False
    while p < end:
        b = BUF[p]
        p += 1
        op = b & 0xF0
        imm = b & 0x0F
        if op == 0x00:
            break
        if op == 0x10:
            pass
        elif op == 0x20:
            _, p = uleb(BUF, p)
        elif op == 0x30:
            pass
        elif op == 0x40:
            e = BUF.find(b"\x00", p, p + 4096)
            if e < 0:
                desync = True
                break
            name = BUF[p:e].decode("utf-8", "replace")
            p = e + 1
        elif op == 0x50:
            if imm > 2:
                desync = True
                break
            btype = imm
        elif op == 0x60:
            _, p = sleb(BUF, p)
        elif op == 0x70:
            seg_index = imm
            seg_offset, p = uleb(BUF, p)
            seg = MO.seg_by_index(seg_index)
            if seg is None or seg_offset >= seg.vmsize:
                desync = True
                break
        elif op == DO_BIND:
            recs.append((seg_index, seg_offset, name))
            seg_offset += 8
        elif op == ADD_ULEB:
            skip, p = uleb(BUF, p)
            recs.append((seg_index, seg_offset, name))
            seg_offset += 8 + skip
        elif op == SCALED:
            recs.append((seg_index, seg_offset, name))
            seg_offset += 8 + imm * 8
        elif op == ULEB_TIMES:
            count, p = uleb(BUF, p)
            skip, p = uleb(BUF, p)
            for _k in range(min(count, 100)):
                recs.append((seg_index, seg_offset, name))
                seg_offset += 8 + skip
        else:
            desync = True
            break
    return recs, desync, p == end or BUF[p - 1] == 0


CANDS = {
    "A (0x80,0x90,0xA0,0xB0)": (0x80, 0x90, 0xA0, 0xB0),
    "B (0x90,0xA0,0xB0,0xC0)": (0x90, 0xA0, 0xB0, 0xC0),
    "D (0x90,0x80,0xA0,0xB0)": (0x90, 0x80, 0xA0, 0xB0),
}

for label, table in CANDS.items():
    for stream, off, size in (("bind", MO.bind_off, MO.bind_size),
                              ("weak", MO.weak_off, MO.weak_size)):
        recs, desync, clean_end = decode(off, size, table)
        match = miss = 0
        examples = []
        for si, so, nm in recs:
            seg = MO.seg_by_index(si)
            if not seg:
                continue
            addr = seg.vmaddr + so
            if addr in truth:
                if truth[addr] == nm:
                    match += 1
                else:
                    miss += 1
                    if len(examples) < 3:
                        examples.append((hex(addr), truth[addr], nm))
        print("%-26s %s: recs=%-8d desync=%-5s match=%-4d miss=%-4d %s"
              % (label, stream, len(recs), desync, match, miss,
                 examples[:2]))
