#!/usr/bin/env python3
"""Full validation of Model P bind opcodes:
0x80 = ADD_ADDR_ULEB (pure skip, wrapping u64), 0x90 = DO_BIND,
0xA0 = bind+uleb skip, 0xB0 = bind+imm*8, 0xC0 = uleb times skipping uleb.
Cross-check every record that lands on a GOT/la_symbol_ptr slot against
the indirect symbol table.
"""
import sys
sys.path.insert(0, "/home/z/my-project/scripts")
from fn35_macho import MachO, uleb, sleb, S_NON_LAZY_SYMBOL_POINTERS, \
    S_LAZY_SYMBOL_POINTERS

MO = MachO("/home/z/my-project/fn35/extracted/Payload/"
           "FortniteClient.app/FortniteClient")
MO.load_symbols()
BUF = MO.buf

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

M = (1 << 64) - 1


def decode(off, size):
    p = off
    end = off + size
    seg_index = 0
    seg_offset = 0
    btype = 1
    addend = 0
    name = None
    recs = []
    unknown = []
    while p < end:
        pos = p - off
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
                unknown.append((pos, "no-nul"))
                break
            name = BUF[p:e].decode("utf-8", "replace")
            p = e + 1
        elif op == 0x50:
            if imm > 2:
                unknown.append((pos, "type %d" % imm))
                break
            btype = imm
        elif op == 0x60:
            addend, p = sleb(BUF, p)
        elif op == 0x70:
            seg_index = imm
            seg_offset, p = uleb(BUF, p)
        elif op == 0x80:                     # pure skip (wrapping)
            skip, p = uleb(BUF, p)
            seg_offset = (seg_offset + skip) & M
        elif op == 0x90:                     # DO_BIND
            recs.append((seg_index, seg_offset, name, btype, addend))
            seg_offset += 8
        elif op == 0xA0:                     # bind + uleb skip
            skip, p = uleb(BUF, p)
            recs.append((seg_index, seg_offset, name, btype, addend))
            seg_offset += 8 + skip
        elif op == 0xB0:                     # bind + imm*8
            recs.append((seg_index, seg_offset, name, btype, addend))
            seg_offset += 8 + imm * 8
        elif op == 0xC0:                     # uleb times skipping uleb
            count, p = uleb(BUF, p)
            skip, p = uleb(BUF, p)
            for _k in range(min(count, 200000)):
                recs.append((seg_index, seg_offset, name, btype, addend))
                seg_offset += 8 + skip
        else:
            unknown.append((pos, "op 0x%02x after %s" % (b, name)))
            break
    return recs, unknown


total_match = total_miss = 0
for stream, off, size in (("bind", MO.bind_off, MO.bind_size),
                          ("weak", MO.weak_off, MO.weak_size)):
    recs, unknown = decode(off, size)
    match = miss = 0
    misses = []
    for si, so, nm, bt, ad in recs:
        seg = MO.seg_by_index(si)
        if not seg:
            continue
        addr = seg.vmaddr + so
        if addr in truth:
            if truth[addr] == nm:
                match += 1
            else:
                miss += 1
                if len(misses) < 4:
                    misses.append((hex(addr), truth[addr][:40],
                                   (nm or "?")[:40]))
    total_match += match
    total_miss += miss
    print("%s: recs=%5d unknown=%s match=%4d miss=%4d"
          % (stream, len(recs), unknown[:2], match, miss))
    for m in misses:
        print("   MISS %s truth=%s got=%s" % m)
print("TOTAL: match=%d miss=%d" % (total_match, total_miss))
