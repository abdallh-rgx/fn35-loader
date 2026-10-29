#!/usr/bin/env python3
"""Resolve GOT bind symbols for the spin stub wrappers + find callers
of 0x102c5256c by scanning __TEXT for BL instructions."""
import struct
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN

EXE = "/home/z/my-project/fn35/extracted/Payload/FortniteClient.app/FortniteClient"

def load(path):
    with open(path, "rb") as f:
        blob = f.read()
    segs = []
    symtab = None
    dysym = None
    dyld_info = None
    off = 32
    magic, cputype, cpusub, filetype, ncmds, sizeofcmds, flags = \
        struct.unpack_from("<IIIIIII", blob, 0)
    for _ in range(ncmds):
        cmd, cmdsize = struct.unpack_from("<II", blob, off)
        if cmd == 0x19:
            name = blob[off+8:off+24].split(b"\0")[0].decode()
            vmaddr, vmsize, fileoff, filesize = \
                struct.unpack_from("<QQQQ", blob, off+24)
            segs.append((name, vmaddr, vmsize, fileoff, filesize))
        elif cmd == 0x1b:  # LC_SYMTAB
            symoff, nsyms, stroff, strsize = struct.unpack_from("<IIII", blob, off+8)
            symtab = (symoff, nsyms, stroff)
        elif cmd == 0x2b:  # LC_DYLD_INFO_ONLY
            ro = struct.unpack_from("<IIIII", blob, off+8)
            # reorder_off, reorder_n, bind_off, bind_n, weak..., lazy..., export...
            dyld_info = struct.unpack_from("<IIIIIII", blob, off+8)
        elif cmd == 0x80000022:  # LC_DYLD_CHAINED_FIXUPS
            pass
        off += cmdsize
    return blob, segs, symtab, dyld_info

def a2f(addr, segs):
    for name, vm, vs, fo, fs in segs:
        if vm <= addr < vm + vs:
            return fo + (addr - vm)
    return None

def parse_binds(blob, segs, dyld_info):
    """Parse classic dyld bind opcodes: return {slot_addr: sym_name}."""
    if not dyld_info:
        return {}
    bind_off, bind_size = dyld_info[2], dyld_info[3]
    lazy_off, lazy_size = dyld_info[4], dyld_info[5]
    seg_by_idx = {i: s for i, s in enumerate(segs)}
    out = {}
    for base_off, base_sz in ((bind_off, bind_size), (lazy_off, lazy_size)):
        if not base_off or not base_sz:
            continue
        p = base_off
        end = base_off + base_sz
        seg_idx = 0
        seg_off = 0
        sym = ""
        lib_ordinal = 0
        while p < end:
            opb = blob[p]
            op = opb & 0xF0
            imm = opb & 0x0F
            p += 1
            if op == 0x00:  # BIND_DONE
                break
            elif op == 0x10:  # SET_DYLIB_ORDINAL
                lib_ordinal = imm
            elif op == 0x20:  # SET_DYLIB_ORDINAL_ULEB
                while True:
                    b = blob[p]; p += 1
                    if not b & 0x80:
                        break
            elif op == 0x30:  # SET_DYLIB_ORDINAL_IMM
                lib_ordinal = imm - 15
            elif op == 0x40:  # SET_SYMBOL_TRAILING
                e = blob.index(b"\0", p)
                sym = blob[p:e].decode(errors="replace")
                p = e + 1
            elif op == 0x50:  # SET_TYPE_IMM
                pass
            elif op == 0x60:  # SET_ADDEND_SLEB
                while True:
                    b = blob[p]; p += 1
                    if not b & 0x80:
                        break
            elif op == 0x70:  # SET_SEGMENT_AND_OFFSET
                seg_idx = imm
                seg_off = read_uleb(blob, p, end)
            elif op == 0x80:  # ADD_ADDRESS_SLEB
                d = read_sleb(blob, p, end)
                seg_off += d
            elif op == 0x90:  # SET_ADDRESS_ULEB
                seg_off = read_uleb(blob, p, end)
            elif op == 0xA0:  # DO_BIND
                seg = seg_by_idx.get(seg_idx)
                if seg:
                    addr = seg[1] + seg_off
                    out[addr] = sym
                seg_off += 8
            elif op == 0xB0:  # DO_BIND_APPEND_ULEB
                d = read_uleb(blob, p, end)
                seg = seg_by_idx.get(seg_idx)
                if seg:
                    addr = seg[1] + seg_off
                    out[addr] = sym
                seg_off += 8 + d
            elif op == 0xC0:  # DO_BIND_ULEB_TIMES_SKIPPING_ULEB
                cnt = read_uleb(blob, p, end)
                skip = read_uleb(blob, p, end)
                seg = seg_by_idx.get(seg_idx)
                for _ in range(cnt):
                    if seg:
                        addr = seg[1] + seg_off
                        out[addr] = sym
                    seg_off += 8 + skip
            else:
                break
    return out

def read_uleb(b, p, end):
    r = 0; s = 0
    while p < end:
        x = b[p]; p += 1
        r |= (x & 0x7F) << s
        if not x & 0x80:
            break
        s += 7
    return r

def read_sleb(b, p, end):
    r = 0; s = 0
    while p < end:
        x = b[p]; p += 1
        r |= (x & 0x7F) << s
        s += 7
        if not x & 0x80:
            if x & 0x40:
                r -= (1 << s)
            break
    return r

BL_TARGETS_OF_INTEREST = {0x102c5256c}

def main():
    blob, segs, symtab, dyld_info = load(EXE)
    binds = parse_binds(blob, segs, dyld_info)
    print("[bind] %d bind slots parsed" % len(binds))
    # resolve the GOT slots used by the wrappers
    # 0x10305db1c -> adrp x16, 0x1037c2000; ldr x16,[x16,#0xf20] -> 0x1037c2f20
    slots = {
        "mach_abs?  (0x10305db1c)": 0x1037c2f20,
        "??         (0x10305d504)": None,
        "lock       (0x10305e074)": None,
        "unlock     (0x10305e08c)": None,
        "getspe     (0x10305e020)": None,
        "condwait   (0x10305dfb4)": None,
        "condwait?  (0x10305dfc0)": None,
    }
    md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
    def got_of(wrapper):
        fo = a2f(wrapper, segs)
        code = blob[fo:fo+16]
        base = None; off2 = None
        for ins in md.disasm(code, wrapper):
            if ins.mnemonic == "adrp":
                base = int(ins.op_str.split("#")[1], 16)
            elif ins.mnemonic == "ldr" and "x16, [x16" in ins.op_str:
                try:
                    off2 = int(ins.op_str.split("#")[1].rstrip("]"), 16)
                except Exception:
                    off2 = 0
            if base is not None and off2 is not None:
                return base + off2
        return None
    for k in list(slots):
        w = int(k.split("(")[1].rstrip(")"), 16)
        s = got_of(w)
        nm = binds.get(s, "?")
        print("[got] %s slot=0x%x -> %s" % (k, s or 0, nm))
    # scan __TEXT for bl 0x102c5256c
    text = [s for s in segs if s[0] == "__TEXT"][0]
    n, vm, vs, fo, fs = text
    print("\n[scan] searching __TEXT for bl 0x102c5256c ...")
    hits = []
    data = blob[fo:fo+fs]
    for i in range(0, len(data) - 4, 4):
        w = struct.unpack_from("<I", data, i)[0]
        if (w >> 26) == 0x25:  # BL
            imm = w & 0x3FFFFFF
            if imm & 0x2000000:
                imm -= 0x4000000
            tgt = vm + i + (imm << 2)
            if tgt in BL_TARGETS_OF_INTEREST:
                hits.append(vm + i)
    print("[scan] %d callers:" % len(hits))
    for h in hits[:20]:
        lo = h - 0x40
        fo2 = a2f(lo, segs)
        print("  ---- caller near 0x%x ----" % h)
        for ins in md.disasm(blob[fo2:fo2+0x50], lo):
            mark = "  <<< CALLER BRANCH" if ins.address == h - 4 else ""
            print("  0x%x: %-8s %s%s" % (ins.address, ins.mnemonic,
                                          ins.op_str, mark))

if __name__ == "__main__":
    main()
