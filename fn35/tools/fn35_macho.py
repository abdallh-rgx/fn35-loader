#!/usr/bin/env python3
"""FN3.5 loader: Mach-O (ARM64) parser + dyld link-time info.

Parses the Fortnite 3.5 iOS executable: segments, sections, symbol table,
indirect (GOT) tables, dyld binding opcodes. Used by fn35_loader.py.
"""
import struct

MH_MAGIC_64 = 0xFEEDFACF
CPU_TYPE_ARM64 = 0x0100000C

LC_SYMTAB = 0x02
LC_DYSYMTAB = 0x0B
LC_LOAD_DYLIB = 0x0C
LC_SEGMENT_64 = 0x19
LC_UUID = 0x1B
LC_VERSION_MIN_IPHONEOS = 0x25
LC_FUNCTION_STARTS = 0x26
LC_MAIN = 0x28 | 0x80000000
LC_DATA_IN_CODE = 0x29
LC_DYLD_INFO = 0x22
LC_DYLD_INFO_ONLY = 0x22 | 0x80000000
LC_SOURCE_VERSION = 0x2A
LC_ENCRYPTION_INFO_64 = 0x2C
LC_BUILD_VERSION = 0x32

S_ZEROFILL = 0x1
S_CSTRING_LITERALS = 0x2
S_NON_LAZY_SYMBOL_POINTERS = 0x6
S_LAZY_SYMBOL_POINTERS = 0x7
S_SYMBOL_STUBS = 0x8
S_MOD_INIT_FUNC_POINTERS = 0x9
S_MOD_TERM_FUNC_POINTERS = 0xA
S_THREAD_LOCAL_REGULAR = 0x11
S_THREAD_LOCAL_ZEROFILL = 0x12
S_THREAD_LOCAL_VARIABLES = 0x13
S_THREAD_LOCAL_INIT_FUNCTION_POINTERS = 0x15

INDIRECT_SYMBOL_LOCAL = 0x80000000
INDIRECT_SYMBOL_ABS = 0x40000000

N_EXT = 0x01
N_TYPE = 0x0E
N_UNDF = 0x0
N_SECT = 0x0E
N_ABS = 0x2


def align_up(x, a):
    return (x + a - 1) & ~(a - 1)


def align_down(x, a):
    return x & ~(a - 1)


def uleb(buf, off):
    result = 0
    shift = 0
    while True:
        b = buf[off]
        off += 1
        result |= (b & 0x7F) << shift
        if not (b & 0x80):
            return result, off
        shift += 7


def sleb(buf, off):
    result = 0
    shift = 0
    while True:
        b = buf[off]
        off += 1
        result |= (b & 0x7F) << shift
        shift += 7
        if not (b & 0x80):
            if b & 0x40:
                result -= (1 << shift)
            return result, off


class Section:
    __slots__ = ("seg", "name", "addr", "size", "align", "offset",
                 "flags", "reserved1", "reserved2")
    def __init__(self, seg, name, addr, size, align, offset, flags, r1, r2):
        self.seg = seg; self.name = name; self.addr = addr; self.size = size
        self.align = align; self.offset = offset; self.flags = flags
        self.reserved1 = r1; self.reserved2 = r2
    def __repr__(self):
        return "<sec %s,%s addr=0x%x size=0x%x flags=0x%x>" % (
            self.seg, self.name, self.addr, self.size, self.flags)


class Segment:
    __slots__ = ("name", "vmaddr", "vmsize", "fileoff", "filesize",
                 "maxprot", "initprot", "nsects")
    def __init__(self, name, vmaddr, vmsize, fileoff, filesize,
                 maxprot, initprot, nsects):
        self.name = name; self.vmaddr = vmaddr; self.vmsize = vmsize
        self.fileoff = fileoff; self.filesize = filesize
        self.maxprot = maxprot; self.initprot = initprot; self.nsects = nsects
    def __repr__(self):
        return "<seg %s vmaddr=0x%x vmsize=0x%x filesize=0x%x>" % (
            self.name, self.vmaddr, self.vmsize, self.filesize)


class Sym:
    __slots__ = ("strx", "type", "sect", "desc", "value")
    def __init__(self, strx, typ, sect, desc, value):
        self.strx = strx; self.type = typ; self.sect = sect
        self.desc = desc; self.value = value


class BindRecord:
    __slots__ = ("seg_index", "seg_offset", "symbol", "btype", "addend",
                 "ordinal", "weak")
    def __init__(self, si, so, sym, bt, add, ordr, weak):
        self.seg_index = si; self.seg_offset = so; self.symbol = sym
        self.btype = bt; self.addend = add; self.ordinal = ordr; self.weak = weak
    def __repr__(self):
        return "<bind seg=%d off=0x%x sym=%s type=%d addend=%d%s>" % (
            self.seg_index, self.seg_offset, self.symbol, self.btype,
            self.addend, " weak" if self.weak else "")


class MachOError(Exception):
    pass


class MachO:
    def __init__(self, path):
        with open(path, "rb") as f:
            self.buf = f.read()
        self.path = path
        (magic, cputype, cpusub, filetype, ncmds, sizeofcmds, _res) = \
            struct.unpack_from("<IIIIIII", self.buf, 0)
        if magic != MH_MAGIC_64:
            raise MachOError("bad magic 0x%x" % magic)
        if cputype != CPU_TYPE_ARM64:
            raise MachOError("not ARM64 (0x%x)" % cputype)
        self.filetype = filetype
        self.segments = []
        self.sections = []
        self.dylibs = []
        self.symoff = self.nsyms = self.stroff = self.strsize = 0
        self.indirectsymoff = self.nindirectsyms = 0
        self.iundefsym = self.nundefsym = 0
        self.rebase_off = self.rebase_size = 0
        self.bind_off = self.bind_size = 0
        self.weak_off = self.weak_size = 0
        self.lazy_off = self.lazy_size = 0
        self.export_off = self.export_size = 0
        self.entryoff = 0
        self.cryptid = -1
        self.uuid = None
        self.minos = None
        self.source_version = None

        p = 32
        for _ in range(ncmds):
            cmd, cmdsize = struct.unpack_from("<II", self.buf, p)
            if cmd == LC_SEGMENT_64:
                segname = self._cstr_at(p + 8, 16)
                vmaddr, vmsize, fileoff, filesize, maxprot, initprot, nsects = \
                    struct.unpack_from("<QQQQIII", self.buf, p + 24)
                seg = Segment(segname, vmaddr, vmsize, fileoff, filesize,
                              maxprot, initprot, nsects)
                self.segments.append(seg)
                q = p + 72
                for _s in range(nsects):
                    sn = self._cstr_at(q, 16)
                    sg = self._cstr_at(q + 16, 16)
                    addr, size = struct.unpack_from("<QQ", self.buf, q + 32)
                    offset, align, reloff, nreloc, flags, r1, r2, r3 = \
                        struct.unpack_from("<IIIIIIII", self.buf, q + 48)
                    self.sections.append(
                        Section(sg, sn, addr, size, align, offset, flags, r1, r2))
                    q += 80
            elif cmd == LC_SYMTAB:
                (self.symoff, self.nsyms, self.stroff, self.strsize) = \
                    struct.unpack_from("<IIII", self.buf, p + 8)
            elif cmd == LC_DYSYMTAB:
                vals = struct.unpack_from("<18I", self.buf, p + 8)
                self.iundefsym = vals[4]
                self.nundefsym = vals[5]
                self.indirectsymoff = vals[12]      # p+56
                self.nindirectsyms = vals[13]       # p+60
            elif cmd in (LC_DYLD_INFO, LC_DYLD_INFO_ONLY):
                (self.rebase_off, self.rebase_size, self.bind_off,
                 self.bind_size, self.weak_off, self.weak_size,
                 self.lazy_off, self.lazy_size, self.export_off,
                 self.export_size) = struct.unpack_from("<10I", self.buf, p + 8)
            elif cmd == LC_MAIN:
                self.entryoff, = struct.unpack_from("<Q", self.buf, p + 8)
            elif cmd == LC_LOAD_DYLIB:
                nameoff, = struct.unpack_from("<I", self.buf, p + 8)
                self.dylibs.append(self._cstr_at(p + nameoff))
            elif cmd == LC_UUID:
                self.uuid = self.buf[p + 8: p + 24].hex()
            elif cmd == LC_VERSION_MIN_IPHONEOS:
                ver, sdk = struct.unpack_from("<II", self.buf, p + 8)
                self.minos = "%d.%d.%d" % (
                    (ver >> 16) & 0xFF, (ver >> 8) & 0xFF, ver & 0xFF)
            elif cmd == LC_SOURCE_VERSION:
                sv, = struct.unpack_from("<Q", self.buf, p + 8)
                self.source_version = sv
            elif cmd == LC_ENCRYPTION_INFO_64:
                self.cryptoff, self.cryptsize, self.cryptid = \
                    struct.unpack_from("<III", self.buf, p + 8)
            p += cmdsize
        self.syms = []
        self.indirect = []

    # ---- raw helpers -------------------------------------------------
    def _cstr_at(self, off, maxlen=4096):
        end = self.buf.find(b"\x00", off, off + maxlen)
        if end < 0:
            end = min(off + maxlen, len(self.buf))
        return self.buf[off:end].decode("utf-8", "replace")

    def cstr_at(self, off, maxlen=1 << 22):
        return self._cstr_at(off, maxlen)

    def load_symbols(self):
        for i in range(self.nsyms):
            off = self.symoff + i * 16
            strx, typ, sect, desc, value = struct.unpack_from(
                "<IBBHQ", self.buf, off)
            self.syms.append(Sym(strx, typ, sect, desc, value))
        if self.indirectsymoff:
            self.indirect = list(struct.unpack_from(
                "<%dI" % self.nindirectsyms, self.buf, self.indirectsymoff))
        return len(self.syms)

    def sym_name(self, idx):
        if idx is None or idx >= len(self.syms):
            return None
        s = self.syms[idx]
        if s.strx == 0:
            return None
        return self.cstr_at(self.stroff + s.strx)

    def seg_by_index(self, i):
        return self.segments[i] if 0 <= i < len(self.segments) else None

    def seg_by_name(self, name):
        for s in self.segments:
            if s.name == name:
                return s
        return None

    def text_vm(self):
        t = self.seg_by_name("__TEXT")
        return t.vmaddr if t else 0

    def sections_in(self, segname, sectname):
        return [s for s in self.sections
                if s.seg == segname and s.name == sectname]

    # ---- dyld-relevant iterators ------------------------------------
    def iter_pointer_slots(self):
        """Yield (slot_addr, indirect_index_or_None) for GOT/lazy sections."""
        for sec in self.sections:
            if sec.flags not in (S_NON_LAZY_SYMBOL_POINTERS,
                                 S_LAZY_SYMBOL_POINTERS):
                continue
            base = sec.reserved1 or 0
            for i in range(sec.size // 8):
                idx = base + i
                if idx < len(self.indirect):
                    yield sec.addr + 8 * i, self.indirect[idx]
                else:
                    yield sec.addr + 8 * i, None

    def mod_init_funcs(self):
        out = []
        for sec in self.sections:
            if sec.flags != S_MOD_INIT_FUNC_POINTERS or sec.size < 8:
                continue
            for off in range(sec.offset, sec.offset + sec.size, 8):
                v, = struct.unpack_from("<Q", self.buf, off)
                if v:
                    out.append(v)
        return out

    def tlv_template(self):
        """Return (base, size) of the thread-local data template."""
        lo = None
        hi = None
        for sec in self.sections:
            if sec.flags in (S_THREAD_LOCAL_REGULAR, S_THREAD_LOCAL_ZEROFILL):
                lo = sec.addr if lo is None else min(lo, sec.addr)
                hi = sec.addr + sec.size if hi is None else max(
                    hi, sec.addr + sec.size)
        if lo is None:
            return 0, 0
        return lo, hi - lo

    def parse_binds(self):
        """Interpret dyld bind/weak-bind opcode streams -> [BindRecord]."""
        recs = []
        if self.bind_size:
            recs += self._parse_bind_stream(self.bind_off, self.bind_size,
                                            False)
        if self.weak_size:
            recs += self._parse_bind_stream(self.weak_off, self.weak_size,
                                            True)
        return recs

    def _parse_bind_stream(self, off, size, weak):
        """Bind opcode table determined empirically (see fn35_modelp.py,
        validated 652/652 against the indirect symbol table):
          0x80 = ADD_ADDR_ULEB (pure skip, u64 wrapping)
          0x90 = DO_BIND
          0xA0 = DO_BIND + uleb skip
          0xB0 = DO_BIND + imm*8
          0xC0 = DO_BIND uleb times skipping uleb
        """
        M = (1 << 64) - 1
        recs = []
        seg_index = 0
        seg_offset = 0
        btype = 1
        addend = 0
        ordinal = 0
        name = None
        p = off
        end = off + size

        def do_bind(count=1, extra=0):
            nonlocal seg_offset
            if name and 0 <= count <= 200000:
                for _k in range(count):
                    recs.append(BindRecord(seg_index, seg_offset, name,
                                          btype, addend, ordinal, weak))
                    seg_offset += 8 + extra

        while p < end:
            b = self.buf[p]
            p += 1
            op = b & 0xF0
            imm = b & 0x0F
            if op == 0x00:      # DONE
                break
            if op == 0x10:      # SET_DYLIB_ORDINAL_IMM
                ordinal = imm
            elif op == 0x20:    # SET_DYLIB_ORDINAL_ULEB
                ordinal, p = uleb(self.buf, p)
            elif op == 0x30:    # SET_DYLIB_SPECIAL_IMM
                ordinal = imm
            elif op == 0x40:    # SET_SYMBOL_TRAILING_FLAGS_IMM
                end_ = self.buf.find(b"\x00", p, p + 4096)
                if end_ < 0:
                    end_ = min(p + 256, len(self.buf))
                name = self.buf[p:end_].decode("utf-8", "replace")
                p = end_ + 1
            elif op == 0x50:    # SET_TYPE_IMM
                btype = imm
            elif op == 0x60:    # SET_ADDEND_SLEB
                addend, p = sleb(self.buf, p)
            elif op == 0x70:    # SET_SEGMENT_AND_OFFSET_ULEB
                seg_index = imm
                seg_offset, p = uleb(self.buf, p)
            elif op == 0x80:    # ADD_ADDR_ULEB (pure skip, wrapping)
                skip, p = uleb(self.buf, p)
                seg_offset = (seg_offset + skip) & M
            elif op == 0x90:    # DO_BIND
                do_bind(1, 0)
            elif op == 0xA0:    # DO_BIND_ADD_ADDR_ULEB
                extra, p = uleb(self.buf, p)
                do_bind(1, extra)
            elif op == 0xB0:    # DO_BIND_ADD_ADDR_IMM_SCALED
                do_bind(1, imm * 8)
            elif op == 0xC0:    # DO_BIND_ULEB_TIMES_SKIPPING_ULEB
                count, p = uleb(self.buf, p)
                extra, p = uleb(self.buf, p)
                do_bind(count, extra)
            # 0xD0/0xE0 THREADED: not expected in this binary
        return recs

    def link_stats(self):
        n_ptrs = sum(
            1 for sec in self.sections
            if sec.flags in (S_NON_LAZY_SYMBOL_POINTERS,
                             S_LAZY_SYMBOL_POINTERS)
            for _ in range(sec.size // 8))
        return {
            "segments": len(self.segments),
            "sections": len(self.sections),
            "dylibs": len(self.dylibs),
            "symbols": len(self.syms),
            "pointer_slots": n_ptrs,
            "indirect_entries": len(self.indirect),
            "bind_records": len(self.parse_binds()),
            "cryptid": self.cryptid,
            "entryoff": self.entryoff,
        }
