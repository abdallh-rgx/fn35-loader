//! # fn35-macho — safe Mach-O (iOS ARM64) parser
//!
//! Rust port of `scripts/fn35_macho.py`, mirroring its behaviour 1:1
//! (verified differentially against the real FortniteClient binary —
//! see tests/differential.rs). Parses:
//!
//! * load commands: segments/sections, symtab, dysymtab, dyld_info
//!   (bind/weak/lazy streams), main, dylibs, uuid, minos, source
//!   version, encryption info
//! * symbols + indirect symbol table
//! * dyld bind opcodes (`_parse_bind_stream`) — ADD_ADDR / DO_BIND
//!   families exactly as the Python (validated 652/652 against the
//!   indirect symbol table there)
//! * __mod_init_func lists, __thread_vars template, GOT/la_symbol_ptr
//!   slot iteration
//!
//! `#![forbid(unsafe_code)]` — pure parsing, no unsafe, no deps.
#![forbid(unsafe_code)]

use std::fs;
use std::path::Path;

// ---- load commands / section flags ---------------------------------------
pub const LC_SEGMENT_64: u32 = 0x19;
pub const LC_SYMTAB: u32 = 0x02;
pub const LC_DYSYMTAB: u32 = 0x0B;
pub const LC_LOAD_DYLIB: u32 = 0x0C;
pub const LC_UUID: u32 = 0x1B;
pub const LC_VERSION_MIN_IPHONEOS: u32 = 0x25;
pub const LC_MAIN: u32 = 0x28 | 0x80000000;
pub const LC_DYLD_INFO: u32 = 0x22;
pub const LC_DYLD_INFO_ONLY: u32 = 0x22 | 0x80000000;
pub const LC_SOURCE_VERSION: u32 = 0x2A;
pub const LC_ENCRYPTION_INFO_64: u32 = 0x2C;

pub const S_ZEROFILL: u32 = 0x1;
pub const S_CSTRING_LITERALS: u32 = 0x2;
pub const S_NON_LAZY_SYMBOL_POINTERS: u32 = 0x6;
pub const S_LAZY_SYMBOL_POINTERS: u32 = 0x7;
pub const S_SYMBOL_STUBS: u32 = 0x8;
pub const S_MOD_INIT_FUNC_POINTERS: u32 = 0x9;
pub const S_MOD_TERM_FUNC_POINTERS: u32 = 0xA;
pub const S_THREAD_LOCAL_REGULAR: u32 = 0x11;
pub const S_THREAD_LOCAL_ZEROFILL: u32 = 0x12;
pub const S_THREAD_LOCAL_VARIABLES: u32 = 0x13;
pub const S_THREAD_LOCAL_INIT_FUNCTION_POINTERS: u32 = 0x15;

pub const INDIRECT_SYMBOL_LOCAL: u32 = 0x80000000;
pub const INDIRECT_SYMBOL_ABS: u32 = 0x40000000;


const CPU_TYPE_ARM64: u32 = 0x0100000C;

#[derive(Clone, Debug)]
pub struct Section {
    pub seg: String,
    pub name: String,
    pub addr: u64,
    pub size: u64,
    pub align: u32,
    pub offset: u32,
    pub flags: u32,
    pub r1: u32,
    pub r2: u32,
}

#[derive(Clone, Debug)]
pub struct Segment {
    pub name: String,
    pub vmaddr: u64,
    pub vmsize: u64,
    pub fileoff: u64,
    pub filesize: u64,
    pub maxprot: u32,
    pub initprot: u32,
    pub nsects: u32,
}

#[derive(Clone, Copy, Debug)]
pub struct Sym {
    pub strx: u32,
    pub typ: u8,
    pub sect: u8,
    pub desc: u16,
    pub value: u64,
}

#[derive(Clone, Debug)]
pub struct BindRecord {
    pub seg_index: u32,
    pub seg_offset: u64,
    pub symbol: String,
    pub btype: u32,
    pub addend: i64,
    pub ordinal: u32,
    pub weak: bool,
}

#[derive(Debug)]
pub struct MachOError(pub String);

impl std::fmt::Display for MachOError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "macho error: {}", self.0)
    }
}

pub fn align_down(x: u64, a: u64) -> u64 {
    x & !(a - 1)
}

pub fn align_up(x: u64, a: u64) -> u64 {
    (x + a - 1) & !(a - 1)
}

fn uleb(buf: &[u8], off: usize) -> (u64, usize) {
    let mut result: u64 = 0;
    let mut shift = 0u32;
    let mut p = off;
    loop {
        let b = buf[p];
        p += 1;
        result |= ((b & 0x7F) as u64) << shift;
        if b & 0x80 == 0 {
            break;
        }
        shift += 7;
        if shift > 63 {
            break;
        }
    }
    (result, p)
}

fn sleb(buf: &[u8], off: usize) -> (i64, usize) {
    let mut result: i64 = 0;
    let mut shift = 0u32;
    let mut p = off;
    loop {
        let b = buf[p];
        p += 1;
        result |= ((b & 0x7F) as i64) << shift;
        shift += 7;
        if b & 0x80 == 0 {
            if shift < 64 && (b & 0x40) != 0 {
                result |= -1i64 << shift;
            }
            break;
        }
        if shift > 63 {
            break;
        }
    }
    (result, p)
}

#[derive(Clone, Debug)]
pub struct MachO {
    pub path: String,
    pub filetype: u32,
    pub segments: Vec<Segment>,
    pub sections: Vec<Section>,
    pub dylibs: Vec<String>,
    pub symoff: u32,
    pub nsyms: u32,
    pub stroff: u32,
    pub strsize: u32,
    pub indirectsymoff: u32,
    pub nindirectsyms: u32,
    pub iundefsym: u32,
    pub nundefsym: u32,
    pub rebase_off: u32,
    pub rebase_size: u32,
    pub bind_off: u32,
    pub bind_size: u32,
    pub weak_off: u32,
    pub weak_size: u32,
    pub lazy_off: u32,
    pub lazy_size: u32,
    pub export_off: u32,
    pub export_size: u32,
    pub entryoff: u64,
    pub cryptid: i32,
    pub uuid: Option<String>,
    pub minos: Option<String>,
    pub source_version: Option<u64>,
    pub syms: Vec<Sym>,
    pub indirect: Vec<u32>,
    buf: Vec<u8>,
}

fn cstr_at(buf: &[u8], off: usize, maxlen: usize) -> String {
    let end = buf.iter().skip(off).take(maxlen)
        .position(|&b| b == 0).map(|i| off + i)
        .unwrap_or_else(|| std::cmp::min(off + maxlen, buf.len()));
    String::from_utf8_lossy(&buf[off..end]).into_owned()
}

impl MachO {
    pub fn open(path: &Path) -> Result<MachO, MachOError> {
        let buf = fs::read(path)
            .map_err(|e| MachOError(format!("read {}: {}", path.display(), e)))?;
        MachO::parse(buf, path.display().to_string())
    }

    pub fn parse(buf: Vec<u8>, path: String) -> Result<MachO, MachOError> {
        if buf.len() < 32 {
            return Err(MachOError("short header".into()));
        }
        let magic = u32::from_le_bytes(buf[0..4].try_into().unwrap());
        let cputype = u32::from_le_bytes(buf[4..8].try_into().unwrap());
        if magic != 0xFEEDFACF {
            return Err(MachOError(format!("bad magic 0x{:x}", magic)));
        }
        if cputype != CPU_TYPE_ARM64 {
            return Err(MachOError(format!("not ARM64 (0x{:x})", cputype)));
        }
        let filetype = u32::from_le_bytes(buf[12..16].try_into().unwrap());
        let ncmds = u32::from_le_bytes(buf[16..20].try_into().unwrap()) as usize;

        let mut m = MachO {
            path, filetype, buf,
            segments: Vec::new(), sections: Vec::new(), dylibs: Vec::new(),
            symoff: 0, nsyms: 0, stroff: 0, strsize: 0,
            indirectsymoff: 0, nindirectsyms: 0,
            iundefsym: 0, nundefsym: 0,
            rebase_off: 0, rebase_size: 0,
            bind_off: 0, bind_size: 0,
            weak_off: 0, weak_size: 0,
            lazy_off: 0, lazy_size: 0,
            export_off: 0, export_size: 0,
            entryoff: 0, cryptid: -1,
            uuid: None, minos: None, source_version: None,
            syms: Vec::new(), indirect: Vec::new(),
        };

        let mut p = 32usize;
        for _ in 0..ncmds {
            if p + 8 > m.buf.len() {
                break;
            }
            let cmd = u32::from_le_bytes(m.buf[p..p + 4].try_into().unwrap());
            let cmdsize = u32::from_le_bytes(
                m.buf[p + 4..p + 8].try_into().unwrap()) as usize;
            if cmdsize == 0 || p + cmdsize > m.buf.len() {
                break;
            }
            match cmd {
                LC_SEGMENT_64 => {
                    let segname = cstr_at(&m.buf, p + 8, 16);
                    let r = |o: usize| -> u64 {
                        u64::from_le_bytes(
                            m.buf[o..o + 8].try_into().unwrap())
                    };
                    let vmaddr = r(p + 24);
                    let vmsize = r(p + 32);
                    let fileoff = r(p + 40);
                    let filesize = r(p + 48);
                    let maxprot = u32::from_le_bytes(
                        m.buf[p + 56..p + 60].try_into().unwrap());
                    let initprot = u32::from_le_bytes(
                        m.buf[p + 60..p + 64].try_into().unwrap());
                    let nsects = u32::from_le_bytes(
                        m.buf[p + 64..p + 68].try_into().unwrap());
                    m.segments.push(Segment {
                        name: segname, vmaddr, vmsize, fileoff, filesize,
                        maxprot, initprot, nsects,
                    });
                    let mut q = p + 72;
                    for _ in 0..nsects {
                        if q + 80 > m.buf.len() {
                            break;
                        }
                        let sn = cstr_at(&m.buf, q, 16);
                        let sg = cstr_at(&m.buf, q + 16, 16);
                        let addr = u64::from_le_bytes(
                            m.buf[q + 32..q + 40].try_into().unwrap());
                        let size = u64::from_le_bytes(
                            m.buf[q + 40..q + 48].try_into().unwrap());
                        let u32a = |o: usize| u32::from_le_bytes(
                            m.buf[o..o + 4].try_into().unwrap());
                        m.sections.push(Section {
                            seg: sg, name: sn, addr, size,
                            align: u32a(q + 52), offset: u32a(q + 48),
                            flags: u32a(q + 64), r1: u32a(q + 68),
                            r2: u32a(q + 72),
                        });
                        q += 80;
                    }
                }
                LC_SYMTAB => {
                    let u32a = |o: usize| u32::from_le_bytes(
                        m.buf[o..o + 4].try_into().unwrap());
                    m.symoff = u32a(p + 8);
                    m.nsyms = u32a(p + 12);
                    m.stroff = u32a(p + 16);
                    m.strsize = u32a(p + 20);
                }
                LC_DYSYMTAB => {
                    let u32a = |o: usize| u32::from_le_bytes(
                        m.buf[o..o + 4].try_into().unwrap());
                    let v = (0..18).map(|i| u32a(p + 8 + i * 4))
                        .collect::<Vec<u32>>();
                    m.iundefsym = v[4];
                    m.nundefsym = v[5];
                    m.indirectsymoff = v[12];
                    m.nindirectsyms = v[13];
                }
                LC_DYLD_INFO | LC_DYLD_INFO_ONLY => {
                    let u32a = |o: usize| u32::from_le_bytes(
                        m.buf[o..o + 4].try_into().unwrap());
                    m.rebase_off = u32a(p + 8);
                    m.rebase_size = u32a(p + 12);
                    m.bind_off = u32a(p + 16);
                    m.bind_size = u32a(p + 20);
                    m.weak_off = u32a(p + 24);
                    m.weak_size = u32a(p + 28);
                    m.lazy_off = u32a(p + 32);
                    m.lazy_size = u32a(p + 36);
                    m.export_off = u32a(p + 40);
                    m.export_size = u32a(p + 44);
                }
                LC_MAIN => {
                    m.entryoff = u64::from_le_bytes(
                        m.buf[p + 8..p + 16].try_into().unwrap());
                }
                LC_LOAD_DYLIB => {
                    let nameoff = u32::from_le_bytes(
                        m.buf[p + 8..p + 12].try_into().unwrap()) as usize;
                    m.dylibs.push(cstr_at(&m.buf, p + nameoff, 4096));
                }
                LC_UUID => {
                    m.uuid = Some(m.buf[p + 8..p + 24].iter()
                        .map(|b| format!("{:02x}", b)).collect());
                }
                LC_VERSION_MIN_IPHONEOS => {
                    let ver = u32::from_le_bytes(
                        m.buf[p + 8..p + 12].try_into().unwrap());
                    m.minos = Some(format!(
                        "{}.{}.{}", (ver >> 16) & 0xFF,
                        (ver >> 8) & 0xFF, ver & 0xFF));
                }
                LC_SOURCE_VERSION => {
                    m.source_version = Some(u64::from_le_bytes(
                        m.buf[p + 8..p + 16].try_into().unwrap()));
                }
                LC_ENCRYPTION_INFO_64 => {
                    m.cryptid = u32::from_le_bytes(
                        m.buf[p + 16..p + 20].try_into().unwrap()) as i32;
                }
                _ => {}
            }
            p += cmdsize;
        }
        Ok(m)
    }

    // ---- raw helpers -----------------------------------------------
    pub fn cstr_at(&self, off: usize) -> String {
        cstr_at(&self.buf, off, 1 << 22)
    }

    pub fn load_symbols(&mut self) -> usize {
        self.syms.clear();
        for i in 0..self.nsyms as usize {
            let off = self.symoff as usize + i * 16;
            if off + 16 > self.buf.len() {
                break;
            }
            self.syms.push(Sym {
                strx: u32::from_le_bytes(
                    self.buf[off..off + 4].try_into().unwrap()),
                typ: self.buf[off + 4],
                sect: self.buf[off + 5],
                desc: u16::from_le_bytes(
                    self.buf[off + 6..off + 8].try_into().unwrap()),
                value: u64::from_le_bytes(
                    self.buf[off + 8..off + 16].try_into().unwrap()),
            });
        }
        if self.indirectsymoff != 0 {
            let n = self.nindirectsyms as usize;
            let base = self.indirectsymoff as usize;
            self.indirect = (0..n).map(|i| {
                u32::from_le_bytes(
                    self.buf[base + i * 4..base + i * 4 + 4]
                        .try_into().unwrap())
            }).collect();
        }
        self.syms.len()
    }

    pub fn sym_name(&self, idx: usize) -> Option<String> {
        let s = self.syms.get(idx)?;
        if s.strx == 0 {
            return None;
        }
        Some(self.cstr_at(self.stroff as usize + s.strx as usize))
    }

    pub fn seg_by_index(&self, i: usize) -> Option<&Segment> {
        self.segments.get(i)
    }

    pub fn seg_by_name(&self, name: &str) -> Option<&Segment> {
        self.segments.iter().find(|s| s.name == name)
    }

    pub fn text_vm(&self) -> u64 {
        self.seg_by_name("__TEXT").map(|t| t.vmaddr).unwrap_or(0)
    }

    pub fn sections_in(&self, segname: &str, sectname: &str)
                       -> Vec<&Section> {
        self.sections.iter()
            .filter(|s| s.seg == segname && s.name == sectname)
            .collect()
    }

    // ---- dyld-relevant iterators -----------------------------------
    /// GOT / la_symbol_ptr slots -> (address, indirect_index_or_None)
    /// for every entry. Mirrors iter_pointer_slots() exactly: only the
    /// NON_LAZY/LAZY POINTER sections, indirect base = reserved1, and
    /// out-of-range entries yield None (caller skips them).
    pub fn iter_pointer_slots(&self) -> Vec<(u64, Option<u32>)> {
        let mut out = Vec::new();
        for sec in &self.sections {
            if sec.flags != S_NON_LAZY_SYMBOL_POINTERS
                && sec.flags != S_LAZY_SYMBOL_POINTERS {
                continue;
            }
            let base = if sec.r1 != 0 { sec.r1 as usize } else { 0 };
            for i in 0..(sec.size / 8) {
                let idx = base + i as usize;
                if idx < self.indirect.len() {
                    out.push((sec.addr + 8 * i, Some(self.indirect[idx])));
                } else {
                    out.push((sec.addr + 8 * i, None));
                }
            }
        }
        out
    }

    /// __mod_init_func entries (module initializers to run at launch);
    /// S_MOD_INIT_FUNC_POINTERS-flagged sections, zero entries skipped.
    pub fn mod_init_funcs(&self) -> Vec<u64> {
        let mut out = Vec::new();
        for sec in &self.sections {
            if sec.flags != S_MOD_INIT_FUNC_POINTERS || sec.size < 8 {
                continue;
            }
            let mut off = sec.offset as usize;
            let end = off + sec.size as usize;
            while off + 8 <= self.buf.len() && off < end {
                let v = u64::from_le_bytes(
                    self.buf[off..off + 8].try_into().unwrap());
                if v != 0 {
                    out.push(v);
                }
                off += 8;
            }
        }
        out
    }

    /// Thread-local data template range: min addr..max end over all
    /// TLV REGULAR/ZEROFILL sections.
    pub fn tlv_template(&self) -> (u64, u64) {
        let mut lo: Option<u64> = None;
        let mut hi: Option<u64> = None;
        for sec in &self.sections {
            if sec.flags == S_THREAD_LOCAL_REGULAR
                || sec.flags == S_THREAD_LOCAL_ZEROFILL {
                lo = Some(lo.map_or(sec.addr, |l| l.min(sec.addr)));
                hi = Some(hi.map_or(sec.addr + sec.size,
                                   |h| h.max(sec.addr + sec.size)));
            }
        }
        match (lo, hi) {
            (Some(l), Some(h)) => (l, h - l),
            _ => (0, 0),
        }
    }

    // ---- dyld bind opcodes ------------------------------------------
    pub fn parse_binds(&self) -> Vec<BindRecord> {
        let mut recs = Vec::new();
        if self.bind_size > 0 {
            recs.extend(self.parse_bind_stream(
                self.bind_off as usize, self.bind_size as usize, false));
        }
        if self.weak_size > 0 {
            recs.extend(self.parse_bind_stream(
                self.weak_off as usize, self.weak_size as usize, true));
        }
        if self.lazy_size > 0 {
            recs.extend(self.parse_bind_stream(
                self.lazy_off as usize, self.lazy_size as usize, false));
        }
        recs
    }

    /// Bind opcode table determined empirically (validated 652/652
    /// against the indirect symbol table in the Python):
    ///   0x80 = ADD_ADDR_ULEB (pure skip, u64 wrapping)
    ///   0x90 = DO_BIND
    ///   0xA0 = DO_BIND + uleb skip
    ///   0xB0 = DO_BIND + imm*8
    ///   0xC0 = DO_BIND uleb times skipping uleb
    fn parse_bind_stream(&self, off: usize, size: usize, weak: bool)
                         -> Vec<BindRecord> {
        let mut recs = Vec::new();
        let mut seg_index = 0u32;
        let mut seg_offset = 0u64;
        let mut btype = 1u32;
        let mut addend = 0i64;
        let mut ordinal = 0u32;
        let mut name: Option<String> = None;
        let mut p = off;
        let end = off + size;

        macro_rules! do_bind {
            ($count:expr, $extra:expr) => {{
                let count: u64 = $count;
                let extra: u64 = $extra;
                if let Some(nm) = &name {
                    if count <= 200000 {
                        for _ in 0..count {
                            recs.push(BindRecord {
                                seg_index, seg_offset,
                                symbol: nm.clone(), btype, addend,
                                ordinal, weak,
                            });
                            seg_offset = seg_offset
                                .wrapping_add(8).wrapping_add(extra);
                        }
                    }
                }
            }};
        }

        while p < end {
            let b = self.buf[p];
            p += 1;
            let op = b & 0xF0;
            let imm = (b & 0x0F) as u32;
            match op {
                0x00 => break,                       // DONE
                0x10 => ordinal = imm,
                0x20 => { let (v, np) = uleb(&self.buf, p); ordinal = v as u32; p = np; }
                0x30 => ordinal = imm,
                0x40 => {                            // SET_SYMBOL_TRAILING_FLAGS_IMM
                    let lim = std::cmp::min(p + 4096, self.buf.len());
                    let e = self.buf[p..lim].iter()
                        .position(|&c| c == 0).map(|i| p + i)
                        .unwrap_or_else(|| {
                            std::cmp::min(p + 256, self.buf.len())
                        });
                    name = Some(String::from_utf8_lossy(
                        &self.buf[p..e]).into_owned());
                    p = e + 1;
                }
                0x50 => btype = imm,
                0x60 => { let (v, np) = sleb(&self.buf, p); addend = v; p = np; }
                0x70 => {                            // SET_SEGMENT_AND_OFFSET_ULEB
                    seg_index = imm;
                    let (v, np) = uleb(&self.buf, p);
                    seg_offset = v;
                    p = np;
                }
                0x80 => {                            // ADD_ADDR_ULEB
                    let (skip, np) = uleb(&self.buf, p);
                    seg_offset = seg_offset.wrapping_add(skip);
                    p = np;
                }
                0x90 => do_bind!(1, 0),
                0xA0 => {
                    let (extra, np) = uleb(&self.buf, p);
                    do_bind!(1, extra);
                    p = np;
                }
                0xB0 => do_bind!(1, (imm as u64) * 8),
                0xC0 => {
                    let (count, np) = uleb(&self.buf, p);
                    let (extra, np2) = uleb(&self.buf, np);
                    do_bind!(count, extra);
                    p = np2;
                }
                _ => {}                              // 0xD0/0xE0 threaded
            }
        }
        recs
    }

    pub fn link_stats(&self) -> LinkStats {
        let n_ptrs: u64 = self.sections.iter()
            .filter(|s| s.flags == S_NON_LAZY_SYMBOL_POINTERS
                     || s.flags == S_LAZY_SYMBOL_POINTERS)
            .map(|s| s.size / 8).sum();
        LinkStats {
            segments: self.segments.len(),
            sections: self.sections.len(),
            dylibs: self.dylibs.len(),
            symbols: self.syms.len(),
            pointer_slots: n_ptrs,
            indirect_entries: self.indirect.len(),
            bind_records: self.parse_binds().len(),
            cryptid: self.cryptid,
            entryoff: self.entryoff,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct LinkStats {
    pub segments: usize,
    pub sections: usize,
    pub dylibs: usize,
    pub symbols: usize,
    pub pointer_slots: u64,
    pub indirect_entries: usize,
    pub bind_records: usize,
    pub cryptid: i32,
    pub entryoff: u64,
}

impl Section {
    /// section_64.reserved2 lives at +76 (after flags/r1/r2... in our
    /// Section we keep r1(=reserved1 at +68) and r2(=reserved2 at +72)).
    pub fn reserved2(&self) -> u32 {
        self.r2
    }
}
