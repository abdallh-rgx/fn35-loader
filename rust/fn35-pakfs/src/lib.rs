//! fn35-pakfs: UE4 pak (version 4) reader with AES-256-ECB index/data
//! encryption and per-block zlib compression, 100% safe Rust.
//!
//! Fortnite 3.5 stores the whole project tree inside
//! cookeddata/fortnitegame/Content/Paks/pakchunkearly-iosclient.pak.
//! The engine resolves guest paths like
//! "../../../FortniteGame/FortniteGame.uproject" against the pak mount;
//! this crate implements the same suffix-based, case-insensitive
//! resolution as the Python reference (scripts/fn35_pakfs.py), and is
//! differentially verified against it (tests/oracle.json).
//!
//! Pak format (empirically verified, mirrors fn35_pakfs.py):
//!   footer (last 44 bytes): magic 0x5A6F12E1, version=4, index_offset,
//!       index_size, sha1[20]
//!   index: AES-256-ECB encrypted with the build key, then:
//!       FString mount_point, i32 count, then per entry:
//!         FString name; i64 off; i64 size; i64 usize; i32 comp;
//!         20B sha1; then
//!         comp != 0: i32 nblocks, blocks{i64,i64}[], u8 enc, i32 cbs
//!         comp == 0: i32 enc, u8 pad
//!       entry data at 'off' repeats the same header (minus name) before
//!       data; blocks are absolute offsets pointing past that header.
#![forbid(unsafe_code)]

use aes::cipher::{BlockDecrypt, KeyInit};
use std::collections::HashMap;
use std::path::Path;

pub const AES_KEY: [u8; 32] = [
    0xA3, 0x27, 0x8B, 0xA7, 0xDD, 0xD7, 0x51, 0xA7, 0x54, 0x56, 0x41,
    0x5A, 0x36, 0xC3, 0x55, 0x91, 0x38, 0xE9, 0x91, 0x34, 0xD0, 0x89,
    0x58, 0xC4, 0x4C, 0x2F, 0xD2, 0x9E, 0x4B, 0xBF, 0x34, 0x2B,
];
pub const PAK_MAGIC: u32 = 0x5A6F12E1;
pub const FOOTER_SIZE: usize = 44;
pub const COMPRESSION_NONE: i32 = 0;

#[derive(Debug)]
pub enum PakError {
    Io(std::io::Error),
    TooSmall,
    BadMagic(u32),
    BadVersion(u32),
    TruncatedIndex(&'static str),
    BadUtf8,
    BadEntryHeader,
}

impl std::fmt::Display for PakError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PakError::Io(e) => write!(f, "io: {}", e),
            PakError::TooSmall => write!(f, "file smaller than a footer"),
            PakError::BadMagic(m) => write!(f, "bad magic 0x{:08X}", m),
            PakError::BadVersion(v) => write!(f, "bad version {}", v),
            PakError::TruncatedIndex(w) => {
                write!(f, "index truncated at {}", w)
            }
            PakError::BadUtf8 => write!(f, "entry name not utf-8"),
            PakError::BadEntryHeader => write!(f, "entry header overrun"),
        }
    }
}
impl std::error::Error for PakError {}

/// One index entry.
#[derive(Debug, Clone)]
pub struct Entry {
    pub name: String,
    pub off: i64,
    pub size: i64,
    pub usize_: i64,
    pub comp: i32,
    pub enc: bool,
    pub blocks: Vec<(i64, i64)>,
    pub cbs: i32,
    pub hdr: usize,
}

/// The pak (fully parsed; entry data is read on demand).
pub struct Pak {
    data: Vec<u8>,
    pub mount: String,
    entries: HashMap<String, Entry>,
    /// lowercase name -> canonical name (suffix resolver)
    lc_entries: HashMap<String, String>,
    dirs: Vec<String>,
    /// lowercase dir -> canonical
    lc_dirs: HashMap<String, String>,
}

struct Cursor<'a> {
    b: &'a [u8],
    o: usize,
}

impl<'a> Cursor<'a> {
    fn new(b: &'a [u8]) -> Self {
        Cursor { b, o: 0 }
    }
    fn take(&mut self, n: usize) -> Result<&'a [u8], PakError> {
        if self.o + n > self.b.len() {
            return Err(PakError::TruncatedIndex("read past end"));
        }
        let s = &self.b[self.o..self.o + n];
        self.o += n;
        Ok(s)
    }
    fn i32(&mut self) -> Result<i32, PakError> {
        let b = self.take(4)?;
        Ok(i32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }
    fn u32(&mut self) -> Result<u32, PakError> {
        Ok(self.i32()? as u32)
    }
    fn i64(&mut self) -> Result<i64, PakError> {
        let b = self.take(8)?;
        Ok(i64::from_le_bytes([
            b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
        ]))
    }
    fn u8(&mut self) -> Result<u8, PakError> {
        Ok(self.take(1)?[0])
    }
    fn fstr(&mut self) -> Result<String, PakError> {
        let n = self.i32()?;
        if n <= 0 {
            return Ok(String::new());
        }
        let raw = self.take(n as usize)?;
        if raw.is_empty() {
            return Ok(String::new());
        }
        let end = if raw[raw.len() - 1] == 0 {
            &raw[..raw.len() - 1]
        } else {
            raw
        };
        String::from_utf8(end.to_vec()).map_err(|_| PakError::BadUtf8)
    }
}

/// AES-256-ECB decryption in-place (padded buffer, multiple of 16).
fn aes_ecb_decrypt(buf: &mut [u8]) {
    let key = aes::Aes256::new_from_slice(&AES_KEY).expect("32-byte key");
    for chunk in buf.chunks_exact_mut(16) {
        let mut block = aes::cipher::generic_array::GenericArray::from_mut_slice(chunk);
        key.decrypt_block(&mut block);
    }
}

/// Raw zlib-stream inflate (per-block; each block is an independent
/// zlib stream). Trailing bytes after the deflate stream are ignored,
/// mirroring python's decompressobj().decompress() unused_data behavior.
fn zlib_inflate(data: &[u8]) -> Result<Vec<u8>, PakError> {
    if data.len() < 2 {
        return Err(PakError::BadEntryHeader);
    }
    miniz_oxide::inflate::decompress_to_vec(&data[2..])
        .map_err(|_| PakError::BadEntryHeader)
}

impl Pak {
    pub fn open(path: &Path) -> Result<Pak, PakError> {
        let data = std::fs::read(path).map_err(PakError::Io)?;
        Pak::parse(data)
    }

    pub fn parse(data: Vec<u8>) -> Result<Pak, PakError> {
        if data.len() < FOOTER_SIZE {
            return Err(PakError::TooSmall);
        }
        let ftr = &data[data.len() - FOOTER_SIZE..];
        let magic =
            u32::from_le_bytes([ftr[0], ftr[1], ftr[2], ftr[3]]);
        if magic != PAK_MAGIC {
            return Err(PakError::BadMagic(magic));
        }
        let version = u32::from_le_bytes([ftr[4], ftr[5], ftr[6], ftr[7]]);
        if version != 4 {
            return Err(PakError::BadVersion(version));
        }
        let idx_off = i64::from_le_bytes([
            ftr[8], ftr[9], ftr[10], ftr[11], ftr[12], ftr[13], ftr[14],
            ftr[15],
        ]);
        let idx_size = i64::from_le_bytes([
            ftr[16], ftr[17], ftr[18], ftr[19], ftr[20], ftr[21],
            ftr[22], ftr[23],
        ]);
        if idx_off < 0 || idx_size < 0
            || (idx_off as u64) + (idx_size as u64) > data.len() as u64
        {
            return Err(PakError::TruncatedIndex("index out of bounds"));
        }

        // index is AES-ECB encrypted; pad size up to a 16-multiple
        let mut idx = data[idx_off as usize
            ..(idx_off + idx_size) as usize]
            .to_vec();
        let padded = (idx.len() + 15) & !15;
        idx.resize(padded, 0);
        aes_ecb_decrypt(&mut idx);
        idx.truncate(idx_size as usize);

        let mut r = Cursor::new(&idx);
        let mount = r.fstr()?;
        let n = r.i32()?;
        let mut entries = HashMap::new();
        let mut dirs: Vec<String> = Vec::new();
        let mut dir_set = std::collections::HashSet::new();
        for _ in 0..n {
            let name = r.fstr()?;
            let off = r.i64()?;
            let size = r.i64()?;
            let usize_ = r.i64()?;
            let comp = r.i32()?;
            r.take(20)?; // sha1
            let (enc, blocks, cbs, hdr) = if comp != COMPRESSION_NONE {
                let nb = r.i32()?;
                if nb < 0 {
                    return Err(PakError::BadEntryHeader);
                }
                let mut blocks = Vec::with_capacity(nb as usize);
                for _ in 0..nb {
                    let s = r.i64()?;
                    let e = r.i64()?;
                    blocks.push((s, e));
                }
                let enc = r.u8()? != 0;
                let cbs = r.i32()?;
                let hdr = 8 + 8 + 8 + 4 + 20 + 4 + 16 * nb as usize + 1 + 4;
                (enc, blocks, cbs, hdr)
            } else {
                let enc = r.i32()? != 0;
                r.u8()?; // pad
                (enc, Vec::new(), 0, 8 + 8 + 8 + 4 + 20 + 5)
            };
            // register parent dirs
            let parts: Vec<&str> = name.split('/').collect();
            for k in 1..parts.len() {
                let d = parts[..k].join("/");
                if dir_set.insert(d.clone()) {
                    dirs.push(d);
                }
            }
            entries.insert(
                name.clone(),
                Entry {
                    name,
                    off,
                    size,
                    usize_,
                    comp,
                    enc,
                    blocks,
                    cbs,
                    hdr,
                },
            );
        }
        let mut lc_entries = HashMap::with_capacity(entries.len());
        for name in entries.keys() {
            lc_entries.insert(name.to_lowercase(), name.clone());
        }
        let mut lc_dirs = HashMap::with_capacity(dirs.len());
        for d in &dirs {
            lc_dirs.insert(d.to_lowercase(), d.clone());
        }
        Ok(Pak {
            data,
            mount,
            entries,
            lc_entries,
            dirs,
            lc_dirs,
        })
    }

    pub fn entry_count(&self) -> usize {
        self.entries.len()
    }
    pub fn dir_count(&self) -> usize {
        self.dirs.len()
    }
    pub fn entry_names(&self) -> Vec<&str> {
        let mut v: Vec<&str> =
            self.entries.keys().map(|s| s.as_str()).collect();
        v.sort_unstable();
        v
    }
    pub fn get(&self, name: &str) -> Option<&Entry> {
        self.entries.get(name)
    }

    /// Lexical component split collapsing '.' and '..' (mirrors the
    /// python _components).
    fn components(gpath: &str) -> Vec<String> {
        let mut out: Vec<String> = Vec::new();
        for c in gpath.split('/') {
            if c == "." || c.is_empty() {
                continue;
            }
            if c == ".." {
                out.pop();
                continue;
            }
            out.push(c.to_string());
        }
        out
    }

    /// Suffix-based, case-insensitive guest-path resolution. Longest
    /// (earliest component) match wins.
    pub fn resolve(&self, gpath: &str) -> Option<&Entry> {
        let comps = Pak::components(gpath);
        for i in 0..comps.len() {
            let cand = comps[i..].join("/").to_lowercase();
            if let Some(real) = self.lc_entries.get(&cand) {
                return self.entries.get(real);
            }
        }
        None
    }

    pub fn resolve_dir(&self, gpath: &str) -> Option<&str> {
        let comps = Pak::components(gpath);
        for i in 0..comps.len() {
            let cand = comps[i..].join("/").to_lowercase();
            if let Some(real) = self.lc_dirs.get(&cand) {
                return Some(real.as_str());
            }
        }
        None
    }

    /// Immediate children names of a pak directory.
    pub fn list_dir(&self, pak_dir: &str) -> Vec<String> {
        let prefix = format!("{}/", pak_dir);
        let mut out: Vec<String> = Vec::new();
        let mut seen = std::collections::HashSet::new();
        for name in self.entries.keys() {
            if let Some(rest) = name.strip_prefix(&prefix) {
                if let Some(idx) = rest.find('/') {
                    let child = &rest[..idx];
                    if seen.insert(child.to_string()) {
                        out.push(child.to_string());
                    }
                } else {
                    seen.insert(rest.to_string());
                    out.push(rest.to_string());
                }
            }
        }
        for d in &self.dirs {
            if let Some(rest) = d.strip_prefix(&prefix) {
                if !rest.contains('/') && seen.insert(rest.to_string()) {
                    out.push(rest.to_string());
                }
            }
        }
        out
    }

    /// Read + decrypt + inflate one entry's data.
    pub fn read_entry(&self, e: &Entry) -> Result<Vec<u8>, PakError> {
        if e.comp == COMPRESSION_NONE {
            let start = (e.off + e.hdr as i64) as usize;
            let want = (e.size as usize + 15) & !15;
            if start + want > self.data.len() {
                return Err(PakError::BadEntryHeader);
            }
            let mut raw = self.data[start..start + want].to_vec();
            if e.enc {
                aes_ecb_decrypt(&mut raw);
            }
            raw.truncate(e.size as usize);
            Ok(raw)
        } else {
            let mut out: Vec<u8> = Vec::new();
            for &(s, en) in &e.blocks {
                let (s, en) = (s as usize, en as usize);
                if en < s || en > self.data.len() {
                    return Err(PakError::BadEntryHeader);
                }
                // encrypted blocks are PADDED to a 16-multiple on disk;
                // read the padded span, decrypt, keep exactly (en - s)
                let want = en - s;
                let padded = (want + 15) & !15;
                if s + padded > self.data.len() {
                    return Err(PakError::BadEntryHeader);
                }
                let mut chunk = self.data[s..s + padded].to_vec();
                if e.enc {
                    aes_ecb_decrypt(&mut chunk);
                }
                chunk.truncate(want);
                out.extend_from_slice(&zlib_inflate(&chunk)?);
            }
            Ok(out)
        }
    }
}
