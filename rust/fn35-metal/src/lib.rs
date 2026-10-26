//! # fn35-metal — safe core of the fn35 Metal shim
//!
//! This crate is the Rust re-implementation of the Metal API subset the
//! Fortnite 3.5 iOS loader must serve on the way to the login screen:
//! devices, command queues/buffers with a commit/schedule/complete
//! lifecycle, bounds-checked MTLBuffers, mip-aware MTLTextures and a
//! metallib container parser.
//!
//! Every guard in this file mirrors `scripts/metal_z3_spec.py`
//! (`step_concrete`) 1:1. The Z3 spec proves:
//!   * P1  no encode after commit
//!   * P2  lifecycle monotonicity
//!   * P3  resource bounds safety
//!   * P4  handle validity (dead handles always rejected)
//!   * P5  bounded liveness (commit -> <=2 ticks -> completed)
//! and `tests/conformance.rs` replays 300 traces generated from the
//! proven model through THIS code, asserting identical rc/kind/phase.
//!
//! `#![forbid(unsafe_code)]`: there is not a single unsafe block in the
//! entire crate; raw pointers only appear (contained) in the FFI crate.
#![forbid(unsafe_code)]

use std::collections::HashMap;

// ---------------------------------------------------------------------------
// Return codes (the FFI contract; mirror of metal_z3_spec / fn35_metal.py)
// ---------------------------------------------------------------------------
pub const OK: u32 = 0;
pub const E_DEAD: u32 = 1; // dead/invalid handle
pub const E_PHASE: u32 = 2; // lifecycle phase violation
pub const E_BOUNDS: u32 = 3; // region/size out of bounds
pub const E_KIND: u32 = 4; // wrong object kind for the op
pub const E_PARSE: u32 = 5; // metallib parse failure

// ---------------------------------------------------------------------------
// Object kinds / lifecycle phases
// ---------------------------------------------------------------------------
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Kind {
    None = 0,
    Device = 1,
    Queue = 2,
    CmdBuf = 3,
    Buffer = 4,
    Texture = 5,
    Library = 6,
    Rpass = 7,
    Pipeline = 8,
    Fence = 9,
}

impl Kind {
    pub fn as_u32(self) -> u32 {
        self as u32
    }
}

/// Command-buffer lifecycle. The lattice is strictly upward except that
/// `Errored` and `Completed` are terminal siblings (both rank 5).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Phase {
    Dead = 0,
    Created = 1,
    Active = 2,
    Committed = 3,
    Scheduled = 4,
    Completed = 5,
    Errored = 6,
}

impl Phase {
    pub fn rank(self) -> u32 {
        match self {
            Phase::Dead => 0,
            Phase::Created => 1,
            Phase::Active => 2,
            Phase::Committed => 3,
            Phase::Scheduled => 4,
            Phase::Completed | Phase::Errored => 5,
        }
    }
    pub fn as_u32(self) -> u32 {
        self as u32
    }
}

// ---------------------------------------------------------------------------
// Objects
// ---------------------------------------------------------------------------
pub struct TextureInfo {
    pub width: u32,
    pub height: u32,
    pub levels: u32,
    pub format: u32, // 1 = BGRA8 (4 bytes/pixel)
    /// level -> pixel rows (row-major, width*4 bytes per row)
    pub planes: Vec<Vec<u8>>,
}

impl TextureInfo {
    /// Mip dimension at `level` with the min-1 rule (Z3 spec:
    /// `max(1, w >> lvl)`).
    fn mip_dim(base: u32, level: u32) -> u32 {
        if level >= 32 {
            1
        } else {
            std::cmp::max(1, base >> level)
        }
    }

    fn bytes_per_pixel(format: u32) -> Option<usize> {
        match format {
            1 | 80 => Some(4), // BGRA8 (1 = rust core, 80 = MTL format id)
            _ => None,
        }
    }
}

pub struct LibraryInfo {
    pub functions: Vec<String>,
}

pub struct Object {
    pub kind: Kind,
    pub phase: Phase,
    pub err: u32,
    pub buf: Vec<u8>,
    pub tex: Option<TextureInfo>,
    pub lib: Option<LibraryInfo>,
    // --- render-pipeline extension (Z3 spec session 7) ---
    /// render pass -> color-attachment texture handle (0 = none)
    pub attach: u64,
    /// pipeline -> has a valid vertex function
    pub pipe_valid: bool,
    /// fence -> signaled flag
    pub signaled: bool,
    /// cmdbuf -> bound pipeline handle (0 = none)
    pub cb_pipe: u64,
}

impl Object {
    fn new_device() -> Self {
        Object { kind: Kind::Device, phase: Phase::Dead, err: 0,
                 buf: Vec::new(), tex: None, lib: None,
                 attach: 0, pipe_valid: false, signaled: false,
                 cb_pipe: 0 }
    }
    fn dead() -> Self {
        Object { kind: Kind::None, phase: Phase::Dead, err: 0,
                 buf: Vec::new(), tex: None, lib: None,
                 attach: 0, pipe_valid: false, signaled: false,
                 cb_pipe: 0 }
    }
}

pub const MAX_BUFFER_BYTES: u64 = 1 << 30; // 1 GiB shadow cap
pub const MAX_TEX_PLANE_BYTES: u64 = 1 << 30; // 1 GiB plane cap

// ---------------------------------------------------------------------------
// The registry (handle -> object). Handles are u64, 0 is never issued.
// ---------------------------------------------------------------------------
pub struct MetalState {
    objects: HashMap<u64, Object>,
    next_handle: u64,
    last_error: u32,
}

impl Default for MetalState {
    fn default() -> Self {
        MetalState { objects: HashMap::new(), next_handle: 1, last_error: 0 }
    }
}

impl MetalState {
    pub fn new() -> Self {
        Self::default()
    }

    fn alloc(&mut self, make: impl FnOnce() -> Object) -> u64 {
        let h = self.next_handle;
        self.next_handle += 1;
        self.objects.insert(h, make());
        h
    }

    fn get(&self, h: u64) -> Option<&Object> {
        self.objects.get(&h)
    }

    fn set_err(&mut self, rc: u32) -> u32 {
        self.last_error = rc;
        rc
    }

    pub fn last_error(&self) -> u32 {
        self.last_error
    }

    /// FFI-only: record a failing rc for fn35_metal_last_error().
    pub fn set_last_error(&mut self, rc: u32) {
        if rc != OK {
            self.last_error = rc;
        }
    }

    pub fn live_count(&self) -> u32 {
        self.objects.len() as u32
    }

    pub fn is_live(&self, h: u64) -> bool {
        self.get(h).map(|o| o.kind != Kind::None).unwrap_or(false)
    }

    pub fn obj_kind(&self, h: u64) -> u32 {
        self.get(h).map(|o| o.kind.as_u32()).unwrap_or(Kind::None.as_u32())
    }

    pub fn cb_phase(&self, h: u64) -> u32 {
        self.get(h).map(|o| o.phase.as_u32()).unwrap_or(Phase::Dead.as_u32())
    }

    // -- constructors -------------------------------------------------------

    /// MTLCreateSystemDefaultDevice. Always succeeds (nil-device model:
    /// we ARE the device).
    pub fn device_create(&mut self) -> u64 {
        self.alloc(Object::new_device)
    }

    fn require_live_kind(&self, h: u64, want: Kind) -> Option<u32> {
        match self.get(h) {
            Some(o) if o.kind != Kind::None => {}
            _ => return Some(E_DEAD),
        }
        if self.obj_kind(h) != want.as_u32() {
            return Some(E_KIND);
        }
        None
    }

    /// device.newCommandQueue: requires a live device handle.
    pub fn queue_new(&mut self, dev: u64) -> (u64, u32) {
        if let Some(rc) = self.require_live_kind(dev, Kind::Device) {
            return (0, self.set_err(rc));
        }
        let h = self.alloc(|| Object {
            kind: Kind::Queue, phase: Phase::Dead, err: 0,
            buf: Vec::new(), tex: None, lib: None,
            attach: 0, pipe_valid: false, signaled: false, cb_pipe: 0,
        });
        (h, OK)
    }

    /// queue.commandBuffer: new cmdbuf enters phase Active.
    pub fn cb_new(&mut self, queue: u64) -> (u64, u32) {
        if let Some(rc) = self.require_live_kind(queue, Kind::Queue) {
            return (0, self.set_err(rc));
        }
        let h = self.alloc(|| Object {
            kind: Kind::CmdBuf, phase: Phase::Active, err: 0,
            buf: Vec::new(), tex: None, lib: None,
            attach: 0, pipe_valid: false, signaled: false, cb_pipe: 0,
        });
        (h, OK)
    }

    // -- cmdbuf lifecycle ---------------------------------------------------

    /// cb.addRenderEncoder: P1 — only while phase == Active.
    pub fn cb_encode(&mut self, cb: u64) -> u32 {
        if let Some(rc) = self.require_live_kind(cb, Kind::CmdBuf) {
            return self.set_err(rc);
        }
        if self.get(cb).unwrap().phase != Phase::Active {
            return self.set_err(E_PHASE);
        }
        OK
    }

    /// cb.commit: Active -> Committed.
    pub fn cb_commit(&mut self, cb: u64) -> u32 {
        if let Some(rc) = self.require_live_kind(cb, Kind::CmdBuf) {
            return self.set_err(rc);
        }
        if self.get(cb).unwrap().phase != Phase::Active {
            return self.set_err(E_PHASE);
        }
        self.objects.get_mut(&cb).unwrap().phase = Phase::Committed;
        OK
    }

    /// Scheduler tick: Committed -> Scheduled -> Completed.
    pub fn cb_tick(&mut self, cb: u64) -> u32 {
        if let Some(rc) = self.require_live_kind(cb, Kind::CmdBuf) {
            return self.set_err(rc);
        }
        let next = match self.get(cb).unwrap().phase {
            Phase::Committed => Phase::Scheduled,
            Phase::Scheduled => Phase::Completed,
            _ => return self.set_err(E_PHASE),
        };
        self.objects.get_mut(&cb).unwrap().phase = next;
        OK
    }

    /// GPU fault: a live submission fails with an error code.
    /// Requires Committed or Scheduled (a fault happens during execution).
    pub fn cb_fail(&mut self, cb: u64, code: u32) -> u32 {
        if let Some(rc) = self.require_live_kind(cb, Kind::CmdBuf) {
            return self.set_err(rc);
        }
        if self.get(cb).unwrap().phase != Phase::Committed
            && self.get(cb).unwrap().phase != Phase::Scheduled {
            return self.set_err(E_PHASE);
        }
        let om = self.objects.get_mut(&cb).unwrap();
        om.phase = Phase::Errored;
        om.err = code;
        OK
    }

    /// cb.waitUntilCompleted: returns the stored error if Errored, else OK.
    /// Requires phase >= Committed (the terminal states included).
    pub fn cb_wait(&mut self, cb: u64) -> (u32, u32) {
        if let Some(rc) = self.require_live_kind(cb, Kind::CmdBuf) {
            return (self.set_err(rc), 0);
        }
        let o = self.get(cb).unwrap();
        match o.phase {
            Phase::Committed | Phase::Scheduled | Phase::Completed
            | Phase::Errored => {}
            _ => return (self.set_err(E_PHASE), 0),
        }
        let err = o.err;
        if o.phase == Phase::Errored {
            (err, err)
        } else {
            (OK, err)
        }
    }

    // -- buffers ------------------------------------------------------------

    pub fn buf_new(&mut self, dev: u64, length: u64,
                   init: Option<&[u8]>) -> (u64, u32) {
        if let Some(rc) = self.require_live_kind(dev, Kind::Device) {
            return (0, self.set_err(rc));
        }
        // SPEC: `ln < 0 -> E_BOUNDS`. The FFI carries length as u64, so a
        // negative i64 arrives with the sign bit set: reject >= 2^63.
        if length > i64::MAX as u64 {
            return (0, self.set_err(E_BOUNDS));
        }
        // SPEC: any length >= 0 is accepted (Z3 model has no cap).
        // Storage: bounded shadow — the spec-visible buf_len is the full
        // requested length; only min(length, MAX_BUFFER_BYTES) bytes are
        // physically held. Accesses beyond the shadow are region-valid
        // (rc OK) but don't touch host memory (nil-device model).
        let shadow = length.min(MAX_BUFFER_BYTES) as usize;
        let mut storage = vec![0u8; shadow];
        if let Some(data) = init {
            let n = std::cmp::min(data.len(), storage.len());
            storage[..n].copy_from_slice(&data[..n]);
        }
        let h = self.alloc(|| Object {
            kind: Kind::Buffer, phase: Phase::Dead, err: 0,
            buf: storage, tex: None, lib: None,
            attach: 0, pipe_valid: false, signaled: false, cb_pipe: 0,
        });
        if length > MAX_BUFFER_BYTES {
            // record the logical length where the shadow can't see it:
            // tex field is unused for buffers; borrow its width as len_hi
            let o = self.objects.get_mut(&h).unwrap();
            o.tex = Some(TextureInfo {
                width: (length >> 32) as u32,
                height: length as u32,
                levels: 0, format: 0, planes: Vec::new(),
            });
        }
        (h, OK)
    }

    pub fn buf_len(&self, b: u64) -> u64 {
        match self.get(b) {
            Some(o) if o.kind == Kind::Buffer => {
                if let Some(t) = o.tex.as_ref() {
                    // logical length stashed when it exceeded the shadow
                    ((t.width as u64) << 32) | t.height as u64
                } else {
                    o.buf.len() as u64
                }
            }
            _ => 0,
        }
    }

    /// P3: off + ln <= len, computed in u128 so u64 inputs cannot
    /// overflow their way past the check. Checks against the LOGICAL
    /// length (spec-visible), not the bounded shadow.
    fn buf_region_ok(&self, b: u64, off: u64, ln: u64) -> bool {
        match self.get(b) {
            Some(o) if o.kind == Kind::Buffer => {
                (off as u128 + ln as u128) <= self.buf_len(b) as u128
            }
            _ => false,
        }
    }

    pub fn buf_check_region(&mut self, b: u64, off: u64, ln: u64) -> u32 {
        if let Some(rc) = self.require_live_kind(b, Kind::Buffer) {
            return self.set_err(rc);
        }
        if !self.buf_region_ok(b, off, ln) {
            return self.set_err(E_BOUNDS);
        }
        OK
    }

    pub fn buf_write(&mut self, b: u64, off: u64, data: &[u8]) -> u32 {
        let rc = self.buf_check_region(b, off, data.len() as u64);
        if rc != OK {
            return rc;
        }
        // shadow-clipped copy (rc semantics already decided above)
        let o = self.objects.get_mut(&b).unwrap();
        let s = (off as usize).min(o.buf.len());
        let n = std::cmp::min(data.len(), o.buf.len().saturating_sub(s));
        o.buf[s..s + n].copy_from_slice(&data[..n]);
        OK
    }

    pub fn buf_read(&mut self, b: u64, off: u64, out: &mut [u8]) -> u32 {
        let rc = self.buf_check_region(b, off, out.len() as u64);
        if rc != OK {
            return rc;
        }
        // shadow-clipped read (beyond-shadow bytes read as zero)
        let o = self.get(b).unwrap();
        let s = (off as usize).min(o.buf.len());
        let n = std::cmp::min(out.len(), o.buf.len().saturating_sub(s));
        out[..n].copy_from_slice(&o.buf[s..s + n]);
        for byte in out[n..].iter_mut() {
            *byte = 0;
        }
        OK
    }

    // -- textures -----------------------------------------------------------

    pub fn tex_new(&mut self, dev: u64, w: u32, h: u32, levels: u32,
                   format: u32) -> (u64, u32) {
        if let Some(rc) = self.require_live_kind(dev, Kind::Device) {
            return (0, self.set_err(rc));
        }
        // SPEC (Z3): w>0 && h>0 && lvl>0 — NO other cap. The FFI carries
        // these as u32, so negative i32s arrive with the sign bit set:
        // anything above i32::MAX is rejected (spec's `<= 0` guard).
        // Storage is fully lazy: planes are only materialized on writes
        // to that level (see tex_write), so huge dims never OOM the host.
        if w == 0 || h == 0 || levels == 0
            || w > i32::MAX as u32 || h > i32::MAX as u32
            || levels > i32::MAX as u32 {
            return (0, self.set_err(E_BOUNDS));
        }
        let h_ = self.alloc(|| Object {
            kind: Kind::Texture, phase: Phase::Dead, err: 0,
            buf: Vec::new(),
            tex: Some(TextureInfo {
                width: w, height: h, levels, format,
                planes: Vec::new(),
            }),
            lib: None,
            attach: 0, pipe_valid: false, signaled: false, cb_pipe: 0,
        });
        (h_, OK)
    }

    /// Region check exactly as the Z3 spec: level bounds first, then the
    /// rect against the mip dimensions at that level. u64 math throughout
    /// (the FFI passes u32s; negatives arrive as huge values and must be
    /// REJECTED, never wrap-accepted).
    pub fn tex_check_region(&mut self, t: u64, x: u32, y: u32, w: u32,
                            h: u32, level: u32) -> u32 {
        if let Some(rc) = self.require_live_kind(t, Kind::Texture) {
            return self.set_err(rc);
        }
        let tex = self.get(t).unwrap().tex.as_ref().unwrap();
        if level >= tex.levels {
            return self.set_err(E_BOUNDS);
        }
        let lw = TextureInfo::mip_dim(tex.width, level) as u64;
        let lh = TextureInfo::mip_dim(tex.height, level) as u64;
        let (x, y, w, h) = (x as u64, y as u64, w as u64, h as u64);
        if x + w > lw || y + h > lh {
            return self.set_err(E_BOUNDS);
        }
        OK
    }

    pub fn tex_write(&mut self, t: u64, x: u32, y: u32, w: u32, h: u32,
                     level: u32, data: &[u8]) -> u32 {
        let rc = self.tex_check_region(t, x, y, w, h, level);
        if rc != OK {
            return rc;
        }
        let bpp = TextureInfo::bytes_per_pixel(
            self.get(t).unwrap().tex.as_ref().unwrap().format)
            .unwrap_or(4);
        let needed = (w as u128) * (h as u128) * (bpp as u128);
        if (data.len() as u128) < needed {
            return self.set_err(E_BOUNDS);
        }
        // ensure the mip plane exists (lazy, bounded)
        let need_bytes = {
            let tex = self.get(t).unwrap().tex.as_ref().unwrap();
            let mw = TextureInfo::mip_dim(tex.width, level) as u128;
            let mh = TextureInfo::mip_dim(tex.height, level) as u128;
            mw * mh * (bpp as u128)
        };
        if need_bytes <= MAX_TEX_PLANE_BYTES as u128 {
            while self.get(t).unwrap().tex.as_ref().unwrap()
                    .planes.len() <= level as usize {
                let l = self.get(t).unwrap().tex.as_ref().unwrap()
                    .planes.len() as u32;
                let (mw, mh) = {
                    let tex = self.get(t).unwrap().tex.as_ref().unwrap();
                    (TextureInfo::mip_dim(tex.width, l) as usize,
                     TextureInfo::mip_dim(tex.height, l) as usize)
                };
                self.objects.get_mut(&t).unwrap()
                    .tex.as_mut().unwrap()
                    .planes.push(vec![0u8; mw * bpp * mh]);
            }
            let pw = TextureInfo::mip_dim(
                self.get(t).unwrap().tex.as_ref().unwrap().width, level)
                as usize;
            for r in 0..(h as usize) {
                let dst = ((y as usize) + r) * pw * bpp
                    + (x as usize) * bpp;
                let src = r * (w as usize) * bpp;
                let plane = &mut self.objects.get_mut(&t).unwrap()
                    .tex.as_mut().unwrap().planes[level as usize];
                plane[dst..dst + (w as usize) * bpp]
                    .copy_from_slice(&data[src..src + (w as usize) * bpp]);
            }
        }
        // beyond-policy planes: region checks already passed; the write
        // is accepted without host storage (nil-device shadow model)
        OK
    }

    pub fn tex_read(&mut self, t: u64, x: u32, y: u32, w: u32, h: u32,
                    level: u32, out: &mut [u8]) -> u32 {
        let rc = self.tex_check_region(t, x, y, w, h, level);
        if rc != OK {
            return rc;
        }
        let bpp = TextureInfo::bytes_per_pixel(
            self.get(t).unwrap().tex.as_ref().unwrap().format)
            .unwrap_or(4);
        let needed = (w as u128) * (h as u128) * (bpp as u128);
        if (out.len() as u128) < needed {
            return self.set_err(E_BOUNDS);
        }
        let tex = self.get(t).unwrap().tex.as_ref().unwrap();
        if (level as usize) >= tex.planes.len() {
            return self.set_err(E_BOUNDS);
        }
        let pw = TextureInfo::mip_dim(tex.width, level) as usize;
        let plane = &tex.planes[level as usize];
        for r in 0..(h as usize) {
            let src = ((y as usize) + r) * pw * bpp + (x as usize) * bpp;
            let dst = r * (w as usize) * bpp;
            out[dst..dst + (w as usize) * bpp]
                .copy_from_slice(&plane[src..src + (w as usize) * bpp]);
        }
        OK
    }

    // -- libraries ----------------------------------------------------------

    /// device.newLibraryWithData: parse an AIR .metallib container.
    ///
    /// Layout (as synthesized by the loader and accepted here):
    /// ```text
    /// "MTLB" <u32 version> then chunks: <tag[4]> <u32 len> <bytes>
    ///   "METD" -> JSON {"functions": ["vertex_0", ...]}
    ///   "METB" -> AIR bitcode (stored opaquely)
    /// ```
    pub fn lib_new(&mut self, dev: u64, data: &[u8]) -> (u64, u32) {
        if let Some(rc) = self.require_live_kind(dev, Kind::Device) {
            return (0, self.set_err(rc));
        }
        let functions = match parse_metallib(data) {
            Some(f) => f,
            None => return (0, self.set_err(E_PARSE)),
        };
        let h = self.alloc(|| Object {
            kind: Kind::Library, phase: Phase::Dead, err: 0,
            buf: Vec::new(), tex: None,
            lib: Some(LibraryInfo { functions }),
            attach: 0, pipe_valid: false, signaled: false, cb_pipe: 0,
        });
        (h, OK)
    }

    pub fn lib_has_function(&self, lib: u64, name: &str) -> bool {
        self.get(lib)
            .and_then(|o| o.lib.as_ref())
            .map(|l| l.functions.iter().any(|f| f == name))
            .unwrap_or(false)
    }

    pub fn lib_function_count(&self, lib: u64) -> u32 {
        self.get(lib)
            .and_then(|o| o.lib.as_ref())
            .map(|l| l.functions.len() as u32)
            .unwrap_or(0)
    }

    /// Returns the function name; `None` if out of range.
    pub fn lib_function_name(&self, lib: u64, idx: u32) -> Option<&str> {
        self.get(lib)
            .and_then(|o| o.lib.as_ref())
            .and_then(|l| l.functions.get(idx as usize).map(|s| s.as_str()))
    }

    // -- registry ------------------------------------------------------------

    /// handle.release: P4 — dead handles always rejected; live ones are
    /// dropped and the handle never resolves again.
    pub fn release(&mut self, h: u64) -> u32 {
        match self.get(h) {
            Some(o) if o.kind != Kind::None => {}
            _ => return self.set_err(E_DEAD),
        }
        // in-use guards (keep attachments/bindings from dangling -
        // the Z3 I5/I6 invariants depend on this)
        let kind = self.objects.get(&h).map(|o| o.kind);
        if kind == Some(Kind::Texture) {
            let in_use = self.objects.values()
                .any(|o| o.kind == Kind::Rpass && o.attach == h);
            if in_use {
                return self.set_err(E_KIND); // attached to a render pass
            }
        }
        if kind == Some(Kind::Pipeline) {
            let in_use = self.objects.values()
                .any(|o| o.kind == Kind::CmdBuf && o.cb_pipe == h);
            if in_use {
                return self.set_err(E_KIND); // bound to a command buffer
            }
        }
        self.objects.insert(h, Object::dead());
        OK
    }

    // -----------------------------------------------------------------------
    // Render-pipeline extension (guards are the Z3 spec, verbatim)
    // -----------------------------------------------------------------------
    pub fn rpass_new(&mut self, dev: u64) -> (u64, u32) {
        match self.get(dev) {
            Some(o) if o.kind == Kind::Device => {}
            Some(_) => return (0, self.set_err(E_KIND)),
            None => return (0, self.set_err(E_DEAD)),
        }
        let h = self.alloc(|| Object {
            kind: Kind::Rpass, phase: Phase::Dead, err: 0,
            buf: Vec::new(), tex: None, lib: None,
            attach: 0, pipe_valid: false, signaled: false, cb_pipe: 0 });
        (h, 0)
    }

    pub fn rpass_attach(&mut self, rpass: u64, texture: u64) -> u32 {
        match self.get(rpass) {
            Some(o) if o.kind == Kind::Rpass => {}
            Some(_) => return self.set_err(E_KIND),
            None => return self.set_err(E_DEAD),
        }
        match self.get(texture) {
            Some(o) if o.kind == Kind::Texture => {}
            Some(_) => return self.set_err(E_KIND),
            None => return self.set_err(E_DEAD),
        }
        self.objects.get_mut(&rpass).unwrap().attach = texture;
        OK
    }

    pub fn enc_rpass(&mut self, cb: u64, rpass: u64) -> u32 {
        match self.get(cb) {
            Some(o) if o.kind == Kind::CmdBuf => {
                if o.phase != Phase::Active {
                    return self.set_err(E_PHASE);
                }
            }
            Some(_) => return self.set_err(E_KIND),
            None => return self.set_err(E_DEAD),
        }
        match self.get(rpass) {
            Some(o) if o.kind == Kind::Rpass => {
                if o.attach == 0 {
                    return self.set_err(E_KIND); // no color attachment
                }
            }
            Some(_) => return self.set_err(E_KIND),
            None => return self.set_err(E_DEAD),
        }
        // verify the attachment still resolves (I5 at runtime)
        let at = self.objects.get(&rpass).unwrap().attach;
        match self.get(at) {
            Some(o) if o.kind == Kind::Texture => {}
            _ => return self.set_err(E_KIND),
        }
        OK
    }

    pub fn pipeline_new(&mut self, lib: u64) -> (u64, u32) {
        match self.get(lib) {
            Some(o) if o.kind == Kind::Library => {}
            Some(_) => return (0, self.set_err(E_KIND)),
            None => return (0, self.set_err(E_DEAD)),
        }
        let has_fn = self.objects.get(&lib)
            .and_then(|o| o.lib.as_ref())
            .map(|l| !l.functions.is_empty())
            .unwrap_or(false);
        if !has_fn {
            return (0, self.set_err(E_PARSE));
        }
        let h = self.alloc(|| Object {
            kind: Kind::Pipeline, phase: Phase::Dead, err: 0,
            buf: Vec::new(), tex: None, lib: None,
            attach: 0, pipe_valid: true, signaled: false, cb_pipe: 0 });
        (h, 0)
    }

    pub fn enc_setpipe(&mut self, cb: u64, pipeline: u64) -> u32 {
        match self.get(cb) {
            Some(o) if o.kind == Kind::CmdBuf => {
                if o.phase != Phase::Active {
                    return self.set_err(E_PHASE);
                }
            }
            Some(_) => return self.set_err(E_KIND),
            None => return self.set_err(E_DEAD),
        }
        match self.get(pipeline) {
            Some(o) if o.kind == Kind::Pipeline && o.pipe_valid => {}
            Some(_) => return self.set_err(E_KIND),
            None => return self.set_err(E_DEAD),
        }
        self.objects.get_mut(&cb).unwrap().cb_pipe = pipeline;
        OK
    }

    pub fn enc_draw(&mut self, cb: u64, vertex_count: u64,
                    instance_count: u64) -> u32 {
        match self.get(cb) {
            Some(o) if o.kind == Kind::CmdBuf => {
                if o.phase != Phase::Active {
                    return self.set_err(E_PHASE);
                }
            }
            Some(_) => return self.set_err(E_KIND),
            None => return self.set_err(E_DEAD),
        }
        let pipe = self.objects.get(&cb).unwrap().cb_pipe;
        match self.get(pipe) {
            Some(o) if o.kind == Kind::Pipeline && o.pipe_valid => {}
            _ => return self.set_err(E_KIND), // draw requires a bound pipeline
        }
        if vertex_count == 0 || vertex_count > u32::MAX as u64 {
            return self.set_err(E_BOUNDS);
        }
        if instance_count == 0 || instance_count > u32::MAX as u64 {
            return self.set_err(E_BOUNDS);
        }
        OK
    }

    pub fn enc_blit(&mut self, cb: u64, src: u64, dst: u64,
                    src_off: u64, dst_off: u64, size: u64) -> u32 {
        match self.get(cb) {
            Some(o) if o.kind == Kind::CmdBuf => {
                if o.phase != Phase::Active {
                    return self.set_err(E_PHASE);
                }
            }
            Some(_) => return self.set_err(E_KIND),
            None => return self.set_err(E_DEAD),
        }
        // dead-target checks for BOTH sides first (spec: slot-range and
        // dead-slot checks precede kind checks - keeps E_DEAD priority
        // over E_KIND when one side is dead and the other mistyped)
        match (self.get(src), self.get(dst)) {
            (Some(s), Some(d)) if s.kind != Kind::None
                && d.kind != Kind::None => {}
            _ => return self.set_err(E_DEAD),
        }
        let slen = match self.get(src) {
            Some(o) if o.kind == Kind::Buffer => o.buf.len() as u64,
            Some(_) => return self.set_err(E_KIND),
            None => return self.set_err(E_DEAD),
        };
        let dlen = match self.get(dst) {
            Some(o) if o.kind == Kind::Buffer => o.buf.len() as u64,
            Some(_) => return self.set_err(E_KIND),
            None => return self.set_err(E_DEAD),
        };
        let over = |a: u64, n: u64, len: u64| a.checked_add(n)
            .map(|e| e <= len).unwrap_or(false);
        if !over(src_off, size, slen) || !over(dst_off, size, dlen) {
            return self.set_err(E_BOUNDS);
        }
        OK
    }

    pub fn fence_new(&mut self, dev: u64) -> (u64, u32) {
        match self.get(dev) {
            Some(o) if o.kind == Kind::Device => {}
            Some(_) => return (0, self.set_err(E_KIND)),
            None => return (0, self.set_err(E_DEAD)),
        }
        let h = self.alloc(|| Object {
            kind: Kind::Fence, phase: Phase::Dead, err: 0,
            buf: Vec::new(), tex: None, lib: None,
            attach: 0, pipe_valid: false, signaled: false, cb_pipe: 0 });
        (h, 0)
    }

    pub fn fence_signal(&mut self, f: u64) -> u32 {
        match self.get(f) {
            Some(o) if o.kind == Kind::Fence => {}
            Some(_) => return self.set_err(E_KIND),
            None => return self.set_err(E_DEAD),
        }
        self.objects.get_mut(&f).unwrap().signaled = true;
        OK
    }

    pub fn fence_wait(&mut self, f: u64) -> u32 {
        match self.get(f) {
            Some(o) if o.kind == Kind::Fence => {
                if !o.signaled {
                    return self.set_err(E_PHASE); // unsignaled fence
                }
            }
            Some(_) => return self.set_err(E_KIND),
            None => return self.set_err(E_DEAD),
        }
        OK
    }
}

// ---------------------------------------------------------------------------
// metallib container parser
// ---------------------------------------------------------------------------
pub fn parse_metallib(data: &[u8]) -> Option<Vec<String>> {
    if data.len() < 8 || &data[0..4] != b"MTLB" {
        return None;
    }
    let mut pos = 8usize;
    let mut functions: Option<Vec<String>> = None;
    let mut saw_metb = false;
    while pos + 8 <= data.len() {
        let tag = &data[pos..pos + 4];
        let len = u32::from_le_bytes(
            [data[pos + 4], data[pos + 5], data[pos + 6],
             data[pos + 7]]) as usize;
        pos += 8;
        if pos.checked_add(len)? > data.len() {
            return None;
        }
        let body = &data[pos..pos + len];
        match tag {
            b"METD" => {
                functions = Some(parse_functions_json(body)?);
            }
            b"METB" => {
                saw_metb = true;
            }
            _ => {} // unknown chunk: skip (forward compat)
        }
        pos += len;
    }
    match functions {
        Some(f) if saw_metb || !f.is_empty() => Some(f),
        _ => None,
    }
}

/// Minimal scan for {"functions": [...]} without pulling serde into the
/// core's runtime dependencies. Names must be ASCII, no escapes.
fn parse_functions_json(body: &[u8]) -> Option<Vec<String>> {
    let s = std::str::from_utf8(body).ok()?;
    let start = s.find("\"functions\"")?;
    let open = s[start..].find('[')? + start;
    let close = s[open..].find(']')? + open;
    let mut out = Vec::new();
    let inner = &s[open + 1..close];
    for part in inner.split(',') {
        let p = part.trim();
        if p.is_empty() {
            continue;
        }
        let q = p.trim_matches('"');
        if q.is_empty() {
            continue;
        }
        if q.contains('\\') || q.contains('"') {
            return None; // escapes unsupported: refuse instead of guess
        }
        out.push(q.to_string());
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lifecycle_matches_spec_walkthrough() {
        let mut m = MetalState::new();
        let dev = m.device_create();
        assert_ne!(dev, 0);
        let (q, rc) = m.queue_new(dev);
        assert_eq!(rc, OK);
        let (cb, rc) = m.cb_new(q);
        assert_eq!(rc, OK);
        assert_eq!(m.cb_phase(cb), Phase::Active as u32);
        assert_eq!(m.cb_encode(cb), OK);
        assert_eq!(m.cb_commit(cb), OK);
        // P1: encode after commit is rejected
        assert_eq!(m.cb_encode(cb), E_PHASE);
        assert_eq!(m.cb_tick(cb), OK);
        assert_eq!(m.cb_phase(cb), Phase::Scheduled as u32);
        assert_eq!(m.cb_tick(cb), OK);
        assert_eq!(m.cb_phase(cb), Phase::Completed as u32);
        // ticks past completion are rejected (P2)
        assert_eq!(m.cb_tick(cb), E_PHASE);
        let (rc, _) = m.cb_wait(cb);
        assert_eq!(rc, OK);
        // P4: released handle is dead
        assert_eq!(m.release(cb), OK);
        assert!(!m.is_live(cb));
        assert_eq!(m.release(cb), E_DEAD);
        assert_eq!(m.cb_encode(cb), E_DEAD);
    }

    #[test]
    fn buffer_bounds() {
        let mut m = MetalState::new();
        let dev = m.device_create();
        let (b, rc) = m.buf_new(dev, 16, Some(&[1, 2, 3, 4]));
        assert_eq!(rc, OK);
        assert_eq!(m.buf_len(b), 16);
        assert_eq!(m.buf_check_region(b, 8, 8), OK);
        assert_eq!(m.buf_check_region(b, 8, 9), E_BOUNDS);
        assert_eq!(m.buf_check_region(b, u64::MAX, 2), E_BOUNDS);
        let mut out = [0u8; 4];
        assert_eq!(m.buf_read(b, 0, &mut out), OK);
        assert_eq!(out, [1, 2, 3, 4]);
        assert_eq!(m.buf_write(b, 12, &[9; 5]), E_BOUNDS);
        assert_eq!(m.buf_write(b, 12, &[9; 4]), OK);
    }

    #[test]
    fn texture_mip_bounds() {
        let mut m = MetalState::new();
        let dev = m.device_create();
        // spec has NO level cap: levels=128
        let (t, rc) = m.tex_new(dev, 128, 64, 128, 1);
        assert_eq!(rc, OK);
        // full level-0 write is fine
        assert_eq!(m.tex_check_region(t, 0, 0, 128, 64, 0), OK);
        // one past the edge is not
        assert_eq!(m.tex_check_region(t, 0, 0, 129, 64, 0), E_BOUNDS);
        // level 1 is 64x32
        assert_eq!(m.tex_check_region(t, 0, 0, 64, 32, 1), OK);
        assert_eq!(m.tex_check_region(t, 0, 0, 65, 32, 1), E_BOUNDS);
        // level 128 does not exist (levels=128: 0..127)
        assert_eq!(m.tex_check_region(t, 0, 0, 1, 1, 128), E_BOUNDS);
        // "negative" x arrives as u32::MAX via the FFI — must be rejected
        assert_eq!(m.tex_check_region(t, u32::MAX, 0, 1, 1, 0), E_BOUNDS);
        // deep level min-1 rule: 128>>7 == 1 (level 7 is 1x1)
        assert_eq!(m.tex_check_region(t, 0, 0, 1, 1, 7), OK);
    }

    #[test]
    fn buffer_logical_len_beyond_shadow() {
        let mut m = MetalState::new();
        let dev = m.device_create();
        // spec accepts any length >= 0 (Z3 has no cap)
        let (b, rc) = m.buf_new(dev, 1u64 << 40, None);
        assert_eq!(rc, OK);
        assert_eq!(m.buf_len(b), 1u64 << 40);
        assert_eq!(m.buf_check_region(b, (1 << 40) - 4, 4), OK);
        assert_eq!(m.buf_check_region(b, 1 << 40, 1), E_BOUNDS);
        // in-shadow write/read still works
        assert_eq!(m.buf_write(b, 0, &[1, 2, 3, 4]), OK);
        let mut out = [0u8; 4];
        assert_eq!(m.buf_read(b, 0, &mut out), OK);
        assert_eq!(out, [1, 2, 3, 4]);
    }

    #[test]
    fn metallib_parse() {
        let metd = b"{\"functions\":[\"vs_main\",\"ps_main\"]}";
        let mut data = Vec::new();
        data.extend_from_slice(b"MTLB");
        data.extend_from_slice(&2u32.to_le_bytes());
        data.extend_from_slice(b"METD");
        data.extend_from_slice(&(metd.len() as u32).to_le_bytes());
        data.extend_from_slice(metd);
        data.extend_from_slice(b"METB");
        data.extend_from_slice(&1u32.to_le_bytes());
        data.push(0x42);
        let mut m = MetalState::new();
        let dev = m.device_create();
        let (lib, rc) = m.lib_new(dev, &data);
        assert_eq!(rc, OK);
        assert_eq!(m.lib_function_count(lib), 2);
        assert!(m.lib_has_function(lib, "vs_main"));
        assert!(!m.lib_has_function(lib, "nope"));
        assert_eq!(m.lib_function_name(lib, 1), Some("ps_main"));
        // garbage is refused
        let (bad, rc) = m.lib_new(dev, b"not a metallib");
        assert_eq!((bad, rc), (0, E_PARSE));
        assert_eq!(m.last_error(), E_PARSE);
    }
}
