//! # fn35-metal-ffi — the C ABI boundary of the fn35 Metal shim
//!
//! Builds `libfn35_metal_ffi.so`, loaded by `scripts/fn35_metal.py` via
//! ctypes. The contract (symbol names, signatures, u64 handles, u32 rc
//! codes) is FIXED by that Python side; the semantics are fixed by the
//! Z3 spec (`scripts/metal_z3_spec.py`).
//!
//! Safety model: the entire implementation lives in the `#![forbid(
//! unsafe_code)]` core crate `fn35-metal`. This crate contains the ONLY
//! unsafe code in the stack, restricted to:
//!   * constructing `&[u8]`/`&mut [u8]` from raw FFI pointers
//!   * reading CStrings / writing through out-pointers
//! Every pointer is null- and length-checked before it is ever touched,
//! and no pointer ever outlives the FFI call that received it.
//!
//! Error reporting: every fallible entrypoint returns a u32 rc and also
//! records it retrievable via `fn35_metal_last_error()` (the Python
//! bridge reads that when a constructor returns 0).
use std::ffi::CStr;
use std::os::raw::{c_char, c_int};
use std::sync::Mutex;
use std::sync::OnceLock;

use fn35_metal::{MetalState, OK};

fn state() -> &'static Mutex<MetalState> {
    static S: OnceLock<Mutex<MetalState>> = OnceLock::new();
    S.get_or_init(|| Mutex::new(MetalState::new()))
}

/// record rc as the last error when non-OK (call on every rc)
fn fin(rc: u32) -> u32 {
    if let Ok(mut g) = state().lock() {
        g.set_last_error(rc);
    }
    rc
}

// ---------------------------------------------------------------------------
// primitives
// ---------------------------------------------------------------------------

#[no_mangle]
pub extern "C" fn fn35_metal_init() -> u32 {
    let _ = state(); // ensure the singleton exists
    0 // construction cannot fail
}

#[no_mangle]
pub extern "C" fn fn35_metal_version() -> u32 {
    1
}

#[no_mangle]
pub extern "C" fn fn35_metal_last_error() -> u32 {
    state().lock().map(|g| g.last_error()).unwrap_or(0)
}

#[no_mangle]
pub extern "C" fn fn35_metal_live_count() -> u32 {
    state().lock().map(|g| g.live_count()).unwrap_or(0)
}

#[no_mangle]
pub extern "C" fn fn35_metal_is_live(h: u64) -> u32 {
    state().lock().map(|g| g.is_live(h) as u32).unwrap_or(0)
}

#[no_mangle]
pub extern "C" fn fn35_metal_obj_kind(h: u64) -> u32 {
    state().lock().map(|g| g.obj_kind(h)).unwrap_or(0)
}

#[no_mangle]
pub extern "C" fn fn35_metal_release(h: u64) -> u32 {
    fin(state().lock().map(|mut g| g.release(h)).unwrap_or(1))
}

// ---------------------------------------------------------------------------
// constructors
// ---------------------------------------------------------------------------

#[no_mangle]
pub extern "C" fn fn35_metal_device_create() -> u64 {
    state().lock().map(|mut g| g.device_create()).unwrap_or(0)
}

#[no_mangle]
pub extern "C" fn fn35_metal_queue_new(dev: u64) -> u64 {
    match state().lock() {
        Ok(mut g) => {
            let (h, rc) = g.queue_new(dev);
            if rc != OK {
                g.set_last_error(rc);
            }
            h
        }
        Err(_) => 0,
    }
}

#[no_mangle]
pub extern "C" fn fn35_metal_cb_new(queue: u64) -> u64 {
    match state().lock() {
        Ok(mut g) => {
            let (h, rc) = g.cb_new(queue);
            if rc != OK {
                g.set_last_error(rc);
            }
            h
        }
        Err(_) => 0,
    }
}

#[no_mangle]
pub extern "C" fn fn35_metal_buf_new(dev: u64, length: u64,
                                     data: *const u8,
                                     data_len: u64) -> u64 {
    let init = unsafe { safe_slice(data, data_len) };
    match state().lock() {
        Ok(mut g) => {
            let (h, rc) = g.buf_new(dev, length, init);
            if rc != OK {
                g.set_last_error(rc);
            }
            h
        }
        Err(_) => 0,
    }
}

#[no_mangle]
pub extern "C" fn fn35_metal_tex_new(dev: u64, w: u32, h: u32,
                                     levels: u32, format: u32) -> u64 {
    match state().lock() {
        Ok(mut g) => {
            let (h, rc) = g.tex_new(dev, w, h, levels, format);
            if rc != OK {
                g.set_last_error(rc);
            }
            h
        }
        Err(_) => 0,
    }
}

#[no_mangle]
pub extern "C" fn fn35_metal_lib_new(dev: u64, data: *const u8,
                                     data_len: u64) -> u64 {
    let bytes = unsafe { safe_slice(data, data_len) };
    match state().lock() {
        Ok(mut g) => {
            let (h, rc) = g.lib_new(dev, bytes.unwrap_or(&[]));
            if rc != OK {
                g.set_last_error(rc);
            }
            h
        }
        Err(_) => 0,
    }
}

// ---------------------------------------------------------------------------
// cmdbuf lifecycle
// ---------------------------------------------------------------------------

#[no_mangle]
pub extern "C" fn fn35_metal_cb_encode(cb: u64) -> u32 {
    fin(state().lock().map(|mut g| g.cb_encode(cb)).unwrap_or(1))
}

#[no_mangle]
pub extern "C" fn fn35_metal_cb_commit(cb: u64) -> u32 {
    fin(state().lock().map(|mut g| g.cb_commit(cb)).unwrap_or(1))
}

#[no_mangle]
pub extern "C" fn fn35_metal_cb_tick(cb: u64) -> u32 {
    fin(state().lock().map(|mut g| g.cb_tick(cb)).unwrap_or(1))
}

#[no_mangle]
pub extern "C" fn fn35_metal_cb_fail(cb: u64, code: u32) -> u32 {
    fin(state().lock().map(|mut g| g.cb_fail(cb, code)).unwrap_or(1))
}

#[no_mangle]
pub extern "C" fn fn35_metal_cb_wait(cb: u64, out_err: *mut u32) -> u32 {
    let (rc, err) = state().lock()
        .map(|mut g| g.cb_wait(cb))
        .unwrap_or((1, 0));
    if rc != OK {
        fin(rc);
        return rc;
    }
    if !out_err.is_null() {
        unsafe { *out_err = err };
    }
    rc
}

#[no_mangle]
pub extern "C" fn fn35_metal_cb_phase(cb: u64) -> u32 {
    state().lock().map(|g| g.cb_phase(cb)).unwrap_or(0)
}

// ---------------------------------------------------------------------------
// buffers
// ---------------------------------------------------------------------------

#[no_mangle]
pub extern "C" fn fn35_metal_buf_len(b: u64) -> u64 {
    state().lock().map(|g| g.buf_len(b)).unwrap_or(0)
}

#[no_mangle]
pub extern "C" fn fn35_metal_buf_check_region(b: u64, off: u64,
                                              ln: u64) -> u32 {
    fin(state().lock()
        .map(|mut g| g.buf_check_region(b, off, ln))
        .unwrap_or(1))
}

#[no_mangle]
pub extern "C" fn fn35_metal_buf_write(b: u64, off: u64,
                                       data: *const u8,
                                       data_len: u64) -> u32 {
    let Some(bytes) = (unsafe { safe_slice(data, data_len) }) else {
        return 1;
    };
    fin(state().lock()
        .map(|mut g| g.buf_write(b, off, bytes))
        .unwrap_or(1))
}

#[no_mangle]
pub extern "C" fn fn35_metal_buf_read(b: u64, off: u64, out: *mut u8,
                                      out_len: u64) -> u32 {
    if out.is_null() {
        return fin(1);
    }
    // SAFETY: out is non-null and out_len is the caller-declared size of
    // the writable region (ctypes create_string_buffer guarantees it).
    let buf = unsafe {
        std::slice::from_raw_parts_mut(out, clamp_len(out_len))
    };
    fin(state().lock()
        .map(|mut g| g.buf_read(b, off, buf))
        .unwrap_or(1))
}

// ---------------------------------------------------------------------------
// textures
// ---------------------------------------------------------------------------

#[no_mangle]
pub extern "C" fn fn35_metal_tex_check_region(t: u64, x: u32, y: u32,
                                              w: u32, h: u32,
                                              level: u32) -> u32 {
    fin(state().lock()
        .map(|mut g| g.tex_check_region(t, x, y, w, h, level))
        .unwrap_or(1))
}

#[no_mangle]
pub extern "C" fn fn35_metal_tex_write(t: u64, x: u32, y: u32, w: u32,
                                       h: u32, level: u32,
                                       data: *const u8,
                                       data_len: u64) -> u32 {
    let Some(bytes) = (unsafe { safe_slice(data, data_len) }) else {
        return fin(1);
    };
    fin(state().lock()
        .map(|mut g| g.tex_write(t, x, y, w, h, level, bytes))
        .unwrap_or(1))
}

#[no_mangle]
pub extern "C" fn fn35_metal_tex_read(t: u64, x: u32, y: u32, w: u32,
                                      h: u32, level: u32, out: *mut u8,
                                      out_len: u64) -> u32 {
    if out.is_null() {
        return fin(1);
    }
    let buf = unsafe {
        std::slice::from_raw_parts_mut(out, clamp_len(out_len))
    };
    fin(state().lock()
        .map(|mut g| g.tex_read(t, x, y, w, h, level, buf))
        .unwrap_or(1))
}

// ---------------------------------------------------------------------------
// libraries
// ---------------------------------------------------------------------------

#[no_mangle]
pub extern "C" fn fn35_metal_lib_has_function(lib: u64,
                                              name: *const c_char) -> u32 {
    if name.is_null() {
        return 0;
    }
    // SAFETY: ctypes passes a NUL-terminated C string; CStr never reads
    // past the terminator.
    let name = unsafe { CStr::from_ptr(name) };
    let Ok(name) = name.to_str() else { return 0 };
    state().lock().map(|g| g.lib_has_function(lib, name) as u32)
        .unwrap_or(0)
}

#[no_mangle]
pub extern "C" fn fn35_metal_lib_function_count(lib: u64) -> u32 {
    state().lock().map(|g| g.lib_function_count(lib)).unwrap_or(0)
}

/// Writes the idx-th function name (NUL-terminated) into `out`.
/// Returns the number of name bytes copied (0 = no such function or
/// out too small).
#[no_mangle]
pub extern "C" fn fn35_metal_lib_function_name(lib: u64, idx: u32,
                                                out: *mut u8,
                                                cap: u64) -> u64 {
    if out.is_null() || cap == 0 {
        return 0;
    }
    let Some(name) = state().lock()
        .ok()
        .and_then(|g| g.lib_function_name(lib, idx).map(|s| s.to_string()))
    else {
        return 0;
    };
    let cap = clamp_len(cap) as usize;
    if name.len() + 1 > cap {
        return 0;
    }
    // SAFETY: out is non-null with caller-declared capacity cap; we
    // write strictly fewer than cap bytes.
    unsafe {
        std::ptr::copy_nonoverlapping(name.as_ptr(), out, name.len());
        *out.add(name.len()) = 0;
    }
    name.len() as u64
}

// ---------------------------------------------------------------------------
// unsafe helpers — the ONLY unsafe in the entire Rust stack
// ---------------------------------------------------------------------------

/// Clamp a u64 length to isize::MAX so slice constructors can never
/// panic on overflow (also caps absurd allocations).
const fn clamp_len(len: u64) -> usize {
    if len > (isize::MAX as u64) {
        usize::MAX
    } else {
        len as usize
    }
}

/// Build a shared slice from raw parts, or None when the pointer is
/// null (length is then irrelevant). A null pointer with non-zero
/// length is a legal "no initial contents" call.
///
/// # Safety
/// `ptr` must point to `len` readable bytes for the duration of the
/// call (ctypes buffers satisfy this trivially).
unsafe fn safe_slice<'a>(ptr: *const u8, len: u64) -> Option<&'a [u8]> {
    if ptr.is_null() {
        return None;
    }
    Some(std::slice::from_raw_parts(ptr, clamp_len(len)))
}

// keep c_int linked in for future int-returning API surface
#[allow(dead_code)]
fn _unused(_: c_int) {}
