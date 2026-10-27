//! # fn35-cstr
//!
//! C string / memory / conversion semantics ported 1:1 from the Python
//! loader's `fn35_clib.py`, differential-verified against it (see
//! `tests/differential.rs` + `scripts/fn35_cstr_oracle.py`).
//!
//! Design notes:
//! * Inputs are guest-memory VIEWS: `&[u8]` from the pointer to the end
//!   of the mapped region (the Python side reads via `rdb`, same shape).
//! * Pointer-returning C functions return `Option<usize>` (byte offset
//!   from the argument base); `None` is C NULL.
//! * The `gcstr` port preserves the ORIGINAL chunked-256 read algorithm
//!   — including the quirk that `strnlen` can exceed `maxlen` when the
//!   NUL sits within the same 256-byte chunk (the Python reads a full
//!   256-byte chunk per iteration; `maxlen` only bounds the loop).
//! * `strtod` preserves the `used = len(str(val))` quirk (the reported
//!   consumed count is the length of the VALUE's Python-repr, not the
//!   token), which requires a faithful `python_float_str`.

#![forbid(unsafe_code)]

pub const GCSTR_DEFAULT_MAXLEN: usize = 1 << 20;

/// Port of `FNLoader.gcstr`: read in 256-byte chunks until NUL or the
/// loop bound; decode UTF-8 with replacement.
pub fn gcstr(buf: &[u8], maxlen: usize) -> String {
    let mut out: Vec<u8> = Vec::new();
    let mut pos = 0usize;
    while out.len() < maxlen {
        let chunk = &buf[pos..buf.len().min(pos + 256)];
        if chunk.is_empty() {
            break;
        }
        match chunk.iter().position(|&b| b == 0) {
            Some(z) => {
                out.extend_from_slice(&chunk[..z]);
                break;
            }
            None => {
                out.extend_from_slice(chunk);
                pos += chunk.len();
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn s_view(buf: &[u8]) -> String {
    gcstr(buf, GCSTR_DEFAULT_MAXLEN)
}

// ================= memory =================

pub fn memcpy(dst: &mut [u8], src: &[u8], n: usize) {
    let n = n.min(dst.len()).min(src.len());
    dst[..n].copy_from_slice(&src[..n]);
}

pub fn memset(dst: &mut [u8], c: u8, n: usize) {
    let n = n.min(dst.len());
    for b in dst[..n].iter_mut() {
        *b = c;
    }
}

pub fn bzero(dst: &mut [u8], n: usize) {
    memset(dst, 0, n);
}

/// Lexicographic -1 / 0 / 1 (Python `bytes < bytes` semantics).
pub fn memcmp(a: &[u8], b: &[u8], n: usize) -> i32 {
    if n == 0 {
        return 0;
    }
    let n = n.min(a.len()).min(b.len());
    let (x, y) = (&a[..n], &b[..n]);
    if x < y {
        -1
    } else if x > y {
        1
    } else {
        0
    }
}

// ================= strings =================

pub fn strlen(s: &[u8]) -> usize {
    s_view(s).len()
}

pub fn strnlen(s: &[u8], n: usize) -> usize {
    gcstr(s, n.max(1)).len()
}

fn cmp3(x: &str, y: &str) -> i32 {
    if x < y {
        -1
    } else if x > y {
        1
    } else {
        0
    }
}

pub fn strcmp(a: &[u8], b: &[u8]) -> i32 {
    cmp3(&s_view(a), &s_view(b))
}

pub fn strncmp(a: &[u8], b: &[u8], n: usize) -> i32 {
    let sa = gcstr(a, n.max(1)).as_bytes()[..n.min(gcstr(a, n.max(1)).len())].to_vec();
    let sb = gcstr(b, n.max(1)).as_bytes()[..n.min(gcstr(b, n.max(1)).len())].to_vec();
    // compare the TRUNCATED byte strings like Python does after encode()
    cmp3_bytes(&sa, &sb)
}

fn cmp3_bytes(x: &[u8], y: &[u8]) -> i32 {
    if x < y {
        -1
    } else if x > y {
        1
    } else {
        0
    }
}

pub fn strcasecmp(a: &[u8], b: &[u8]) -> i32 {
    cmp3(&s_view(a).to_lowercase(), &s_view(b).to_lowercase())
}

pub fn strncasecmp(a: &[u8], b: &[u8], n: Option<usize>) -> i32 {
    let mut sa = s_view(a).to_lowercase();
    let mut sb = s_view(b).to_lowercase();
    if let Some(n) = n {
        sa = sa.chars().take(n).collect();
        sb = sb.chars().take(n).collect();
    }
    cmp3(&sa, &sb)
}

/// Writes (src + NUL) at dst; returns the written bytes.
pub fn strcpy(src: &str) -> Vec<u8> {
    let mut v = src.as_bytes().to_vec();
    v.push(0);
    v
}

/// Python: `(s[:n] + b"\\x00" * n)[:n]` — exact truncation+zero-fill.
pub fn strncpy(src: &str, n: usize) -> Vec<u8> {
    let s = src.as_bytes();
    let mut v = s[..n.min(s.len())].to_vec();
    let zeros = vec![0u8; n];
    v.extend_from_slice(&zeros);
    v.truncate(n);
    v
}

/// Python: writes `s[:size-1] + b"\\x00"`; returns (written, ret=len(s)).
pub fn strlcpy(src: &str, size: usize) -> (Vec<u8>, usize) {
    let s = src.as_bytes();
    let mut out = Vec::new();
    if size != 0 {
        out.extend_from_slice(&s[..(size - 1).min(s.len())]);
        out.push(0);
    }
    (out, s.len())
}

/// Python quirk: writes `s[:room]` (NO terminating NUL!) at
/// `dst + len(dst)`; returns (offset, bytes, ret = len(dst)+len(src)).
pub fn strlcat(dst_cur: &str, src: &str, size: usize) -> (usize, Vec<u8>, usize) {
    let cur = dst_cur.as_bytes();
    let s = src.as_bytes();
    let mut out = Vec::new();
    if size != 0 && cur.len() < size - 1 {
        let room = size - 1 - cur.len();
        out.extend_from_slice(&s[..room.min(s.len())]);
    }
    (cur.len(), out, cur.len() + s.len())
}

/// Writes (cur + src + NUL); returns the written bytes.
pub fn strcat(dst_cur: &str, src: &str) -> Vec<u8> {
    let mut v = dst_cur.as_bytes().to_vec();
    v.extend_from_slice(src.as_bytes());
    v.push(0);
    v
}

pub fn strstr(hay: &str, needle: &str) -> Option<usize> {
    if needle.is_empty() {
        return Some(0);
    }
    // Python str.find operates on decoded chars; the returned pointer
    // offset is a CHAR index into the decoded string.
    hay.find(needle)
}

pub fn strchr(s: &str, c: i64) -> Option<usize> {
    let st = s;
    if c == 0 {
        return Some(st.chars().count());
    }
    let ch = char::from_u32((c & 0xFF) as u32).unwrap_or('\0');
    match st.find(ch) {
        // Python's find returns a CHAR index; pointer = base + char index
        Some(i) => Some(st[..i].chars().count()),
        None => None,
    }
}

pub fn strrchr(s: &str, c: i64) -> Option<usize> {
    let ch = char::from_u32((c & 0xFF) as u32).unwrap_or('\0');
    match s.rfind(ch) {
        Some(i) => Some(s[..i].chars().count()),
        None => {
            if c == 0 {
                Some(s.chars().count())
            } else {
                None
            }
        }
    }
}

pub fn strchrnul(s: &str, c: i64) -> usize {
    let ch = char::from_u32((c & 0xFF) as u32).unwrap_or('\0');
    match s.find(ch) {
        Some(i) => s[..i].chars().count(),
        None => s.chars().count(),
    }
}

pub fn digit_val(c: char) -> u32 {
    if c.is_ascii_digit() {
        return c as u32 - 48;
    }
    if c.is_ascii_lowercase() {
        return c as u32 - 87;
    }
    if c.is_ascii_uppercase() {
        return c as u32 - 55;
    }
    99
}

/// Returns (value_masked_u64, consumed_chars, no_digits_flag).
/// Mirrors `_strtol` including the 0x-prefix no-digits quirks.
pub fn strtol(s: &str, base: u32) -> (u64, usize, bool) {
    let st: Vec<char> = s.chars().collect();
    let n = st.len();
    let mut i = 0usize;
    while i < n && " \t\n\r\u{c}\u{b}".contains(st[i]) {
        i += 1;
    }
    let mut sign: i128 = 1;
    if i < n && (st[i] == '+' || st[i] == '-') {
        if st[i] == '-' {
            sign = -1;
        }
        i += 1;
    }
    let mut b = base & 0xFF;
    if b == 0 {
        b = 10;
        if i + 1 < n
            && st[i] == '0'
            && (st[i + 1] == 'x' || st[i + 1] == 'X')
            && i + 2 < n
            && digit_val(st[i + 2]) < 16
        {
            b = 16;
        } else if i < n && st[i] == '0' {
            b = 8;
        }
    }
    if b == 16 && i + 1 < n && st[i] == '0' && (st[i + 1] == 'x' || st[i + 1] == 'X') {
        i += 2;
    }
    let start = i;
    let mut val: u128 = 0;
    while i < n {
        let d = digit_val(st[i]);
        if d >= b {
            break;
        }
        val = val * b as u128 + d as u128;
        i += 1;
    }
    if i == start
        && !(start > 0 && st[start - 1..start].first() == Some(&'0') && b == 16)
    {
        // no digits consumed
        return (0, 0, true);
    }
    let v = ((sign * val as i128) as i64) as u64;
    (v, i, false)
}

// ================= Python float repr (CPython str(float)) =================

/// Faithful port of CPython's `str(float)` (shortest-roundtrip digits,
/// decimal form iff 1e-4 <= |x| < 1e16, else scientific with 2-digit
/// minimum exponent and no trailing `.0`).
pub fn python_float_str(v: f64) -> String {
    if v.is_nan() {
        return "nan".to_string();
    }
    if v.is_infinite() {
        return if v < 0.0 { "-inf".into() } else { "inf".into() };
    }
    let neg = v.is_sign_negative();
    let a = v.abs();
    // shortest roundtrip digits via Rust's LowerExp
    let e = format!("{:e}", a); // e.g. "3.14e0", "1e16"
    let (mant, exp) = e.split_once('e').unwrap();
    let exp: i32 = exp.parse().unwrap();
    let (int_part, frac_part) = match mant.split_once('.') {
        Some((i_, f_)) => (i_.to_string(), f_.to_string()),
        None => (mant.to_string(), String::new()),
    };
    let mut digits = format!("{}{}", int_part, frac_part);
    let ndig_intfrac = int_part.len();
    // strip trailing zeros of the fraction (shortest form)
    while digits.len() > 1 && digits.ends_with('0') && frac_part.ends_with('0') {
        digits.pop();
    }
    let sign_str = if neg { "-" } else { "" };
    if (-4..16).contains(&exp) {
        // decimal form
        if exp >= 0 {
            let e = exp as usize;
            let mut ip = String::new();
            if digits.len() > e {
                ip = digits[..e].to_string();
                let fp = &digits[e..];
                if fp.is_empty() {
                    format!("{}{}.0", sign_str, ip)
                } else {
                    format!("{}{}.{}", sign_str, ip, fp)
                }
            } else {
                ip = digits.clone() + &"0".repeat(e - digits.len());
                format!("{}{}.0", sign_str, ip)
            }
        } else {
            let zp = (-exp - 1) as usize;
            format!("{}0.{}{}", sign_str, "0".repeat(zp), digits)
        }
    } else {
        // scientific: d[.ddd]e±XX (>= 2 exponent digits)
        let m = if digits.len() == 1 {
            digits.clone()
        } else {
            format!("{}.{}", &digits[..1], &digits[1..])
        };
        let sign = if exp < 0 { '-' } else { '+' };
        let ea = exp.abs();
        if ea < 10 {
            format!("{}{}e{}0{}", sign_str, m, sign, ea)
        } else {
            format!("{}{}e{}{}", sign_str, m, sign, ea)
        }
    }
    // silence unused warning path
    let _ = ndig_intfrac;
}

/// Python `float()` subset parser (the token after split()).
pub fn python_float_parse(s: &str) -> Option<f64> {
    let t = s.trim();
    if t.is_empty() {
        return None;
    }
    let lower = t.to_ascii_lowercase();
    if lower == "inf" || lower == "infinity" {
        return Some(f64::INFINITY);
    }
    if lower == "-inf" || lower == "-infinity" {
        return Some(f64::NEG_INFINITY);
    }
    if lower == "nan" || lower == "-nan" {
        return Some(f64::NAN);
    }
    let body = lower.strip_prefix('-').unwrap_or(&lower);
    let body = if body.starts_with('+') { &body[1..] } else { body };
    if body.is_empty() {
        return None;
    }
    if !valid_number(body) {
        return None;
    }
    // reject underscores at the edges / doubles (Python PEP 515)
    if body.starts_with('_') || body.ends_with('_')
        || body.contains("__")
        || body.starts_with("._")
        || body.contains("_.")
        || body.starts_with(".e")
    {
        return None;
    }
    // Rust's parse rejects underscores entirely; strip them (we already
    // validated their placement)
    let cleaned: String = body.chars().filter(|c| *c != '_').collect();
    if let Ok(v) = cleaned.parse::<f64>() {
        if v.is_finite() {
            return Some(if lower.starts_with('-') { -v } else { v });
        }
        return Some(if lower.starts_with('-') {
            f64::NEG_INFINITY
        } else {
            f64::INFINITY
        });
    }
    None
}

fn valid_number(s: &str) -> bool {
    // [digits][.digits][e[+-]digits] — at least one digit somewhere,
    // underscores allowed between digits only
    let bytes: Vec<char> = s.chars().collect();
    let mut i = 0;
    let mut saw_digit = false;
    let n = bytes.len();
    while i < n && (bytes[i].is_ascii_digit() || bytes[i] == '_') {
        if bytes[i] != '_' {
            saw_digit = true;
        }
        i += 1;
    }
    if i < n && bytes[i] == '.' {
        i += 1;
        while i < n && (bytes[i].is_ascii_digit() || bytes[i] == '_') {
            if bytes[i] != '_' {
                saw_digit = true;
            }
            i += 1;
        }
    }
    if saw_digit && i < n && (bytes[i] == 'e' || bytes[i] == 'E') {
        i += 1;
        if i < n && (bytes[i] == '+' || bytes[i] == '-') {
            i += 1;
        }
        let mut saw_e = false;
        while i < n && (bytes[i].is_ascii_digit() || bytes[i] == '_') {
            if bytes[i] != '_' {
                saw_e = true;
            }
            i += 1;
        }
        if !saw_e {
            return false;
        }
    }
    saw_digit && i == n
}

/// Python `str.split()[0]` token semantics for strtod.
fn first_token(s: &str) -> Option<&str> {
    s.split_whitespace().next()
}

/// strtod port: (value, used = len(str(val))). The empty-token quirk
/// yields used = 3 for ""/"  " (len("0.0")); errors yield used = 0.
pub fn strtod(s: &str) -> (f64, usize) {
    match first_token(s) {
        None => (0.0, python_float_str(0.0).len()),
        Some(tok) => match python_float_parse(tok) {
            Some(v) => (v, python_float_str(v).len()),
            None => (0.0, 0),
        },
    }
}

/// Python `int(strip or "0")` port (base 10, PEP 515 underscores).
pub fn python_int_parse(s: &str) -> Option<i128> {
    let t = s.trim();
    let t = if t.is_empty() { "0" } else { t };
    let (neg, body) = match t.strip_prefix('-') {
        Some(b) => (true, b),
        None => (false, t.strip_prefix('+').unwrap_or(t)),
    };
    if body.is_empty()
        || body.starts_with('_')
        || body.ends_with('_')
        || body.contains("__")
    {
        return None;
    }
    let mut v: i128 = 0;
    for c in body.chars() {
        if c == '_' {
            continue;
        }
        let d = c.to_digit(10)?;
        v = v.checked_mul(10)?.checked_add(d as i128)?;
    }
    Some(if neg { -v } else { v })
}

pub fn atoi(s: &str) -> Option<i64> {
    python_int_parse(s).map(|v| v as i64)
}

pub fn atof(s: &str) -> f64 {
    let t = s.trim();
    let t = if t.is_empty() { "0" } else { t };
    python_float_parse(t).unwrap_or(0.0)
}
