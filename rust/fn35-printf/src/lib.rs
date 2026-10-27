//! fn35-printf: the printf-family format engine of the fn35 loader.
//!
//! A faithful port of `fmt_engine` in scripts/fn35_clib.py: flags
//! (`-+ #0`), width and precision (including `*`), skipped length
//! modifiers (`hlqjztL`), and the conversions the Fortnite binary
//! actually exercises: `di uU oxX p c s fFeEgG @ %%` (plus the
//! loader-specific `%@` objc-pointer form).
//!
//! The varargs source is abstracted behind [`VarArgs`] so the engine is
//! pure and differentially testable: the tests replay the same
//! (format, value-list) pairs as the Python oracle.
#![forbid(unsafe_code)]

/// Varargs source: x-named integer regs, d-named float regs, stack.
/// Values arrive already decoded (u64 raw ints, f64 doubles, strings).
pub trait VarArgs {
    fn next_int(&mut self) -> u64;
    fn next_dbl(&mut self) -> f64;
    /// pointer-ish argument rendered by %s / %@ (None = null pointer)
    fn next_ptr(&mut self) -> u64;
    /// string for the pointer most recently returned by next_ptr
    fn cstr_at(&mut self, p: u64) -> Option<String>;
}

/// A simple in-order source for tests and oracles.
pub struct SeqArgs {
    pub ints: Vec<u64>,
    pub dbls: Vec<f64>,
    pub strs: Vec<String>,
    ii: usize,
    di: usize,
    si: usize,
    last_ptr: u64,
}

impl SeqArgs {
    pub fn new(ints: Vec<u64>, dbls: Vec<f64>, strs: Vec<String>) -> Self {
        SeqArgs { ints, dbls, strs, ii: 0, di: 0, si: 0, last_ptr: 0 }
    }
}

impl VarArgs for SeqArgs {
    fn next_int(&mut self) -> u64 {
        let v = self.ints.get(self.ii).copied().unwrap_or(0);
        self.ii += 1;
        v
    }
    fn next_dbl(&mut self) -> f64 {
        let v = self.dbls.get(self.di).copied().unwrap_or(0.0);
        self.di += 1;
        v
    }
    fn next_ptr(&mut self) -> u64 {
        // interleave with the int stream like the real ABI does (pointer
        // args occupy integer registers)
        let v = self.next_int();
        self.last_ptr = v;
        v
    }
    fn cstr_at(&mut self, _p: u64) -> Option<String> {
        let s = self.strs.get(self.si).cloned();
        self.si += 1;
        s
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum FmtError {
    /// format string not valid utf-8 (upstream passes bytes; the guest
    /// uses utf-8 in practice; callers replace bad bytes first)
    BadUtf8,
}

fn to_i64(v: u64) -> i64 {
    v as i64
}

/// format one string. Mirrors python `fmt_engine(fmt, src)` exactly,
/// including the `%@` objc form and the `(null)` %s behaviour.
pub fn fmt_engine(
    fmt: &str,
    src: &mut dyn VarArgs,
) -> Result<String, FmtError> {
    let b: Vec<char> = fmt.chars().collect();
    let n = b.len();
    let mut out = String::new();
    let mut i = 0usize;

    while i < n {
        let c = b[i];
        if c != '%' {
            out.push(c);
            i += 1;
            continue;
        }
        i += 1;
        if i >= n {
            break;
        }
        if b[i] == '%' {
            out.push('%');
            i += 1;
            continue;
        }
        // flags
        let mut left = false;
        let mut plus = false;
        let mut space = false;
        let mut zero = false;
        let mut alt = false;
        while i < n && "-+ #0".contains(b[i]) {
            match b[i] {
                '-' => left = true,
                '+' => plus = true,
                ' ' => space = true,
                '0' => zero = true,
                '#' => alt = true,
                _ => {}
            }
            i += 1;
        }
        // width
        let mut width: Option<usize> = None;
        if i < n && b[i] == '*' {
            let w = to_i64(src.next_int());
            // negative *-width means left-align with abs value (C99)
            if w < 0 {
                left = true;
                width = Some((-(w as i128)) as usize);
            } else {
                width = Some(w as usize);
            }
            i += 1;
        } else {
            let mut w: usize = 0;
            let mut got = false;
            while i < n && b[i].is_ascii_digit() {
                w = w.saturating_mul(10)
                    .saturating_add(b[i] as usize - '0' as usize);
                i += 1;
                got = true;
            }
            if got {
                width = Some(w);
            }
        }
        // precision
        let mut prec: Option<usize> = None;
        if i < n && b[i] == '.' {
            i += 1;
            if i < n && b[i] == '*' {
                let p = to_i64(src.next_int());
                // negative *-precision is "omitted" (C99)
                if p >= 0 {
                    prec = Some(p as usize);
                }
                i += 1;
            } else {
                let mut p: usize = 0;
                while i < n && b[i].is_ascii_digit() {
                    p = p.saturating_mul(10)
                        .saturating_add(b[i] as usize - '0' as usize);
                    i += 1;
                }
                prec = Some(p);
            }
        }
        // length modifiers (ignored; arm64 is fixed-width)
        while i < n && "hlqjztL".contains(b[i]) {
            i += 1;
        }
        if i >= n {
            break;
        }
        let conv = b[i];
        i += 1;

        let pad = |s: &str, w: Option<usize>| -> String {
            let w = match w {
                Some(w) if s.chars().count() < w => w,
                _ => return s.to_string(),
            };
            let fillc = if zero && !left { '0' } else { ' ' };
            let fill: usize = w - s.chars().count();
            if left {
                let mut r = s.to_string();
                r.extend(std::iter::repeat(' ').take(fill));
                r
            } else {
                let mut r: String =
                    std::iter::repeat(fillc).take(fill).collect();
                r.push_str(s);
                r
            }
        };

        match conv {
            'd' | 'i' => {
                let v = to_i64(src.next_int());
                let mut s = v.unsigned_abs().to_string();
                if let Some(p) = prec {
                    s = pad0(&s, p);
                }
                let sign = if v < 0 {
                    "-"
                } else if plus {
                    "+"
                } else if space {
                    " "
                } else {
                    ""
                };
                out.push_str(&pad(&format!("{}{}", sign, s), width));
            }
            'u' | 'U' => {
                let v = src.next_int();
                let mut s = v.to_string();
                if let Some(p) = prec {
                    s = pad0(&s, p);
                }
                out.push_str(&pad(&s, width));
            }
            'o' | 'x' | 'X' => {
                let v = src.next_int();
                let mut s = match conv {
                    'o' => {
                        let t = format!("{:o}", v);
                        if alt && !t.starts_with('0') {
                            format!("0{}", t)
                        } else {
                            t
                        }
                    }
                    'x' => {
                        if alt && v != 0 {
                            format!("0x{:x}", v)
                        } else {
                            format!("{:x}", v)
                        }
                    }
                    _ => {
                        if alt && v != 0 {
                            format!("0X{:X}", v)
                        } else {
                            format!("{:X}", v)
                        }
                    }
                };
                if let Some(p) = prec {
                    s = pad0(&s, p);
                }
                out.push_str(&pad(&s, width));
            }
            'p' => {
                let v = src.next_int();
                out.push_str(&pad(&format!("0x{:x}", v), width));
            }
            'c' => {
                let v = (src.next_int() & 0xFF) as u8 as char;
                out.push(v);
            }
            's' => {
                let p = src.next_ptr();
                let mut s = match src.cstr_at(p) {
                    Some(t) if p != 0 => t,
                    _ => "(null)".to_string(),
                };
                if let Some(pr) = prec {
                    s = s.chars().take(pr).collect();
                }
                out.push_str(&pad(&s, width));
            }
            'f' | 'F' | 'e' | 'E' | 'g' | 'G' => {
                let d = src.next_dbl();
                let pr = prec.unwrap_or(6);
                let s = match conv {
                    'f' | 'F' => format!("{:.*}", pr, d),
                    'e' => fmt_e(d, pr, false),
                    'E' => fmt_e(d, pr, true),
                    'g' => fmt_g(d, pr, false),
                    'G' => fmt_g(d, pr, true),
                    _ => unreachable!(),
                };
                let s = if conv.is_ascii_uppercase() {
                    s.to_uppercase()
                } else {
                    s
                };
                let s = if plus && !s.starts_with('-') {
                    format!("+{}", s)
                } else {
                    s
                };
                out.push_str(&pad(&s, width));
            }
            '@' => {
                let p = src.next_ptr();
                out.push_str(&format!("<objc {:x}>", p));
            }
            other => {
                out.push('%');
                out.push(other);
            }
        }
    }
    Ok(out)
}

fn pad0(s: &str, p: usize) -> String {
    if s.chars().count() >= p {
        return s.to_string();
    }
    let fill = p - s.chars().count();
    let mut r: String = std::iter::repeat('0').take(fill).collect();
    r.push_str(s);
    r
}

/// %e with C-locale semantics: d.dddddde±dd (exponent >= 2 digits)
fn fmt_e(d: f64, prec: usize, upper: bool) -> String {
    if !d.is_finite() {
        return finite_str(d, upper);
    }
    let s = format!("{:.*e}", prec, d);
    // Rust prints 1e2 as "1e2"; C prints "1e+02". Fix exponent form.
    fix_exp(&s)
}

/// %g: significant digits, strip trailing zeros (C semantics; the
/// strip applies to BOTH the fixed and the exponent form)
fn fmt_g(d: f64, prec: usize, upper: bool) -> String {
    if !d.is_finite() {
        return finite_str(d, upper);
    }
    let p = if prec == 0 { 1 } else { prec };
    // decide exponent like C: X = floor(log10(|d|)); %e if X < -4 or X >= p
    let ax = d.abs();
    let mut s = if ax != 0.0 {
        let exp = ax.log10().floor() as i32;
        if exp < -4 || exp >= p as i32 {
            format!("{:.*e}", p - 1, d)
        } else {
            format!("{:.*}", (p as i32 - 1 - exp).max(0) as usize, d)
        }
    } else {
        format!("{:.*}", p - 1, d)
    };
    // strip trailing zeros from the MANTISSA (C: trailing zeros are
    // removed from the fractional portion in both forms); the exponent
    // part must be kept intact
    if let Some(epos) = s.find(['e', 'E']) {
        let (mant, exp) = s.split_at(epos);
        let mut mant = mant.to_string();
        if mant.contains('.') {
            while mant.ends_with('0') {
                mant.pop();
            }
            if mant.ends_with('.') {
                mant.pop();
            }
        }
        s = format!("{}{}", mant, exp);
    } else if s.contains('.') {
        while s.ends_with('0') {
            s.pop();
        }
        if s.ends_with('.') {
            s.pop();
        }
    }
    fix_exp(&s)
}

fn fix_exp(s: &str) -> String {
    // Rust: "1.5e2" -> C: "1.5e+02"; "-3e-7" stays "-3e-07"
    if let Some(epos) = s.find(['e', 'E']) {
        let (mant, exp) = s.split_at(epos);
        let ec = exp.chars().next().unwrap();
        let rest: String = exp.chars().skip(1).collect();
        let (sign, digits) = match rest.strip_prefix('-') {
            Some(d) => ("-", d.to_string()),
            None => ("+", rest),
        };
        let digits = if digits.len() < 2 {
            format!("0{}", digits)
        } else {
            digits
        };
        return format!("{}{}{}{}", mant, ec, sign, digits);
    }
    s.to_string()
}

fn finite_str(d: f64, _upper: bool) -> String {
    if d.is_nan() {
        "nan".to_string()
    } else if d > 0.0 {
        "inf".to_string()
    } else {
        "-inf".to_string()
    }
}
