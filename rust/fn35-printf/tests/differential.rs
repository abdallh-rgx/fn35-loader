//! Differential test: Rust printf engine vs the Python oracle
//! (scripts/fn35_clib.py fmt_engine). Skipped when oracle missing.
use fn35_printf::{fmt_engine, SeqArgs, VarArgs};

#[derive(serde::Deserialize)]
struct RawCase {
    fmt: String,
    ints: Vec<u64>,
    /// floats encoded as numbers, or "inf"/"-inf"/"nan" strings
    dbls: Vec<serde_json::Value>,
    strs: Vec<String>,
    out: String,
}

fn dbl_of(v: &serde_json::Value) -> f64 {
    if let Some(s) = v.as_str() {
        match s {
            "inf" => f64::INFINITY,
            "-inf" => f64::NEG_INFINITY,
            "nan" => f64::NAN,
            _ => 0.0,
        }
    } else {
        v.as_f64().unwrap_or(0.0)
    }
}

#[test]
fn differential_vs_python_oracle() {
    let oracle_path =
        concat!(env!("CARGO_MANIFEST_DIR"), "/tests/oracle.json");
    let Ok(raw) = std::fs::read_to_string(oracle_path) else {
        panic!("oracle.json missing: run scripts/fn35_printf_oracle.py");
    };
    let cases: Vec<RawCase> = serde_json::from_str(&raw).unwrap();
    assert!(cases.len() >= 30, "expected a broad sample");

    let mut n = 0;
    for (i, c) in cases.iter().enumerate() {
        // %s consumes a pointer from the int stream then a string;
        // SeqArgs::next_ptr consumes an int, cstr_at pops strs in order
        let mut src = SeqArgs::new(
            c.ints.clone(),
            c.dbls.iter().map(dbl_of).collect(),
            c.strs.clone());
        let got = fmt_engine(&c.fmt, &mut src).unwrap();
        assert_eq!(
            got, c.out,
            "case {} fmt {:?}: rust={:?} python={:?}",
            i, c.fmt, got, c.out
        );
        n += 1;
    }
    eprintln!("printf differential: {} cases, all match", n);
}

#[test]
fn ptr_null_string() {
    // %s with a null pointer renders (null)
    struct NullSrc;
    impl VarArgs for NullSrc {
        fn next_int(&mut self) -> u64 { 0 }
        fn next_dbl(&mut self) -> f64 { 0.0 }
        fn next_ptr(&mut self) -> u64 { 0 }
        fn cstr_at(&mut self, _p: u64) -> Option<String> { None }
    }
    let got = fmt_engine("[%s]", &mut NullSrc).unwrap();
    assert_eq!(got, "[(null)]");
}

#[test]
fn objc_form() {
    let mut src = SeqArgs::new(vec![0x1055d64e0], vec![], vec![]);
    let got = fmt_engine("%@", &mut src).unwrap();
    assert_eq!(got, "<objc 1055d64e0>");
}

#[test]
fn c_exponent_form() {
    // C prints %e exponent with sign and >= 2 digits
    let mut src = SeqArgs::new(vec![], vec![1234.5], vec![]);
    let got = fmt_engine("%e", &mut src).unwrap();
    assert_eq!(got, "1.234500e+03");
    let mut src = SeqArgs::new(vec![], vec![1e-7], vec![]);
    let got = fmt_engine("%e", &mut src).unwrap();
    assert_eq!(got, "1.000000e-07");
}
