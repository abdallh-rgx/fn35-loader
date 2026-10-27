//! python_float_str fidelity fuzz: 417 reprs (396 random f64 bit
//! patterns + specials + inf/nan). Each repr round-trips (shortest
//! roundtrip property), so parsing it back gives the exact f64 whose
//! Python str() must equal our port.
#![forbid(unsafe_code)]

use fn35_cstr::python_float_str;

#[test]
fn float_repr_fuzz() {
    let data = include_str!("float_repr.json");
    let reprs: Vec<String> = serde_json::from_str(data).unwrap();
    let mut fails = 0;
    for r in &reprs {
        let expected = match r.as_str() {
            "inf" => "inf".to_string(),
            "-inf" => "-inf".to_string(),
            "nan" => "nan".to_string(),
            other => other.to_string(),
        };
        let mine = match r.as_str() {
            "inf" => python_float_str(f64::INFINITY),
            "-inf" => python_float_str(f64::NEG_INFINITY),
            "nan" => python_float_str(f64::NAN),
            other => {
                let v: f64 = other.parse().unwrap();
                python_float_str(v)
            }
        };
        if mine != expected {
            fails += 1;
            eprintln!("FAIL repr {} -> {} (want {})", r, mine, expected);
        }
    }
    assert_eq!(fails, 0, "{} float-repr failures", fails);
    println!("float-repr fuzz: {} vectors green", reprs.len());
}
