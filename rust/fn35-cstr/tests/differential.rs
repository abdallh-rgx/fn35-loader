//! Differential test vs the Python fn35_clib oracle (237 vectors).
#![forbid(unsafe_code)]

use fn35_cstr::*;

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn py_parse_float(repr: &str) -> f64 {
    // the oracle records val via Python repr; round-trip via Rust
    if repr == "inf" {
        f64::INFINITY
    } else if repr == "-inf" {
        f64::NEG_INFINITY
    } else if repr == "nan" {
        f64::NAN
    } else {
        repr.parse().unwrap()
    }
}

#[test]
fn differential() {
    let data = include_str!("oracle.json");
    let vecs: Vec<serde_json::Value> = serde_json::from_str(data).unwrap();
    let mut fails = 0;
    for (idx, v) in vecs.iter().enumerate() {
        let fn_name = v["fn"].as_str().unwrap();
        let ok = match fn_name {
            "strlen" => {
                let s = v["s"].as_str().unwrap().as_bytes();
                v["ret"].as_u64().unwrap() == strlen(s) as u64
            }
            "strnlen" => {
                let s = v["s"].as_str().unwrap().as_bytes();
                v["ret"].as_u64().unwrap() == strnlen(s, v["n"].as_u64().unwrap() as usize) as u64
            }
            "strcmp" => {
                let (a, b) = (
                    v["a"].as_str().unwrap().as_bytes(),
                    v["b"].as_str().unwrap().as_bytes(),
                );
                v["ret"].as_i64().unwrap() == strcmp(a, b) as i64
            }
            "strncmp" => {
                let (a, b) = (
                    v["a"].as_str().unwrap().as_bytes(),
                    v["b"].as_str().unwrap().as_bytes(),
                );
                let n = v["n"].as_u64().unwrap() as usize;
                v["ret"].as_i64().unwrap() == strncmp(a, b, n) as i64
            }
            "strcasecmp" => {
                let (a, b) = (
                    v["a"].as_str().unwrap().as_bytes(),
                    v["b"].as_str().unwrap().as_bytes(),
                );
                v["ret"].as_i64().unwrap() == strcasecmp(a, b) as i64
            }
            "strncasecmp" => {
                let (a, b) = (
                    v["a"].as_str().unwrap().as_bytes(),
                    v["b"].as_str().unwrap().as_bytes(),
                );
                let n = v["n"].as_u64().unwrap() as usize;
                v["ret"].as_i64().unwrap() == strncasecmp(a, b, Some(n)) as i64
            }
            "memcpy" => {
                let src = unhex(v["src"].as_str().unwrap());
                let n = v["n"].as_u64().unwrap() as usize;
                let mut dst = unhex(v["dst"].as_str().unwrap());
                dst.resize(n.max(dst.len()), 0);
                memcpy(&mut dst, &src, n);
                unhex(v["out"].as_str().unwrap()) == dst[..n]
            }
            "memset" => {
                let n = v["n"].as_u64().unwrap() as usize;
                let mut dst = vec![0xAAu8; n];
                memset(&mut dst, v["c"].as_u64().unwrap() as u8, n);
                unhex(v["out"].as_str().unwrap()) == dst
            }
            "bzero" => {
                let n = v["n"].as_u64().unwrap() as usize;
                let mut dst = vec![0xAAu8; n];
                bzero(&mut dst, n);
                unhex(v["out"].as_str().unwrap()) == dst
            }
            "memcmp" => {
                let (a, b) = (
                    unhex(v["a"].as_str().unwrap()),
                    unhex(v["b"].as_str().unwrap()),
                );
                let n = v["n"].as_u64().unwrap() as usize;
                v["ret"].as_i64().unwrap() == memcmp(&a, &b, n) as i64
            }
            "strncpy" => {
                let (src, n) = (
                    v["src"].as_str().unwrap(),
                    v["n"].as_u64().unwrap() as usize,
                );
                strncpy(src, n) == unhex(v["out"].as_str().unwrap())
            }
            "strlcpy" => {
                let (src, size) = (
                    v["src"].as_str().unwrap(),
                    v["size"].as_u64().unwrap() as usize,
                );
                let (out, ret) = strlcpy(src, size);
                ret == v["ret"].as_u64().unwrap() as usize
                    && out == unhex(v["out"].as_str().unwrap())
            }
            "strlcat" => {
                let (dst, src, size) = (
                    v["dst"].as_str().unwrap(),
                    v["src"].as_str().unwrap(),
                    v["size"].as_u64().unwrap() as usize,
                );
                let (at, out, ret) = strlcat(dst, src, size);
                at == v["at"].as_u64().unwrap() as usize
                    && ret == v["ret"].as_u64().unwrap() as usize
                    && out == unhex(v["out"].as_str().unwrap())
            }
            "strcat" => {
                let (dst, src) = (
                    v["dst"].as_str().unwrap(),
                    v["src"].as_str().unwrap(),
                );
                strcat(dst, src) == unhex(v["out"].as_str().unwrap())
            }
            "strstr" => {
                let (h, nd) = (
                    v["hay"].as_str().unwrap(),
                    v["needle"].as_str().unwrap(),
                );
                let mine = strstr(h, nd);
                match (&v["ret"], mine) {
                    (serde_json::Value::Null, None) => true,
                    (serde_json::Value::Null, Some(_)) => false,
                    (serde_json::Value::Number(x), Some(m)) => {
                        x.as_u64().unwrap() == m as u64
                    }
                    (_, None) => false,
                    _ => false,
                }
            }
            "strchr" | "strrchr" | "strchrnul" => {
                let (s, c) = (
                    v["s"].as_str().unwrap(),
                    v["c"].as_i64().unwrap(),
                );
                let mine = match fn_name {
                    "strchr" => strchr(s, c),
                    "strrchr" => strrchr(s, c),
                    _ => Some(strchrnul(s, c)),
                };
                match (&v["ret"], mine) {
                    (serde_json::Value::Null, None) => true,
                    (serde_json::Value::Number(x), Some(m)) => {
                        x.as_u64().unwrap() == m as u64
                    }
                    _ => false,
                }
            }
            "digit_val" => {
                let c = v["c"].as_str().unwrap().chars().next().unwrap();
                v["ret"].as_u64().unwrap() == digit_val(c) as u64
            }
            "strtol" => {
                let (s, base) = (
                    v["s"].as_str().unwrap(),
                    v["base"].as_u64().unwrap() as u32,
                );
                let (val, consumed, no_digits) = strtol(s, base);
                if no_digits {
                    v["consumed"].as_i64().unwrap() == 0
                } else {
                    val == v["ret"].as_u64().unwrap()
                        && consumed as i64 == v["consumed"].as_i64().unwrap()
                }
            }
            "strtod" => {
                let s = v["s"].as_str().unwrap();
                let (val, used) = strtod(s);
                let py = py_parse_float(v["val"].as_str().unwrap());
                (val == py || (val.is_nan() && py.is_nan()))
                    && used as i64 == v["consumed"].as_i64().unwrap()
            }
            "atoi" => {
                let s = v["s"].as_str().unwrap();
                atoi(s) == v["ret"].as_i64().unwrap()
            }
            "atof" => {
                let s = v["s"].as_str().unwrap();
                let mine = atof(s);
                let py = py_parse_float(v["val"].as_str().unwrap());
                mine == py || (mine.is_nan() && py.is_nan())
            }
            other => panic!("unknown fn {}", other),
        };
        if !ok {
            fails += 1;
            eprintln!("FAIL[{}] {} {}", idx, fn_name, v);
        }
    }
    assert_eq!(fails, 0, "{} differential failures", fails);
    println!("cstr differential: {} vectors green", vecs.len());
}
