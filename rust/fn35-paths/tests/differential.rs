//! Differential test: Rust path translator vs the Python oracle
//! (scripts/fn35_loader.py translate_path).
use fn35_paths::PathTranslator;

#[derive(serde::Deserialize)]
struct Case {
    guest: Option<String>,
    host: Option<String>,
}

const SB: &str = "/home/z/my-project/fn35/sandbox";

#[test]
fn differential_vs_python_oracle() {
    let oracle_path =
        concat!(env!("CARGO_MANIFEST_DIR"), "/tests/oracle.json");
    let Ok(raw) = std::fs::read_to_string(oracle_path) else {
        panic!("oracle.json missing: run scripts/fn35_paths_oracle.py");
    };
    let cases: Vec<Case> = serde_json::from_str(&raw).unwrap();
    assert!(cases.len() >= 20, "expected a broad sample");

    let t = PathTranslator::new(SB);
    for (i, c) in cases.iter().enumerate() {
        let got = match &c.guest {
            None => None,
            Some(g) => t.translate(g),
        };
        assert_eq!(
            got, c.host,
            "case {} guest {:?}: rust={:?} python={:?}",
            i, c.guest, got, c.host
        );
    }
    eprintln!("paths differential: {} cases, all match", cases.len());
}

#[test]
fn null_and_empty() {
    let t = PathTranslator::new(SB);
    assert_eq!(t.translate(""), None);
    assert_eq!(t.translate("/x/y/z"), Some(format!("{}/System/x/y/z", SB)));
}

#[test]
fn components_walker() {
    use fn35_paths::components;
    let c = components("/a/./b/../c//d/");
    assert_eq!(c, vec!["a".to_string(), "c".to_string(), "d".to_string()]);
}
