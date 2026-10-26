//! Differential test: Rust pak reader vs the Python oracle
//! (scripts/fn35_pakfs_oracle.py) on the REAL game pak. Skipped
//! gracefully when the pak is not present (CI).
//!
//! Oracle values are produced by:
//!   python3 scripts/fn35_pakfs_oracle.py \
//!     > rust/fn35-pakfs/tests/oracle.json
use fn35_pakfs::Pak;
use sha2::{Digest, Sha256};

fn pak_path() -> Option<&'static std::path::Path> {
    let p = std::path::Path::new(
        "/home/z/my-project/fn35/extracted/Payload/FortniteClient.app/\
         cookeddata/fortnitegame/Content/Paks/pakchunkearly-iosclient.pak",
    );
    p.is_file().then_some(p)
}

#[test]
fn differential_vs_python_oracle() {
    let Some(path) = pak_path() else {
        eprintln!("pak not present; skipping (CI)");
        return;
    };
    let oracle_path =
        concat!(env!("CARGO_MANIFEST_DIR"), "/tests/oracle.json");
    let Ok(oracle_raw) = std::fs::read_to_string(oracle_path) else {
        panic!("oracle.json missing: run scripts/fn35_pakfs_oracle.py");
    };
    let o: serde_json::Value =
        serde_json::from_str(&oracle_raw).unwrap();

    let pak = Pak::open(path).unwrap();

    assert_eq!(pak.mount, o["mount"].as_str().unwrap(), "mount");
    assert_eq!(pak.entry_count(), o["count"].as_u64().unwrap() as usize,
               "entry count");
    assert_eq!(pak.dir_count(), o["dir_count"].as_u64().unwrap() as usize,
               "dir count");

    // full name table identical (sorted prefix from the oracle)
    let names = pak.entry_names();
    let onames: Vec<&str> = o["names"].as_array().unwrap()
        .iter().map(|v| v.as_str().unwrap()).collect();
    assert_eq!(&names[..onames.len()], &onames[..], "name table");

    // byte-identical extraction for every sampled entry
    let entries = o["entries"].as_object().unwrap();
    let mut checked = 0usize;
    let mut total_bytes = 0usize;
    for (name, meta) in entries {
        let e = pak.get(name)
            .unwrap_or_else(|| panic!("entry {} missing", name));
        assert_eq!(e.size, meta["size"].as_i64().unwrap(), "{} size", name);
        assert_eq!(e.usize_, meta["usize"].as_i64().unwrap(),
                   "{} usize", name);
        assert_eq!(e.comp, meta["comp"].as_i64().unwrap() as i32,
                   "{} comp", name);
        let data = pak.read_entry(e)
            .unwrap_or_else(|err| panic!("{} read: {}", name, err));
        assert_eq!(data.len(), meta["len"].as_u64().unwrap() as usize,
                   "{} extracted length", name);
        let sha = Sha256::digest(&data);
        assert_eq!(hex(&sha), meta["sha256"].as_str().unwrap(),
                   "{} sha256", name);
        checked += 1;
        total_bytes += data.len();
    }
    eprintln!("differential: {} entries, {} bytes, all sha256 match",
              checked, total_bytes);
    assert!(checked >= 50, "expected a broad sample");
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{:02x}", x)).collect()
}

#[test]
fn resolve_guest_paths() {
    let Some(path) = pak_path() else {
        eprintln!("pak not present; skipping (CI)");
        return;
    };
    let pak = Pak::open(path).unwrap();

    // the two exact opens the engine made at the LogInit wall
    let a = pak.resolve("/private/var/containers/Bundle/Application/\
                         6B3F2A11-4C4E-4E22-9A04-7D9E1A55C0FF/\
                         FortniteClient.app/cookeddata/fortnitegame/\
                         fortnitegame.uproject");
    assert!(a.is_some(), "bundle-relative uproject");
    let b = pak.resolve("/FortniteGame/FortniteGame.uproject");
    assert!(b.is_some(), "root-absolute uproject");
    // relative form used by FPaths
    assert!(pak
        .resolve("../../../FortniteGame/Config/DefaultEngine.ini")
        .is_some(), "relative config ini");
    // case-insensitivity
    assert!(pak
        .resolve("../../../fortnitegame/config/defaultengine.ini")
        .is_some(), "lowercase config ini");
    // dir resolution
    assert!(pak.resolve_dir("../../../FortniteGame/Config").is_some());
    assert!(pak.resolve_dir("../../../FortniteGame/Content").is_some());
    // misses must miss
    assert!(pak.resolve("../../../FortniteGame/Nope.uasset").is_none());
    // children of the config dir
    let kids = pak.list_dir("FortniteGame/Config");
    assert!(kids.iter().any(|k| k == "DefaultEngine.ini"),
            "config children: {:?}", kids);
}

#[test]
fn tiny_bad_inputs() {
    // too small
    assert!(matches!(
        Pak::parse(vec![0u8; 10]),
        Err(fn35_pakfs::PakError::TooSmall)
    ));
    // wrong magic
    let mut f = vec![0u8; 44];
    f[44 - 44] = 1;
    assert!(matches!(
        Pak::parse(f),
        Err(fn35_pakfs::PakError::BadMagic(_))
    ));
}
