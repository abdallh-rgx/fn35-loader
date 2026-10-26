//! Differential test: Rust parser vs the Python oracle (fn35_macho.py)
//! on the REAL FortniteClient binary. Skipped gracefully when the
//! binary is not present (CI).
//!
//! Oracle values are produced by:
//!   python3 scripts/fn35_macho_oracle.py > rust/fn35-macho/tests/oracle.json
use fn35_macho::MachO;

fn bin_path() -> Option<String> {
    let p = "/home/z/my-project/fn35/extracted/Payload/FortniteClient.app/FortniteClient";
    std::path::Path::new(p).exists().then(|| p.to_string())
}

#[test]
fn differential_vs_python_oracle() {
    let Some(path) = bin_path() else {
        eprintln!("binary not present; skipping (CI)");
        return;
    };
    let oracle_path = concat!(env!("CARGO_MANIFEST_DIR"),
                              "/tests/oracle.json");
    let Ok(oracle_raw) = std::fs::read_to_string(oracle_path) else {
        panic!("oracle.json missing: run scripts/fn35_macho_oracle.py");
    };
    let o: std::collections::HashMap<String, serde_json::Value> =
        serde_json::from_str(&oracle_raw).unwrap();

    let mut m = MachO::open(std::path::Path::new(&path)).unwrap();
    m.load_symbols();
    let st = m.link_stats();

    let g = |k: &str| o.get(k).unwrap().clone();
    assert_eq!(st.segments, g("segments").as_u64().unwrap() as usize,
               "segments");
    assert_eq!(st.sections, g("sections").as_u64().unwrap() as usize,
               "sections");
    assert_eq!(st.dylibs, g("dylibs").as_u64().unwrap() as usize, "dylibs");
    assert_eq!(st.symbols, g("symbols").as_u64().unwrap() as usize,
               "symbols");
    assert_eq!(st.pointer_slots, g("pointer_slots").as_u64().unwrap(),
               "pointer_slots");
    assert_eq!(st.indirect_entries,
               g("indirect_entries").as_u64().unwrap() as usize,
               "indirect_entries");
    assert_eq!(st.bind_records,
               g("bind_records").as_u64().unwrap() as usize,
               "bind_records");
    assert_eq!(st.cryptid, g("cryptid").as_i64().unwrap() as i32,
               "cryptid");
    assert_eq!(st.entryoff, g("entryoff").as_u64().unwrap(), "entryoff");

    // deeper: slot list + mod_inits + tlv + first binds
    let slots: Vec<(u64, Option<u32>)> = m.iter_pointer_slots();
    let o_slots: Vec<(u64, Option<u32>)> =
        serde_json::from_value(g("slots")).unwrap();
    assert_eq!(slots.len(), o_slots.len(), "slot count");
    let mut mism = 0;
    for (a, b) in slots.iter().zip(o_slots.iter()) {
        if a != b {
            mism += 1;
        }
    }
    assert_eq!(mism, 0, "slot entries differ");

    let inits = m.mod_init_funcs();
    let o_inits: Vec<u64> =
        serde_json::from_value(g("mod_inits")).unwrap();
    assert_eq!(inits, o_inits, "mod_init_funcs");

    let tlv = m.tlv_template();
    let o_tlv: (u64, u64) =
        serde_json::from_value(g("tlv")).unwrap();
    assert_eq!(tlv, o_tlv, "tlv_template");

    let binds = m.parse_binds();
    let o_binds: Vec<(u32, u64, String)> =
        serde_json::from_value(g("binds_head")).unwrap();
    for (i, ob) in o_binds.iter().enumerate() {
        let rb = &binds[i];
        assert_eq!(rb.seg_index, ob.0, "bind {i} seg_index");
        assert_eq!(rb.seg_offset, ob.1, "bind {i} seg_offset");
        assert_eq!(rb.symbol, ob.2, "bind {i} symbol");
    }

    // symbol names round-trip for the first N slots
    let o_names: Vec<Option<String>> =
        serde_json::from_value(g("slot_names_head")).unwrap();
    for (i, on) in o_names.iter().enumerate() {
        let rn = slots[i].1
            .and_then(|idx| m.sym_name(idx as usize));
        assert_eq!(rn.as_deref(), on.as_deref(),
                   "sym_name for slot {i}");
    }
    println!("differential OK: {} slots, {} binds, {} inits, tlv={:?}",
             slots.len(), binds.len(), inits.len(), tlv);
}
