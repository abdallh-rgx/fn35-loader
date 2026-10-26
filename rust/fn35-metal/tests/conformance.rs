//! Conformance: replay the Z3-oracle traces through the safe Rust core.
//!
//! The traces (`tests/conformance_traces.json`, 300 of them) are emitted
//! by `scripts/metal_z3_spec.py` from the PROVEN transition relation.
//! The Python side already replays them through ctypes -> this core; this
//! test goes further: it verifies rc AND kind AND phase AND buf_len for
//! every step, directly against the Rust state machine.

use fn35_metal::{Kind, MetalState, Phase};

#[derive(serde::Deserialize)]
struct Step {
    op: String,
    h: usize,
    #[serde(default)]
    args: Args,
    rc: u32,
    #[serde(default)]
    phase_after: Option<String>,
    #[serde(default)]
    kind_after: Option<String>,
    #[serde(default)]
    buf_len: Option<u64>,
}

#[derive(serde::Deserialize, Default, Debug)]
struct Args {
    #[serde(default)]
    off: i64,
    #[serde(default)]
    ln: i64,
    #[serde(default)]
    x: i64,
    #[serde(default)]
    y: i64,
    #[serde(default)]
    w: i64,
    #[serde(default)]
    ht: i64,
    #[serde(default)]
    lvl: i64,
}

fn kind_of(s: &str) -> u32 {
    match s {
        "K_NONE" => Kind::None.as_u32(),
        "K_DEVICE" => Kind::Device.as_u32(),
        "K_QUEUE" => Kind::Queue.as_u32(),
        "K_CMDBUF" => Kind::CmdBuf.as_u32(),
        "K_BUFFER" => Kind::Buffer.as_u32(),
        "K_TEXTURE" => Kind::Texture.as_u32(),
        "K_LIBRARY" => Kind::Library.as_u32(),
        "K_RPASS" => Kind::Rpass.as_u32(),
        "K_PIPELINE" => Kind::Pipeline.as_u32(),
        "K_FENCE" => Kind::Fence.as_u32(),
        "K_CPIPE" => Kind::Cpipe.as_u32(),
        "K_SMP" => Kind::Smp.as_u32(),
        _ => panic!("unknown kind {s}"),
    }
}

fn phase_of(s: &str) -> u32 {
    match s {
        "P_DEAD" => Phase::Dead as u32,
        "P_CREATED" => Phase::Created as u32,
        "P_ACTIVE" => Phase::Active as u32,
        "P_COMMITTED" => Phase::Committed as u32,
        "P_SCHEDULED" => Phase::Scheduled as u32,
        "P_COMPLETED" => Phase::Completed as u32,
        "P_ERRORED" => Phase::Errored as u32,
        _ => panic!("unknown phase {s}"),
    }
}

/// the metallib blob the Python harness feeds OP_LIB_NEW
fn minimal_metallib() -> Vec<u8> {
    let metd = b"{\"functions\":[\"vshader\"]}";
    let mut d = Vec::new();
    d.extend_from_slice(b"MTLB");
    d.extend_from_slice(&2u32.to_le_bytes());
    d.extend_from_slice(b"METD");
    d.extend_from_slice(&(metd.len() as u32).to_le_bytes());
    d.extend_from_slice(metd);
    d.extend_from_slice(b"METB");
    d.extend_from_slice(&1u32.to_le_bytes());
    d.push(0x42);
    d
}

fn u32v(v: i64) -> u32 {
    v as u32
}

fn u64v(v: i64) -> u64 {
    v as u64
}

#[test]
fn z3_oracle_conformance() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"),
                       "/tests/conformance_traces.json");
    let data = std::fs::read(path).expect("traces file");
    let traces: Vec<Vec<Step>> = serde_json::from_slice(&data)
        .expect("trace json");
    assert!(!traces.is_empty(), "no traces");

    let mm = minimal_metallib();
    let mut total = 0usize;
    let mut mismatches = 0usize;

    for (ti, trace) in traces.iter().enumerate() {
        let mut m = MetalState::new();
        // slot -> handle (0 = unallocated)
        let mut slots: [u64; 4] = [0; 4];
        for step in trace {
            let h = slots[step.h];
            total += 1;
            let mut got = 0u32;
            let a = &step.args;
            match step.op.as_str() {
                "OP_NOP" => {}
                "OP_DEV_NEW" => {
                    // slot semantics: allocating into an occupied slot
                    // is E_KIND in the Z3 model
                    if h != 0 {
                        got = 4;
                    } else {
                        slots[step.h] = m.device_create();
                    }
                }
                "OP_QUEUE_NEW" => match m.queue_new(h) {
                    (nh, 0) if nh != 0 => slots[step.h] = nh,
                    (_, rc) => got = rc,
                },
                "OP_CB_NEW" => match m.cb_new(h) {
                    (nh, 0) if nh != 0 => slots[step.h] = nh,
                    (_, rc) => got = rc,
                },
                "OP_ENCODE" => got = m.cb_encode(h),
                "OP_COMMIT" => got = m.cb_commit(h),
                "OP_TICK" => got = m.cb_tick(h),
                "OP_WAIT" => {
                    let (rc, _) = m.cb_wait(h);
                    got = rc;
                }
                "OP_BUF_NEW" => match m.buf_new(h, u64v(a.ln), None) {
                    (nh, 0) if nh != 0 => slots[step.h] = nh,
                    (_, rc) => got = rc,
                },
                "OP_BUF_WRITE" => {
                    got = m.buf_check_region(h, u64v(a.off), u64v(a.ln))
                }
                "OP_TEX_NEW" => {
                    match m.tex_new(h, u32v(a.w), u32v(a.ht),
                                    u32v(a.lvl), 1) {
                        (nh, 0) if nh != 0 => slots[step.h] = nh,
                        (_, rc) => got = rc,
                    }
                }
                "OP_TEX_WRITE" => {
                    got = m.tex_check_region(h, u32v(a.x), u32v(a.y),
                                             u32v(a.w), u32v(a.ht),
                                             u32v(a.lvl))
                }
                "OP_TEX_READ" => {
                    got = m.tex_check_region(h, u32v(a.x), u32v(a.y),
                                             u32v(a.w), u32v(a.ht),
                                             u32v(a.lvl))
                }
                "OP_RPASS_NEW" => match m.rpass_new(h) {
                    (nh, 0) if nh != 0 => slots[step.h] = nh,
                    (_, rc) => got = rc,
                },
                "OP_RPASS_ATTACH" => {
                    let t = if a.off >= 0 { (a.off % 4) as usize } else {
                        usize::MAX };
                    let th = if t < 4 { slots[t] } else { 0 };
                    got = m.rpass_attach(h, th)
                }
                "OP_ENC_RPASS" => {
                    let r = if a.off >= 0 { (a.off % 4) as usize } else {
                        usize::MAX };
                    let rh = if r < 4 { slots[r] } else { 0 };
                    got = m.enc_rpass(h, rh)
                }
                "OP_PIPELINE_NEW" => match m.pipeline_new(h) {
                    (nh, 0) if nh != 0 => slots[step.h] = nh,
                    (_, rc) => got = rc,
                },
                "OP_ENC_SETPIPE" => {
                    let p = if a.off >= 0 { (a.off % 4) as usize } else {
                        usize::MAX };
                    let ph = if p < 4 { slots[p] } else { 0 };
                    got = m.enc_setpipe(h, ph)
                }
                "OP_ENC_DRAW" => {
                    got = m.enc_draw(h, u64v(a.x), u64v(a.y))
                }
                "OP_ENC_BLIT" => {
                    let s = if a.off >= 0 { (a.off % 4) as usize } else {
                        usize::MAX };
                    let d = if a.ln >= 0 { (a.ln % 4) as usize } else {
                        usize::MAX };
                    let sh = if s < 4 { slots[s] } else { 0 };
                    let dh = if d < 4 { slots[d] } else { 0 };
                    got = m.enc_blit(h, sh, dh, u64v(a.x), u64v(a.y),
                                     u64v(a.w))
                }
                "OP_FENCE_NEW" => match m.fence_new(h) {
                    (nh, 0) if nh != 0 => slots[step.h] = nh,
                    (_, rc) => got = rc,
                },
                "OP_FENCE_SIGNAL" => got = m.fence_signal(h),
                "OP_FENCE_WAIT" => got = m.fence_wait(h),
                "OP_CPIPE_NEW" => match m.cpipe_new(h) {
                    (nh, 0) if nh != 0 => slots[step.h] = nh,
                    (_, rc) => got = rc,
                },
                "OP_SMP_NEW" => match m.smp_new(h, a.off as u32) {
                    (nh, 0) if nh != 0 => slots[step.h] = nh,
                    (_, rc) => got = rc,
                },
                "OP_ENC_COMPUTE" => got = m.enc_compute(h),
                "OP_ENC_SETCPIPE" => {
                    let p = if a.off >= 0 { (a.off % 4) as usize } else {
                        usize::MAX };
                    let ph = if p < 4 { slots[p] } else { 0 };
                    got = m.enc_setcpipe(h, ph)
                }
                "OP_ENC_DISPATCH" => {
                    got = m.enc_dispatch(h, u64v(a.x), u64v(a.y),
                                         u64v(a.w))
                }
                "OP_LIB_NEW" => match m.lib_new(h, &mm) {
                    (nh, 0) if nh != 0 => slots[step.h] = nh,
                    (_, rc) => got = rc,
                },
                "OP_RELEASE" => {
                    got = m.release(h);
                    if got == 0 {
                        slots[step.h] = 0;
                    }
                }
                other => panic!("unknown op {other}"),
            }
            if got != step.rc {
                mismatches += 1;
                if mismatches < 6 {
                    eprintln!("MISMATCH trace {ti} op {} h={} args={:?} \
                               rust={got} z3={}", step.op, step.h, a,
                              step.rc);
                }
            }
            // stronger checks: post-state of handle h
            let cur = slots[step.h];
            if let Some(k) = &step.kind_after {
                let want = kind_of(k);
                let have = if cur == 0 {
                    Kind::None.as_u32()
                } else {
                    m.obj_kind(cur)
                };
                assert_eq!(have, want,
                    "trace {ti} op {}: kind {have} != {want}",
                    step.op);
            }
            if let Some(p) = &step.phase_after {
                let want = phase_of(p);
                let have = if cur == 0 {
                    Phase::Dead as u32
                } else {
                    m.cb_phase(cur)
                };
                assert_eq!(have, want,
                    "trace {ti} op {}: phase {have} != {want}",
                    step.op);
            }
            if let Some(bl) = step.buf_len {
                let have = if cur == 0 { 0 } else { m.buf_len(cur) };
                assert_eq!(have, bl,
                    "trace {ti} op {}: buf_len {have} != {bl}",
                    step.op);
            }
        }
    }
    println!("conformance: {} traces / {} steps, {} mismatches",
             traces.len(), total, mismatches);
    assert_eq!(mismatches, 0, "Rust core diverged from the Z3 oracle");
}
