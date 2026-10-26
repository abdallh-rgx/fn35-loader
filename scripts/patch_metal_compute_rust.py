#!/usr/bin/env python3
"""patch_metal_compute_rust.py — extend the safe-Rust Metal core with
the compute-dispatch op surface (mirrors the Z3 spec patch).

pipe_valid: bool -> u8   (0 none / 1 render-fn / 2 compute-fn)
new field:   cb_cpipe: u64 (0 = none)
new kinds:   Cpipe = 10, Smp = 11
new methods: cpipe_new, smp_new, enc_compute, enc_setcpipe, enc_dispatch
release:    cpipe in-use guard (Z3 I8)
"""
P = "/home/z/my-project/rust/fn35-metal/src/lib.rs"
src = open(P).read()
orig = len(src)


def rep(old, new, count=1):
    global src
    n = src.count(old)
    assert n >= count, "anchor missing (%d): %r" % (n, old[:70])
    src = src.replace(old, new, count)


# ---------------------------------------------------------------- Kind enum
rep('''    Rpass = 7,
    Pipeline = 8,
    Fence = 9,
}''',
    '''    Rpass = 7,
    Pipeline = 8,
    Fence = 9,
    Cpipe = 10,
    Smp = 11,
}''')

# ---------------------------------------------------------- Object + fields
rep('''    /// pipeline -> has a valid vertex function
    pub pipe_valid: bool,''',
    '''    /// pipeline -> 1 has a vertex fn; cpipe -> 2 has a compute fn
    pub pipe_valid: u8,''')

rep('''    /// cmdbuf -> bound pipeline handle (0 = none)
    pub cb_pipe: u64,
}''',
    '''    /// cmdbuf -> bound pipeline handle (0 = none)
    pub cb_pipe: u64,
    /// cmdbuf -> bound compute pipeline handle (0 = none)
    pub cb_cpipe: u64,
}''')

# every Object literal: pipe_valid false->0, true->1 and add cb_cpipe: 0
src = src.replace("pipe_valid: false, signaled: false, cb_pipe: 0",
                  "pipe_valid: 0, signaled: false, cb_pipe: 0, cb_cpipe: 0")
src = src.replace("pipe_valid: true, signaled: false, cb_pipe: 0",
                  "pipe_valid: 1, signaled: false, cb_pipe: 0, cb_cpipe: 0")
# the two multiline Object::new_device/new_dead forms (with trailing newline)
src = src.replace("""attach: 0, pipe_valid: 0, signaled: false,
                 cb_pipe: 0, cb_cpipe: 0 }""",
                  """attach: 0, pipe_valid: 0, signaled: false,
                 cb_pipe: 0, cb_cpipe: 0 }""")

# guards on render pipe validity: bool -> ==1
rep('''        match self.get(pipeline) {
            Some(o) if o.kind == Kind::Pipeline && o.pipe_valid => {}''',
    '''        match self.get(pipeline) {
            Some(o) if o.kind == Kind::Pipeline && o.pipe_valid == 1 => {}''')
rep('''        let pipe = self.objects.get(&cb).unwrap().cb_pipe;
        match self.get(pipe) {
            Some(o) if o.kind == Kind::Pipeline && o.pipe_valid => {}''',
    '''        let pipe = self.objects.get(&cb).unwrap().cb_pipe;
        match self.get(pipe) {
            Some(o) if o.kind == Kind::Pipeline && o.pipe_valid == 1 => {}''')

# ------------------------------------------------------------ release guard
rep('''        if kind == Some(Kind::Pipeline) {
            let in_use = self.objects.values()
                .any(|o| o.kind == Kind::CmdBuf && o.cb_pipe == h);
            if in_use {
                return self.set_err(E_KIND); // bound to a command buffer
            }
        }''',
    '''        if kind == Some(Kind::Pipeline) {
            let in_use = self.objects.values()
                .any(|o| o.kind == Kind::CmdBuf && o.cb_pipe == h);
            if in_use {
                return self.set_err(E_KIND); // bound to a command buffer
            }
        }
        if kind == Some(Kind::Cpipe) {
            let in_use = self.objects.values()
                .any(|o| o.kind == Kind::CmdBuf && o.cb_cpipe == h);
            if in_use {
                return self.set_err(E_KIND); // bound to a command buffer
            }
        }''')

# ---------------------------------------------- compute methods (after enc_draw)
# append before the final closing brace of impl — anchor on the last method
COMPUTE = '''
    // -----------------------------------------------------------------------
    // Compute extension (guards are the Z3 spec, verbatim)
    // -----------------------------------------------------------------------
    pub fn cpipe_new(&mut self, lib: u64) -> (u64, u32) {
        match self.get(lib) {
            Some(o) if o.kind == Kind::Library => {}
            Some(_) => return (0, self.set_err(E_KIND)),
            None => return (0, self.set_err(E_DEAD)),
        }
        let has_fn = self.objects.get(&lib)
            .and_then(|o| o.lib.as_ref())
            .map(|l| !l.functions.is_empty())
            .unwrap_or(false);
        if !has_fn {
            return (0, self.set_err(E_PARSE));
        }
        let h = self.alloc(|| Object {
            kind: Kind::Cpipe, phase: Phase::Dead, err: 0,
            buf: Vec::new(), tex: None, lib: None,
            attach: 0, pipe_valid: 2, signaled: false,
            cb_pipe: 0, cb_cpipe: 0 });
        (h, 0)
    }

    pub fn smp_new(&mut self, dev: u64, coord_mode: u32) -> (u64, u32) {
        match self.get(dev) {
            Some(o) if o.kind == Kind::Device => {}
            Some(_) => return (0, self.set_err(E_KIND)),
            None => return (0, self.set_err(E_DEAD)),
        }
        if coord_mode > 1 {
            return (0, self.set_err(E_KIND)); // legal coord enums only
        }
        let h = self.alloc(|| Object {
            kind: Kind::Smp, phase: Phase::Dead, err: 0,
            buf: Vec::new(), tex: None, lib: None,
            attach: 0, pipe_valid: 0, signaled: false,
            cb_pipe: 0, cb_cpipe: 0 });
        (h, 0)
    }

    pub fn enc_compute(&mut self, cb: u64) -> u32 {
        match self.get(cb) {
            Some(o) if o.kind == Kind::CmdBuf => {
                if o.phase != Phase::Active {
                    return self.set_err(E_PHASE);
                }
            }
            Some(_) => return self.set_err(E_KIND),
            None => return self.set_err(E_DEAD),
        }
        OK
    }

    pub fn enc_setcpipe(&mut self, cb: u64, cpipe: u64) -> u32 {
        match self.get(cb) {
            Some(o) if o.kind == Kind::CmdBuf => {
                if o.phase != Phase::Active {
                    return self.set_err(E_PHASE);
                }
            }
            Some(_) => return self.set_err(E_KIND),
            None => return self.set_err(E_DEAD),
        }
        match self.get(cpipe) {
            Some(o) if o.kind == Kind::Cpipe && o.pipe_valid == 2 => {}
            Some(_) => return self.set_err(E_KIND),
            None => return self.set_err(E_DEAD),
        }
        self.objects.get_mut(&cb).unwrap().cb_cpipe = cpipe;
        OK
    }

    pub fn enc_dispatch(&mut self, cb: u64, tgx: u64, tgy: u64,
                        tgz: u64) -> u32 {
        match self.get(cb) {
            Some(o) if o.kind == Kind::CmdBuf => {
                if o.phase != Phase::Active {
                    return self.set_err(E_PHASE);
                }
            }
            Some(_) => return self.set_err(E_KIND),
            None => return self.set_err(E_DEAD),
        }
        let cpipe = self.objects.get(&cb).unwrap().cb_cpipe;
        match self.get(cpipe) {
            Some(o) if o.kind == Kind::Cpipe && o.pipe_valid == 2 => {}
            _ => return self.set_err(E_KIND), // live cpipe required
        }
        if tgx == 0 || tgy == 0 || tgz == 0
            || tgx > u32::MAX as u64 || tgy > u32::MAX as u64
            || tgz > u32::MAX as u64 {
            return self.set_err(E_BOUNDS); // Metal rejects empty grids
        }
        OK
    }
}
'''
# replace the FINAL closing brace of the impl block: the file ends with
# tests + maybe more. Find last "}\n" that closes impl Metal — anchor on
# the enc_blit method ending... safer: find the last method then its end.
# The file's impl block ends right before "#[cfg(test)]" or end.
tail_anchor = src.rstrip()
assert tail_anchor.endswith("}")
# drop the final closing brace of impl (the last } in the file IF the
# impl is the outermost construct; verify structure)
idx = src.rstrip().rfind("\n}")
assert idx > 0, "impl closing brace not found"
src = src[:idx + 1] + COMPUTE + src[idx + 2:]

open(P, "w").write(src)
print("patched %d -> %d bytes (+%d)" % (orig, len(src), len(src) - orig))
