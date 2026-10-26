#!/usr/bin/env python3
"""patch_metal_compute.py — extend the Z3 Metal spec with the
compute-dispatch op surface (session 8).

New ops:  OP_CPIPE_NEW, OP_ENC_COMPUTE, OP_ENC_SETCPIPE,
          OP_ENC_DISPATCH, OP_SMP_NEW
New kinds: K_CPIPE, K_SMP
New state: cb_cpipe (cmdbuf -> bound compute pipeline handle)
New invariants: I4b (cpipe => pipe_valid==2), I8 (binding never dangles),
                cross-slot ref rule for cb_cpipe
New BMC props: P1b extension (compute encodes need ACTIVE),
               P3d (dispatch grid dims > 0),
               P8 (dispatch needs a live, valid, bound compute pipeline)

Run, then `python3 metal_z3_spec.py` re-proves everything and re-emits
the conformance traces for the full-stack differential.
"""
import sys

P = "/home/z/my-project/scripts/metal_z3_spec.py"
src = open(P).read()
orig = len(src)


def rep(old, new, count=1):
    global src
    n = src.count(old)
    assert n >= count, "anchor missing (%d): %r" % (n, old[:70])
    src = src.replace(old, new, count)


# ---------------------------------------------------------------- OPS/KINDS
rep('"OP_FENCE_NEW", "OP_FENCE_SIGNAL", "OP_FENCE_WAIT"]',
    '"OP_FENCE_NEW", "OP_FENCE_SIGNAL", "OP_FENCE_WAIT",\n'
    '       # --- compute extension (session 8) ---\n'
    '       "OP_CPIPE_NEW", "OP_ENC_COMPUTE", "OP_ENC_SETCPIPE",\n'
    '       "OP_ENC_DISPATCH", "OP_SMP_NEW"]')

rep('K_RPASS", "K_PIPELINE", "K_FENCE"]',
    'K_RPASS", "K_PIPELINE", "K_FENCE", "K_CPIPE", "K_SMP"]')

# ---------------------------------------------------------------- ModelState
rep('        self.cb_pipe = [-1] * n_handles  # cmdbuf -> bound pipeline',
    '        self.cb_pipe = [-1] * n_handles  # cmdbuf -> bound pipeline\n'
    '        # --- compute extension state ---\n'
    '        self.cb_cpipe = [-1] * n_handles  # cmdbuf -> bound cpipe')

rep('        m.signaled = list(self.signaled); m.cb_pipe = list(self.cb_pipe)',
    '        m.signaled = list(self.signaled); m.cb_pipe = list(self.cb_pipe)\n'
    '        m.cb_cpipe = list(self.cb_cpipe)')

# ------------------------------------------------------- concrete semantics
CONCRETE = '''
    # ---- compute extension (session 8) ----------------------------------
    if op == "OP_CPIPE_NEW":
        if not live:
            return E_DEAD
        if m.kind[h] != "K_LIBRARY":
            return E_KIND           # compute pipelines are built from a lib
        m.kind[h] = "K_CPIPE"
        m.pipe_valid[h] = 2         # has a compute entry point
        return OK

    if op == "OP_SMP_NEW":
        # h=slot, off=coord mode (0=normalized, 1=clamped, else E_KIND)
        if not live:
            return E_DEAD
        if m.kind[h] != "K_DEVICE":
            return E_KIND
        if off not in (0, 1):
            return E_KIND           # coord mode must be a legal enum
        m.kind[h] = "K_SMP"
        return OK

    if op == "OP_ENC_COMPUTE":
        # begin a compute pass on a command buffer
        if not live:
            return E_DEAD
        if m.kind[h] != "K_CMDBUF":
            return E_KIND
        if m.phase[h] != "P_ACTIVE":
            return E_PHASE
        return OK

    if op == "OP_ENC_SETCPIPE":
        if not live:
            return E_DEAD
        if m.kind[h] != "K_CMDBUF":
            return E_KIND
        if m.phase[h] != "P_ACTIVE":
            return E_PHASE
        p = off % m.n if off >= 0 else off   # cpipe slot
        if p < 0 or p >= m.n:
            return E_DEAD
        if m.kind[p] == "K_NONE":
            return E_DEAD           # dead target handle (ABI parity)
        if m.kind[p] != "K_CPIPE" or m.pipe_valid[p] != 2:
            return E_KIND
        m.cb_cpipe[h] = p
        return OK

    if op == "OP_ENC_DISPATCH":
        # h=cmdbuf, x/y/w = threadgroup grid dims
        if not live:
            return E_DEAD
        if m.kind[h] != "K_CMDBUF":
            return E_KIND
        if m.phase[h] != "P_ACTIVE":
            return E_PHASE
        p = m.cb_cpipe[h]
        if p < 0 or p >= m.n or m.kind[p] != "K_CPIPE" \\
                or m.pipe_valid[p] != 2:
            return E_KIND           # dispatch requires a live cpipe
        if x <= 0 or y <= 0 or w <= 0:
            return E_BOUNDS         # Metal rejects empty grids
        return OK

'''
rep('    return OK  # OP_NOP', CONCRETE + '    return OK  # OP_NOP')

# RELEASE: in-use guard must cover cb_cpipe too
rep('''            for i in range(m.n):
                if m.cb_pipe[i] == h:
                    return E_KIND   # still bound to a command buffer''',
    '''            for i in range(m.n):
                if m.cb_pipe[i] == h or m.cb_cpipe[i] == h:
                    return E_KIND   # still bound to a command buffer''')

# RELEASE: clear line
rep('        m.cb_pipe[h] = -1',
    '        m.cb_pipe[h] = -1; m.cb_cpipe[h] = -1')

# ------------------------------------------------------------ symbolic side
rep('''    nat, npv, nsg, ncp = (next_s["attach"], next_s["pipe_valid"],
                          next_s["signaled"], next_s["cb_pipe"])''',
    '''    nat, npv, nsg, ncp = (next_s["attach"], next_s["pipe_valid"],
                          next_s["signaled"], next_s["cb_pipe"])
    ncc = next_s["cb_cpipe"]''')

rep('''                   (signaled, nsg), (cb_pipe, ncp)]:''',
    '''                   (signaled, nsg), (cb_pipe, ncp),
                   (cb_cpipe, ncc)]:''')

rep('''    attach, pipe_valid, signaled, cb_pipe = (s["attach"],
        s["pipe_valid"], s["signaled"], s["cb_pipe"])''',
    '''    attach, pipe_valid, signaled, cb_pipe = (s["attach"],
        s["pipe_valid"], s["signaled"], s["cb_pipe"])
    cb_cpipe = s["cb_cpipe"]''')

# RELEASE symbolic: refs must include cb_cpipe; effect resets it
rep('''        refs = []
        for i in range(z["N"]):
            if i != h:
                refs.append(attach[i] == h)
                refs.append(cb_pipe[i] == h)''',
    '''        refs = []
        for i in range(z["N"]):
            if i != h:
                refs.append(attach[i] == h)
                refs.append(cb_pipe[i] == h)
                refs.append(cb_cpipe[i] == h)''')

rep('''                                   nat[h] == -1, npv[h] == 0,
                                   nsg[h] == 0, ncp[h] == -1)))''',
    '''                                   nat[h] == -1, npv[h] == 0,
                                   nsg[h] == 0, ncp[h] == -1,
                                   ncc[h] == -1)))''')

# new symbolic effect branches (before FENCE_NEW branch)
rep('''    elif op == "OP_FENCE_NEW":''',
    '''    elif op == "OP_CPIPE_NEW":
        c.append(z3.Implies(live & (kind[h] == z["K_LIBRARY"]),
                            z3.And(nk[h] == z["K_CPIPE"],
                                   npv[h] == 2)))
    elif op == "OP_SMP_NEW":
        c.append(z3.Implies(live & (kind[h] == z["K_DEVICE"]),
                            nk[h] == z["K_SMP"]))
    elif op == "OP_ENC_SETCPIPE":
        p = z3.If(off >= 0, off % z["N"], off)
        in_range = z3.And(p >= 0, p < z["N"])
        c.append(z3.Implies(live & (kind[h] == z["K_CMDBUF"]) &
                            (phase[h] == z["P_ACTIVE"]) &
                            in_range &
                            (kind_at(z, s, p) == z["K_CPIPE"]) &
                            (kind_at_valid(z, s, p) == 2),
                            ncc[h] == p))
    elif op == "OP_FENCE_NEW":''')

# kind_at_valid currently returns pipe_valid nested-If; the compute
# extension needs value 2 for cpipes — already generic, no change needed.

# ---------------------------------------------------------------- invariants
rep('''        # I7: fence signal is boolean''',
    '''        # I4b: compute pipeline implies a compute entry point
        iv.append(z3.Implies(s["kind"][i] == z["K_CPIPE"],
                             s["pipe_valid"][i] == 2))
        # I8: a cmdbuf's bound compute pipeline never dangles
        iv.append(z3.Implies(z3.And(s["kind"][i] == z["K_CMDBUF"],
                                   s["cb_cpipe"][i] >= 0),
                             kind_at(z, s, s["cb_cpipe"][i])
                             == z["K_CPIPE"]))
        # I7: fence signal is boolean''')

rep('''        iv.append(z3.Implies(s["cb_pipe"][i] >= 0,
                             s["kind"][i] == z["K_CMDBUF"]))''',
    '''        iv.append(z3.Implies(s["cb_pipe"][i] >= 0,
                             s["kind"][i] == z["K_CMDBUF"]))
        iv.append(z3.Implies(s["cb_cpipe"][i] >= 0,
                             s["kind"][i] == z["K_CMDBUF"]))''')

# mk_state: add the new field
rep('''             "cb_pipe": [z3.Int(f"cp_{tag}_{i}") for i in range(z["N"])]}''',
    '''             "cb_pipe": [z3.Int(f"cp_{tag}_{i}") for i in range(z["N"])],
             "cb_cpipe": [z3.Int(f"cc_{tag}_{i}") for i in range(z["N"])]}''')

# ------------------------------------------------------------- proof harness
rep('''    PROVE_OPS = ["OP_CB_NEW", "OP_COMMIT", "OP_TICK", "OP_BUF_NEW",
                 "OP_TEX_NEW", "OP_RELEASE", "OP_ENCODE",
                 "OP_RPASS_NEW", "OP_RPASS_ATTACH", "OP_ENC_RPASS",
                 "OP_PIPELINE_NEW", "OP_ENC_SETPIPE", "OP_ENC_DRAW",
                 "OP_ENC_BLIT", "OP_TEX_READ", "OP_FENCE_NEW",
                 "OP_FENCE_SIGNAL", "OP_FENCE_WAIT"]''',
    '''    PROVE_OPS = ["OP_CB_NEW", "OP_COMMIT", "OP_TICK", "OP_BUF_NEW",
                 "OP_TEX_NEW", "OP_RELEASE", "OP_ENCODE",
                 "OP_RPASS_NEW", "OP_RPASS_ATTACH", "OP_ENC_RPASS",
                 "OP_PIPELINE_NEW", "OP_ENC_SETPIPE", "OP_ENC_DRAW",
                 "OP_ENC_BLIT", "OP_TEX_READ", "OP_FENCE_NEW",
                 "OP_FENCE_SIGNAL", "OP_FENCE_WAIT",
                 "OP_CPIPE_NEW", "OP_ENC_COMPUTE", "OP_ENC_SETCPIPE",
                 "OP_ENC_DISPATCH", "OP_SMP_NEW"]''')

rep('''                "OP_FENCE_NEW", "OP_FENCE_SIGNAL", "OP_FENCE_WAIT"]''',
    '''                "OP_FENCE_NEW", "OP_FENCE_SIGNAL", "OP_FENCE_WAIT",
                "OP_CPIPE_NEW", "OP_ENC_COMPUTE", "OP_ENC_SETCPIPE",
                "OP_ENC_DISPATCH", "OP_SMP_NEW"]''')

rep('''        "OP_FENCE_NEW": {"K_DEVICE"},
        "OP_FENCE_SIGNAL": {"K_FENCE"},
        "OP_FENCE_WAIT": {"K_FENCE"},
    }''',
    '''        "OP_FENCE_NEW": {"K_DEVICE"},
        "OP_FENCE_SIGNAL": {"K_FENCE"},
        "OP_FENCE_WAIT": {"K_FENCE"},
        "OP_CPIPE_NEW": {"K_LIBRARY"},
        "OP_ENC_COMPUTE": {"K_CMDBUF"},
        "OP_ENC_SETCPIPE": {"K_CMDBUF"},
        "OP_ENC_DISPATCH": {"K_CMDBUF"},
        "OP_SMP_NEW": {"K_DEVICE"},
    }''')

# progressive_op: rank + compute-driving choices
rep('''        RANK = ["K_NONE", "K_LIBRARY", "K_PIPELINE", "K_TEXTURE",
                "K_FENCE", "K_RPASS", "K_BUFFER", "K_QUEUE",
                "K_CMDBUF", "K_DEVICE"]''',
    '''        RANK = ["K_NONE", "K_LIBRARY", "K_PIPELINE", "K_CPIPE",
                "K_SMP", "K_TEXTURE", "K_FENCE", "K_RPASS", "K_BUFFER",
                "K_QUEUE", "K_CMDBUF", "K_DEVICE"]''')

rep('''        if k == "K_DEVICE":
            return rng.choice(["OP_QUEUE_NEW", "OP_BUF_NEW", "OP_TEX_NEW",
                               "OP_LIB_NEW", "OP_RPASS_NEW", "OP_FENCE_NEW"]), best''',
    '''        if k == "K_DEVICE":
            return rng.choice(["OP_QUEUE_NEW", "OP_BUF_NEW", "OP_TEX_NEW",
                               "OP_LIB_NEW", "OP_RPASS_NEW", "OP_FENCE_NEW",
                               "OP_SMP_NEW"]), best''')

rep('''                if any(m.kind[i] == "K_PIPELINE" for i in range(4)):
                    enc.append("OP_ENC_SETPIPE")
                    if m.cb_pipe[best] >= 0:
                        enc += ["OP_ENC_DRAW", "OP_ENC_DRAW"]''',
    '''                if any(m.kind[i] == "K_PIPELINE" for i in range(4)):
                    enc.append("OP_ENC_SETPIPE")
                    if m.cb_pipe[best] >= 0:
                        enc += ["OP_ENC_DRAW", "OP_ENC_DRAW"]
                enc.append("OP_ENC_COMPUTE")
                if any(m.kind[i] == "K_CPIPE" for i in range(4)):
                    enc.append("OP_ENC_SETCPIPE")
                    if m.cb_cpipe[best] >= 0:
                        enc += ["OP_ENC_DISPATCH", "OP_ENC_DISPATCH"]''')

rep('''        if k == "K_LIBRARY":
            return "OP_PIPELINE_NEW", best''',
    '''        if k == "K_LIBRARY":
            return rng.choice(["OP_PIPELINE_NEW", "OP_CPIPE_NEW"]), best''')

# slot-targeting: point SETCPIPE at real cpipe slots; SMP coord modes
rep('''            elif op == "OP_ENC_DRAW":
                args["x"] = rng.choice([1, 3, 64, 1000])  # vc > 0
                args["y"] = rng.choice([1, 2, 4])          # ic >= 1''',
    '''            elif op == "OP_ENC_SETCPIPE":
                cps = [i for i in range(4) if m.kind[i] == "K_CPIPE"]
                if cps:
                    args["off"] = rng.choice(cps)
            elif op == "OP_ENC_DISPATCH":
                args["x"] = rng.choice([1, 4, 64])   # tgX > 0
                args["y"] = rng.choice([1, 2, 8])    # tgY > 0
                args["w"] = rng.choice([1, 2])       # tgZ > 0
            elif op == "OP_SMP_NEW":
                args["off"] = rng.choice([0, 1, 2])  # coord modes
            elif op == "OP_ENC_DRAW":
                args["x"] = rng.choice([1, 3, 64, 1000])  # vc > 0
                args["y"] = rng.choice([1, 2, 4])          # ic >= 1''')

# ------------------------------------------------------- new BMC properties
rep('''            # P1b: render-pass/draw/blit encodes accepted => ACTIVE
            if op in ("OP_ENC_RPASS", "OP_ENC_SETPIPE", "OP_ENC_DRAW",
                      "OP_ENC_BLIT") and rc == 0 \\
                    and phase_before != "P_ACTIVE":
                n_viol += 1''',
    '''            # P1b: render-pass/draw/blit/compute encodes => ACTIVE
            if op in ("OP_ENC_RPASS", "OP_ENC_SETPIPE", "OP_ENC_DRAW",
                      "OP_ENC_BLIT", "OP_ENC_COMPUTE", "OP_ENC_SETCPIPE") \\
                    and rc == 0 and phase_before != "P_ACTIVE":
                n_viol += 1
            # P3d: dispatch accepted => grid dims all > 0
            if op == "OP_ENC_DISPATCH" and rc == 0 and \\
                    not (args["x"] > 0 and args["y"] > 0
                         and args["w"] > 0):
                n_viol += 1
            # P8: dispatch accepted => the bound cpipe was live+valid
            # (cb_cpipe and the target's kind are untouched by dispatch,
            #  so post-state == call-time state for these fields)
            if op == "OP_ENC_DISPATCH" and rc == 0:
                pb = m.cb_cpipe[h]
                if pb < 0 or pb >= 4 or m.kind[pb] != "K_CPIPE" \\
                        or m.pipe_valid[pb] != 2:
                    n_viol += 1''')

rep('''    print(f"[P1/P3/P4] randomized safety over 20000 traces "''',
    '''    print(f"[P1/P3/P4/P8] randomized safety over 20000 traces "''')

open(P, "w").write(src)
print("patched %d -> %d bytes (+%d)" % (orig, len(src), len(src) - orig))
import ast
ast.parse(src)
print("syntax OK")
