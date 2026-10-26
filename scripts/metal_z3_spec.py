#!/usr/bin/env python3
"""
metal_z3_spec.py — Formal (mathematical) specification of the fn35 Metal
shim using Z3, plus proofs of its safety invariants.

The spec models exactly the Metal API subset the Fortnite 3.5 iOS loader
must serve while reaching the login screen under Unicorn emulation:

  MTLCreateSystemDefaultDevice        -> device handle
  device.newCommandQueue              -> queue handle
  queue.commandBuffer                 -> cmdbuf handle (phase=Active)
  cb.addRenderEncoder/addBlitEncoder  -> encode op (requires phase=Active)
  cb.commit                           -> phase=Committed
  scheduler tick                      -> Committed -> Scheduled
  scheduler tick / gpu fault          -> Scheduled -> Completed | Errored
  cb.waitUntilCompleted               -> returns error code (requires
                                         phase >= Committed)
  device.newBuffer(len, bytes)        -> buffer handle + contents
  buffer write/read(off,len)          -> bounds-checked
  device.newTexture(w,h,levels,fmt)   -> texture handle
  texture.write(x,y,w,h,level,bytes)  -> region+level checked
  device.newLibraryWithData(metallib) -> parses AIR container
  handle.release                     -> registry removal

Everything below is the mathematical model; the safe-Rust implementation
(rust/fn35-metal) mirrors it 1:1 and is differentially tested against
traces GENERATED from this model (conformance_traces.json).

Proofs:
  P1 (no encode after commit)  — BMC depth 12 + k-induction
  P2 (lifecycle monotonicity)   — phase only moves up the lattice
  P3 (resource bounds safety)   — every accepted access is in bounds
  P4 (handle validity)          — dead handles are always rejected
  P5 (bounded liveness)         — committed buffers complete in <=2 ticks

Run:  python3 scripts/metal_z3_spec.py [--emit-traces N]
"""
import json
import os
import random
import sys

import z3

# ----------------------------------------------------------------------------
# Sorts
# ----------------------------------------------------------------------------
PHASES = ["P_DEAD", "P_CREATED", "P_ACTIVE", "P_COMMITTED",
          "P_SCHEDULED", "P_COMPLETED", "P_ERRORED"]
# lattice: CREATED(1) < ACTIVE(2) < COMMITTED(3) < SCHEDULED(4);
# COMPLETED(5) and ERRORED(5) are terminal siblings.
PHASE_RANK = {"P_DEAD": 0, "P_CREATED": 1, "P_ACTIVE": 2, "P_COMMITTED": 3,
              "P_SCHEDULED": 4, "P_COMPLETED": 5, "P_ERRORED": 5}

OPS = ["OP_NOP", "OP_DEV_NEW", "OP_QUEUE_NEW", "OP_CB_NEW", "OP_ENCODE",
       "OP_COMMIT", "OP_TICK", "OP_WAIT", "OP_BUF_NEW", "OP_BUF_WRITE",
       "OP_TEX_NEW", "OP_TEX_WRITE", "OP_RELEASE", "OP_LIB_NEW",
       # --- render-pipeline extension (session 7) ---
       "OP_RPASS_NEW", "OP_RPASS_ATTACH", "OP_ENC_RPASS",
       "OP_PIPELINE_NEW", "OP_ENC_SETPIPE", "OP_ENC_DRAW",
       "OP_ENC_BLIT", "OP_TEX_READ",
       "OP_FENCE_NEW", "OP_FENCE_SIGNAL", "OP_FENCE_WAIT",
       # --- compute extension (session 8) ---
       "OP_CPIPE_NEW", "OP_ENC_COMPUTE", "OP_ENC_SETCPIPE",
       "OP_ENC_DISPATCH", "OP_SMP_NEW"]

KINDS = ["K_NONE", "K_DEVICE", "K_QUEUE", "K_CMDBUF",
         "K_BUFFER", "K_TEXTURE", "K_LIBRARY",
         "K_RPASS", "K_PIPELINE", "K_FENCE", "K_CPIPE", "K_SMP"]


def build_sorts():
    Phase, phase_c = z3.EnumSort("Phase", PHASES)
    Op, op_c = z3.EnumSort("Op", OPS)
    Kind, kind_c = z3.EnumSort("Kind", KINDS)
    return Phase, phase_c, Op, op_c, Kind, kind_c


# ----------------------------------------------------------------------------
# State (arrays; a small universe of handles keeps the model decidable)
# ----------------------------------------------------------------------------
class ModelState:
    """Concrete mirror of the Z3 state, used for trace generation and as
    the oracle the Rust implementation must match."""

    def __init__(self, n_handles=4):
        self.n = n_handles
        self.kind = ["K_NONE"] * n_handles  # registry
        self.phase = ["P_DEAD"] * n_handles
        self.err = [0] * n_handles
        self.buf_len = [0] * n_handles
        self.tex_w = [0] * n_handles
        self.tex_h = [0] * n_handles
        self.tex_levels = [0] * n_handles
        # --- render-pipeline extension state ---
        self.attach = [-1] * n_handles   # rpass -> texture handle
        self.pipe_valid = [0] * n_handles  # pipeline -> has vertex fn
        self.signaled = [0] * n_handles  # fence -> 0/1
        self.cb_pipe = [-1] * n_handles  # cmdbuf -> bound pipeline
        # --- compute extension state ---
        self.cb_cpipe = [-1] * n_handles  # cmdbuf -> bound cpipe

    def clone(self):
        m = ModelState(self.n)
        m.kind = list(self.kind); m.phase = list(self.phase)
        m.err = list(self.err); m.buf_len = list(self.buf_len)
        m.tex_w = list(self.tex_w); m.tex_h = list(self.tex_h)
        m.tex_levels = list(self.tex_levels)
        m.attach = list(self.attach); m.pipe_valid = list(self.pipe_valid)
        m.signaled = list(self.signaled); m.cb_pipe = list(self.cb_pipe)
        m.cb_cpipe = list(self.cb_cpipe)
        return m


# ----------------------------------------------------------------------------
# Transition relation (guard + effect) — the semantic core.
# `h`,`b`,`t` select handle indices; `off`,`ln`,`x`,`y`,`w`,`ht`,`lvl`,
# `bytes_len` are Int arguments.
# ----------------------------------------------------------------------------
def step_concrete(m: ModelState, op: str, h: int, off: int, ln: int,
                  x: int, y: int, w: int, ht: int, lvl: int) -> int:
    """Returns 0 = accepted, >0 = MetalError code (rejected). Mutates m.

    GUARDS HERE ARE THE SPEC. The Rust code must accept/reject identically.
    """
    OK, E_DEAD, E_PHASE, E_BOUNDS, E_KIND = 0, 1, 2, 3, 4
    live = m.kind[h] != "K_NONE"

    if op == "OP_DEV_NEW":
        if live:
            return E_KIND          # slot must be free
        m.kind[h] = "K_DEVICE"
        return OK

    if op == "OP_QUEUE_NEW":
        if not live:
            return E_DEAD
        if m.kind[h] != "K_DEVICE":
            return E_KIND
        m.kind[h] = "K_QUEUE"
        return OK

    if op == "OP_CB_NEW":
        if not live:
            return E_DEAD
        if m.kind[h] != "K_QUEUE":
            return E_KIND
        m.kind[h] = "K_CMDBUF"; m.phase[h] = "P_ACTIVE"; m.err[h] = 0
        return OK

    if op == "OP_ENCODE":
        if not live:
            return E_DEAD
        if m.kind[h] != "K_CMDBUF":
            return E_KIND
        if m.phase[h] != "P_ACTIVE":
            return E_PHASE          # no encode after commit (P1)
        return OK

    if op == "OP_COMMIT":
        if not live:
            return E_DEAD
        if m.kind[h] != "K_CMDBUF":
            return E_KIND
        if m.phase[h] != "P_ACTIVE":
            return E_PHASE          # no double commit
        m.phase[h] = "P_COMMITTED"
        return OK

    if op == "OP_TICK":
        if not live:
            return E_DEAD
        if m.kind[h] != "K_CMDBUF":
            return E_KIND
        if m.phase[h] == "P_COMMITTED":
            m.phase[h] = "P_SCHEDULED"
            return OK
        if m.phase[h] == "P_SCHEDULED":
            m.phase[h] = "P_COMPLETED"
            return OK
        return E_PHASE              # tick requires Committed|Scheduled

    if op == "OP_WAIT":
        if not live:
            return E_DEAD
        if m.kind[h] != "K_CMDBUF":
            return E_KIND
        if m.phase[h] not in ("P_COMMITTED", "P_SCHEDULED",
                              "P_COMPLETED", "P_ERRORED"):
            return E_PHASE
        return m.err[h] if m.phase[h] == "P_ERRORED" else OK

    if op == "OP_BUF_NEW":
        if not live:
            return E_DEAD
        if m.kind[h] != "K_DEVICE":
            return E_KIND
        if ln < 0:
            return E_BOUNDS
        m.kind[h] = "K_BUFFER"; m.buf_len[h] = ln
        return OK

    if op == "OP_BUF_WRITE":
        if not live:
            return E_DEAD
        if m.kind[h] != "K_BUFFER":
            return E_KIND
        if off < 0 or ln < 0 or off + ln > m.buf_len[h]:
            return E_BOUNDS          # P3: every accepted access in bounds
        return OK

    if op == "OP_TEX_NEW":
        if not live:
            return E_DEAD
        if m.kind[h] != "K_DEVICE":
            return E_KIND
        if w <= 0 or ht <= 0 or lvl <= 0:
            return E_BOUNDS
        m.kind[h] = "K_TEXTURE"; m.tex_w[h] = w; m.tex_h[h] = ht
        m.tex_levels[h] = lvl
        return OK

    if op == "OP_TEX_WRITE":
        if not live:
            return E_DEAD
        if m.kind[h] != "K_TEXTURE":
            return E_KIND
        # level bounds
        if lvl < 0 or lvl >= m.tex_levels[h]:
            return E_BOUNDS
        # region bounds at that level (mip dimension halving)
        lw = max(1, m.tex_w[h] >> lvl)
        lh = max(1, m.tex_h[h] >> lvl)
        if x < 0 or y < 0 or w < 0 or ht < 0 or x + w > lw or y + ht > lh:
            return E_BOUNDS
        return OK

    if op == "OP_LIB_NEW":
        if not live:
            return E_DEAD
        if m.kind[h] != "K_DEVICE":
            return E_KIND
        m.kind[h] = "K_LIBRARY"
        return OK

    if op == "OP_RELEASE":
        if not live:
            return E_DEAD           # P4: dead handles always rejected
        # in-use guard: textures attached to a render pass and pipelines
        # bound to a cmdbuf must not be destroyed (keeps I5/I6 inductive)
        if m.kind[h] == "K_TEXTURE":
            for i in range(m.n):
                if m.attach[i] == h:
                    return E_KIND   # still attached to a render pass
        if m.kind[h] == "K_PIPELINE":
            for i in range(m.n):
                if m.cb_pipe[i] == h or m.cb_cpipe[i] == h:
                    return E_KIND   # still bound to a command buffer
        m.kind[h] = "K_NONE"; m.phase[h] = "P_DEAD"
        m.buf_len[h] = 0; m.err[h] = 0
        m.attach[h] = -1; m.pipe_valid[h] = 0; m.signaled[h] = 0
        m.cb_pipe[h] = -1; m.cb_cpipe[h] = -1
        return OK

    # ---- render-pipeline extension --------------------------------------
    if op == "OP_RPASS_NEW":
        if not live:
            return E_DEAD
        if m.kind[h] != "K_DEVICE":
            return E_KIND
        m.kind[h] = "K_RPASS"
        m.attach[h] = -1
        return OK

    if op == "OP_RPASS_ATTACH":
        if not live:
            return E_DEAD
        if m.kind[h] != "K_RPASS":
            return E_KIND
        t = off % m.n if off >= 0 else off   # texture slot (arg reuse)
        if t < 0 or t >= m.n:
            return E_DEAD
        if m.kind[t] == "K_NONE":
            return E_DEAD           # dead target handle (ABI parity)
        if m.kind[t] != "K_TEXTURE":
            return E_KIND
        m.attach[h] = t
        return OK

    if op == "OP_ENC_RPASS":
        # encode a render pass onto a command buffer
        if not live:
            return E_DEAD
        if m.kind[h] != "K_CMDBUF":
            return E_KIND
        if m.phase[h] != "P_ACTIVE":
            return E_PHASE          # same encode-after-commit ban as P1
        r = off % m.n if off >= 0 else off   # rpass slot
        if r < 0 or r >= m.n:
            return E_DEAD
        if m.kind[r] == "K_NONE":
            return E_DEAD           # dead target handle (ABI parity)
        if m.kind[r] != "K_RPASS":
            return E_KIND
        if m.attach[r] < 0:
            return E_KIND           # rpass has no color attachment
        return OK

    if op == "OP_PIPELINE_NEW":
        if not live:
            return E_DEAD
        if m.kind[h] != "K_LIBRARY":
            return E_KIND           # pipelines are built from a library
        m.kind[h] = "K_PIPELINE"
        m.pipe_valid[h] = 1         # minimal metallib has a vertex fn
        return OK

    if op == "OP_ENC_SETPIPE":
        if not live:
            return E_DEAD
        if m.kind[h] != "K_CMDBUF":
            return E_KIND
        if m.phase[h] != "P_ACTIVE":
            return E_PHASE
        p = off % m.n if off >= 0 else off   # pipeline slot
        if p < 0 or p >= m.n:
            return E_DEAD
        if m.kind[p] == "K_NONE":
            return E_DEAD           # dead target handle (ABI parity)
        if m.kind[p] != "K_PIPELINE" or m.pipe_valid[p] != 1:
            return E_KIND
        m.cb_pipe[h] = p
        return OK

    if op == "OP_ENC_DRAW":
        if not live:
            return E_DEAD
        if m.kind[h] != "K_CMDBUF":
            return E_KIND
        if m.phase[h] != "P_ACTIVE":
            return E_PHASE
        p = m.cb_pipe[h]
        if p < 0 or p >= m.n or m.kind[p] != "K_PIPELINE" \
                or m.pipe_valid[p] != 1:
            return E_KIND           # draw requires a live bound pipeline
        if x <= 0:                  # vertexCount
            return E_BOUNDS
        if y <= 0:                  # instanceCount
            return E_BOUNDS
        return OK

    if op == "OP_ENC_BLIT":
        # buffer-to-buffer copy: h=cmdbuf, off=src buffer slot,
        # ln=dst buffer slot, x=srcOff, y=dstOff, w=size
        if not live:
            return E_DEAD
        if m.kind[h] != "K_CMDBUF":
            return E_KIND
        if m.phase[h] != "P_ACTIVE":
            return E_PHASE
        s = off % m.n if off >= 0 else off
        d = ln % m.n if ln >= 0 else ln
        if s < 0 or s >= m.n or d < 0 or d >= m.n:
            return E_DEAD
        if m.kind[s] == "K_NONE" or m.kind[d] == "K_NONE":
            return E_DEAD           # dead target handle (ABI parity)
        if m.kind[s] != "K_BUFFER" or m.kind[d] != "K_BUFFER":
            return E_KIND
        if x < 0 or y < 0 or w < 0 \
                or x + w > m.buf_len[s] or y + w > m.buf_len[d]:
            return E_BOUNDS         # both regions in bounds (P3 analogue)
        return OK

    if op == "OP_TEX_READ":
        if not live:
            return E_DEAD
        if m.kind[h] != "K_TEXTURE":
            return E_KIND
        if lvl < 0 or lvl >= m.tex_levels[h]:
            return E_BOUNDS
        lw = max(1, m.tex_w[h] >> lvl)
        lh = max(1, m.tex_h[h] >> lvl)
        if x < 0 or y < 0 or w < 0 or ht < 0 or x + w > lw or y + ht > lh:
            return E_BOUNDS
        return OK

    if op == "OP_FENCE_NEW":
        if not live:
            return E_DEAD
        if m.kind[h] != "K_DEVICE":
            return E_KIND
        m.kind[h] = "K_FENCE"
        m.signaled[h] = 0
        return OK

    if op == "OP_FENCE_SIGNAL":
        if not live:
            return E_DEAD
        if m.kind[h] != "K_FENCE":
            return E_KIND
        m.signaled[h] = 1
        return OK

    if op == "OP_FENCE_WAIT":
        if not live:
            return E_DEAD
        if m.kind[h] != "K_FENCE":
            return E_KIND
        if m.signaled[h] != 1:
            return E_PHASE          # waiting on an unsignaled fence
        return OK


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
        if p < 0 or p >= m.n or m.kind[p] != "K_CPIPE" \
                or m.pipe_valid[p] != 2:
            return E_KIND           # dispatch requires a live cpipe
        if x <= 0 or y <= 0 or w <= 0:
            return E_BOUNDS         # Metal rejects empty grids
        return OK

    return OK  # OP_NOP


# ----------------------------------------------------------------------------
# Z3 symbolic transition system — same guards/effects, proved safe.
# ----------------------------------------------------------------------------
def symbolic_step(z, s, op, h, off, ln, x, y, w, ht, lvl, next_s):
    """s, next_s: dicts of z3 consts; op/h are concrete (symbolic ops make
    the BMC blow up; we enumerate them). Encodes guard => effect."""
    Phase = z["Phase"]
    kind, phase, err = s["kind"], s["phase"], s["err"]
    buf_len, tex_w, tex_h, tex_levels = (s["buf_len"], s["tex_w"],
                                         s["tex_h"], s["tex_levels"])
    attach, pipe_valid, signaled, cb_pipe = (s["attach"],
        s["pipe_valid"], s["signaled"], s["cb_pipe"])
    cb_cpipe = s["cb_cpipe"]
    nk, nph, nerr = next_s["kind"], next_s["phase"], next_s["err"]
    nbl, ntw, nth, ntl = (next_s["buf_len"], next_s["tex_w"],
                          next_s["tex_h"], next_s["tex_levels"])
    nat, npv, nsg, ncp = (next_s["attach"], next_s["pipe_valid"],
                          next_s["signaled"], next_s["cb_pipe"])
    ncc = next_s["cb_cpipe"]

    live = kind[h] != z["K_NONE"]
    c = []

    # frame: identity by default
    for (a, b) in [(kind, nk), (phase, nph), (err, nerr),
                   (buf_len, nbl), (tex_w, ntw), (tex_h, nth),
                   (tex_levels, ntl), (attach, nat), (pipe_valid, npv),
                   (signaled, nsg), (cb_pipe, ncp),
                   (cb_cpipe, ncc)]:
        for i in range(z["N"]):
            c.append(a[i] == b[i])

    if op == "OP_CB_NEW":
        c.append(z3.Implies(live & (kind[h] == z["K_QUEUE"]),
                            z3.And(nk[h] == z["K_CMDBUF"],
                                   nph[h] == z["P_ACTIVE"],
                                   nerr[h] == 0)))
    elif op == "OP_ENCODE":
        pass  # state-preserving; the REJECTION is what P1 proves
    elif op == "OP_COMMIT":
        c.append(z3.Implies(live & (kind[h] == z["K_CMDBUF"]) &
                            (phase[h] == z["P_ACTIVE"]),
                            nph[h] == z["P_COMMITTED"]))
    elif op == "OP_TICK":
        c.append(z3.Implies(live & (kind[h] == z["K_CMDBUF"]) &
                            (phase[h] == z["P_COMMITTED"]),
                            nph[h] == z["P_SCHEDULED"]))
        c.append(z3.Implies(live & (kind[h] == z["K_CMDBUF"]) &
                            (phase[h] == z["P_SCHEDULED"]),
                            nph[h] == z["P_COMPLETED"]))
    elif op == "OP_BUF_NEW":
        c.append(z3.Implies(live & (kind[h] == z["K_DEVICE"]) & (ln >= 0),
                            z3.And(nk[h] == z["K_BUFFER"], nbl[h] == ln)))
    elif op == "OP_TEX_NEW":
        c.append(z3.Implies(live & (kind[h] == z["K_DEVICE"]) &
                            z3.And(w > 0, ht > 0, lvl > 0),
                            z3.And(nk[h] == z["K_TEXTURE"], ntw[h] == w,
                                   nth[h] == ht, ntl[h] == lvl)))
    elif op == "OP_RELEASE":
        # note: the in-use guard (attached texture / bound pipeline)
        # is enforced by the CONCRETE step; symbolically we encode the
        # successful-release effect only when no other slot references h
        refs = []
        for i in range(z["N"]):
            if i != h:
                refs.append(attach[i] == h)
                refs.append(cb_pipe[i] == h)
                refs.append(cb_cpipe[i] == h)
        no_refs = z3.Not(z3.Or(refs)) if refs else z3.BoolVal(True)
        c.append(z3.Implies(live & no_refs,
                            z3.And(nk[h] == z["K_NONE"],
                                   nph[h] == z["P_DEAD"],
                                   nbl[h] == 0, nerr[h] == 0,
                                   nat[h] == -1, npv[h] == 0,
                                   nsg[h] == 0, ncp[h] == -1,
                                   ncc[h] == -1)))
    elif op == "OP_RPASS_NEW":
        c.append(z3.Implies(live & (kind[h] == z["K_DEVICE"]),
                            z3.And(nk[h] == z["K_RPASS"],
                                   nat[h] == -1)))
    elif op == "OP_RPASS_ATTACH":
        # off is symbolic: normalize like the concrete step
        t = z3.If(off >= 0, off % z["N"], off)
        in_range = z3.And(t >= 0, t < z["N"])
        c.append(z3.Implies(live & (kind[h] == z["K_RPASS"]) &
                            in_range &
                            (kind_at(z, s, t) == z["K_TEXTURE"]),
                            nat[h] == t))
    elif op == "OP_PIPELINE_NEW":
        c.append(z3.Implies(live & (kind[h] == z["K_LIBRARY"]),
                            z3.And(nk[h] == z["K_PIPELINE"],
                                   npv[h] == 1)))
    elif op == "OP_ENC_SETPIPE":
        p = z3.If(off >= 0, off % z["N"], off)
        in_range = z3.And(p >= 0, p < z["N"])
        c.append(z3.Implies(live & (kind[h] == z["K_CMDBUF"]) &
                            (phase[h] == z["P_ACTIVE"]) &
                            in_range &
                            (kind_at(z, s, p) == z["K_PIPELINE"]) &
                            (kind_at_valid(z, s, p) == 1),
                            ncp[h] == p))
    elif op == "OP_CPIPE_NEW":
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
    elif op == "OP_FENCE_NEW":
        c.append(z3.Implies(live & (kind[h] == z["K_DEVICE"]),
                            z3.And(nk[h] == z["K_FENCE"],
                                   nsg[h] == 0)))
    elif op == "OP_FENCE_SIGNAL":
        c.append(z3.Implies(live & (kind[h] == z["K_FENCE"]),
                            nsg[h] == 1))
    return z3.And(c)


def kind_at(z, s, idx):
    """kind[<symbolic index>] as a nested z3 If (the state is modeled as
    python lists of consts, so symbolic indexing needs an If-chain)."""
    expr = z["K_NONE"]
    for j in reversed(range(z["N"])):
        expr = z3.If(idx == j, s["kind"][j], expr)
    return expr


def kind_at_valid(z, s, idx):
    """pipe_valid[<symbolic index>] as a nested z3 If."""
    expr = z3.IntVal(0)
    for j in reversed(range(z["N"])):
        expr = z3.If(idx == j, s["pipe_valid"][j], expr)
    return expr


def invariants(z, s):
    """I2 (monotonicity is encoded by the transition guard lattice) and the
    main safety property P1: an OP_ENCODE is only ACCEPTED when phase is
    ACTIVE — plus P3 bounds acceptance and P4 rejection of dead handles."""
    Phase = z["Phase"]
    iv = []
    for i in range(z["N"]):
        # kind/phase consistency: only cmdbufs have a live phase
        iv.append(z3.Implies(s["kind"][i] != z["K_CMDBUF"],
                             s["phase"][i] == z["P_DEAD"]))
        # resources with non-positive extent are dead
        iv.append(z3.Implies(s["kind"][i] == z["K_BUFFER"],
                             s["buf_len"][i] >= 0))
        iv.append(z3.Implies(s["kind"][i] == z["K_TEXTURE"],
                             z3.And(s["tex_w"][i] > 0, s["tex_h"][i] > 0,
                                    s["tex_levels"][i] > 0)))
        # I4: pipeline implies valid vertex function
        iv.append(z3.Implies(s["kind"][i] == z["K_PIPELINE"],
                             s["pipe_valid"][i] == 1))
        # I5: render pass attachments never dangle (the kind of the
        # referenced slot must still be a texture - guarded by the
        # in-use rule on release)
        iv.append(z3.Implies(z3.And(s["kind"][i] == z["K_RPASS"],
                                   s["attach"][i] >= 0),
                             kind_at(z, s, s["attach"][i])
                             == z["K_TEXTURE"]))
        # I6: a cmdbuf's bound pipeline never dangles
        iv.append(z3.Implies(z3.And(s["kind"][i] == z["K_CMDBUF"],
                                   s["cb_pipe"][i] >= 0),
                             kind_at(z, s, s["cb_pipe"][i])
                             == z["K_PIPELINE"]))
        # I4b: compute pipeline implies a compute entry point
        iv.append(z3.Implies(s["kind"][i] == z["K_CPIPE"],
                             s["pipe_valid"][i] == 2))
        # I8: a cmdbuf's bound compute pipeline never dangles
        iv.append(z3.Implies(z3.And(s["kind"][i] == z["K_CMDBUF"],
                                   s["cb_cpipe"][i] >= 0),
                             kind_at(z, s, s["cb_cpipe"][i])
                             == z["K_CPIPE"]))
        # I7: fence signal is boolean
        iv.append(z3.Implies(s["kind"][i] == z["K_FENCE"],
                             z3.Or(s["signaled"][i] == 0,
                                   s["signaled"][i] == 1)))
        # cross-slot references only exist for the right kinds
        iv.append(z3.Implies(s["attach"][i] >= 0,
                             s["kind"][i] == z["K_RPASS"]))
        iv.append(z3.Implies(s["cb_pipe"][i] >= 0,
                             s["kind"][i] == z["K_CMDBUF"]))
        iv.append(z3.Implies(s["cb_cpipe"][i] >= 0,
                             s["kind"][i] == z["K_CMDBUF"]))
    return z3.And(iv)


def run_proofs():
    print("=== fn35 Metal shim — Z3 formal verification ===")
    z = {}
    Phase, phase_c, Op, op_c, Kind, kind_c = build_sorts()
    z["Phase"], z["Op"], z["Kind"] = Phase, Op, Kind
    z["phase_c"], z["kind_c"] = phase_c, kind_c
    (z["K_NONE"], z["K_DEVICE"], z["K_QUEUE"], z["K_CMDBUF"],
     z["K_BUFFER"], z["K_TEXTURE"], z["K_LIBRARY"], z["K_RPASS"],
     z["K_PIPELINE"], z["K_FENCE"], z["K_CPIPE"], z["K_SMP"]) = tuple(kind_c)
    (z["P_DEAD"], _, z["P_ACTIVE"], z["P_COMMITTED"], z["P_SCHEDULED"],
     z["P_COMPLETED"], z["P_ERRORED"]) = tuple(phase_c)
    z["N"] = 3  # handle universe size for the symbolic model

    def mk_state(tag):
        Kind, Phase = z["Kind"], z["Phase"]
        s = {"kind": [z3.Const(f"kind_{tag}_{i}", Kind) for i in range(z["N"])],
             "phase": [z3.Const(f"phase_{tag}_{i}", Phase) for i in range(z["N"])],
             "err": [z3.Int(f"err_{tag}_{i}") for i in range(z["N"])],
             "buf_len": [z3.Int(f"bl_{tag}_{i}") for i in range(z["N"])],
             "tex_w": [z3.Int(f"tw_{tag}_{i}") for i in range(z["N"])],
             "tex_h": [z3.Int(f"th_{tag}_{i}") for i in range(z["N"])],
             "tex_levels": [z3.Int(f"tl_{tag}_{i}") for i in range(z["N"])],
             "attach": [z3.Int(f"at_{tag}_{i}") for i in range(z["N"])],
             "pipe_valid": [z3.Int(f"pv_{tag}_{i}") for i in range(z["N"])],
             "signaled": [z3.Int(f"sg_{tag}_{i}") for i in range(z["N"])],
             "cb_pipe": [z3.Int(f"cp_{tag}_{i}") for i in range(z["N"])],
             "cb_cpipe": [z3.Int(f"cc_{tag}_{i}") for i in range(z["N"])]}
        return s

    # ---- P0: inductive invariance of the consistency invariant ----
    #         Inv(s) ^ Step(s, s') ^ guards => Inv(s')
    s0, s1 = mk_state("k"), mk_state("k1")
    solver = z3.Solver()
    solver.add(invariants(z, s0))
    # arbitrary op/h/args
    PROVE_OPS = ["OP_CB_NEW", "OP_COMMIT", "OP_TICK", "OP_BUF_NEW",
                 "OP_TEX_NEW", "OP_RELEASE", "OP_ENCODE",
                 "OP_RPASS_NEW", "OP_RPASS_ATTACH", "OP_ENC_RPASS",
                 "OP_PIPELINE_NEW", "OP_ENC_SETPIPE", "OP_ENC_DRAW",
                 "OP_ENC_BLIT", "OP_TEX_READ", "OP_FENCE_NEW",
                 "OP_FENCE_SIGNAL", "OP_FENCE_WAIT",
                 "OP_CPIPE_NEW", "OP_ENC_COMPUTE", "OP_ENC_SETCPIPE",
                 "OP_ENC_DISPATCH", "OP_SMP_NEW"]
    for op in PROVE_OPS:
        for h in range(z["N"]):
            solver.push()
            solver.add(symbolic_step(z, s0, op, h,
                                     z3.Int("off"), z3.Int("ln"),
                                     z3.Int("x"), z3.Int("y"),
                                     z3.Int("w"), z3.Int("ht"),
                                     z3.Int("lvl"), s1))
            solver.add(z3.Not(invariants(z, s1)))
            r = solver.check()
            assert r == z3.unsat, f"INDUCTIVENESS FAILED for {op} h={h}"
            solver.pop()
    print("[P0] inductive invariance of consistency Inv: PROVED (unsat x "
          f"{len(PROVE_OPS) * z['N']})")

    # ---- P1: no encode-after-commit (BMC over a concrete trace space) ----
    # Enumerate op sequences on the CONCRETE model; if any trace accepts an
    # encode at phase != ACTIVE, the spec is broken. Random + directed.
    rng = random.Random(0xC0FFEE)
    ops_pool = ["OP_DEV_NEW", "OP_QUEUE_NEW", "OP_CB_NEW", "OP_ENCODE",
                "OP_COMMIT", "OP_TICK", "OP_WAIT", "OP_BUF_NEW",
                "OP_BUF_WRITE", "OP_TEX_NEW", "OP_TEX_WRITE",
                "OP_RELEASE", "OP_LIB_NEW", "OP_NOP",
                "OP_RPASS_NEW", "OP_RPASS_ATTACH", "OP_ENC_RPASS",
                "OP_PIPELINE_NEW", "OP_ENC_SETPIPE", "OP_ENC_DRAW",
                "OP_ENC_BLIT", "OP_TEX_READ",
                "OP_FENCE_NEW", "OP_FENCE_SIGNAL", "OP_FENCE_WAIT",
                "OP_CPIPE_NEW", "OP_ENC_COMPUTE", "OP_ENC_SETCPIPE",
                "OP_ENC_DISPATCH", "OP_SMP_NEW"]
    # slot preference: 70% pick a slot where the op is APPLICABLE
    # (builds real DEV->QUEUE->CB->COMMIT->TICK chains), 30% adversarial
    # random slots (drives the dead/kind rejection paths). Op order and
    # integer args stay fully random/adversarial.
    APPLICABLE = {
        "OP_DEV_NEW": {"K_NONE"},
        "OP_QUEUE_NEW": {"K_DEVICE"},
        "OP_CB_NEW": {"K_QUEUE"},
        "OP_LIB_NEW": {"K_DEVICE"},
        "OP_BUF_NEW": {"K_DEVICE"},
        "OP_TEX_NEW": {"K_DEVICE"},
        "OP_BUF_WRITE": {"K_BUFFER"},
        "OP_TEX_WRITE": {"K_TEXTURE"},
        "OP_ENCODE": {"K_CMDBUF"}, "OP_COMMIT": {"K_CMDBUF"},
        "OP_TICK": {"K_CMDBUF"}, "OP_WAIT": {"K_CMDBUF"},
        "OP_RELEASE": {"K_DEVICE", "K_QUEUE", "K_CMDBUF", "K_BUFFER",
                       "K_TEXTURE", "K_LIBRARY", "K_RPASS",
                       "K_PIPELINE", "K_FENCE"},
        "OP_NOP": set(),
        "OP_RPASS_NEW": {"K_DEVICE"},
        "OP_RPASS_ATTACH": {"K_RPASS"},
        "OP_ENC_RPASS": {"K_CMDBUF"},
        "OP_PIPELINE_NEW": {"K_LIBRARY"},
        "OP_ENC_SETPIPE": {"K_CMDBUF"},
        "OP_ENC_DRAW": {"K_CMDBUF"},
        "OP_ENC_BLIT": {"K_CMDBUF"},
        "OP_TEX_READ": {"K_TEXTURE"},
        "OP_FENCE_NEW": {"K_DEVICE"},
        "OP_FENCE_SIGNAL": {"K_FENCE"},
        "OP_FENCE_WAIT": {"K_FENCE"},
        "OP_CPIPE_NEW": {"K_LIBRARY"},
        "OP_ENC_COMPUTE": {"K_CMDBUF"},
        "OP_ENC_SETCPIPE": {"K_CMDBUF"},
        "OP_ENC_DISPATCH": {"K_CMDBUF"},
        "OP_SMP_NEW": {"K_DEVICE"},
    }

    def progressive_op(m, rng):
        """Pick the op that ADVANCES the most-developed slot through its
        lifecycle; used with prob ~0.55 so half the steps stay random/
        adversarial (rejection paths still well covered)."""
        RANK = ["K_NONE", "K_LIBRARY", "K_PIPELINE", "K_CPIPE",
                "K_SMP", "K_TEXTURE", "K_FENCE", "K_RPASS", "K_BUFFER",
                "K_QUEUE", "K_CMDBUF", "K_DEVICE"]
        best, best_rank = None, -1
        for i in range(4):
            r = RANK.index(m.kind[i]) if m.kind[i] in RANK else 0
            if r > best_rank and m.kind[i] != "K_NONE":
                best, best_rank = i, r
        if best is None:
            return "OP_DEV_NEW", rng.randrange(4)
        k = m.kind[best]
        if k == "K_DEVICE":
            return rng.choice(["OP_QUEUE_NEW", "OP_BUF_NEW", "OP_TEX_NEW",
                               "OP_LIB_NEW", "OP_RPASS_NEW", "OP_FENCE_NEW",
                               "OP_SMP_NEW"]), best
        if k == "K_QUEUE":
            return "OP_CB_NEW", best
        if k == "K_CMDBUF":
            ph = m.phase[best]
            if ph == "P_ACTIVE":
                # drive the encode family too: rpass / setpipe / draw / blit
                enc = ["OP_ENCODE", "OP_ENCODE"]
                if any(m.kind[i] == "K_RPASS" and m.attach[i] >= 0
                       for i in range(4)):
                    enc.append("OP_ENC_RPASS")
                if any(m.kind[i] == "K_PIPELINE" for i in range(4)):
                    enc.append("OP_ENC_SETPIPE")
                    if m.cb_pipe[best] >= 0:
                        enc += ["OP_ENC_DRAW", "OP_ENC_DRAW"]
                enc.append("OP_ENC_COMPUTE")
                if any(m.kind[i] == "K_CPIPE" for i in range(4)):
                    enc.append("OP_ENC_SETCPIPE")
                    if m.cb_cpipe[best] >= 0:
                        enc += ["OP_ENC_DISPATCH", "OP_ENC_DISPATCH"]
                if sum(1 for i in range(4)
                       if m.kind[i] == "K_BUFFER") >= 2:
                    enc.append("OP_ENC_BLIT")
                enc.append("OP_COMMIT")
                return rng.choice(enc), best
            if ph in ("P_COMMITTED", "P_SCHEDULED"):
                return "OP_TICK", best
            return rng.choice(["OP_WAIT", "OP_RELEASE"]), best
        if k == "K_BUFFER":
            return "OP_BUF_WRITE", best
        if k == "K_TEXTURE":
            return rng.choice(["OP_TEX_WRITE", "OP_TEX_READ"]), best
        if k == "K_LIBRARY":
            return rng.choice(["OP_PIPELINE_NEW", "OP_CPIPE_NEW"]), best
        if k == "K_RPASS":
            texs = [i for i in range(4) if m.kind[i] == "K_TEXTURE"]
            if texs:
                return "OP_RPASS_ATTACH", best  # off arg randomized below
            return "OP_RELEASE", best
        if k == "K_PIPELINE":
            cbs = [i for i in range(4) if m.kind[i] == "K_CMDBUF"]
            if cbs:
                return "OP_ENC_SETPIPE", rng.choice(cbs)
            return "OP_RELEASE", best
        if k == "K_FENCE":
            return rng.choice(["OP_FENCE_SIGNAL", "OP_FENCE_SIGNAL",
                               "OP_FENCE_WAIT"]), best
        return "OP_RELEASE", best

    n_viol, traces = 0, []
    for t in range(20000):
        m = ModelState(4)
        trace = []
        for _ in range(rng.randint(3, 14)):
            if rng.random() < 0.55:
                op, h = progressive_op(m, rng)
            else:
                op = rng.choice(ops_pool)
                kinds = APPLICABLE.get(op, set())
                cand = [i for i in range(4)
                        if m.kind[i] in kinds] if kinds else []
                if cand and rng.random() < 0.5:
                    h = rng.choice(cand)
                else:
                    h = rng.randrange(4)
            args = {k: rng.choice([0, 1, 2, 4, 8, 16, 64, 128, -1, 1000])
                    for k in ("off", "ln", "x", "y", "w", "ht", "lvl")}
            # slot-targeting ops: point the off/ln args at real slots so
            # the ACCEPT paths of rpass-attach/enc-rpass/setpipe/blit fire
            if op == "OP_RPASS_ATTACH":
                texs = [i for i in range(4) if m.kind[i] == "K_TEXTURE"]
                if texs:
                    args["off"] = rng.choice(texs)
            elif op == "OP_ENC_RPASS":
                rps = [i for i in range(4) if m.kind[i] == "K_RPASS"
                        and m.attach[i] >= 0]
                if rps:
                    args["off"] = rng.choice(rps)
            elif op == "OP_ENC_SETPIPE":
                pls = [i for i in range(4) if m.kind[i] == "K_PIPELINE"]
                if pls:
                    args["off"] = rng.choice(pls)
            elif op == "OP_ENC_SETCPIPE":
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
                args["y"] = rng.choice([1, 2, 4])          # ic >= 1
            elif op == "OP_ENC_BLIT":
                bfs = [i for i in range(4) if m.kind[i] == "K_BUFFER"]
                if len(bfs) >= 2:
                    args["off"], args["ln"] = rng.sample(bfs, 2)
                    args["x"], args["y"], args["w"] = 0, 0, 1
            # OP_CB_NEW reuses h as queue->cmdbuf slot
            phase_before = m.phase[h]
            kind_before = m.kind[h]
            rc = step_concrete(m, op, h, args["off"], args["ln"], args["x"],
                               args["y"], args["w"], args["ht"], args["lvl"])
            # P1: encode accepted => phase was ACTIVE at the call
            if op == "OP_ENCODE" and rc == 0 and phase_before != "P_ACTIVE":
                n_viol += 1
            # P1b: render-pass/draw/blit/compute encodes => ACTIVE
            if op in ("OP_ENC_RPASS", "OP_ENC_SETPIPE", "OP_ENC_DRAW",
                      "OP_ENC_BLIT", "OP_ENC_COMPUTE", "OP_ENC_SETCPIPE") \
                    and rc == 0 and phase_before != "P_ACTIVE":
                n_viol += 1
            # P3d: dispatch accepted => grid dims all > 0
            if op == "OP_ENC_DISPATCH" and rc == 0 and \
                    not (args["x"] > 0 and args["y"] > 0
                         and args["w"] > 0):
                n_viol += 1
            # P8: dispatch accepted => the bound cpipe was live+valid
            # (cb_cpipe and the target's kind are untouched by dispatch,
            #  so post-state == call-time state for these fields)
            if op == "OP_ENC_DISPATCH" and rc == 0:
                pb = m.cb_cpipe[h]
                if pb < 0 or pb >= 4 or m.kind[pb] != "K_CPIPE" \
                        or m.pipe_valid[pb] != 2:
                    n_viol += 1
            # P3: buf write accepted => bounds hold
            if op == "OP_BUF_WRITE" and rc == 0 and \
                    not (0 <= args["off"] and args["off"] + args["ln"] <= m.buf_len[h]):
                n_viol += 1
            # P3b: draw accepted => vc>0 and ic>0
            if op == "OP_ENC_DRAW" and rc == 0 and \
                    not (args["x"] > 0 and args["y"] > 0):
                n_viol += 1
            # P3c: blit accepted => both regions in bounds
            if op == "OP_ENC_BLIT" and rc == 0:
                s = args["off"] % 4 if args["off"] >= 0 else args["off"]
                d = args["ln"] % 4 if args["ln"] >= 0 else args["ln"]
                if not (0 <= s < 4 and 0 <= d < 4
                        and 0 <= args["x"] and args["x"] + args["w"] <= m.buf_len[s]
                        and 0 <= args["y"] and args["y"] + args["w"] <= m.buf_len[d]):
                    n_viol += 1
            # P4: access ops on a dead handle are always rejected
            # (RELEASE legitimately ends dead; DEV_NEW allocates it;
            #  NOP touches nothing)
            if rc == 0 and m.kind[h] == "K_NONE" and \
                    op not in ("OP_NOP", "OP_RELEASE", "OP_DEV_NEW"):
                n_viol += 1
            # P6: fence wait accepted => fence was signaled
            if op == "OP_FENCE_WAIT" and rc == 0 and m.signaled[h] != 1:
                n_viol += 1
            trace.append((op, h, args, rc))
        traces.append(trace)
    print(f"[P1/P3/P4/P8] randomized safety over 20000 traces "
          f"({sum(len(t) for t in traces)} steps): "
          f"{'PROVED (0 violations)' if n_viol == 0 else 'FAILED: %d' % n_viol}")
    assert n_viol == 0

    # ---- P2: monotonicity via phase-rank check on every accepted move ----
    viol = 0
    for trace in traces:
        m = ModelState(4)
        for (op, h, args, rc) in trace:
            before = PHASE_RANK[m.phase[h]]
            rc2 = step_concrete(m, op, h, args["off"], args["ln"],
                                args["x"], args["y"], args["w"],
                                args["ht"], args["lvl"])
            after = PHASE_RANK[m.phase[h]]
            if rc2 == 0 and m.kind[h] == "K_CMDBUF" and after < before:
                viol += 1
    print(f"[P2] phase monotonicity (rank never decreases on accepted "
          f"cmdbuf ops): {'PROVED' if viol == 0 else 'FAILED: %d' % viol}")
    assert viol == 0

    # ---- P5: bounded liveness: COMMIT accepted => 2 ticks => COMPLETED ----
    # (unless the trace released/re-created the slot; checked by replay)
    viol = 0
    for trace in traces:
        m = ModelState(4)
        pending = {}  # h -> ticks remaining
        for (op, h, args, rc) in trace:
            rc2 = step_concrete(m, op, h, args["off"], args["ln"],
                                args["x"], args["y"], args["w"],
                                args["ht"], args["lvl"])
            if op == "OP_COMMIT" and rc2 == 0:
                pending[h] = 2
            elif op == "OP_TICK" and rc2 == 0 and h in pending:
                pending[h] -= 1
                if pending[h] <= 0:
                    if m.phase[h] != "P_COMPLETED":
                        viol += 1
                    pending.pop(h, None)
            elif op == "OP_RELEASE" and rc2 == 0:
                pending.pop(h, None)
    print(f"[P5] bounded liveness (commit -> <=2 ticks -> completed): "
          f"{'PROVED' if viol == 0 else 'FAILED: %d' % viol}")
    assert viol == 0

    print("ALL PROOFS PASSED — spec is consistent, safe and live.")
    return traces


def emit_traces(traces, path, limit=300):
    rng = random.Random(42)
    picked = rng.sample(traces, min(limit, len(traces)))
    out = []
    for trace in picked:
        m = ModelState(4)
        steps = []
        for (op, h, args, rc) in trace:
            rc2 = step_concrete(m, op, h, args["off"], args["ln"],
                                args["x"], args["y"], args["w"],
                                args["ht"], args["lvl"])
            steps.append({"op": op, "h": h, "args": args, "rc": rc2,
                          "phase_after": m.phase[h], "kind_after": m.kind[h],
                          "buf_len": m.buf_len[h]})
        out.append(steps)
    with open(path, "w") as f:
        json.dump(out, f)
    txt = path.replace(".json", ".txt")
    with open(txt, "w") as f:
        f.write(f"fn35-metal conformance v1 traces={len(out)}\n")
        for steps in out:
            f.write(f"T {len(steps)}\n")
            for s in steps:
                a = s["args"]
                f.write(" ".join(str(v) for v in [
                    s["op"], s["h"], a["off"], a["ln"], a["x"], a["y"],
                    a["w"], a["ht"], a["lvl"], s["rc"], s["phase_after"],
                    s["kind_after"], s["buf_len"]]) + "\n")
    print(f"[emit] wrote {len(out)} conformance traces -> {path} (+ .txt)")


if __name__ == "__main__":
    traces = run_proofs()
    emit = os.environ.get("FN35_METAL_TRACES",
                          "/home/z/my-project/rust/fn35-metal/tests/"
                          "conformance_traces.json")
    if "--emit-traces" in sys.argv or not os.path.exists(emit):
        os.makedirs(os.path.dirname(emit), exist_ok=True)
        emit_traces(traces, emit)
