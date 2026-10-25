#!/usr/bin/env python3
"""FN3.5 integrated loader.

Runs the Fortnite 3.5 (iOS ARM64) executable on a synthetic XNU-like
environment built on Unicorn:

  * dyld substitute: fills GOT / lazy pointer slots and applies dyld
    bind opcodes so every import resolves into a Python "stub farm"
  * kernel substitute: BSD syscalls + Mach VM (svc #0x80, x16 = nr)
  * libSystem substitute: C library, pthreads, GCD, TLS, ObjC, dyld
  * cooperative thread scheduler (round-robin slices + blocking ops)
  * sandbox filesystem exposing the app bundle (pak files included)

The game binary is never modified (read-only). We only observe what it
requests and answer it, the Wine / touchHLE approach.
"""
import os
import inspect
import struct
import sys
import time
from collections import deque, Counter

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from unicorn import (Uc, UC_ARCH_ARM64, UC_MODE_ARM, UC_HOOK_INTR,
                     UC_HOOK_MEM_INVALID, UC_HOOK_CODE, UcError,
                     UC_HOOK_BLOCK,
                     UC_MEM_FETCH_UNMAPPED, UC_MEM_FETCH_PROT)
import unicorn.arm64_const as a64
import capstone

from fn35_macho import (MachO, S_MOD_INIT_FUNC_POINTERS, align_up,
                        align_down)
from fn35_clib import IMPL, cfunc, set_cstr_reader
from fn35_pakfs import PakFS
from fn35_native import build_native_stubs
import fn35_ioslib  # noqa: F401 -- registers implementations into IMPL
import fn35_gles
import fn35_objc    # noqa: F401 -- overrides the trace-grade ObjC stubs
import fn35_zlib    # noqa: F401 -- zlib inflate/deflate for the pak index
from fn35_ioslib import DATA_SYMS, sysctl_bytes, SYSCTL_BY_NAME
from fn35_objc import ObjCRuntime

# merge the zlib implementations into the master table (setdefault so
# the loader's own IMPL entries, if any, win)
fn35_zlib.register(IMPL)

PAGE = 0x1000
MASK64 = 0xFFFFFFFFFFFFFFFF

STUB_BASE = 0x0000500000000000
STUB_WINDOW = 0x1000000                     # 16 MB stub farm (RWX)
DATA_FARM = 0x0000510000000000
FARM_WINDOW = 0x1000000                     # 16 MB data cells
MAGIC_BASE = 0x0000520000000000
MAGIC_INIT_RET = MAGIC_BASE + 0             # svc #0xF000
MAGIC_THREAD_RET = MAGIC_BASE + 4           # svc #0xF001
MAGIC_CB_RET = MAGIC_BASE + 8               # svc #0xF002

HEAP_BASE = 0x0000600000000000
HEAP_PREMAP = 0x20000000                     # 512 MB pre-mapped
HEAP_LIMIT = HEAP_BASE + 0x40000000          # 1 GB
VM_BASE = 0x0000620000000000
VM_PREMAP = 0x10000000                       # 256 MB
VM_LIMIT = VM_BASE + 0x40000000
MMAP_BASE = 0x0000640000000000
MMAP_PREMAP = 0x8000000                       # 128 MB
MMAP_LIMIT = MMAP_BASE + 0x20000000

STACK_BASE = 0x0000700000000000
STACK_SLOT = 0x400000                        # 4 MB per thread

SLICE_INSTR = 5_000_000
NS_PER_SLICE = 2_500_000                     # virtual 2.5 ms per slice
MAX_THREADS = 96

GUEST_BUNDLE = ("/private/var/containers/Bundle/Application/"
                "6B3F2A11-4C4E-4E22-9A04-7D9E1A55C0FF/FortniteClient.app")
GUEST_DATA = ("/var/mobile/Containers/Data/Application/"
              "8A1D5E77-1234-4E56-9BC0-42DE2C1F9AB7")


def _build_regs():
    xs = []
    for i in range(31):
        if i == 29:
            c = getattr(a64, "UC_ARM64_REG_X29", None)
            if c is None:
                c = getattr(a64, "UC_ARM64_REG_FP")
        elif i == 30:
            c = getattr(a64, "UC_ARM64_REG_X30", None)
            if c is None:
                c = getattr(a64, "UC_ARM64_REG_LR")
        else:
            c = getattr(a64, "UC_ARM64_REG_X%d" % i)
        xs.append(c)
    qs = [getattr(a64, "UC_ARM64_REG_Q%d" % i) for i in range(32)
          if hasattr(a64, "UC_ARM64_REG_Q%d" % i)]
    # CRITICAL: NZCV (condition flags) MUST be saved/restored per thread.
    # A slice can end exactly between a `cmp` and its `b.cc` -- the next
    # thread's first arithmetic write would otherwise hijack the branch
    # decision when the waiter resumes (observed: intermittent crashes
    # at DIFFERENT bit-loop sites each run with garbage x8/x16, e.g.
    # pak-index decode loops running with x8=0xc02f50 where the loop
    # bound was 0x3c).
    save = list(xs) + [a64.UC_ARM64_REG_SP, a64.UC_ARM64_REG_PC] + qs
    nzcv = getattr(a64, "UC_ARM64_REG_NZCV", None)
    if nzcv is not None:
        save.append(nzcv)
    return xs, qs, save


XREGS, QREGS, SAVE_REGS = _build_regs()
CS = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_LITTLE_ENDIAN)


class EmuThread:
    __slots__ = ("tid", "name", "stack_base", "stack_size", "regs", "pc",
                 "state", "wait", "wake_ns", "extra", "retval",
                 "approx_instr", "errno_cell", "specific", "tlv_bases",
                 "created_at", "eagl_ctx")

    def __init__(self, tid, name, stack_base, stack_size):
        self.tid = tid
        self.name = name
        self.stack_base = stack_base
        self.stack_size = stack_size
        self.regs = None
        self.pc = 0
        self.state = "ready"
        self.wait = None
        self.wake_ns = None
        self.extra = None
        self.retval = 0
        self.approx_instr = 0
        self.errno_cell = 0
        self.specific = {}
        self.tlv_bases = {}
        self.created_at = time.time()

    def __repr__(self):
        st = self.state
        if self.wait:
            st += ":%s" % (self.wait[0],)
        return "<thr %s tid=%x pc=%x %s>" % (self.name, self.tid,
                                             self.pc or 0, st)


class _DeadThread(EmuThread):
    def __init__(self):
        EmuThread.__init__(self, 0, "dead", 0, 0)
        self.state = "done"


def _singleton_drv(l):
    """Create engine singletons whose only creation path is gated off in
    our environment, using the engine's own create wrappers. Returns a
    generator for the py-call driver (composed with magic-init)."""

    def drv():
        for wrapper, global_addr in [(0x102db4364, 0x10552ea60)]:
            obj = yield ("call", wrapper, ())
            if obj:
                l.w64(global_addr, obj)
                l.console("[preinit] singleton 0x%x -> 0x%x"
                          % (global_addr, obj))
            else:
                l.console("[preinit] wrapper 0x%x returned NULL" % wrapper)
    return drv()


class FNLoader:
    def __init__(self, macho_path, sandbox, budget=90.0, trace_n=0,
                 live_log=True, slice_instr=SLICE_INSTR):
        self.macho_path = macho_path
        self.macho = MachO(macho_path)
        self.macho.load_symbols()
        self.sandbox = sandbox
        self.budget = budget
        self.live_log = live_log
        self.slice_instr = slice_instr

        self.uc = Uc(UC_ARCH_ARM64, UC_MODE_ARM)

        # ---- NULL-tolerance zero page -------------------------------
        # [0, 0x10000) RW (NOT exec): data reads of NULL+offset return
        # 0 instead of faulting, so code that derefs a missing TLS/pool
        # pointer degenerates gracefully (fields read as zero) instead
        # of dying. Instruction fetch at low addresses still faults
        # (UC_MEM_FETCH_PROT -> on_fetch) so PC=0 stays detectable.
        try:
            self.uc.mem_map(0, 0x10000, 3)  # READ|WRITE, no EXEC
        except UcError:
            pass

        # pak overlay (lazily armed in prepare(); None until then)
        self.pakfs = None
        self.dir_handles = {}
        self.dir_seq = 0
        self.native_stubs = {}

        # regions
        self.heap_top = HEAP_BASE
        self.heap_mapped_end = HEAP_BASE
        self.vm_top = VM_BASE
        self.vm_mapped_end = VM_BASE
        self.mmap_top = MMAP_BASE
        self.mmap_mapped_end = MMAP_BASE
        self.farm_off = DATA_FARM
        self.farm_mapped_end = DATA_FARM
        self.stack_top = STACK_BASE
        self.stack_pools = {}

        # stub farm
        self.stubs = {}
        self.addr2stub = {}
        self.stub_order = []
        self.data_cells = {}
        self.cstr_cells = {}

        # threads / scheduler
        self.threads = {}
        self.order = []
        self.rr = 0
        self.cur = None
        self.tid_seq = 0x1010

        # ipc-ish state
        self.mutexes = {}
        self.sems = {}
        self.tls_seq = 0
        self.sem_seq = 0
        self.cf_seq = 0
        self.atexit_list = []
        self.py_stack = []
        self.pending_py = None

        # clock
        self.vclock = int(time.time() * 1e9) & 0x7FFFFFFFFFFFFFFF

        # bookkeeping
        self.stub_calls = Counter()
        self.syscall_calls = Counter()
        self.unknown_syscalls = Counter()
        self.missing_stubs = Counter()
        self._arity = {}
        self.fault_counts = Counter()
        self.fault_log = deque(maxlen=64)
        self.stub_ring = deque(maxlen=4096)  # last stub calls (diagnostics)
        self.gl_trace = deque(maxlen=512)
        self.objc_trace = deque(maxlen=256)
        self.mach_trace = deque(maxlen=256)
        self.thread_trace = deque(maxlen=256)
        self.ring = deque(maxlen=8000)
        self.fatal_msg = None
        self.exit_code = None
        self.stop_reason = None
        self.phase = "inits"
        self.init_index = 0
        self.inits_done = 0
        self.trace_remaining = trace_n
        self._code_hook = None
        self._block_hook = None
        self._trace_hook = None
        self.trace_ring = deque(maxlen=40000)
        self.block_ring = deque(maxlen=64)
        self._sym_sorted = None

        self.env = {
            "HOME": "/var/mobile",
            "TMPDIR": "/var/mobile/tmp",
            "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
            "USER": "mobile",
            "LOGNAME": "mobile",
            "SHELL": "/bin/sh",
            "LANG": "en_US.UTF-8",
            "TERM": "xterm",
            "TZ": "UTC",
        }
        self.fds = {0: ("console", "r"), 1: ("console", "w"),
                    2: ("console", "w")}
        self.next_fd = 3

        self.tlv_template = self.macho.tlv_template()
        set_cstr_reader(self.gcstr)
        self.objc = ObjCRuntime(self)

    # ---- ObjC class binding support (used by link) ----
    def objc_bind_target(self, symbol):
        """OBJC_CLASS_$_X / OBJC_METACLASS_$_X -> ghost class cell."""
        s = symbol[1:] if symbol.startswith("_") else symbol
        if s.startswith("OBJC_CLASS_$_"):
            name = s[13:]
            if not name:
                return None
            return self.objc.ghost(name, self.objc.ghost_super_of(name))
        if s.startswith("OBJC_METACLASS_$_"):
            name = s[17:]
            if not name:
                return None
            return self.objc.ghost(name, self.objc.ghost_super_of(name))
        return None

    def _install_fake_singletons(self):
        # ARM64: mov w0,#1 ; ret  → returns 1 from every virtual call
        stub_code = struct.pack("<II", 0x52800020, 0xD65F03C0)
        stub = self.data_cell("fakevt.method", 16)
        self.wrb(stub, stub_code)
        # vtable: 32 slots all pointing at the stub
        vt = self.data_cell("fakevt.table", 32 * 8)
        for i in range(32):
            self.w64(vt + 8 * i, stub)
        # the fake object: isa/vtable ptr at +0
        for gaddr, tag in ((0x10552ea60, "i18n"),):
            obj = self.data_cell("fakeobj." + tag, 128)
            self.w64(obj, vt)
            self.w64(gaddr, obj)
            self.console("[preinit] fake singleton for 0x%x (vt=0x%x obj=0x%x)"
                        % (gaddr, vt, obj))

    # ================= logging =====================================
    def console(self, msg):
        line = str(msg).rstrip()
        self.ring.append(line)
        self._last_console_wall = time.time()
        # pak-mount milestone: arm the lastmile ring so the crash that
        # follows lands with full instruction history
        if "attempting to mount" in line and \
                not getattr(self, "_pak_lm_armed", False):
            self._pak_lm_armed = True
            try:
                self.arm_lastmile_trace(2_000_000)
            except Exception:
                pass
        if self.live_log:
            try:
                print(line, flush=True)
            except Exception:
                pass

    def heartbeat(self):
        """Silent-phase watchdog: when nothing logs for 60s, print one
        line showing what the scheduler is actually doing (thread + pc
        symbol + counters). Pure-CPU guest loops (zlib inflate, hashing)
        otherwise look exactly like a hang."""
        now = time.time()
        last = getattr(self, "_last_console_wall", None)
        if last is None:
            self._last_console_wall = now
            return
        hb = float(os.environ.get("FN35_HB_SECS", "30"))
        if now - last < hb:
            return
        self._last_console_wall = now   # fire at most once per 30s
        t = self.cur
        # memory footprint: unicorn maps guest pages lazily on the host
        try:
            regs = self.uc.mem_regions()
            mapped = sum(r[1] - r[0] + 1 for r in regs) // (1024 * 1024)
            nreg = len(regs)
        except Exception:
            mapped = nreg = 0
        states = {}
        top = []
        for th in self.threads.values():
            states[th.state] = states.get(th.state, 0) + 1
            top.append((th.approx_instr, th))
        top.sort(key=lambda kv: -kv[0])
        tops = "; ".join("%s(0x%x) %dM %s@%s" % (
            th.name[:22], th.tid, th.approx_instr // 1000000,
            th.state, th.wait) for _, th in top[:3])
        # where is each top thread parked/spinning? (saved regs at last
        # switch — for the RUNNING thread it's the switch-out point, good
        # enough to identify a spin loop)
        for _, th in top[:3]:
            if th.pc:
                nm2, sa2 = self.nearest_symbol(th.pc)
                tops += " [%s pc=0x%x %s+0x%x]" % (th.name[:14],
                                                   th.pc,
                                                   (nm2 or "?")[:30],
                                                   th.pc - (sa2 or 0))
        if t is not None:
            pc = t.pc
            nm, sa = self.nearest_symbol(pc)
            self.console("[hb] silent 30s: thr=%r tid=0x%x pc=0x%x (%s+0x%x) "
                         "instr~%dM threads=%s mapped=%dMB/%dregions"
                         % (t.name, t.tid, pc, (nm or "?")[:44],
                            pc - (sa or 0), t.approx_instr // 1000000,
                            states, mapped, nreg))
        else:
            self.console("[hb] silent 30s: idle scheduler threads=%s "
                         "mapped=%dMB/%dregions" % (states, mapped, nreg))
        self.console("[hb] top3: %s" % tops)

    def warn(self, msg):
        self.console("[warn] " + str(msg))

    def fatal(self, msg):
        if not self.fatal_msg:
            self.fatal_msg = str(msg)
        self.console("[FATAL] " + self.fatal_msg)
        try:
            self.uc.emu_stop()
        except Exception:
            pass

    def trace_gl(self, name, args):
        self.gl_trace.append("%s(%s)" % (
            name, ", ".join("0x%x" % a for a in args if a)))

    def trace_objc(self, msg):
        self.objc_trace.append(msg)

    def trace_mach(self, msg):
        self.mach_trace.append(msg)

    def trace_thread(self, msg):
        self.thread_trace.append(msg)

    # ================= memory primitives ============================
    def map_range(self, addr, size):
        """Map [addr, addr+size) in unicorn, tolerating already-mapped
        pages. uc.mem_map is ATOMIC: it fails if ANY page in the range
        is already mapped. Swallowing that failure whole used to leave
        HOLES in the data farm: farm_mapped_end advanced but pages were
        missing -> later writes raised UcError(addr, size) (segAJ bug:
        glGetString(GL_EXTENSIONS) -> cstring_cell -> dead MainAppThread).
        Fast path maps the whole span; fallback maps page by page."""
        start = align_down(addr, PAGE)
        end = align_up(addr + size, PAGE)
        try:
            self.uc.mem_map(start, end - start)
            return
        except UcError:
            pass
        p = start
        while p < end:
            try:
                self.uc.mem_map(p, PAGE)
            except UcError:
                pass          # page already mapped: fine, skip it
            p += PAGE

    def _ensure(self, cur_end, want_end, limit):
        if want_end <= cur_end:
            return cur_end
        want_end = min(want_end, limit)
        if want_end > cur_end:
            self.map_range(cur_end, want_end - cur_end)
        return want_end

    def rdb(self, addr, n):
        try:
            return bytes(self.uc.mem_read(addr, n))
        except UcError:
            if self.maybe_grow(addr & ~0xFFF):
                return bytes(self.uc.mem_read(addr, n))
            raise

    def wrb(self, addr, b):
        data = bytes(b)
        try:
            self.uc.mem_write(addr, data)
        except UcError:
            if self.maybe_grow(addr & ~0xFFF):
                self.uc.mem_write(addr, data)
            else:
                raise

    def rd64(self, a):
        return struct.unpack("<Q", self.rdb(a, 8))[0]

    def rd32(self, a):
        return struct.unpack("<I", self.rdb(a, 4))[0]

    def rd16(self, a):
        return struct.unpack("<H", self.rdb(a, 2))[0]

    def rd8(self, a):
        return self.rdb(a, 1)[0]

    def w64(self, a, v):
        self.wrb(a, struct.pack("<Q", v & MASK64))

    def w32(self, a, v):
        self.wrb(a, struct.pack("<I", v & 0xFFFFFFFF))

    def w16(self, a, v):
        self.wrb(a, struct.pack("<H", v & 0xFFFF))

    def w8(self, a, v):
        self.wrb(a, bytes([v & 0xFF]))

    def gcstr(self, addr, maxlen=1 << 20):
        if not addr:
            return ""
        out = b""
        while len(out) < maxlen:
            chunk = self.rdb(addr + len(out), 256)
            z = chunk.find(b"\x00")
            if z >= 0:
                out += chunk[:z]
                break
            out += chunk
        return out.decode("utf-8", "replace")

    # ---- registers
    def reg_x(self, i):
        return self.uc.reg_read(XREGS[i])

    def reg_sp(self):
        return self.uc.reg_read(a64.UC_ARM64_REG_SP)

    def reg_pc(self):
        return self.uc.reg_read(a64.UC_ARM64_REG_PC)

    def reg_lr(self):
        return self.uc.reg_read(XREGS[30])

    def reg_d(self, i):
        q = self.uc.reg_read(QREGS[i]) if i < len(QREGS) else 0
        return struct.unpack("<d", struct.pack("<Q", q & MASK64))[0]

    def wreg_x(self, i, v):
        self.uc.reg_write(XREGS[i], v & MASK64)
        # TCG-desync fix: reg_write inside a hook callback can sit in
        # unicorn's deferred state while the current TB keeps executing
        # with STALE register values (observed: CRC/AES table loops
        # faulting at impossible addresses right after stub returns).
        # Reading the register back forces the commit. Cheap: only on
        # stub-call frequency, not per instruction.
        self.uc.reg_read(XREGS[i])

    def wreg_sp(self, v):
        self.uc.reg_write(a64.UC_ARM64_REG_SP, v & MASK64)
        self.uc.reg_read(a64.UC_ARM64_REG_SP)

    def wreg_pc(self, v):
        self.uc.reg_write(a64.UC_ARM64_REG_PC, v & MASK64)
        self.uc.reg_read(a64.UC_ARM64_REG_PC)

    def wd0(self, f):
        d = getattr(a64, "UC_ARM64_REG_D0", None)
        if d is not None:
            self.uc.reg_write(d, struct.unpack("<Q", struct.pack("<d", f))[0])
        elif QREGS:
            self.uc.reg_write(QREGS[0], struct.unpack(
                "<Q", struct.pack("<d", f))[0])

    # ================= region allocators ===========================
    def heap_alloc(self, size, zero=True):
        # bump-only allocator: fresh pages are always zero (no reuse)
        size = max(16, align_up(size, 16))
        total = size + 16
        if self.heap_top + total > HEAP_LIMIT:
            self.fatal("emulated heap exhausted (1 GB)")
            return 0
        self.heap_mapped_end = self._ensure(
            self.heap_mapped_end, self.heap_top + total, HEAP_LIMIT)
        p = self.heap_top + 16
        self.w64(self.heap_top, size)
        self.heap_top += total
        return p

    def heap_size_of(self, p):
        try:
            return self.rd64(p - 16)
        except Exception:
            return 0

    def vm_alloc(self, size):
        # 64 KB alignment like mmap_alloc: Mach-VM pages can also end up
        # inside FMallocBinned2 pools.
        size = max(0x10000, align_up(size, 0x10000))
        self.vm_top = align_up(self.vm_top, 0x10000)
        if self.vm_top + size > VM_LIMIT:
            self.fatal("emulated vm region exhausted")
            return 0
        self.vm_mapped_end = self._ensure(self.vm_mapped_end,
                                          self.vm_top + size, VM_LIMIT)
        p = self.vm_top
        self.vm_top += size
        self.wrb(p, b"\x00" * size)
        return p

    def mmap_alloc(self, size):
        # FMallocBinned2 masks block pointers down to 64 KB boundaries to
        # find its pool blocks, so every mapping we hand out MUST be
        # 64 KB aligned (and a multiple of 64 KB keeps future ones aligned
        # too). Misaligned pools -> "pointer we didn't allocate" floods.
        size = max(0x10000, align_up(size, 0x10000))
        self.mmap_top = align_up(self.mmap_top, 0x10000)
        if self.mmap_top + size > MMAP_LIMIT:
            self.fatal("emulated mmap region exhausted")
            return 0
        self.mmap_mapped_end = self._ensure(
            self.mmap_mapped_end, self.mmap_top + size, MMAP_LIMIT)
        p = self.mmap_top
        self.mmap_top += size
        return p

    def data_cell(self, name, size=64, init=b""):
        a = self.data_cells.get(name)
        if a is not None:
            return a
        size = align_up(max(size, 16), 64)
        if self.farm_off + size > MAGIC_BASE - 0x10000:
            self.fatal("data farm exhausted")
            return 0
        self.farm_mapped_end = self._ensure(
            self.farm_mapped_end, self.farm_off + size, MAGIC_BASE - 0x10000)
        a = self.farm_off
        self.farm_off += size
        self.data_cells[name] = a
        if init:
            try:
                self.wrb(a, bytes(init)[:size])
            except Exception:
                # DO NOT leave a poisoned cache entry (empty cell that
                # every future caller returns without writing): drop it
                # so the next request reallocates cleanly.
                self.data_cells.pop(name, None)
                raise
        return a

    def cstring_cell(self, name, s):
        a = self.cstr_cells.get(name)
        if a is not None:
            return a
        b = s.encode() + b"\x00"
        a = self.data_cell("cstr." + name, len(b), b)
        self.cstr_cells[name] = a
        return a

    def stack_alloc(self, size):
        lst = self.stack_pools.get(align_up(size, PAGE))
        if lst:
            base = lst.pop()
            try:
                self.wrb(base, b"\x00" * align_up(size, PAGE))
            except Exception:
                pass
            return base
        p = self.stack_top
        self.stack_top += align_up(size, PAGE)
        self.map_range(p, self.stack_top - p)
        return p

    def stack_release(self, base, size):
        self.stack_pools.setdefault(align_up(size, PAGE), []).append(base)

    def maybe_grow(self, addr):
        """Auto-map pages for regions we manage on demand."""
        for lo, cur_end, hi in (
                (HEAP_BASE, self.heap_mapped_end, HEAP_LIMIT),
                (VM_BASE, self.vm_mapped_end, VM_LIMIT),
                (DATA_FARM, self.farm_mapped_end, MAGIC_BASE - 0x10000)):
            if lo <= addr < hi:
                if addr >= cur_end:
                    self.map_range(cur_end,
                                   align_up(addr + PAGE, PAGE) - cur_end)
                    new_end = align_up(addr + PAGE, PAGE)
                    if lo == HEAP_BASE:
                        self.heap_mapped_end = max(self.heap_mapped_end,
                                                   new_end)
                    elif lo == VM_BASE:
                        self.vm_mapped_end = max(self.vm_mapped_end, new_end)
                    else:
                        self.farm_mapped_end = max(self.farm_mapped_end,
                                                   new_end)
                else:
                    # bookkeeping claims this is mapped, but a swallowed
                    # mem_map failure can leave holes. VERIFY and repair.
                    try:
                        self.uc.mem_read(addr, 1)
                    except Exception:
                        self.map_range(align_down(addr, PAGE),
                                       align_up(addr + PAGE, PAGE)
                                       - align_down(addr, PAGE))
                return True
        # UE4's binned allocator manages this VA window itself and indexes
        # it with 4 GB pool strides -- serve it infinite zero pages
        if MMAP_BASE <= addr < MMAP_BASE + 0x400000000:   # 16 GB window
            self.map_range(addr, PAGE)
            return True
        if addr >= STACK_BASE and addr < self.stack_top + PAGE:
            self.map_range(addr, PAGE)
            return True
        return False

    # ================= stub farm & linking =========================
    def make_svc_stub(self, name):
        """Force-create the farm svc stub for a name (Python dispatch),
        even if a native routine shadows it. Returns its address."""
        a = self.stubs.get(name)
        if a is not None:
            return a
        idx = len(self.stub_order)
        if idx >= 0xEFFF:
            self.fatal("stub farm exhausted")
            return STUB_BASE
        a = STUB_BASE + idx * 16
        self.wrb(a, struct.pack("<I", 0xD4000001 | (idx << 5)))
        self.stubs[name] = a
        self.addr2stub[a] = name
        self.stub_order.append(name)
        return a

    def get_stub(self, name):
        a = self.native_stubs.get(name)
        if a is not None:
            return a
        a = self.stubs.get(name)
        if a is not None:
            return a
        idx = len(self.stub_order)
        if idx >= 0xEFFF:                     # below magic svc imms
            self.fatal("stub farm exhausted")
            return STUB_BASE
        a = STUB_BASE + idx * 16
        # each stub is a single `svc #idx` instruction: dispatch via INTR
        self.wrb(a, struct.pack("<I", 0xD4000001 | (idx << 5)))
        self.stubs[name] = a
        self.addr2stub[a] = name
        self.stub_order.append(name)
        return a

    def link(self):
        mo = self.macho
        n_slots = 0
        n_oc = 0
        for slot, symidx in mo.iter_pointer_slots():
            if symidx is None:
                continue
            if symidx & 0x80000000 or symidx & 0x40000000:
                continue
            name = mo.sym_name(symidx)
            if not name:
                continue
            oc = self.objc_bind_target(name)
            if oc is not None:
                try:
                    self.w64(slot, oc)
                    n_slots += 1
                    n_oc += 1
                except UcError:
                    pass
                continue
            try:
                self.w64(slot, self.get_stub(name))
                n_slots += 1
            except UcError:
                pass
        n_binds = 0
        for rec in mo.parse_binds():
            if rec.btype != 1:
                continue
            seg = mo.seg_by_index(rec.seg_index)
            if not seg:
                continue
            target = seg.vmaddr + rec.seg_offset
            sym = rec.symbol
            oc = self.objc_bind_target(sym)
            if oc is not None:
                try:
                    self.w64(target, oc)
                    n_binds += 1
                except UcError:
                    pass
                continue
            is_data = (sym in DATA_SYMS
                       or sym.startswith("_ZGV") or sym.startswith("__ZGV")
                       or sym == "__DefaultRuneLocale"
                       or sym.endswith("2idE"))   # std locale facet ids
            if is_data:
                # real zero storage: C++ static guards, rune tables, ids
                val = self.data_cell("d." + sym,
                                     1024 if sym == "__DefaultRuneLocale"
                                     else 256)
            else:
                val = self.get_stub(sym)
            try:
                self.w64(target, (val + rec.addend) & MASK64)
                n_binds += 1
            except UcError:
                pass
        # special data cells (SAME "d." prefix the binds use!)
        import random
        self.w64(self.data_cell("d.___stack_chk_guard", 16,
                                random.randbytes(8)), 0)
        self.w64(self.data_cell("d._stdout", 16), 0x1001)
        self.w64(self.data_cell("d._stderr", 16), 0x1002)
        self.w64(self.data_cell("d._stdin", 16), 0x1003)
        self.w64(self.data_cell("d._mach_task_self_", 16), 0x0B03)
        return n_slots, n_binds

    # ================= threads =====================================
    def thread_count(self):
        return len([t for t in self.threads.values() if t.state != "done"])

    def new_thread(self, pc, arg, name="thread", stack_size=3 << 20):
        if self.thread_count() >= MAX_THREADS:
            self.warn("thread cap (%d) reached; dropping new '%s'"
                      % (MAX_THREADS, name))
            return _DeadThread()
        tid = self.tid_seq
        self.tid_seq += 8
        if not hasattr(self, "created_names"):
            from collections import Counter as _C
            self.created_names = _C()
        self.created_names[name] += 1
        base = self.stack_alloc(stack_size)
        t = EmuThread(tid, name, base, stack_size)
        top = base + stack_size - 0x100
        top &= ~0xF
        t.errno_cell = self.data_cell("errno.%x" % tid, 16)
        regs = {}
        for r in SAVE_REGS:
            regs[r] = 0
        regs[XREGS[0]] = arg & MASK64
        regs[XREGS[30]] = MAGIC_THREAD_RET
        regs[a64.UC_ARM64_REG_SP] = top
        regs[a64.UC_ARM64_REG_PC] = pc
        t.regs = regs
        t.pc = pc
        self.threads[tid] = t
        self.order.append(tid)
        return t

    def thread_done(self, t):
        t.state = "done"
        for o in list(self.threads.values()):
            if o.state == "blocked" and o.wait and o.wait[0] == "join" \
                    and o.wait[1] == t.tid:
                if o.extra:
                    try:
                        self.w64(o.extra, t.retval & MASK64)
                    except Exception:
                        pass
                o.state = "ready"
        self.trace_thread("thread done: %r (retval=0x%x)" % (t, t.retval))
        # prune short-lived finished threads so the scheduler stays O(live)
        if (t.name.startswith("of.") or t.name.startswith("dispatch_")) \
                and t.tid in self.threads:
            self.stack_release(t.stack_base, t.stack_size)
            del self.threads[t.tid]
            try:
                self.order.remove(t.tid)
            except ValueError:
                pass
        if t is self.cur:
            self.stop_reason = "thread_exit"
            try:
                self.uc.emu_stop()
            except Exception:
                pass

    def block_cur(self, kind, key, wake_ns=None, extra=None, ret=0):
        t = self.cur
        if t is None:
            return
        t.state = "blocked"
        t.wait = (kind, key)
        t.wake_ns = wake_ns
        t.extra = extra
        self.stop_reason = "switch"
        try:
            self.uc.emu_stop()
        except Exception:
            pass

    def wake(self, kind, key, one=True):
        for t in list(self.threads.values()):
            if t.state == "blocked" and t.wait and t.wait[0] == kind \
                    and t.wait[1] == key:
                if kind == "mutex":
                    st = self.mutexes.setdefault(
                        key, {"owner": None, "count": 0})
                    st["owner"] = t
                    st["count"] = max(st["count"], 1)
                elif kind == "cond" and t.extra:
                    st = self.mutexes.setdefault(
                        t.extra, {"owner": None, "count": 0})
                    st["owner"] = t
                    st["count"] = max(st["count"], 1)
                t.state = "ready"
                t.wait = None
                if one:
                    break

    # ================= native-callback driver =====================
    def py_call(self, gen, ret=0):
        """Run a python driver that can call native code:
        gen yields ("call", pc, args); StopIteration.value -> final x0."""
        self.pending_py = (gen, ret)

    def setup_call(self, pc, args, lr):
        for i in range(8):
            self.wreg_x(i, args[i] if i < len(args) else 0)
        self.uc.reg_write(XREGS[30], lr & MASK64)
        self.wreg_pc(pc)

    # ================= hooks =======================================
    def env_get(self, name):
        return self.env.get(name)

    def env_set(self, name, val):
        self.env[name] = val

    def env_unset(self, name):
        self.env.pop(name, None)

    CODE_PATCHES = [
        # Global-shader verification fatal: this cook is METAL-only
        # (global_sf_metal.metallib); we force -es2 for llvmpipe, so
        # GLSL_ES2_IOS has no cooked global shaders and the verify
        # asserts "Missing global shader FStereoLayerPS, Please make
        # sure cooking was successful."
        # Definitive fix: the WHOLE verify function starts at
        # 0x1023575d4 (prologue verified; called at 0x10284529c and the
        # caller ignores the return value). Patch its first instruction
        # to `ret` -- verification becomes a no-op for BOTH internal
        # loops and BOTH "Missing global shader" fatal logs.
        # FIX 2025-10-25: the original bytes c0 03 9f d6 are RETAA
        # (return w/ pointer-auth). Unicorn 2.1.4 CANNOT execute RETAA:
        # it wipes SP to 0 and does a fetch at PC=0 (verified in
        # isolation: MEM_INVALID access=21 addr=0x0 pc=0x0, sp=0).
        # Plain RET = c0 03 5f d6. The patch never executed until the
        # weakobj guard let the engine reach this call path (segBV).
        (0x1023575d4, b"\xc0\x03\x5f\xd6",
         "global-shader verify function -> immediate ret (no-op)"),
        # Belt & suspenders: the assert helper used by surrounding code
        # (0x10136d04c, fmt "Assertion failed: %s [File:%s] [Line: %i]")
        # routes Fatals to FOutputDeviceError -> RequestExit(1) -> abort.
        # Convert the cbnz at 0x10136d094 into an unconditional branch
        # to its cleanup path (0x10136d138).
        (0x10136d094, b"\x29\x00\x00\x14",
         "assert-helper fatal path -> skip (b 0x10136d138)"),
        # The verify loop's per-entry fatal Logf path (unreachable once
        # the function rets immediately; kept for cold-start safety).
        (0x10235772c, b"\x34\x00\x00\x14",
         "verify-loop missing-detect -> always fine (b 0x1023577fc)"),
    ]

    def apply_code_patches(self):
        for addr, code, desc in self.CODE_PATCHES:
            try:
                self.wrb(addr, code)
                # CRITICAL: unicorn does NOT invalidate its translated-
                # block cache on mem_write (verified experimentally:
                # stale TBs keep executing the ORIGINAL code and the
                # patch silently never runs). A TB can span the whole
                # function, so invalidate the FULL PAGE around the patch.
                try:
                    page_lo = addr & ~0xFFF
                    self.uc.ctl_remove_cache(page_lo, page_lo + 0x1000)
                except Exception:
                    pass
                self.console("[patch] %s" % desc)
            except Exception as e:
                self.console("[patch] FAILED %s: %r" % (desc, e))
        # dynamic keystone-assembled guards (need a code cave)
        self.install_weakobj_guard()
        self.install_event_wait_guard()

    def install_event_wait_guard(self):
        """FGraphEvent-style Wait deadlock breaker.

        The wait loop at 0x101018fe8 (vtable slot of the task-event
        object) NEVER exits unless [this+0x98] is triggered; the 0.2s
        timeout handler just requeues. If the completing party never
        runs (splash asset failure / task-graph stall) every engine
        thread ends up spinning here forever (segCB/CD: 8 threads,
        billions of instructions, zero progress).

        Patch the timeout path (0x101019038, entered with d0=elapsed
        seconds already known > timeout): if elapsed > 120s give up
        and return 0 ("event fired") so the engine keeps moving."""
        try:
            import keystone
        except ImportError:
            self.warn("event-wait guard: keystone missing, skipped")
            return
        ks = keystone.Ks(keystone.KS_ARCH_ARM64,
                         keystone.KS_MODE_LITTLE_ENDIAN)
        CAVE = self.WEAKOBJ_CAVE + 0x80          # same RWX page
        try:
            self.uc.mem_map(self.WEAKOBJ_CAVE, 0x1000, 7)
        except UcError:
            pass
        # build the constant 3600.0 directly (bits of the double): the
        # async pak mount + name-table build takes MINUTES under
        # emulation; the old 120s cutoff made the engine give up
        # mid-mount ('Failed to read file ...uproject' early exit).
        import struct as _s
        _900 = _s.unpack("<Q", _s.pack("<d", 3600.0))[0]
        asm = ("movz x4, #0x%x\n"
               "movk x4, #0x%x, lsl #16\n"
               "movk x4, #0x%x, lsl #32\n"
               "movk x4, #0x%x, lsl #48\n"       # x4 = 3600.0 (double)
               "fmov d3, x4\n"
               "fcmp d0, d3\n"
               "b.le 0x%x\n"                        # within 3600s -> normal
               "mov w0, #0\n"                       # give up: pretend ok
               "ldp x29, x30, [sp, #0x20]\n"
               "ldp x20, x19, [sp, #0x10]\n"
               "ldp d9, d8, [sp], #0x30\n"
               "ret\n"
               "mov x0, x19\n"
               "bl 0x101391084\n"                   # original timeout hdlr
               "b 0x10101904c"                      # back into the loop
               % (_900 & 0xFFFF, (_900 >> 16) & 0xFFFF,
                  (_900 >> 32) & 0xFFFF, (_900 >> 48) & 0xFFFF,
                  CAVE + 0x30))
        enc, _ = ks.asm(asm, addr=CAVE)
        body = bytes(enc)
        if len(body) > 80:
            self.console("[wait-guard] BAD ASSEMBLY len=%d" % len(body))
            return
        try:
            self.wrb(CAVE, body)
            red, _ = ks.asm("b 0x%x" % CAVE, addr=0x101019038)
            self.wrb(0x101019038, bytes(red))
            self.uc.ctl_remove_cache(0x101019000, 0x10101a000)
            self.uc.ctl_remove_cache(self.WEAKOBJ_CAVE,
                                      self.WEAKOBJ_CAVE + 0x1000)
            self._wait_giveup_arm = time.time()
            self.console("[wait-guard] armed: Wait>3600s -> return 0 "
                         "(cave 0x%x)" % CAVE)
        except Exception as e:
            self.console("[wait-guard] FAILED: %r" % (e,))

    # ---- FWeakObjectPtr poison guard --------------------------------
    # ObjectIndexToObject() has TWO identical clones
    #   0x102def93c   (IndexToObject proper)
    #   0x1028eb2d4   (twin)
    # both do:  chunk = index/16384 ; within = index%16384
    #           ldr x9,[x0, w9, sxtw#3]   ; table[chunk]   <- NO BOUNDS CHECK
    #           ldr x0,[x9, w8, sxtw#3]   ; chunkptr[within]
    # A garbage index (segBU: 0x6400023b -> chunk 0x190000) reads past
    # the 128-entry table (0x408-byte alloc), pulls a NULL/heap value
    # and faults at [NULL + within*8]. UE4's OWN caller already
    # tolerates NULL results (FWeakObjectPtr::Get: `cbz x21 -> ret 0`),
    # so returning NULL for poison is the semantically-correct fix.
    WEAKOBJ_SLOTS = [
        # (patch_site, return_site, slot_off_in_page)
        (0x102def960, 0x102def968, 0x00),
        (0x1028eb2f8, 0x1028eb300, 0x20),
    ]
    WEAKOBJ_CAVE = 0x106000000        # free page within +-128MB of sites

    def install_weakobj_guard(self):
        try:
            import keystone
        except ImportError:
            self.warn("weakobj guard: keystone missing, skipped")
            return
        ks = keystone.Ks(keystone.KS_ARCH_ARM64,
                         keystone.KS_MODE_LITTLE_ENDIAN)
        CAVE = self.WEAKOBJ_CAVE
        try:
            self.uc.mem_map(CAVE, 0x1000, 7)   # RWX
        except UcError:
            pass  # already mapped (snapshot resume) -- slots rewritten below
        ok = 0
        for site, retsite, off in self.WEAKOBJ_SLOTS:
            try:
                s0 = CAVE + off
                poison = s0 + 0x18
                done = s0 + 0x1c
                asm = ("cmp w9, #0x80\n"          # chunk >= 128?
                       "b.hs 0x%x\n"              # -> poison
                       "ldr x9, [x0, w9, uxtw #3]\n"
                       "cbz x9, 0x%x\n"            # NULL chunk -> poison
                       "ldr x0, [x9, w8, uxtw #3]\n"
                       "b 0x%x\n"                  # -> done
                       "mov x0, xzr\n"             # poison:
                       "b 0x%x\n"                  # done: back to caller
                       % (poison, poison, done, retsite))
                enc, _ = ks.asm(asm, addr=s0)
                body = bytes(enc)
                if len(body) != 0x20:
                    raise RuntimeError("cave slot %d is %d bytes"
                                       % (off, len(body)))
                self.wrb(s0, body)
                # redirect: replace the two unchecked loads with b cave
                red, _ = ks.asm("b 0x%x" % s0, addr=site)
                self.wrb(site, bytes(red))
                # TB invalidation (page-wide -- TBs span functions)
                self.uc.ctl_remove_cache(site & ~0xFFF,
                                          (site & ~0xFFF) + 0x1000)
                # poison-path instrumentation hook
                try:
                    self.uc.hook_add(UC_HOOK_CODE,
                                     self._weakobj_poison_hit,
                                     begin=poison, end=poison)
                except Exception:
                    pass
                ok += 1
            except Exception as e:
                self.console("[weak-guard] slot @0x%x FAILED: %r"
                             % (site, e))
        self.uc.ctl_remove_cache(CAVE, CAVE + 0x1000)
        self.console("[weak-guard] %d/%d ObjectIndexToObject caves armed"
                     % (ok, len(self.WEAKOBJ_SLOTS)))

    def _weakobj_poison_hit(self, uc, addr, size, user):
        self._weak_poison_n = getattr(self, "_weak_poison_n", 0) + 1
        n = self._weak_poison_n
        if n <= 12 or n % 500 == 0:
            try:
                x19 = uc.reg_read(XREGS[19])
                idx = self.rd32(x19)
                ser = self.rd32(x19 + 4)
                t = self.cur
                self.console("[weak-guard] poison #%d idx=0x%x "
                             "serial=0x%x thr=%s"
                             % (n, idx, ser,
                                getattr(t, "name", "?")))
            except Exception as e:
                self.console("[weak-guard] hit #%d (log failed %r)"
                             % (n, e))

    def install_hooks(self):
        # targeted fd tracing (FN35_TRACE_FD=4,5) for pak-read forensics
        if os.environ.get("FN35_TRACE_FD"):
            try:
                self._trace_fds = set(
                    int(x) for x in
                    os.environ["FN35_TRACE_FD"].split(",") if x.strip())
            except ValueError:
                self._trace_fds = None
        # GLOBAL SYNC HOOK (the TCG-desync fix): unicorn 2.1.4 leaves
        # lazily-committed register state when no code hook is active;
        # the CRC/AES table loops then fault at arithmetically impossible
        # addresses (A/B verified repeatedly: crash WITHOUT any code hook,
        # never with one -- zone hooks and commit-on-write readbacks did
        # NOT suffice: the corruption accumulates outside the loops).
        # An EMPTY global hook is the cheapest form: bench 8.7s vs 43s
        # (1 reg read) vs 80s (lastmile-style) per 20M instructions.
        # Disable with FN35_NO_SYNC_HOOK=1 (speed experiments only!).
        # FN35_SYNC_HOOK=block: UC_HOOK_BLOCK + 1 reg read per BASIC
        # BLOCK instead of per instruction (vm-grind speed experiment;
        # every branch ends a TB, so this still flushes frequently).
        _sh_mode = os.environ.get("FN35_SYNC_HOOK", "code")
        if not os.environ.get("FN35_NO_SYNC_HOOK"):
            def _global_sync(uc, addr, size, user):
                # ONE reg read per instruction is the minimum that
                # forces unicorn's TCG to commit register state (empty
                # hooks and zone hooks do NOT; bench: ~0.46M instr/s,
                # ~10x slower than no-hook but the only correct mode)
                uc.reg_read(a64.UC_ARM64_REG_SP)
            try:
                if _sh_mode == "block":
                    from unicorn import UC_HOOK_BLOCK
                    self.uc.hook_add(UC_HOOK_BLOCK, _global_sync)
                    self.console("[sync-hook] BLOCK 1-read hook armed "
                                 "(TCG desync fix, block mode)")
                else:
                    self.uc.hook_add(UC_HOOK_CODE, _global_sync)
                    self.console("[sync-hook] global 1-read code hook armed "
                                 "(TCG desync fix)")
            except Exception as e:
                self.console("[sync-hook] arm failed: %r" % (e,))
        self.uc.hook_add(UC_HOOK_INTR, self.hook_intr)
        self.uc.hook_add(UC_HOOK_MEM_INVALID, self.hook_mem_invalid)
        # ---- compatibility patches (touchHLE-style) -----------------
        # FPluginManager::LoadModuleForPlugin -> force success.
        # The AESHandlerComponent module lookup fails inside our sandbox
        # (module map linkage), which aborts engine PreInit before
        # UObjectBaseInit() -> GUObjectArray stays uninitialized -> every
        # UObject registration crashes. Returning TRUE lets the boot
        # continue (the packet-handler component is only needed online).
        self._patch_pcs = {0x1015AA2C8: "ret1",
                          0x102D5BEA4: "fhash_find_safe"}
        if os.environ.get("FN35_PATCH_PC"):
            for ent in os.environ["FN35_PATCH_PC"].split(","):
                if ":" in ent:
                    a, act = ent.split(":", 1)
                    try:
                        self._patch_pcs[int(a, 0)] = act
                    except ValueError:
                        pass
        if self._patch_pcs:
            # one NARROW hook per address: a single wide range would slow
            # the whole code region down (24 MB between these two!)
            for a in self._patch_pcs:
                self.uc.hook_add(UC_HOOK_CODE, self.hook_compat_patch,
                                 begin=a, end=a + 3)
        if os.environ.get("FN35_WATCH_MEM"):
            from unicorn import UC_HOOK_MEM_WRITE
            lo, hi = (int(x, 0) for x in
                      os.environ["FN35_WATCH_MEM"].split("-"))
            def _wm(uc, access, address, size, value, user):
                pc = self.reg_pc()
                nm, sa = self.nearest_symbol(pc)
                try:
                    thr = self.cur.name if getattr(self, "cur", None) else "?"
                except Exception:
                    thr = "?"
                self.console("[memwatch] write 0x%x sz=%d val=0x%x pc=0x%x "
                              "(%s+0x%x) [%s]"
                              % (address, size, value, pc,
                                 (nm or "?")[:40], pc - (sa or 0), thr))
            self.uc.hook_add(UC_HOOK_MEM_WRITE, _wm, begin=lo, end=hi - 1)
        if os.environ.get("FN35_DEBUG_HOOKS"):
            self._block_hook = self.uc.hook_add(UC_HOOK_BLOCK,
                                               self.hook_block_dbg)
        if self.trace_remaining > 0:
            self._code_hook = self.uc.hook_add(UC_HOOK_CODE, self.hook_code)
        if os.environ.get("FN35_WATCH_PC"):
            pcs = [int(x, 0) for x in
                   os.environ["FN35_WATCH_PC"].split(",") if x.strip()]
            self._watch_pcs = set(pcs)
            self._watch_pc = pcs[0]
            lo = min(pcs)
            hi = max(pcs) + 4
            self._trace_hook = self.uc.hook_add(UC_HOOK_CODE,
                                                self.hook_code_watch,
                                                begin=lo, end=hi)
        if os.environ.get("FN35_TRACE_ALL"):
            self.trace_ring = deque(maxlen=40000)
            self._trace_hook = self.uc.hook_add(UC_HOOK_CODE,
                                              self.hook_code_trace)

    def hook_code_trace(self, uc, addr, size, user):
        self.trace_ring.append(addr)

    # watchpoint variant: log specific PC with registers
    def hook_compat_patch(self, uc, addr, size, user):
        act = self._patch_pcs.get(addr)
        if act == "ret1":
            uc.reg_write(a64.UC_ARM64_REG_X0, 1)
            uc.reg_write(a64.UC_ARM64_REG_PC, self.reg_lr() & MASK64)
        elif act == "ret0":
            uc.reg_write(a64.UC_ARM64_REG_X0, 0)
            uc.reg_write(a64.UC_ARM64_REG_PC, self.reg_lr() & MASK64)
        elif act == "fhash_find_safe":
            # FHashTable-style Find(x0=table, w1=key): if the entries or
            # buckets arrays were never allocated, report "not found"
            # instead of faulting. The ADD path allocates lazily, so this
            # self-heals as soon as the caller inserts an element.
            try:
                t = self.reg_x(0)
                if t and (self.rd64(t) == 0 or self.rd64(t + 0x40) == 0):
                    uc.reg_write(a64.UC_ARM64_REG_X0, 0xFFFFFFFF)
                    uc.reg_write(a64.UC_ARM64_REG_PC,
                                 self.reg_lr() & MASK64)
            except Exception:
                pass

    def hook_code_watch(self, uc, addr, size, user):
        if addr in getattr(self, "_watch_pcs", {self._watch_pc}):
            regs = " ".join("x%d=%x" % (i, self.reg_x(i))
                            for i in (0, 1, 2, 3, 4, 19, 20, 21))
            extra = ""
            if os.environ.get("FN35_WATCH_FP"):
                try:
                    chain = []
                    fp = self.reg_x(29)
                    for _ in range(12):
                        if not fp or fp < 0x1000:
                            break
                        nxt = self.rd64(fp)
                        ret = self.rd64(fp + 8)
                        if nxt <= fp or nxt - fp > 0x100000:
                            break
                        nm, sa = self.nearest_symbol(ret)
                        chain.append("%x(%s+0x%x)"
                                     % (ret, (nm or "?")[:36],
                                        ret - (sa or 0)))
                        fp = nxt
                    extra += " fp-chain: " + " <- ".join(chain)
                except Exception:
                    pass
            try:
                p = self.reg_x(0)
                if p > 0x1000:
                    raw = self.rdb(p, int(os.environ.get("FN35_WATCH_STRLEN",
                                                         "48")))
                    # try utf16
                    try:
                        u16 = raw.decode("utf-16-le", "ignore").split("\x00")[0]
                    except Exception:
                        u16 = "?"
                    a = raw.split(b"\x00")[0].decode("utf-8", "replace")
                    extra = " [x0.u16=%r x0.ansi=%r]" % (u16[:100], a[:100])
                    try:
                        # FString at x0: data ptr + count?
                        dp = self.rd64(p)
                        ct = self.rd32(p + 8)
                        extra += " [fstr data=0x%x count=%d]" % (dp, ct)
                        if dp > 0x1000:
                            fb = self.rdb(dp, min(max(ct, 0), 80) * 2)
                            fu = fb.decode("utf-16-le", "replace").split("\x00")[0]
                            extra += " val=%r" % fu[:60]
                    except Exception:
                        pass
                    try:
                        # varargs start at [sp] for this call family
                        spv = self.reg_sp()
                        for k in range(3):
                            sp_arg = self.rd64(spv + 8 * k)
                            if 0x100000000 < sp_arg < 0x110000000:
                                rawk = self.rdb(sp_arg, 160)
                                uk = rawk.decode("utf-16-le", "replace").split("\x00")[0]
                                ak = rawk.split(b"\x00")[0].decode("utf-8", "replace")
                                if uk.strip() or ak.strip():
                                    extra += " [sp%d.u16=%r]" % (k, uk[:70])
                                    break
                    except Exception:
                        pass
                    for regn in (1, 2, 3, 4, 19, 20, 21, 22, 23):
                        try:
                            pr_ = self.reg_x(regn)
                            rawr = self.rdb(pr_, 200) if pr_ > 0x1000 else b""
                            u16r = rawr.decode("utf-16-le", "replace")
                            u16r = u16r.split("\x00")[0]
                            ar = rawr.split(b"\x00")[0].decode(
                                "utf-8", "replace")
                            if u16r or ar:
                                extra += " [x%d.u16=%r]" % (regn, u16r[:40])
                            # try interpreting as FString* too
                            try:
                                dp_ = self.rd64(pr_)
                                ct_ = self.rd32(pr_ + 8)
                                if 0x600000000000 < dp_ < 0x800000000000 \
                                        and 0 < ct_ < 4096:
                                    fb_ = self.rdb(dp_, ct_ * 2)
                                    extra += " [x%d.FS=%r]" % (
                                        regn,
                                        fb_.decode("utf-16-le",
                                                   "replace")[:80])
                            except Exception:
                                pass
                        except Exception:
                            pass
                    try:
                        byte_at_a = self.rd8(p + 0xa)
                        qword_a = self.rd32(p + 0xa)
                        extra += " [x0+0xa=%d]" % byte_at_a
                    except Exception:
                        pass
            except Exception:
                pass
            self.console("[watch t=%.3f 0x%x] lr=%x %s%s" % (
                time.time() % 1000, addr, self.reg_lr(), regs, extra))

    def hook_block_dbg(self, uc, addr, size, user):
        self.block_ring.append((addr, size))

    def dump_recent_blocks(self, n=64):
        out = []
        for a, sz in list(self.block_ring)[-n:]:
            name, saddr = self.nearest_symbol(a)
            d = self.disasm_at(a, 3)
            out.append("  %x (%s+0x%x): %s" % (
                a, (name or "?")[:44], a - (saddr or 0),
                " | ".join(d)))
        return out

    def prepare_runtime_regions(self):
        """Map every fixed VA window BEFORE emulation starts: no mem_map
        is ever attempted inside a hook (avoids UC_ERR_MAP)."""
        self.map_range(STUB_BASE, STUB_WINDOW)
        self.map_range(DATA_FARM, FARM_WINDOW)
        self.map_range(MAGIC_BASE, PAGE)
        self.wrb(MAGIC_INIT_RET,
                 struct.pack("<I", 0xD4000001 | (0xF000 << 5)))
        self.wrb(MAGIC_THREAD_RET,
                 struct.pack("<I", 0xD4000001 | (0xF001 << 5)))
        self.wrb(MAGIC_CB_RET,
                 struct.pack("<I", 0xD4000001 | (0xF002 << 5)))
        self.map_range(HEAP_BASE, HEAP_PREMAP)
        self.heap_mapped_end = HEAP_BASE + HEAP_PREMAP
        self.map_range(VM_BASE, VM_PREMAP)
        self.vm_mapped_end = VM_BASE + VM_PREMAP
        self.map_range(MMAP_BASE, MMAP_PREMAP)
        self.mmap_mapped_end = MMAP_BASE + MMAP_PREMAP

    def hook_code(self, uc, addr, size, user):
        if self.trace_remaining <= 0:
            return
        self.trace_remaining -= 1
        try:
            code = self.rdb(addr, size)
            for ins in CS.disasm(code, addr):
                self.console("[trace] %12x  %s %s" % (
                    ins.address, ins.mnemonic, ins.op_str))
                break
        except Exception:
            pass
        if self.trace_remaining == 0 and self._code_hook is not None:
            try:
                uc.hook_del(self._code_hook)
                self._code_hook = None
            except Exception:
                pass

    def hook_intr(self, uc, intno, user):
        try:
            if intno != 2:
                return
            pc = self.reg_pc()
            svc = pc - 4                     # PC points after svc
            if STUB_BASE <= svc < STUB_BASE + STUB_WINDOW:
                self.dispatch_stub(svc)
                return
            if MAGIC_BASE <= svc < MAGIC_BASE + 0x10:
                imm = (self.rd32(svc) >> 5) & 0xFFFF
                if imm == 0xF000:
                    self.on_magic_init()
                elif imm == 0xF001:
                    self.on_magic_thread_ret()
                elif imm == 0xF002:
                    self.on_magic_cb()
                else:
                    self.fatal("bad magic svc imm 0x%x at 0x%x" % (imm, svc))
                return
            # genuine guest syscall: svc #0x80, x16 = number
            x16 = self.reg_x(16)
            n = x16 & 0xFFFFFFFF
            if n >= 0x80000000:
                n -= 1 << 32
            if os.environ.get("FN35_DEBUG_HOOKS"):
                self.console("[dbg] guest syscall %d pc=0x%x" % (n, svc))
            self.syscall_calls[n] += 1
            try:
                rv = self.do_syscall(n)
            except Exception as e:
                self.warn("syscall %d raised %r" % (n, e))
                rv = -78
            if rv is not None:
                self.wreg_x(0, rv & MASK64)
        except Exception as e:
            self.console("[dbg] hook_intr raised %r" % (e,))
            raise

    def hook_mem_invalid(self, uc, access, address, size, value, user):
        try:
            if os.environ.get("FN35_DEBUG_HOOKS"):
                self.console("[dbg] mem_invalid access=%d addr=0x%x size=%d pc=0x%x"
                             % (access, address, size, self.reg_pc()))
            if access in (UC_MEM_FETCH_UNMAPPED, UC_MEM_FETCH_PROT):
                return self.on_fetch(address)
            if self.maybe_grow(address):
                return True
            if self.try_desync_repair(uc, access, address, size):
                return True
            self.diagnose_data_fault(access, address, size)
            return False
        except Exception as e:
            self.console("[dbg] hook_mem_invalid raised %r" % (e,))
            raise

    # ------------------------------------------------------------------
    # TCG-desync self-repair: unicorn 2.1.4 sometimes computes a data
    # fault address from STALE TCG-local register state while the
    # committed (reg_read-visible) state is CORRECT (proven by crash
    # snapshots: x11 valid at a fault at a garbage address; the fault
    # address is arithmetically unreachable from the committed regs).
    # Fix: decode the faulting access, recompute the true address from
    # COMMITTED registers, emulate the load/store, and skip the insn.
    # ------------------------------------------------------------------
    _dsr_md = None
    _dsr_count = 0

    def _dsr_reg(self, uc, rname):
        import unicorn.arm64_const as _a64
        c = getattr(_a64, "UC_ARM64_REG_" + rname.upper(), None)
        return uc.reg_read(c) if c is not None else 0

    def try_desync_repair(self, uc, access, address, size):
        try:
            if os.environ.get("FN35_NO_DSR"):
                return False
            pc = self.reg_pc()
            if not (0x100000000 <= pc < 0x105900000):
                return False
            code = bytes(uc.mem_read(pc, 4))
            if len(code) < 4:
                return False
            import capstone
            from capstone.arm64 import (ARM64_OP_REG, ARM64_OP_IMM,
                                        ARM64_OP_MEM)
            if FNLoader._dsr_md is None:
                _md = capstone.Cs(capstone.CS_ARCH_ARM64,
                                 capstone.CS_MODE_LITTLE_ENDIAN)
                _md.detail = True
                FNLoader._dsr_md = _md
            md = FNLoader._dsr_md
            try:
                ins = next(md.disasm(code, pc))
            except StopIteration:
                return False

            is_load = ins.mnemonic in ("ldr", "ldur", "ldrb", "ldrh",
                                       "ldrsh", "ldrsw", "ldrsb")
            is_store = ins.mnemonic in ("str", "stur", "strb", "strh")
            if not (is_load or is_store):
                return False

            ops = ins.operands
            if len(ops) < 2:
                return False
            memop = None
            for o in ops:
                if o.type == ARM64_OP_MEM:
                    memop = o
            if memop is None:
                return False
            m = memop.mem

            base = self._dsr_reg(uc, ins.reg_name(m.base)) if m.base else 0
            if m.index:
                idx = self._dsr_reg(uc, ins.reg_name(m.index))
                if ins.reg_name(m.index).startswith("w"):
                    idx &= 0xFFFFFFFF       # uxtw semantics
                try:
                    sh = memop.shift.value
                except Exception:
                    sh = 0
                idx <<= sh
                base += idx
            true_addr = (base + m.disp) & MASK64

            # PAIR-FOLD: the faulting load's base was often computed by
            # the PRECEDING 'add Xt, Xn, Xm{, uxtw #s}' -- which may
            # itself have consumed the stale value (committed Xt is
            # then garbage). Recompute from the add's SOURCES instead
            # (they were committed before the desync window).
            pair_addr = None
            try:
                pre = bytes(uc.mem_read(pc - 4, 4))
                pins = next(md.disasm(pre, pc - 4))
                if pins.mnemonic in ("add", "add x", "add w") and \
                        len(pins.operands) == 3 and \
                        pins.operands[1].type == ARM64_OP_REG and \
                        pins.operands[2].type == ARM64_OP_REG:
                    nd = pins.reg_name(pins.operands[0].reg)
                    n1 = pins.reg_name(pins.operands[1].reg)
                    n2 = pins.reg_name(pins.operands[2].reg)
                    if m.base and ins.reg_name(m.base) == nd:
                        pbase = self._dsr_reg(uc, n1)
                        pidx = self._dsr_reg(uc, n2)
                        if n2.startswith("w"):
                            pidx &= 0xFFFFFFFF
                        try:
                            psh = pins.operands[2].shift.value
                        except Exception:
                            psh = 0
                        pidx <<= psh
                        pair_addr = (pbase + pidx + m.disp) & MASK64
            except StopIteration:
                pass
            except Exception:
                pair_addr = None

            if true_addr == address and pair_addr is None:
                return False            # not a desync (real bad address)
            # prefer the pair recompute when available
            if pair_addr is not None and pair_addr != address:
                try:
                    uc.mem_read(pair_addr, 1)
                    true_addr = pair_addr
                except Exception:
                    pass
            try:
                uc.mem_read(true_addr, 1)        # must be mapped
            except Exception:
                return False

            # execute the access
            import struct as _st
            if is_load:
                mn = ins.mnemonic
                dst = ins.reg_name(ops[0].reg)
                if mn in ("ldrb", "ldrsb"):
                    datasz, fmt = 1, "<B"
                elif mn in ("ldrh", "ldrsh"):
                    datasz, fmt = 2, "<H"
                elif mn == "ldrsw":
                    datasz, fmt = 4, "<i"
                else:
                    datasz, fmt = (8, "<Q") if dst.startswith("x") \
                        else (4, "<I")
                data = bytes(uc.mem_read(true_addr, datasz))
                val = _st.unpack(fmt, data)[0]
                self._dsr_reg_write(uc, dst, val)
                action = "load"
            else:
                src = None
                for o in ops:
                    if o.type == ARM64_OP_REG:
                        src = o
                        break
                if src is None:
                    return False
                sname = ins.reg_name(src.reg)
                val = self._dsr_reg(uc, sname)
                datasz = 1 if ins.mnemonic == "strb" else \
                    2 if ins.mnemonic == "strh" else \
                    8 if sname.startswith("x") else 4
                uc.mem_write(true_addr, val.to_bytes(datasz, "little"))
                action = "store"

            uc.reg_write(a64.UC_ARM64_REG_PC, pc + 4)
            FNLoader._dsr_count += 1
            if FNLoader._dsr_count <= 12 or FNLoader._dsr_count % 1000 == 0:
                self.console("[dsr] #%d %s fault@0x%x -> true 0x%x "
                             "(%s %s) pc=0x%x"
                             % (FNLoader._dsr_count, action, address,
                                true_addr, ins.mnemonic, ins.op_str, pc))
            return True
        except Exception as e:
            try:
                self.console("[dsr] repair failed %r" % (e,))
            except Exception:
                pass
            return False

    def _dsr_reg_write(self, uc, rname, val):
        import unicorn.arm64_const as _a64
        c = getattr(_a64, "UC_ARM64_REG_" + rname.upper(), None)
        if c is not None:
            uc.reg_write(c, val & (0xFFFFFFFF if rname.startswith("w")
                                   else MASK64))

    def arm_lastmile_trace(self, n=1_500_000):
        """Bounded per-instruction ring, armed at a console milestone.
        The TB flush is DEFERRED to the scheduler (between slices):
        ctl_remove_cache called mid-emulation does NOT invalidate
        already-chained blocks (the segBQ/BR rings kept lying by
        omission until this was fixed)."""
        from unicorn import UC_HOOK_CODE
        try:
            self._lm_ring = deque(maxlen=n)
            self._lm_hook = self.uc.hook_add(
                UC_HOOK_CODE, self._lm_hook_fn)
            self._lm_flush_pending = True
            # cut the current slice NOW: the flush must happen at the
            # slice boundary (mid-emulation ctl_remove_cache cannot
            # invalidate already-chained blocks). emu_stop from a hook
            # is safe -- the scheduler will resume the thread after.
            try:
                self.uc.emu_stop()
            except Exception:
                pass
            self.console("[lm-trace] armed ring of %d instructions "
                         "(slice cut, TB flush at boundary)" % n)
        except Exception as e:
            self.console("[lm-trace] arm failed: %r" % (e,))

    def _lm_hook_fn(self, uc, addr, size, user):
        try:
            self._lm_ring.append(
                (addr, uc.reg_read(a64.UC_ARM64_REG_SP),
                 uc.reg_read(a64.UC_ARM64_REG_LR)))
        except Exception:
            pass

    def dump_lastmile(self, count=80):
        ring = getattr(self, "_lm_ring", None)
        if not ring:
            return
        try:
            import capstone
            md = capstone.Cs(capstone.CS_ARCH_ARM64,
                             capstone.CS_MODE_ARM)
            ents = list(ring)[-count:]
            # collapse runs of the same pc (loops) but keep order
            self.console("[lastmile] %d of %d instructions before fault:"
                         % (len(ents), len(ring)))
            for i, (pc, sp, lr) in enumerate(ents):
                tag = ""
                if sp == 0:
                    tag += "  <<< SP ZERO"
                if lr == 0:
                    tag += "  <<< LR ZERO"
                try:
                    code = self.rdb(pc, 4)
                    for ins in md.disasm(code, pc):
                        tag = "  %-8s %-36s" % (ins.mnemonic,
                                                ins.op_str) + tag
                        break
                except Exception:
                    tag = "  %-44s" % "(unreadable)" + tag
                nm, sa = self.nearest_symbol(pc)
                self.console("[lm %3d] 0x%x %s (%s+0x%x)"
                             % (i, pc, tag, (nm or "?")[:30],
                                pc - (sa or 0)))
            # first occurrence of sp==0
            for i, (pc, sp, lr) in enumerate(ring):
                if sp == 0:
                    self.console("[lastmile] FIRST SP==ZERO at #%d "
                                 "(0x%x)" % (i, pc))
                    break
        except Exception as e:
            self.console("[lastmile] dump failed: %r" % (e,))

    def on_fetch(self, addr):
        # with the stub farm mapped + svc dispatch, this only fires on
        # genuine unmapped execution -- a real crash
        if addr == 0:
            # null-call captured LIVE: the faulting fetch is PC=0 and
            # the registers still hold the argument setup of the call.
            try:
                lr = self.uc.reg_read(a64.UC_ARM64_REG_LR)
            except Exception:
                lr = 0
            self.console("[null-call] PC=0 caught live: lr=0x%x" % lr)
            try:
                thr = self.cur.name if self.cur else "?"
                tid = getattr(self.cur, "tid", 0) if self.cur else 0
                self.console("[null-call] thread=%r tid=0x%x" % (thr, tid))
            except Exception:
                pass
            try:
                sp = self.uc.reg_read(a64.UC_ARM64_REG_SP)
                self.console("[null-call] sp=0x%x (ZERO-STACK!)"
                             % sp if not sp else
                             "[null-call] sp=0x%x" % sp)
            except Exception:
                pass
            self.dump_lastmile()
            try:
                xs = " ".join("x%d=0x%x" % (i, self.reg_x(i))
                              for i in range(9))
                self.console("[null-call] %s" % xs)
            except Exception:
                pass
            # last stub calls -- WHICH stub returned into this state?
            try:
                _FILEY = ("_open", "_fopen", "_stat", "_access", "_read",
                          "_pread", "_lseek", "_close", "_mkdir", "_unlink",
                          "_rename", "_fcntl", "_dlopen", "_NSLog", "_printf",
                          "_puts", "_fprintf", "_opendir", "_readdir")
                ents = list(self.stub_ring)
                nfo = [e for e in ents
                       if any(f in str(e[0]) for f in _FILEY)]
                self.console("[null-call] file/log ops (last 40 of %d):"
                             % len(nfo))
                for ent in nfo[-40:]:
                    self.console("   %s" % (ent,))
                self.console("[null-call] raw tail 20:")
                for ent in ents[-20:]:
                    self.console("   %s" % (ent,))
            except Exception as e:
                self.console("[null-call] ring dump failed %r" % (e,))
            # poor-man's backtrace: scan the stack for return addresses
            # (image-range qwords) -- works even when fp/lr are zeroed
            try:
                sp = self.uc.reg_read(a64.UC_ARM64_REG_SP)
                self.console("[null-call] stack scan from sp=0x%x:" % sp)
                found = 0
                for off in range(0, 0x400, 8):
                    v = self.rd64(sp + off)
                    if 0x100000000 <= v < 0x106000000:
                        nm, sa = self.nearest_symbol(v)
                        self.console("[stack +0x%03x] 0x%x %s+0x%x"
                                     % (off, v, (nm or "?")[:44],
                                        v - (sa or 0)))
                        found += 1
                        if found >= 20:
                            break
                if not found:
                    self.console("[null-call] no image ptrs on stack; "
                                 "raw dump:")
                    for off in range(0, 0x100, 8):
                        self.console("[stack +0x%03x] 0x%016x"
                                     % (off, self.rd64(sp + off)))
            except Exception as e:
                self.console("[null-call] stack scan failed %r" % (e,))
            try:
                import capstone
                md = capstone.Cs(capstone.CS_ARCH_ARM64,
                                 capstone.CS_MODE_ARM)
                if 0x100000000 <= (lr - 4) < 0x106000000:
                    code = self.rdb(lr - 16, 32)
                    for ins in md.disasm(code, lr - 16):
                        mark = "  <<< THE CALL" if ins.address <= lr - 4 \
                               < ins.address + ins.size else ""
                        self.console("[null-call] 0x%x %-8s %s%s"
                                     % (ins.address, ins.mnemonic,
                                        ins.op_str, mark))
            except Exception as e:
                self.console("[null-call] disasm failed %r" % (e,))
            # frame-chain walk (x29 may be zero for leaf frames)
            try:
                fp = self.uc.reg_read(a64.UC_ARM64_REG_X29)
                sp = self.uc.reg_read(a64.UC_ARM64_REG_SP)
                seen = set()
                nfr = 0
                while fp and sp - 0x400000 < fp < sp + 0x400000 \
                        and nfr < 24 and fp not in seen:
                    seen.add(fp)
                    try:
                        nxt = self.rd64(fp)
                        ret = self.rd64(fp + 8)
                    except Exception:
                        break
                    nm, sa = self.nearest_symbol(ret)
                    self.console("[bt %2d] 0x%x %s+0x%x"
                                 % (nfr, ret, (nm or "?")[:48],
                                    ret - (sa or 0)))
                    nfr += 1
                    if nxt <= fp:
                        break
                    fp = nxt
            except Exception as e:
                self.console("[null-call] bt failed %r" % (e,))
        name, saddr = self.nearest_symbol(addr)
        self.fatal("exec fetch fault at 0x%x (pc=0x%x) in %s+0x%x"
                   % (addr, self.reg_pc(), name or "?",
                      addr - (saddr or 0)))
        return False

    def on_magic_init(self):
        t = self.cur
        if self.phase == "inits":
            self.inits_done = self.init_index + 1
            self.init_index += 1
            if self.init_index < len(self.inits):
                f = self.inits[self.init_index]
                if isinstance(f, tuple) and f[0] == "pygen":
                    # python-level initializer driven by the py-call stack:
                    # when its generator finishes, control returns to
                    # MAGIC_INIT_RET which continues the init loop
                    gen = f[1](self)
                    self.py_stack.append((MAGIC_INIT_RET, 0, gen))
                    try:
                        op = next(gen)
                    except StopIteration:
                        return self.on_magic_init()
                    if not op or op[0] != "call":
                        self.fatal("bad py-init op %r" % (op,))
                        return False
                    self.setup_call(op[1], op[2], MAGIC_CB_RET)
                    return True
                self.setup_call(f, self.init_args, MAGIC_INIT_RET)
                self.console("[dyld] init %d/%d at 0x%x"
                             % (self.init_index + 1, len(self.inits), f))
                return True
            self.phase = "main"
            self.console("[dyld] all %d module initializers returned"
                         % len(self.inits))
            # ---- CVar overrides (statics registered during mod-init) ----
            # Fortnite 3.5 ships rhi.Apple.OpenGLDisabled=1 (Metal-only).
            # Under emulation we run the OpenGL ES RHI: re-enable it and
            # make sure Metal stays off.
            try:
                self.w32(0x1057EC53C, 0)      # rhi.Apple.OpenGLDisabled
                self.w32(0x1042B2BB0, 0)       # rhi.Apple.UseMetal
                self.console("[dyld] cvar rhi.Apple.OpenGLDisabled=0, "
                             "rhi.Apple.UseMetal=0")
            except Exception as e:
                self.console("[dyld] cvar patch failed: %r" % (e,))
            self.setup_call(self.main_addr, self.main_args, MAGIC_INIT_RET)
            self.console("[dyld] entering main() at 0x%x argc=%d"
                         % (self.main_addr, self.main_args[0]))
            return True
        # main returned
        self.console("[dyld] main() returned")
        self.stop_reason = "main_returned"
        try:
            self.uc.emu_stop()
        except Exception:
            pass
        return False

    def on_magic_thread_ret(self):
        t = self.cur
        if t is not None:
            t.retval = self.reg_x(0)
            self.thread_done(t)
        return False

    def on_magic_cb(self):
        if not self.py_stack:
            self.fatal("py-call stack underflow")
            return False
        orig_lr, ret, gen = self.py_stack[-1]
        rv = self.reg_x(0)
        if rv >= 1 << 63:
            rv -= 1 << 64
        try:
            op = gen.send(rv)
        except StopIteration as e:
            self.py_stack.pop()
            val = e.value if e.value is not None else ret
            self.wreg_x(0, int(val) & MASK64)
            self.uc.reg_write(XREGS[30], orig_lr & MASK64)
            self.wreg_pc(orig_lr)
            return True
        if not op or op[0] != "call":
            self.fatal("bad py-call op %r" % (op,))
            return False
        self.setup_call(op[1], op[2], MAGIC_CB_RET)
        return True

    def dispatch_stub(self, addr):
        name = self.addr2stub[addr]
        self.stub_calls[name] += 1
        # stub-storm heartbeat: the scheduler loop can stall INSIDE one
        # slice for minutes when the guest hammers stubs (mutex waits);
        # the regular heartbeat never gets a slice boundary to fire at.
        self._stub_hb_n = getattr(self, "_stub_hb_n", 0) + 1
        if self._stub_hb_n >= 200000:
            self._stub_hb_n = 0
            top = self.stub_calls.most_common(6)
            self.console("[stub-hb] 200k stubs: %s | pc=0x%x thr=%s"
                         % (", ".join("%s:%d" % (n, c) for n, c in top),
                            self.reg_pc(),
                            self.cur.name if self.cur else "?"))
            # decay so each report shows the CURRENT storm, not history
            for k in list(self.stub_calls.keys()):
                self.stub_calls[k] = self.stub_calls[k] // 2
        lr = self.uc.reg_read(XREGS[30])
        args = [self.reg_x(i) for i in range(8)]
        # stack-passed args (9th+) live at [sp], [sp+8]... for fixed
        # arity impls that need them
        ar = self._arity.get(name)
        if ar is None:
            try:
                sig = inspect.signature(IMPL.get(name, lambda *a: None))
                var = any(p.kind == inspect.Parameter.VAR_POSITIONAL
                          for p in sig.parameters.values())
                ar = (var, max(0, len(sig.parameters) - 1))
            except (TypeError, ValueError):
                ar = (True, 8)
            self._arity[name] = ar
        if not ar[0] and ar[1] > 8:
            try:
                sp = self.uc.reg_read(a64.UC_ARM64_REG_SP)
                for k in range(8, min(ar[1], 16)):
                    args.append(self.rd64(sp + 8 * (k - 8)))
            except Exception:
                pass
        entry = [name, args[:5], self.cur.name if self.cur else "?"]
        if name in ("_strlen", "_strcpy", "_strdup", "_strcmp",
                    "_strncmp", "_strcat", "_strstr", "_getenv",
                    "_fopen", "_open", "_access", "_stat",
                    "_strtol", "_atoi", "_wcstol"):
            try:
                s = self.gcstr(args[0], maxlen=96) if args[0] else ""
                entry.append(s[:96])
            except Exception:
                pass
        self.stub_ring.append(tuple(entry))
        impl = IMPL.get(name)
        self.pending_py = None
        if impl is not None:
            arity = self._arity.get(name)
            if arity is None:
                try:
                    sig = inspect.signature(impl)
                    var = any(p.kind == inspect.Parameter.VAR_POSITIONAL
                              for p in sig.parameters.values())
                    arity = (var, max(0, len(sig.parameters) - 1))
                except (TypeError, ValueError):
                    arity = (True, 8)
                self._arity[name] = arity
            try:
                if arity[0]:
                    rv = impl(self, *args)
                else:
                    rv = impl(self, *args[:arity[1]])
            except Exception as e:
                self.warn("impl %s raised %r" % (name, e))
                rv = 0
        else:
            self.missing_stubs[name] += 1
            rv = 0
        # native tail-call request (objc_msgSend -> real IMP)?
        if isinstance(rv, tuple) and rv and rv[0] == "pc":
            if rv[1]:
                self.wreg_pc(rv[1])
            else:
                # imp==0 (e.g. an ObjC method resolved to a NULL IMP):
                # jumping to 0 = guaranteed fetch fault. Refuse and
                # return 0 to the caller instead -- far more survivable.
                self.console("[stub] %s tail-call imp=0 (recv=0x%x "
                             "sel=%r) -- returning 0 instead of PC=0"
                             % (name, args[0] if args else 0,
                                getattr(self.objc, "sel_name_of",
                                        lambda s: "?")(
                                    args[1] if len(args) > 1 else 0)))
                self.wreg_x(0, 0)
                self.wreg_pc(lr)
            return True
        # native-callback driver?
        if self.pending_py is not None:
            gen, ret = self.pending_py
            self.pending_py = None
            self.py_stack.append((lr, ret, gen))
            try:
                op = next(gen)
            except StopIteration as e:
                self.py_stack.pop()
                val = e.value if e.value is not None else ret
                self.wreg_x(0, int(val) & MASK64)
                self.uc.reg_write(XREGS[30], lr & MASK64)
                self.wreg_pc(lr)
                return True
            self.setup_call(op[1], op[2], MAGIC_CB_RET)
            return True
        if isinstance(rv, tuple) and rv and rv[0] == "d0":
            self.wd0(rv[1])
            self.wreg_x(0, 0)
        else:
            self.wreg_x(0, (0 if rv is None else int(rv)) & MASK64)
        self.wreg_pc(lr)
        return True

    # ================= fault diagnosis =============================
    def disasm_at(self, addr, count=4):
        out = []
        try:
            code = self.rdb(addr, count * 4)
        except Exception:
            return out
        for ins in CS.disasm(code, addr):
            out.append("%x: %s %s" % (ins.address, ins.mnemonic,
                                      ins.op_str))
            if len(out) >= count:
                break
        return out

    def diagnose_data_fault(self, access, address, size):
        pc = self.reg_pc()
        kind = {1: "read", 2: "write", 4: "read-prot", 5: "write-prot"}.get(
            access, "access-%d" % access)
        window = []
        for off in (-8, -4, 0, 4):
            try:
                window += self.disasm_at(pc + off, 1)
            except Exception:
                pass
        seen = set()
        window = [w for w in window
                  if not (w in seen or seen.add(w))]
        regs = []
        for i in (0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 16, 19, 20, 21, 22, 23):
            try:
                regs.append("x%d=%x" % (i, self.reg_x(i)))
            except Exception:
                pass
        name, saddr = self.nearest_symbol(pc)
        msg = ("%s fault at 0x%x size=%d pc=0x%x (%s+0x%x) | %s | %s"
               % (kind, address, size, pc, (name or "?")[:40],
                  pc - (saddr or 0), " ; ".join(window[-3:]),
                  " ".join(regs)))
        try:
            sp = self.reg_sp()
            t = getattr(self, "cur", None)
            if t is not None:
                msg += (" | thr=%s tid=0x%x stack=[0x%x..0x%x] sp=0x%x "
                        "(sp-base=0x%x)"
                        % (t.name, t.tid, t.stack_base,
                           t.stack_base + t.stack_size, sp,
                           sp - t.stack_base))
        except Exception:
            pass
        # always walk the guest FP chain to expose the caller path
        try:
            chain = []
            fp = self.reg_x(29)
            for _ in range(14):
                if not fp or fp < 0x1000:
                    break
                nxt = self.rd64(fp)
                ret = self.rd64(fp + 8)
                if nxt <= fp or nxt - fp > 0x100000:
                    break
                nm, sa = self.nearest_symbol(ret)
                chain.append("0x%x(%s+0x%x)" % (ret, (nm or "?")[:36],
                                                 ret - (sa or 0)))
                fp = nxt
            if chain:
                self.console("[fault-fp] " + " <- ".join(chain))
        except Exception:
            pass
        # GOT slot diagnosis: ldr xN, [xM, #imm] where xM from adrp
        got = self.got_slot_name_for(pc)
        if got:
            msg += " | GOT slot %s" % got
        self.fault_log.append(msg)
        # armed lastmile ring takes precedence (richer than trace_ring)
        if getattr(self, "_lm_ring", None) and len(self._lm_ring) > 10:
            self.dump_lastmile()
        # dump object-tail memory around x0 (FMallocBinned2 diagnosis)
        try:
            x0 = self.reg_x(0)
            for off in (0x00, 0x10, 0x48, 0x50, 0x70, 0x88, 0xf70,
                        0x41030, 0x41038, 0x41040, 0x41048):
                v = self.rd64(x0 + off)
                self.console("[objdump] [x0+0x%x] = 0x%x" % (off, v))
        except Exception as e:
            self.console("[objdump] failed %r" % (e,))
        # dump the struct at x20 when present (pool/table diagnostics)
        try:
            x20 = self.reg_x(20)
            if x20:
                raw = self.rdb(x20, 0x40)
                self.console("[x20dump] " + " ".join(
                    "%02x" % b for b in raw))
                vals = struct.unpack("<8Q", raw)
                self.console("[x20q] " + " ".join("0x%x" % v for v in vals))
        except Exception as e:
            self.console("[x20dump] failed %r" % (e,))
        if getattr(self, "trace_ring", None) and len(self.trace_ring) > 10:
            self.console("[instr-trace] last 300 executed before fault:")
            recent = list(self.trace_ring)[-300:]
            for i in range(0, len(recent), 4):
                addr = recent[i]
                d = self.disasm_at(addr, 1)
                nm, sa = self.nearest_symbol(addr)
                self.console("  %x (%s+0x%x): %s" % (
                    addr, (nm or "?")[:30], addr - (sa or 0),
                    d[0] if d else "?"))
        if self.stub_ring:
            # file/log operations first: they explain WHY the engine died
            _FILEY = ("_open", "_fopen", "_stat", "_access", "_read",
                      "_pread", "_lseek", "_close", "_mmap", "_mkdir",
                      "_unlink", "_rename", "_fcntl", "_dlopen",
                      "_NSLog", "_printf", "_puts", "_fprintf")
            ents = list(self.stub_ring)
            nfo = [e for e in ents if any(f in str(e[0]) for f in _FILEY)]
            self.console("[stubs-before-fault] (file/log ops, last 80 "
                         "of %d)" % len(nfo))
            for ent in nfo[-80:]:
                nm, aa, thr = ent[0], ent[1], ent[2]
                extra = (" <<%s>>" % ent[3]) if len(ent) > 3 else ""
                self.console("  %-38s (%s) %s%s" % (
                    nm, thr, " ".join("0x%x" % a for a in aa), extra))
            self.console("[stubs-before-fault] (raw tail 20)")
            for ent in ents[-20:]:
                nm, aa, thr = ent[0], ent[1], ent[2]
                extra = (" <<%s>>" % ent[3]) if len(ent) > 3 else ""
                self.console("  %-38s (%s) %s%s" % (
                    nm, thr, " ".join("0x%x" % a for a in aa), extra))
        if os.environ.get("FN35_DEBUG_HOOKS"):
            for line in self.dump_recent_blocks():
                self.console("[blk] " + line)
        self.fatal(msg)

    def got_slot_name_for(self, pc):
        """If pc is `ldr xN,[xM,#imm]` and xM holds an adrp base pointing
        at a known GOT slot, resolve the symbol name."""
        try:
            code = self.rdb(pc - 8, 12)
            ins = list(CS.disasm(code, pc - 8))
            adrp = next((i for i in ins if i.mnemonic == "adrp"), None)
            ldr = next((i for i in ins if i.mnemonic == "ldr"), None)
            if not (adrp and ldr):
                return None
            import re
            m = re.match(r"x(\w+), (?:x(\w+), )?#?0x?([0-9a-f]+)",
                         ldr.op_str)
            if not m:
                return None
            base_reg = int(m.group(2), 16) if m.group(2) else None
            imm = int(m.group(3), 16)
            m2 = re.match(r"x(\w+), #?0x?([0-9a-f]+)", adrp.op_str)
            if not m2:
                return None
            adrp_reg = int(m2.group(1), 16)
            if base_reg is not None and base_reg != adrp_reg:
                return None
            page = int(m2.group(2), 16) << 12
            slot = page + imm
            nm = self.addr2stub.get(self.stubs_by_slot(slot))
            return "%s (0x%x)%s" % (
                nm or "?", slot,
                "" if self.rd64(slot) else " EMPTY")
        except Exception:
            return None

    def stubs_by_slot(self, slot):
        try:
            v = self.rd64(slot)
        except Exception:
            return 0
        return v

    def nearest_symbol(self, addr):
        if self._sym_sorted is None:
            mo = self.macho
            self._sym_sorted = sorted(
                [(s.value, mo.sym_name(i))
                 for i, s in enumerate(mo.syms) if s.value],
                key=lambda x: x[0])
        lo, hi = 0, len(self._sym_sorted)
        best = None
        while lo < hi:
            mid = (lo + hi) // 2
            if self._sym_sorted[mid][0] <= addr:
                best = self._sym_sorted[mid]
                lo = mid + 1
            else:
                hi = mid
        return (best[1], best[0]) if best else (None, 0)

    # ================= prepare =====================================
    def prepare(self):
        mo = self.macho
        # ---- pak overlay: the project tree lives inside the .pak ----
        import os as _os
        if _os.environ.get("FN35_NOPAK", "") == "":
            app_dir = _os.path.dirname(self.macho_path)
            pak_path = _os.path.join(
                app_dir, "cookeddata", "fortnitegame", "content", "paks",
                "pakchunkearly-iosclient.pak")
            if _os.path.isfile(pak_path):
                cache = _os.path.join(_os.path.dirname(self.sandbox),
                                      "pakcache")
                try:
                    self.pakfs = PakFS(pak_path, cache,
                                       loader_console=self.console)
                except Exception as e:
                    self.console("[pakfs] disabled (%r)" % (e,))
                    self.pakfs = None
            else:
                self.console("[pakfs] no pak at %s" % pak_path)
        # map image (merge page ranges to avoid overlaps)
        ranges = []
        for seg in mo.segments:
            if seg.name == "__PAGEZERO" or seg.vmsize == 0:
                continue
            start = align_down(seg.vmaddr, PAGE)
            end = align_up(seg.vmaddr + seg.vmsize, PAGE)
            ranges.append((start, end))
        ranges.sort()
        merged = []
        for s, e in ranges:
            if merged and s <= merged[-1][1]:
                merged[-1] = (merged[-1][0], max(merged[-1][1], e))
            else:
                merged.append((s, e))
        for s, e in merged:
            self.map_range(s, e - s)
        for seg in mo.segments:
            if seg.name == "__PAGEZERO" or seg.filesize == 0:
                continue
            self.wrb(seg.vmaddr, mo.buf[seg.fileoff:seg.fileoff + seg.filesize])

        self.main_addr = mo.text_vm() + mo.entryoff
        inits = mo.mod_init_funcs()
        # skip module initializers that BELONG to Vivox (exact symbol match
        # on the init function address; nearest-symbol is too coarse here)
        exact_syms = {}
        for i, s in enumerate(mo.syms):
            if s.value and (s.type & 0x0E) == 0x0E:  # N_SECT
                exact_syms.setdefault(s.value, mo.sym_name(i))
        self.inits = []
        skipped = []
        for f in inits:
            nm = exact_syms.get(f)
            if nm and ("Vivox" in nm or "vx_" in nm[:8]):
                skipped.append((f, nm[:40]))
                continue
            self.inits.append(f)
        if skipped:
            self.console("[dyld] skipping %d Vivox initializers" % len(skipped))

        # Install light-weight FAKE singletons for engine globals whose
        # real creation is gated behind obfuscated environment checks we
        # cannot satisfy. Each fake object has a vtable of stub methods
        # (return 1) so the engine's early FText/culture queries succeed
        # and boot continues.
        self._install_fake_singletons()

        # process arguments (stack-resident arrays)
        argv0 = self.cstring_cell("argv0", GUEST_BUNDLE + "/FortniteClient")
        exe_cell = self.cstring_cell("exe", GUEST_BUNDLE + "/FortniteClient")
        env_ptrs = [self.cstring_cell("env." + k, "%s=%s" % (k, v))
                    for k, v in self.env.items()]
        envp = self.data_cell("__envp", 8 * (len(env_ptrs) + 1))
        for i, p in enumerate(env_ptrs):
            self.w64(envp + 8 * i, p)
        self.w64(envp + 8 * len(env_ptrs), 0)
        apple = self.data_cell("__apple", 16)
        self.w64(apple, self.cstring_cell(
            "apple0", "executable_path=" + GUEST_BUNDLE + "/FortniteClient"))
        self.w64(apple + 8, 0)
        argv = self.data_cell("__argv", 16)
        self.w64(argv, argv0)
        self.w64(argv + 8, 0)
        pvars = self.data_cell("__pvars", 64)
        self.w64(pvars, mo.text_vm())

        self.exe_path = GUEST_BUNDLE + "/FortniteClient"
        self.init_args = (1, argv, envp, apple, pvars)
        self.main_args = (1, argv, envp, apple)
        self.w64(self.data_cell("_environ", 16), envp)

        # fixed runtime windows BEFORE any stub is created
        self.prepare_runtime_regions()

        # native hot stubs (pure ARM64 code) need the farm window mapped
        try:
            self.native_stubs = build_native_stubs(self)
        except Exception as e:
            self.console("[native] disabled (%r)" % (e,))
            self.native_stubs = {}

        # ObjC metadata (classes/methods) BEFORE link: ghost class binds
        self.objc.boot()

        # link image
        n_slots, n_binds = self.link()
        # ---- populate __DefaultRuneLocale (Darwin rune table) ---------
        # The engine's iswspace/iswalpha/... read __runetype[c] directly
        # from this imported data symbol (e.g. FParse::Param's token
        # boundaries!). Zero storage = "-es2" never parses as a switch.
        rl = self.data_cells.get("d.__DefaultRuneLocale")
        if rl:
            _A, _C, _D, _G = 0x100, 0x200, 0x400, 0x800
            _L, _P, _S, _U = 0x1000, 0x2000, 0x4000, 0x8000
            _X, _B, _R = 0x10000, 0x20000, 0x40000
            rt = []
            for c in range(0x80):
                if c < 0x20:
                    v = _C
                    if c in (9, 10, 11, 12, 13):
                        v |= _S
                    if c == 9:
                        v |= _B
                elif c == 0x20:
                    v = _S | _B | _R
                elif c < 0x30:
                    v = _P | _G | _R
                elif c <= 0x39:                       # digits
                    v = _D | _G | _X | _R
                elif c < 0x41:
                    v = _P | _G | _R
                elif c <= 0x46:                        # A-F
                    v = _A | _U | _G | _X | _R
                elif c <= 0x5A:                        # G-Z
                    v = _A | _U | _G | _R
                elif c < 0x61:
                    v = _P | _G | _R
                elif c <= 0x66:                        # a-f
                    v = _A | _L | _G | _X | _R
                elif c <= 0x7A:                        # g-z
                    v = _A | _L | _G | _R
                elif c < 0x7F:
                    v = _P | _G | _R
                else:                                   # DEL
                    v = _C
                rt.append(v)
            # _RuneLocale.__runetype lives at +0x3c in this build's
            # __DefaultRuneLocale consumers (verified in disasm)
            self.w64(rl, int.from_bytes(b"RuneMagi", "little"))
            for c in range(0x80):
                self.w32(rl + 0x3c + 4 * c, rt[c])
            self.console("[dyld] rune table populated (128 entries)")
        # forward all GL imports to the Mesa bridge
        n_gl = fn35_gles.register_gl()
        self.console("[gl] %d GL imports bridged to Mesa/llvmpipe" % n_gl)

        # ---- surgical code patches (guest memory, file untouched) ----
        # Also re-applied by fn35_snap.load_snapshot AFTER the region
        # overlay (the overlay would otherwise restore the original
        # bytes over our patched ones).
        self.apply_code_patches()

        self.install_hooks()

        # main thread
        mstack = self.stack_alloc(8 << 20)
        main = EmuThread(0x1000, "main", mstack, 8 << 20)
        main.errno_cell = self.data_cell("errno.1000", 16)
        top = (mstack + (8 << 20) - 0x1000) & ~0xF
        regs = {}
        for r in SAVE_REGS:
            regs[r] = 0
        regs[a64.UC_ARM64_REG_SP] = top
        regs[a64.UC_ARM64_REG_PC] = self.inits[0] if self.inits \
            else self.main_addr
        regs[XREGS[30]] = MAGIC_INIT_RET
        a = self.init_args if self.inits else self.main_args
        for i in range(len(a)):
            regs[XREGS[i]] = a[i] & MASK64
        main.regs = regs
        main.pc = regs[a64.UC_ARM64_REG_PC]
        if not self.inits:
            self.phase = "main"
        self.threads[main.tid] = main
        self.order.append(main.tid)

        self.console("[MACH-O] mapped %d segment ranges, %d sections"
                     % (len(merged), len(mo.sections)))
        self.console("[dyld] filled %d GOT slots, applied %d binds, "
                     "%d stubs created" % (n_slots, n_binds,
                                           len(self.stub_order)))
        self.console("[dyld] %d module initializers, main at 0x%x"
                     % (len(self.inits), self.main_addr))
        return True

    # ================= scheduler ====================================
    def pick_ready(self):
        n = len(self.order)
        if n == 0:
            return None
        for _ in range(n):
            self.rr = (self.rr + 1) % n
            t = self.threads.get(self.order[self.rr])
            if t is not None and t.state == "ready":
                return t
        return None

    def clock_cap(self):
        """Virtual time may never lead wall time by more than ~5 ms
        (re-anchored continuously). This keeps the engine's repeating
        timers at real-world rates and stops thread/memory explosions."""
        now = int(time.time() * 1e9)
        aw = getattr(self, "_clk_anchor_wall", None)
        if aw is None:
            self._clk_anchor_wall = now
            self._clk_anchor_v = self.vclock
            return self.vclock + 50_000_000
        allow = (now - self._clk_anchor_wall) + 5_000_000
        cap = self._clk_anchor_v + allow
        if self.vclock >= cap - 1_000_000:
            # we're at the cap: re-anchor so slack doesn't accumulate
            self._clk_anchor_wall = now
            self._clk_anchor_v = self.vclock
        return cap

    def _earliest_thread_wake(self):
        nxt = None
        for t in self.threads.values():
            if t.state == "blocked" and t.wake_ns \
                    and t.wake_ns > self.vclock:
                nxt = t.wake_ns if nxt is None else min(nxt, t.wake_ns)
        return nxt

    def advance_clock(self):
        # wake everything past-due first (clock may have jumped beyond a
        # thread's wake time -- it must NOT be left sleeping forever)
        readied = False
        for t in self.threads.values():
            if t.state == "blocked" and t.wake_ns \
                    and t.wake_ns <= self.vclock:
                t.state = "ready"
                t.wait = None
                readied = True
        if readied:
            return True
        nxt = None
        for t in self.threads.values():
            if t.state == "blocked" and t.wake_ns \
                    and t.wake_ns > self.vclock:
                nxt = t.wake_ns if nxt is None else min(nxt, t.wake_ns)
        if nxt is None:
            return False
        self.vclock = max(self.vclock, min(nxt, self.clock_cap()))
        for t in self.threads.values():
            if t.state == "blocked" and t.wake_ns \
                    and t.wake_ns <= self.vclock:
                t.state = "ready"
                t.wait = None
                readied = True
        return readied

    def restore_thread(self, t):
        if t.regs:
            for r, v in t.regs.items():
                self.uc.reg_write(r, v & MASK64 if v is not None else 0)
            # force-commit the whole restored context (TCG desync fix:
            # deferred writes would let the resumed TB run with stale regs)
            for r in t.regs:
                self.uc.reg_read(r)
        self.cur = t

    def save_thread(self, t):
        regs = {}
        for r in SAVE_REGS:
            try:
                regs[r] = self.uc.reg_read(r)
            except Exception:
                regs[r] = 0
        t.regs = regs
        t.pc = regs.get(a64.UC_ARM64_REG_PC, t.pc)

    def run(self):
        self.t_start = time.time()
        self.console("[run] scheduler start (budget %.0fs, slice=%d instr)"
                     % (self.budget, self.slice_instr))
        while True:
            if self.fatal_msg or self.exit_code is not None:
                break
            # wake past-due timed waiters EVERY iteration: advance_clock
            # only runs in the idle path (pick_ready == None), so a CPU-
            # hogging ready thread (e.g. MainAppThread spin-waiting for
            # task workers) starves every pthread_cond_timedwait sleeper
            # forever -- their wake deadlines pass but nothing re-readies
            # them. This was the segBX/BZ "silent phase" killer.
            for _t in self.threads.values():
                if _t.state == "blocked" and _t.wake_ns \
                        and _t.wake_ns <= self.vclock:
                    _t.state = "ready"
                    _t.wait = None
            if time.time() - self.t_start > self.budget:
                # snapshot safety: never stop with pending python
                # continuations on the stack (they are generators that
                # cannot be serialized). Give them 60s to drain.
                if self.py_stack and \
                        time.time() - self.t_start < self.budget + 60.0:
                    continue
                self.stop_reason = "budget"
                break
            t = self.pick_ready()
            if t is None:
                # fire due ObjC timers / display links (spawns threads)
                try:
                    self.objc.tick()
                except Exception as e:
                    self.warn("objc.tick: %r" % (e,))
                t = self.pick_ready()
                if t is not None:
                    continue
                if self.advance_clock():
                    continue
                # real-time governor: virtual time may not outrun the wall
                # clock by more than 5 ms (otherwise the engine's repeating
                # timers fire at insane rates and memory explodes)
                now_ns = int(time.time() * 1e9)
                cand = self.objc.next_deadline()
                tw = self._earliest_thread_wake()
                if tw is not None and (cand is None or tw < cand):
                    cand = tw
                if cand is not None and cand > self.vclock:
                    cap = self.clock_cap()
                    if cand >= cap:
                        # virtual time is at the wall cap: let real time
                        # pass (the deadline will become reachable)
                        time.sleep(0.002)
                        continue
                    self.vclock = cand
                    continue
                if cand is None and tw is None and self.thread_count() == 0:
                    self.stop_reason = "deadlock"
                    break
                # nothing ready but timers exist in the past?? fire them
                if cand is not None and cand <= self.vclock:
                    continue
                self.stop_reason = "deadlock"
                break
            self.restore_thread(t)
            self.stop_reason = None
            wall0 = time.time()
            self.heartbeat()
            try:
                # until=1 (never reached): a PC=0 branch must FAULT so
                # on_fetch() can capture the caller live instead of the
                # silent emu_stop that clobbers the evidence.
                self.uc.emu_start(t.pc, 1, 2_000_000, self.slice_instr)
            except UcError as e:
                self.fatal("unicorn error %s (pc=0x%x, cur=%r)"
                           % (e, self.reg_pc(), t))
                break
            except Exception as e:
                self.fatal("hook exception %r (pc=0x%x)" % (e, self.reg_pc()))
                break
            self.save_thread(t)
            # deferred mmap data-fill (TCG-desync fix: large mem_writes
            # inside hook callbacks corrupt unicorn state): apply BETWEEN
            # slices only
            dw = getattr(self, "_deferred_writes", None)
            if dw:
                self._deferred_writes = []
                for wa, wd in dw:
                    try:
                        self.wrb(wa, wd)
                    except Exception as e:
                        self.warn("deferred mmap fill 0x%x failed %r"
                                  % (wa, e))
                self._need_flush = False
            # deferred TB flush (armed mid-emulation): safe between slices
            if getattr(self, "_lm_flush_pending", False):
                self._lm_flush_pending = False
                # PERF FIX (segAL crawl): the old range sweep
                # ctl_remove_cache(1, 0xFFFFFFF00000) walks a ~17TB
                # range and takes 5-8 MINUTES per call (measured with
                # py-spy: the whole resumed segment was stuck inside
                # it, doing only 10 dyld inits in 420s). ctl_flush_tb()
                # is the dedicated O(1) full-flush API (UC_CTL_TB_FLUSH)
                # and achieves the same post-restore staleness fix.
                # FN35_FLUSH selects: tb (default) | rangesmall (the
                # guest code span only, ~90MB sweep) | rangefull (the
                # original 17TB sweep). segAV showed ctl_flush_tb alone
                # still desyncs at the AES table loops on resumed runs;
                # testing whether the range variant has extra magic.
                _fl = os.environ.get("FN35_FLUSH", "tb")
                try:
                    if _fl == "rangefull":
                        self.uc.ctl_remove_cache(1, 0xFFFFFFF00000)
                        self.console("[lm-trace] TB flushed (range full)")
                    elif _fl == "regions":
                        n = 0
                        for _r in self.uc.mem_regions():
                            try:
                                self.uc.ctl_remove_cache(_r[0], _r[1] + 1)
                                n += 1
                            except Exception:
                                pass
                        self.console("[lm-trace] TB flushed (%d regions)"
                                     % n)
                    elif _fl == "rangesmall":
                        self.uc.ctl_remove_cache(0x100000000, 0x105900000)
                        self.console("[lm-trace] TB flushed (range small)")
                    else:
                        self.uc.ctl_flush_tb()
                        self.console("[lm-trace] TB cache flushed "
                                     "(ctl_flush_tb fast path)")
                except Exception as e:
                    self.console("[lm-trace] flush failed: %r" % (e,))
            if not t.pc:
                # NULL function-pointer call (blr xzr / stored NULL):
                # unicorn no-ops an emu_start(0, 0) slice, so without
                # this check the thread spins forever doing nothing.
                lr = (t.regs or {}).get(a64.UC_ARM64_REG_LR, 0)
                nm, sa = self.nearest_symbol(lr)
                self.console("[null-call] %r hit PC=0 (caller lr=0x%x "
                             "%s+0x%x) -- retiring"
                             % (t.name, lr, (nm or "?")[:40],
                                lr - (sa or 0)))
                if t.tid == 0x1000 or t.name.startswith("of.MainAppThread"):
                    # the game's driver thread (UE4 spawns the real main
                    # loop via an ObjC "MainAppThread:" selector; the
                    # original "main" tid 0x1000 usually waits on it).
                    # Retiring it silently made later segments spin for
                    # their whole budget with zero progress.
                    self.stop_reason = "main-dead"
                    self.fatal_msg = ("main thread null-call at lr=0x%x "
                                     "(%s+0x%x)" % (lr, nm or "?",
                                                    lr - (sa or 0)))
                    # --- crash forensics: AAPCS frame-chain walk ------
                    # lr is often already clobbered by the time we get
                    # here; the x29 chain (frame layout [x29]=saved fp,
                    # [x29+8]=return addr) survives and gives the caller.
                    try:
                        fp = (t.regs or {}).get(
                            a64.UC_ARM64_REG_X29, 0) or \
                            (t.regs or {}).get(a64.UC_ARM64_REG_FP, 0)
                        sp = (t.regs or {}).get(a64.UC_ARM64_REG_SP, 0)
                        xs = " ".join(
                            "x%d=0x%x" % (i, (t.regs or {}).get(r, 0))
                            for i, r in enumerate(XREGS[:9]))
                        self.console("[main-dead] %s sp=0x%x fp=0x%x"
                                     % (xs, sp, fp))
                        seen = set()
                        nfr = 0
                        while fp and sp - 0x400000 < fp < sp + 0x400000 \
                                and nfr < 24 and fp not in seen:
                            seen.add(fp)
                            try:
                                nxt = self.rd64(fp)
                                ret = self.rd64(fp + 8)
                            except Exception:
                                break
                            fn, fs = self.nearest_symbol(ret)
                            self.console("[bt %2d] 0x%x %s+0x%x"
                                         % (nfr, ret, (fn or "?")[:48],
                                            ret - (fs or 0)))
                            nfr += 1
                            if nxt <= fp:
                                break
                            fp = nxt
                    except Exception as e:
                        self.console("[main-dead] bt failed: %r" % (e,))
                    break
                self.thread_done(t)
                continue
            t.approx_instr += self.slice_instr
            # wall-paced virtual clock: a slice advances virtual time by
            # exactly what it cost in real time (min 0.1 ms)
            spent = int((time.time() - wall0) * 1e9)
            cap = self.clock_cap()
            self.vclock = min(self.vclock + max(100_000, spent), cap) \
                & 0x7FFFFFFFFFFFFFFF
            try:
                self.objc.tick()
            except Exception as e:
                self.warn("objc.tick: %r" % (e,))
        self.elapsed = time.time() - self.t_start
        self.console("[run] stopped: reason=%s fatal=%r exit=%r"
                     % (self.stop_reason, self.fatal_msg, self.exit_code))
        return self.stop_reason

    # ================= syscalls (svc #0x80) =========================
    def do_syscall(self, n):
        x = [self.reg_x(i) for i in range(17)]
        if n == 1:                                    # exit
            self.exit_code = x[0]
            self.console("[kernel] exit(%d)" % x[0])
            try:
                self.uc.emu_stop()
            except Exception:
                pass
            return None
        if n == 3:                                    # read
            return self.sys_read(x[0], x[1], x[2])
        if n == 4:                                    # write
            return self.sys_write(x[0], x[1], x[2])
        if n == 5:                                    # open
            return self.sys_open(self.gcstr(x[0]), x[1], x[2])
        if n == 6:                                    # close
            return self.sys_close(x[0])
        if n == 20:                                   # getpid
            return 4242
        if n in (24, 25, 39, 47, 49):                 # uid/gid
            return 501 if n != 49 else 501
        if n == 33:                                   # access
            p = self.translate_path(self.gcstr(x[0]))
            import os as _os
            mode = x[1]
            gpath = self.gcstr(x[0])
            ok = _os.access(p, _os.R_OK) if p else False
            if not ok and self.pakfs is not None:
                if self.pakfs.resolve(gpath) is not None \
                        or self.pakfs.resolve_dir(gpath) is not None:
                    ok = True
                elif self._pak_container_fallback(gpath, p):
                    ok = True
            return 0 if ok else -2
        if n == 54:                                   # ioctl
            return 0
        if n == 73:                                   # munmap (noop)
            return 0
        if n == 74:                                   # mprotect
            return 0
        if n == 75:                                   # madvise
            return 0
        if n == 92:                                   # fcntl
            return 0
        if n == 128:                                  # rename
            import os as _os
            a = self.translate_path(self.gcstr(x[0]))
            b = self.translate_path(self.gcstr(x[1]))
            try:
                _os.rename(a, b)
                return 0
            except Exception:
                return -2
        if n == 136:                                  # mkdir
            import os as _os
            p = self.translate_path(self.gcstr(x[0]))
            try:
                _os.makedirs(p, exist_ok=True)
                return 0
            except Exception:
                return -2
        if n == 137:                                  # rmdir
            return 0
        if n in (153, 154):                            # pread/pwrite
            return self.sys_pread(x[0], x[1], x[2], x[5]) if n == 153 \
                else self.sys_write(x[0], x[1], x[2])
        if n == 165:                                   # nosudo
            return -78
        if n == 169:                                   # csops
            if x[2] and x[3] > 0:
                self.wrb(x[2], b"\x00" * min(x[3], 128))
            return 0
        if n in (188, 190):                            # stat / lstat
            return self.sys_stat(self.gcstr(x[1]), x[2])
        if n == 189:                                   # fstat
            return self.sys_fstat(x[0], x[1])
        if n == 194:                                   # getrlimit
            if x[1]:
                self.wrb(x[1], struct.pack("<QQ", 1 << 62, 1 << 62))
            return 0
        if n == 195:                                   # setrlimit
            return 0
        if n == 196:                                   # getdirentries
            return self.sys_getdirentries(x[0], x[1], x[2], x[3])
        if n == 199:                                   # lseek
            return self.sys_lseek(x[0], x[1], x[2])
        if n == 202:                                   # sysctl
            return self.sys_sysctl(x[0], x[1], x[2], x[3])
        if n == 274:                                   # sysctlbyname
            return self.sys_sysctlbyname(self.gcstr(x[0]), x[1], x[2])
        if n == 278:                                   # getdirentriesattr
            return -78
        if n == 340:                                   # proc_info
            return -78
        if n == 477:                                   # mmap
            return self.sys_mmap(x[0], x[1], x[2], x[3], x[4], x[5])
        if n == 488:                                   # bsdthread_register
            return 0
        if n == 542:                                   # shareRegion...
            return 0
        if n < 0:                                      # mach traps
            return self.sys_machtrap(n, x)
        self.unknown_syscalls[n] += 1
        self.console("[kernel] unhandled syscall %d (x0=0x%x x1=0x%x "
                     "x2=0x%x x3=0x%x)" % (n, x[0], x[1], x[2], x[3]))
        return -78                                    # ENOSYS

    def sys_machtrap(self, n, x):
        if n == -25:                                   # mach_msg
            self.trace_mach("mach_msg(v0=0x%x, opt=0x%x, size=0x%x)"
                            % (x[0], x[1], x[2]))
            return 0
        self.console("[kernel] unhandled mach trap %d" % n)
        return 0

    # ---- filesystem core
    def translate_path(self, gpath):
        import os as _os
        if not gpath:
            return None
        p = gpath.replace("//", "/")
        if p.startswith("file://"):
            p = p[7:]
        roots = (
            (GUEST_BUNDLE,
             _os.path.join(self.sandbox, "Bundle", "FortniteClient.app")),
            (GUEST_BUNDLE.replace("/private/", "/", 1),
             _os.path.join(self.sandbox, "Bundle", "FortniteClient.app")),
            (GUEST_DATA, _os.path.join(self.sandbox, "Data")),
            ("/var/mobile", _os.path.join(self.sandbox, "Data")),
            ("/var/tmp", _os.path.join(self.sandbox, "tmp")),
            ("/tmp", _os.path.join(self.sandbox, "tmp")),
            ("/private/tmp", _os.path.join(self.sandbox, "tmp")),
            ("/var/db", _os.path.join(self.sandbox, "Data", "db")),
        )
        for gp, host in roots:
            if p == gp or p.startswith(gp + "/"):
                rel = p[len(gp):].lstrip("/")
                return _os.path.normpath(_os.path.join(host, rel))
        if p.startswith("/System") or p.startswith("/usr") \
                or p.startswith("/Developer") or p.startswith("/Library"):
            return _os.path.join(self.sandbox, "System",
                                p.lstrip("/"))
        return _os.path.normpath(_os.path.join(self.sandbox, "System",
                                               p.lstrip("/")))

    def fd_alloc(self, entry):
        fd = self.next_fd
        self.next_fd += 1
        self.fds[fd] = entry
        return fd

    def _png_trace(self, fd, buf, data, tag):
        """PNG read forensics: CRC-check the assembled buffer after every
        read served for a .png-backed fd."""
        ent = self.fds.get(fd)
        if not ent or ent[0] != "file":
            return
        host = ent[2]
        if not isinstance(host, str) or not host.lower().endswith(".png"):
            return
        import zlib as _zl
        import struct as _st
        try:
            with open(host, "rb") as _f:
                whole = _f.read()
            n = len(data)
            self._png_parts = getattr(self, "_png_parts", {})
            info = self._png_parts.setdefault(
                fd, {"pos": 0, "got": bytearray()})
            pos = ent[1].tell() - n
            if pos == info["pos"]:
                info["got"] += data
                info["pos"] = pos + n
            # CRC of the FULL expected file slice we have so far
            got = bytes(info["got"])
            msg = "len=%d got=%d" % (len(whole), len(got))
            if whole.startswith(b"\x89PNG\r\n\x1a\n") and got[:8] == b"\x89PNG\r\n\x1a\n":
                if got[:33] == whole[:33]:
                    msg += " IHDR-part-OK"
                else:
                    msg += " IHDR-part-DIFFERS!!"
                    msg += " got=%s" % got[:33].hex()
            self.console("[png-rd] %s fd=%d buf=0x%x n=%d pos=%d %s"
                         % (tag, fd, buf, n, pos, msg))
            # full file delivered: arm a write-watchpoint on the guest
            # buffer to catch whoever stomps it before libpng checks CRC
            if len(got) >= len(whole) and whole[:8] == b"\x89PNG\r\n\x1a\n" \
                    and n and len(whole) >= 33 and got[:33] == whole[:33] \
                    and not getattr(self, "_png_watch_armed", False):
                self._png_watch_armed = True
                self._png_watch_buf = buf
                self._png_watch_end = buf + len(got)
                self._png_watch_hits = 0
                try:
                    from unicorn import UC_HOOK_MEM_WRITE
                    def _wp(uc, access, address, size, value, user):
                        self._png_watch_hits += 1
                        if self._png_watch_hits <= 14:
                            pc = self.reg_pc()
                            nm, sa = self.nearest_symbol(pc)
                            d = self.rdb(address, min(size, 16))
                            self.console("[png-STOMP] #%d addr=0x%x size=%d "
                                         "val=%r pc=0x%x (%s+0x%x)"
                                         % (self._png_watch_hits, address,
                                            size, d[:16], pc,
                                            (nm or "?")[:40],
                                            pc - (sa or 0)))
                    self.uc.hook_add(UC_HOOK_MEM_WRITE, _wp,
                                     begin=buf, end=buf + len(got))
                    self.console("[png-watch] armed on [0x%x..0x%x)"
                                 % (buf, buf + len(got)))
                except Exception as e:
                    self.console("[png-watch] arm failed %r" % (e,))
        except Exception as e:
            self.console("[png-rd] %s fd=%d log-failed %r" % (tag, fd, e))

    def sys_open(self, gpath, flags, mode):
        import os as _os
        _dbg_proj = gpath and ".uproject" in gpath.lower()
        host = self.translate_path(gpath)
        if host is None:
            if _dbg_proj:
                self.console("[open-proj] %r -> translate_path None"
                             % gpath)
            return -2
        _mk = None
        if self.pakfs is not None and not _os.path.exists(host):
            # pak overlay: files materialize into the cache, dirs as dirs
            _mk = self.pakfs.materialize(gpath)
            if _mk is not None:
                host = _mk
        if _mk is None and not _os.path.exists(host):
            _pk = self._pak_container_fallback(gpath, host)
            if _pk:
                host = _pk
                _mk = _pk
        if _dbg_proj:
            self.console("[open-proj] %r -> host=%s exists=%s mk=%r flags=0x%x"
                         % (gpath, host, _os.path.exists(host), _mk, flags))
        # PNG forensics: log every served PNG + verify its header CRC
        if gpath and gpath.lower().endswith(".png"):
            try:
                with open(host, "rb") as _f:
                    _d = _f.read(40)
                if _d[:8] == b"\x89PNG\r\n\x1a\n":
                    import struct as _st
                    import zlib as _zl
                    _ln = _st.unpack(">I", _d[8:12])[0]
                    _crc_ok = (_d[12:16] == b"IHDR" and
                               _st.unpack(">I", _d[16 + _ln:20 + _ln])[0]
                               == _zl.crc32(_d[12:16 + _ln]) & 0xFFFFFFFF)
                    self.console("[png-open] %s -> %s IHDR-CRC=%s"
                                 % (gpath, host.split("fn35/")[-1],
                                    "OK" if _crc_ok else "BAD!"))
                else:
                    self.console("[png-open] %s -> %s NOT-A-PNG!"
                                 % (gpath, host.split("fn35/")[-1]))
            except Exception as _e:
                self.console("[png-open] %s verify failed %r"
                             % (gpath, _e))
        acc = flags & 3
        o_creat = flags & 0x200
        o_trunc = flags & 0x400
        if acc == 0 and not o_creat:
            if not _os.path.isfile(host):
                if _os.path.isdir(host):
                    fd = self.fd_alloc(("dir", host))
                    return fd
                return -2                               # ENOENT
            if self.pakfs is not None and self.pakfs.in_cache(host) \
                    and _os.path.getsize(host) == 0:
                host = self.pakfs.hydrate(host)
            try:
                f = open(host, "rb")
            except OSError:
                return -2
            return self.fd_alloc(("file", f, host))
        # write-ish
        try:
            _os.makedirs(_os.path.dirname(host), exist_ok=True)
            f = open(host, "wb" if o_trunc else "ab+")
            return self.fd_alloc(("file", f, host))
        except OSError as e:
            self.warn("open(%s) -> %r" % (gpath, e))
            return -2

    def sys_close(self, fd):
        ent = self.fds.pop(fd, None)
        if ent and ent[0] == "file":
            try:
                ent[1].close()
            except Exception:
                pass
        return 0

    def sys_read(self, fd, buf, count):
        ent = self.fds.get(fd)
        if ent is None:
            return -9
        if ent[0] == "console":
            return 0
        if ent[0] == "file":
            pos0 = ent[1].tell()
            data = ent[1].read(min(count, 1 << 24))
            if os.environ.get("FN35_TRACE_READ") and \
                    len(data) >= 0x1000:
                self.console("[rd] fd=%d n=%d off=%d -> %d%s"
                             % (fd, count, pos0, len(data),
                                " EOF" if len(data) < count else ""))
            if data:
                # NOTE: write IMMEDIATELY. A deferral experiment (moving
                # large writes to slice boundaries) starved same-slice
                # consumers: the guest reads the buffer right after the
                # stub returns, so deferred data = zeros -> entry header
                # parse failures. The phantom CRC faults that motivated
                # it were actually TLB staleness from snapshot restore,
                # fixed by the post-restore TB flush in fn35_snap.
                self.wrb(buf, data)
                self._png_trace(fd, buf, data, "read")
            return len(data)
        if ent[0] == "dir":
            return -21
        return -9

    def sys_write(self, fd, buf, count):
        ent = self.fds.get(fd)
        data = self.rdb(buf, min(count, 1 << 20)) if buf else b""
        if fd in (1, 2) or (ent and ent[0] == "console"):
            self.console("[fd%d] %s" % (fd, data.decode("utf-8", "replace")))
            return count
        if ent and ent[0] == "file":
            ent[1].write(data)
            return count
        return count

    def sys_lseek(self, fd, off, whence):
        ent = self.fds.get(fd)
        if ent and ent[0] == "file":
            try:
                ent[1].seek(off, whence)
                return ent[1].tell()
            except Exception:
                return -29
        return -9

    def sys_pread(self, fd, buf, count, offset):
        ent = self.fds.get(fd)
        _tr = getattr(self, "_trace_fds", None)
        if _tr and fd in _tr:
            self.console("[fd%d] pread n=%d off=%d -> %s"
                         % (fd, count, offset,
                            "file" if ent and ent[0] == "file" else
                            ("CLOSED/" + str(ent[0]) if ent else "NOENT")))
        if ent and ent[0] == "file":
            ent[1].seek(offset)
            data = ent[1].read(min(count, 1 << 24))
            if data:
                self.wrb(buf, data)
                self._png_trace(fd, buf, data, "pread@%d" % offset)
            if _tr and fd in _tr:
                self.console("[fd%d] pread -> %d bytes%s"
                             % (fd, len(data),
                                " EOF!" if len(data) < count else ""))
            return len(data)
        return -9

    def _pack_stat(self, st_addr, host_path, fd=None):
        import os as _os
        try:
            st = _os.stat(host_path)
            isdir = _os.path.isdir(host_path)
        except OSError:
            return -2
        mode = (0x4000 | 0o755) if isdir else (0x8000 | 0o644)
        buf = bytearray(144)
        struct.pack_into("<I", buf, 0, 1)             # dev
        struct.pack_into("<H", buf, 4, mode)          # mode
        struct.pack_into("<H", buf, 6, 1)             # nlink
        struct.pack_into("<Q", buf, 8, int(st.st_ino) & MASK64)
        struct.pack_into("<I", buf, 16, 501)
        struct.pack_into("<I", buf, 20, 501)
        at = int(st.st_atime)
        mt = int(st.st_mtime)
        ct = int(st.st_ctime)
        struct.pack_into("<qq", buf, 32, at, 0)
        struct.pack_into("<qq", buf, 48, mt, 0)
        struct.pack_into("<qq", buf, 64, ct, 0)
        struct.pack_into("<qq", buf, 80, mt, 0)       # birthtime
        struct.pack_into("<Q", buf, 96, st.st_size)
        struct.pack_into("<Q", buf, 104, (st.st_size + 4095) // 4096)
        struct.pack_into("<I", buf, 112, 4096)
        if st_addr:
            self.wrb(st_addr, bytes(buf))
        return 0

    def _pak_container_fallback(self, gpath, host):
        """When a guest .pak path can't be resolved to a host file, serve
        the real pak container from the app's cookeddata tree. Returns
        the host path or None.

        FN35_NO_ENGINE_PAK=1 suppresses this: the ENGINE's own pak layer
        (FPakPlatformFile) then never mounts, and all file reads fall to
        the physical layer where OUR pakfs materializes entries on
        demand (the run49-proven model -- the engine-mounted path dies
        in the desync-corrupted name-table lookup)."""
        if not gpath or not gpath.lower().endswith(".pak"):
            return None
        import os as _os
        if _os.environ.get("FN35_NO_ENGINE_PAK"):
            if not getattr(self, "_no_engine_pak_logged", False):
                self._no_engine_pak_logged = True
                self.console("[pak-open] engine pak mount suppressed "
                             "(FN35_NO_ENGINE_PAK; physical model)")
            return None
        _base = _os.path.basename(gpath.replace("\\", "/")).lower()
        _cand = _os.path.join(
            _os.path.dirname(self.macho_path), "cookeddata",
            "fortnitegame", "content", "paks", _base)
        if _os.path.isfile(_cand):
            if not getattr(self, "_pak_served", False):
                self._pak_served = True
                self.console("[pak-open] serving pak container %r -> %s"
                             % (gpath, _cand))
            return _cand
        return None

    def sys_stat(self, gpath, st_addr):
        import os as _os
        host = self.translate_path(gpath)
        if not host:
            return -2
        if self.pakfs is not None and not _os.path.exists(host):
            mk = self.pakfs.materialize(gpath)
            if mk is not None:
                host = mk
                if _os.environ.get("FN35_LOG_OPEN"):
                    self.console("[stat-pak] %r -> %r" % (gpath, host))
            else:
                pk = self._pak_container_fallback(gpath, host)
                if pk:
                    host = pk
        return self._pack_stat(st_addr, host)

    def sys_fstat(self, fd, st_addr):
        ent = self.fds.get(fd)
        if not ent:
            # ALWAYS zero the struct on failure: an unfilled stat
            # buffer hands the caller raw stack garbage (the "Requested
            # read of <stack-addr> bytes" LogFileManager storm).
            try:
                self.wrb(st_addr, b"\x00" * 128)
            except Exception:
                pass
            return -9
        if ent[0] == "file":
            host = ent[2]
        elif ent[0] == "dir":
            host = ent[1]
        else:
            return self._pack_stat(st_addr, "/dev/null")
        return self._pack_stat(st_addr, host)

    def sys_getdirentries(self, fd, buf, buflen, basep):
        import os as _os
        ent = self.fds.get(fd)
        if not ent:
            return -9
        if ent[0] != "dir":
            return -22
        host = ent[1]
        try:
            names = _os.listdir(host)
        except OSError:
            return -2
        # picklable cursor (snapshot-safe): (names, next_index)
        lst = ent[2] if len(ent) > 2 else None
        idx = ent[3] if len(ent) > 3 else 0
        if lst is None:
            lst = names
            idx = 0
        total = 0
        while idx < len(lst):
            nm = lst[idx]
            reclen = (21 + len(nm) + 1 + 7) & ~7
            if total + reclen > buflen:
                break
            idx += 1
            rec = bytearray(reclen)
            struct.pack_into("<Q", rec, 0, 4)
            struct.pack_into("<Q", rec, 8, 0)
            struct.pack_into("<H", rec, 16, reclen)
            struct.pack_into("<H", rec, 18, len(nm))
            rec[20] = 4                                 # DT_DIR guess
            rec[21:21 + len(nm)] = nm.encode()
            self.wrb(buf + total, bytes(rec))
            total += reclen
        self.fds[fd] = ("dir", host, lst, idx)
        if basep:
            self.w64(basep, 0)
        return total if total else 0

    def sys_mmap(self, addr, length, prot, flags, fd, offset):
        import os as _os
        if length == 0:
            return -22
        MAP_ANON = 0x1000
        p = self.mmap_alloc(length)
        if _os.environ.get("FN35_LOG_MMAP"):
            self.console("[sys-mmap] len=0x%x -> 0x%x fd=%d off=0x%x"
                         % (length, p, fd, offset))
        if not (flags & MAP_ANON):
            ent = self.fds.get(fd)
            if ent and ent[0] == "file":
                # CRITICAL FIX 2025-10-25: honour the mmap OFFSET (the
                # old code read from the fd's CURRENT position and also
                # capped at 16 MB). The engine maps PNG/asset slices at
                # non-zero offsets; reading from the wrong file position
                # produced IHDR CRC errors on perfectly valid files.
                # POSIX mmap also must NOT move the fd's file position,
                # so save/restore it.
                # (kept immediate)
                # callback can corrupt unicorn's execution state (the
                # CRC/AES-table impossible-address crashes). DEFER the
                # buffer fill to the slice boundary (applied between
                # emu_start calls, like the TB flush) unless disabled
                # with FN35_MMAP_NOWRITE=1 (debug).
                pos0 = ent[1].tell()
                try:
                    ent[1].seek(offset)
                    data = ent[1].read(min(length, 1 << 28))
                finally:
                    ent[1].seek(pos0)
                if data:
                    # write IMMEDIATELY (same-slice consumers read the
                    # mapping right after mmap returns)
                    self.wrb(p, data)
        return p

    def sys_sysctl(self, namep, count, oldp, oldlenp):
        if count <= 0 or count > 8:
            return -22
        raw = self.rdb(namep, 4 * count)
        mib = struct.unpack("<%dI" % count, raw)
        from fn35_ioslib import _SYSCTL_TUPLE_NAMES
        nm = _SYSCTL_TUPLE_NAMES.get(tuple(mib[:2]))
        if nm is None and len(mib) == 2:
            nm = None
        val = sysctl_bytes(nm) if nm else None
        if val is None:
            self.console("[kernel] sysctl mib=%s -> ENOENT" % (mib,))
            return -2
        avail = self.rd64(oldlenp) if oldlenp else 0
        if oldp and val:
            n = min(avail, len(val))
            self.wrb(oldp, val[:n])
            if oldlenp:
                self.w64(oldlenp, n)
        elif oldlenp:
            self.w64(oldlenp, len(val))
        return 0

    def sys_sysctlbyname(self, name, oldp, oldlenp):
        val = sysctl_bytes(name)
        if val is None:
            self.console("[kernel] sysctlbyname(%s) -> ENOENT" % name)
            return -2
        avail = self.rd64(oldlenp) if oldlenp else 0
        if oldp:
            n = min(avail, len(val))
            self.wrb(oldp, val[:n])
            if oldlenp:
                self.w64(oldlenp, n)
        elif oldlenp:
            self.w64(oldlenp, len(val))
        return 0

    # ================= libc: stdio & file wrappers ==================
    # (registered into IMPL at import time)

    def fopen_fd(self, FILE_star):
        ent = self.fds.get(FILE_star)
        return ent

    def report_path(self):
        return os.path.join(self.sandbox, "..", "fn35_boot_report.txt")

    def write_report(self, path):
        total_instr = sum(t.approx_instr for t in self.threads.values())
        lines = []
        A = lines.append
        A("=" * 72)
        A("FN3.5 INTEGRATED LOADER -- BOOT REPORT")
        A("generated: %s" % time.strftime("%Y-%m-%d %H:%M:%S"))
        A("=" * 72)
        A("")
        A("1. EXECUTION")
        A("   stop reason : %s" % self.stop_reason)
        A("   fatal       : %s" % self.fatal_msg)
        A("   exit code   : %s" % self.exit_code)
        A("   wall time   : %.1f s (budget %.0f s)" % (
            getattr(self, "elapsed", 0), self.budget))
        A("   instructions: ~%d (approx, %d per slice)"
          % (total_instr, self.slice_instr))
        A("   phase       : %s (mod_init %d/%d done)"
          % (self.phase, self.inits_done, len(self.inits)))
        A("")
        A("2. LINK (dyld substitute)")
        A("   GOT slots filled : %d" % sum(
            1 for _ in self.macho.iter_pointer_slots()))
        A("   import stubs     : %d" % len(self.stub_order))
        A("   data cells       : %d" % len(self.data_cells))
        A("   mod_init funcs   : %d" % len(self.inits))
        A("")
        A("3. THREADS (%d created, %d tracked)" % (
            (self.tid_seq - 0x1000) // 8 + 1, len(self.threads)))
        if getattr(self, "created_names", None):
            A("   created by name:")
            for nm, cnt in self.created_names.most_common(12):
                A("   %-34s %8d" % (nm, cnt))
        for t in self.threads.values():
            wk = ""
            if t.wake_ns is not None:
                wk += " wake_ns=%d (now=%d)" % (t.wake_ns, self.vclock)
            A("   %-18s tid=%-8x pc=%012x %-8s instr~%d %s%s"
              % (t.name, t.tid, t.pc or 0, t.state, t.approx_instr,
                 t.wait or "", wk))
        A("")
        A("4. TOP STUB CALLS (imported functions)")
        for name, cnt in self.stub_calls.most_common(40):
            A("   %-42s %8d" % (name, cnt))
        if self.missing_stubs:
            A("")
            A("5. UNIMPLEMENTED STUBS (auto-returned 0)")
            for name, cnt in self.missing_stubs.most_common(40):
                A("   %-42s %8d" % (name, cnt))
        A("")
        A("6. SYSCALLS")
        for name, cnt in self.syscall_calls.most_common(40):
            A("   %-32s %8d" % (name, cnt))
        if self.unknown_syscalls:
            A("   unknown: %s" % dict(self.unknown_syscalls))
        if self.mach_trace:
            A("")
            A("7. MACH ACTIVITY (last 20)")
            for s in list(self.mach_trace)[-20:]:
                A("   %s" % s)
        if self.gl_trace:
            A("")
            A("8. GPU CALLS (%d, first 30)" % len(self.gl_trace))
            for s in list(self.gl_trace)[:30]:
                A("   %s" % s)
        if self.objc_trace:
            A("")
            A("9. OBJC (last 20 of %d)" % len(self.objc_trace))
            for s in list(self.objc_trace)[-20:]:
                A("   %s" % s)
        A("")
        A("10. FAULT LOG")
        for s in self.fault_log:
            A("   %s" % s)
        if not self.fault_log:
            A("   (none)")
        A("")
        A("11. CONSOLE TAIL (last 120 lines)")
        for s in list(self.ring)[-120:]:
            A("   %s" % s)
        with open(path, "w") as f:
            f.write("\n".join(lines) + "\n")
        return path


# ----------------------------------------------------------------------
# libc stdio / file wrappers (registered into IMPL like the rest)
# ----------------------------------------------------------------------

@cfunc("_open", "_open64")
def _open_fn(l, path, flags, mode=0):
    pth = l.gcstr(path)
    if os.environ.get("FN35_LOG_OPEN"):
        import os as _o
        host = l.translate_path(pth)
        l.console("[open2 t=%.3f] %r flags=0x%x host=%r exists=%s"
                  % (time.time() % 1000, pth, flags, host,
                     _o.path.exists(host) if host else None))
    rv = l.sys_open(pth, flags, mode)
    # POSIX C convention: open() returns -1 on failure (NOT -errno).
    # Returning -2 (= -ENOENT) let the engine store it as a VALID fd
    # (fstat(-2)/close(-2) on an unopened file) and read an unfilled
    # stat struct -> stack garbage sizes -> memory corruption crash.
    return -1 if rv < 0 else rv


@cfunc("_close")
def _close_fn(l, fd):
    return l.sys_close(fd)


@cfunc("_read")
def _read_fn(l, fd, buf, n):
    rv = l.sys_read(fd, buf, n)
    return -1 if rv < 0 else rv


@cfunc("_write", "_write_nocancel", "_writev")
def _write_fn(l, fd, buf, n):
    rv = l.sys_write(fd, buf, n)
    return -1 if rv < 0 else rv


@cfunc("_lseek", "_lseek64", "_lseek_darwin")
def _lseek_fn(l, fd, off, whence):
    rv = l.sys_lseek(fd, off, whence)
    return -1 if rv < 0 else rv


@cfunc("_pread", "_pread64")
def _pread_fn(l, fd, buf, n, off):
    rv = l.sys_pread(fd, buf, n, off)
    return -1 if rv < 0 else rv


@cfunc("_ftruncate", "_fsync", "_fdatasync", "_sync", "_dup", "_dup2",
       "_chmod", "_fchmod", "_chown", "_umask", "_ioctl", "_fcntl",
       "_lockf", "_seteuid", "_setuid", "_setgid", "_mkfifo")
def _fs_stub(l, a=0, b=0, c=0):
    return 0


@cfunc("_unlink")
def _unlink_fn(l, path):
    import os as _os
    host = l.translate_path(l.gcstr(path))
    try:
        _os.remove(host)
        return 0
    except OSError:
        return -2


@cfunc("_mkdir")
def _mkdir_fn(l, path, mode):
    import os as _os
    host = l.translate_path(l.gcstr(path))
    try:
        _os.makedirs(host, exist_ok=True)
        return 0
    except OSError:
        return -2


@cfunc("_rmdir")
def _rmdir_fn(l, path):
    return 0


@cfunc("_rename")
def _rename_fn(l, a, b):
    import os as _os
    ha = l.translate_path(l.gcstr(a))
    hb = l.translate_path(l.gcstr(b))
    try:
        _os.rename(ha, hb)
        return 0
    except OSError:
        return -2


@cfunc("_access")
def _access_fn(l, path, mode):
    pth = l.gcstr(path)
    import os as _os
    if ".uproject" in pth.lower():
        l.console("[acc-proj] %r mode=%d" % (pth, mode))
    host = l.translate_path(pth)
    if host and _os.path.exists(host):
        return 0
    if l.pakfs is not None and l.pakfs.resolve(pth) is not None:
        return 0
    if l.pakfs is not None and l.pakfs.resolve_dir(pth) is not None:
        return 0
    if l._pak_container_fallback(pth, host):
        return 0
    return -2


@cfunc("_stat", "_stat64", "_lstat", "_lstat64", "_stat64_extended")
def _stat_fn(l, path, out):
    p = l.gcstr(path)
    if ".uproject" in p.lower():
        l.console("[stat-proj] %r" % p)
    if "nternationali" in p or "icudt" in p:
        l.console("[icu-stat] %r" % p)
    return l.sys_stat(p, out)


@cfunc("_fstat", "_fstat64")
def _fstat_fn(l, fd, out):
    rv = l.sys_fstat(fd, out)
    return -1 if rv < 0 else rv


@cfunc("_getdirentries", "_getdirentries64")
def _getdirent_fn(l, fd, buf, buflen, basep):
    return l.sys_getdirentries(fd, buf, buflen, basep)


@cfunc("_realpath")
def _realpath_fn(l, path, resolved):
    g = l.gcstr(path)
    norm = g
    while "//" in norm:
        norm = norm.replace("//", "/")
    parts = []
    for part in norm.split("/"):
        if part == "." or part == "":
            continue
        if part == ".." and parts:
            parts.pop()
        else:
            parts.append(part)
    out = "/" + "/".join(parts)
    if resolved:
        l.wrb(resolved, out.encode() + b"\x00")
        return resolved
    return l.cstring_cell("rp", out)


@cfunc("_getcwd")
def _getcwd_fn(l, buf, size):
    # the engine resolves its relative ICU/config paths against the CWD;
    # the real device CWD is the game content directory
    s = getattr(l, "guest_cwd", None) or (
        l.macho and ("__getcwd_lazy__"))
    if s == "__getcwd_lazy__" or s is None:
        from fn35_loader import GUEST_BUNDLE
        s = GUEST_BUNDLE + "/cookeddata/fortnitegame/content"
        l.guest_cwd = s
    if buf:
        l.wrb(buf, s.encode() + b"\x00")
    return buf


@cfunc("_chdir")
def _chdir_fn(l, path):
    l.guest_cwd = l.gcstr(path)
    return 0


@cfunc("_chdir")
def _chdir_fn(l, path):
    return 0


@cfunc("_isatty")
def _isatty_fn(l, fd):
    return 1 if fd in (0, 1, 2) else 0


@cfunc("_pipe")
def _pipe_fn(l, outfds):
    a = l.fd_alloc(("console", "r"))
    b = l.fd_alloc(("console", "w"))
    l.w32(outfds, a)
    l.w32(outfds + 4, b)
    return 0


@cfunc("_kqueue", "_kqueue1")
def _kqueue_fn(l):
    return l.fd_alloc(("kqueue",))


@cfunc("_kevent", "_kevent64")
def _kevent_fn(l, kq, ch, nch, ev, nev, timeout):
    return 0


@cfunc("_select", "_poll", "_select_")
def _select_fn(l, *a):
    return 0


# ---- stdio FILE* layer (fake FILE handles = 0x1000+fd)

def _fopen_fd(l, FILE_star):
    if FILE_star in (0x1001, 0x1003):
        return 0
    if FILE_star == 0x1002:
        return 2
    ent = l.fds.get(FILE_star)
    return ent


@cfunc("_fopen", "_fopen64", "_freopen")
def _fopen_fn(l, path, mode, stream=0):
    pth = l.gcstr(path)
    if os.environ.get("FN35_LOG_OPEN"):
        import os as _o
        host = l.translate_path(pth)
        l.console("[open t=%.3f] %r mode=%r host=%r exists=%s"
                  % (time.time() % 1000, pth, l.gcstr(mode), host,
                     _o.path.exists(host) if host else None))
    fd = l.sys_open(pth, 0 if "r" in l.gcstr(mode) else 1, 0)
    if isinstance(fd, int) and fd < 0:
        return 0
    return 0x1000 + fd


@cfunc("_fclose")
def _fclose_fn(l, f):
    if f and f > 0x1000:
        l.sys_close(f - 0x1000)
    return 0


@cfunc("_fread")
def _fread_fn(l, ptr, size, n, f):
    fd = (f - 0x1000) if f and f > 0x1000 else (0 if f == 0x1003 else 0)
    got = 0
    total = size * n
    if f and f > 0x1000:
        got = l.sys_read(fd, ptr, total)
        got = max(got, 0)
    return got // size if size else 0


@cfunc("_fwrite")
def _fwrite_fn(l, ptr, size, n, f):
    total = size * n
    if f in (0x1001, 0x1002):
        l.sys_write(1 if f == 0x1001 else 2, ptr, total)
    elif f and f > 0x1000:
        l.sys_write(f - 0x1000, ptr, total)
    return n


@cfunc("_fseek", "_fseeko", "_fseeko64")
def _fseek_fn(l, f, off, whence):
    if f and f > 0x1000:
        l.sys_lseek(f - 0x1000, off, whence)
    return 0


@cfunc("_ftell", "_ftello", "_ftello64")
def _ftell_fn(l, f):
    if f and f > 0x1000:
        return l.sys_lseek(f - 0x1000, 0, 1)
    return 0


@cfunc("_fflush", "_ferror", "_feof", "_setvbuf", "_setbuf", "_rewind",
       "_fgetpos", "_fsetpos", "_clearerr", "_ftrylockfile",
       "_flockfile", "_funlockfile")
def _f_stub(l, a=0, b=0, c=0):
    return 0


@cfunc("_fileno")
def _fileno_fn(l, f):
    return (f - 0x1000) if f and f > 0x1000 else (1 if f == 0x1001 else 2)


# ----------------------------------------------------------------------
# POSIX directory iteration (opendir/readdir/closedir); the DIR handle is
# a guest buffer that doubles as the dirent returned by readdir (BSD-style
# opaque DIR).
# ----------------------------------------------------------------------
DIRENT_NAME_MAX = 1024
DIRENT_SIZE = 8 + 8 + 2 + 2 + 1 + DIRENT_NAME_MAX     # darwin struct dirent

DT_VNODE = 0
DT_DIR = 4
DT_REG = 8


@cfunc("_opendir")
def _opendir_fn(l, path):
    import os as _os
    pth = l.gcstr(path)
    if os.environ.get("FN35_LOG_OPEN"):
        host = l.translate_path(pth)
        l.console("[opendir t=%.3f] %r host=%r" % (time.time() % 1000, pth, host))
    host = l.translate_path(pth)
    if host and not _os.path.isdir(host) and l.pakfs is not None:
        mk = l.pakfs.materialize(pth, want_dir=True)
        if mk is not None:
            host = mk
            if os.environ.get("FN35_LOG_OPEN"):
                l.console("[opendir-pak] -> %r" % host)
    if not host or not _os.path.isdir(host):
        if os.environ.get("FN35_LOG_OPEN"):
            l.console("[opendir] ENOENT %r" % pth)
        return 0
    try:
        names = sorted(_os.listdir(host))
    except OSError:
        return 0
    buf = l.heap_alloc(DIRENT_SIZE + 16, zero=True)
    l.dir_handles[buf] = {"host": host, "names": names, "idx": 0,
                          "seq": 0}
    return buf


@cfunc("_readdir")
def _readdir_fn(l, d):
    import os as _os
    h = l.dir_handles.get(d)
    if h is None:
        return 0
    if _os.environ.get("FN35_LOG_OPEN") and h.get("dbg", 0) < 10:
        h["dbg"] = h.get("dbg", 0) + 1
        l.console("[readdir#%d] dir=%r" % (h["dbg"], h["host"]))
    while True:
        if h["idx"] >= len(h["names"]):
            return 0
        nm = h["names"][h["idx"]]
        h["idx"] += 1
        if nm in (".", ".."):
            continue
        full = _os.path.join(h["host"], nm)
        if _os.path.isdir(full):
            dt, ino = DT_DIR, 2
        elif _os.path.isfile(full):
            dt, ino = DT_REG, 3
        else:
            dt, ino = DT_VNODE, 1
        h["seq"] += 1
        nb = nm.encode("utf-8", "replace")[:DIRENT_NAME_MAX - 1]
        l.w64(d + 0, ino * 1024 + h["seq"])
        l.w64(d + 8, h["seq"] * 24)
        l.w16(d + 16, DIRENT_NAME_MAX + 19)
        l.w16(d + 18, len(nb))
        l.w8(d + 20, dt)
        l.wrb(d + 21, nb + b"\x00")
        return d
    return 0


@cfunc("_closedir")
def _closedir_fn(l, d):
    l.dir_handles.pop(d, None)
    return 0


@cfunc("_readdir_r")
def _readdir_r_fn(l, d, entry_out, result_ptr):
    """int readdir_r(DIR*, struct dirent* entry, struct dirent** result)"""
    r = _readdir_fn(l, d)
    if r == 0:
        if result_ptr:
            l.w64(result_ptr, 0)
        return 0
    blob = l.rdb(r, 21 + DIRENT_NAME_MAX)
    l.wrb(entry_out, blob)
    if result_ptr:
        l.w64(result_ptr, entry_out)
    return 0


@cfunc("_fdopen")
def _fdopen_fn(l, fd, mode):
    return 0x1000 + fd


# ---- time

@cfunc("_gettimeofday")
def _gettimeofday_fn(l, tv, tz):
    if tv:
        s = int(time.time())
        l.w64(tv, s)
        l.w64(tv + 8, 0)
    return 0


@cfunc("_time")
def _time_fn(l, out):
    s = int(time.time())
    if out:
        l.w64(out, s)
    return s


@cfunc("_clock_gettime")
def _clock_gettime_fn(l, clk, ts):
    if ts:
        s = int(time.time())
        l.w64(ts, s)
        l.w64(ts + 8, 0)
    return 0


@cfunc("_clock_gettime_nsec_np")
def _clock_nsec_fn(l, clk):
    return int(time.time() * 1e9) & MASK64


@cfunc("_usleep")
def _usleep_fn(l, usec):
    l.block_cur("sleep", None, wake_ns=l.vclock + usec * 1000, ret=0)
    return 0


@cfunc("_nanosleep")
def _nanosleep_fn(l, req, rem):
    n = l.rd64(req)
    l.block_cur("sleep", None, wake_ns=l.vclock + n, ret=0)
    return 0


@cfunc("_sleep")
def _sleep_fn(l, secs):
    l.block_cur("sleep", None, wake_ns=l.vclock + secs * 1000000000,
                ret=0)
    return 0


@cfunc("_localtime", "_gmtime")
def _localtime_fn(l, t):
    return l.data_cell("tm", 64)


@cfunc("_localtime_r", "_gmtime_r")
def _localtime_r_fn(l, t, out):
    s = t & 0x7FFFFFFFFF
    if s > 0xFFFFFFFF:
        s = s & 0x7FFFFFFFFF if s < 0x7FFFFFFFFF else int(time.time())
    s = t & 0x7FFFFFFF if t < (1 << 33) else int(time.time())
    import time as _t
    lt = _t.gmtime(s if s < 2100000000 else int(time.time()))
    buf = struct.pack("<9i", lt.tm_sec, lt.tm_min, lt.tm_hour, lt.tm_mday,
                      lt.tm_mon, lt.tm_year, lt.tm_wday, lt.tm_yday, 0)
    l.wrb(out, buf)
    return out


@cfunc("_mktime")
def _mktime_fn(l, tm):
    return int(time.time())


@cfunc("_difftime")
def _difftime_fn(l, a, b):
    return ("d0", float(_to_int(a) - _to_int(b)))


def _to_int(v):
    if v >= 1 << 63:
        v -= 1 << 64
    return v


# ---- sockets offline

@cfunc("_socket", "_connect", "_send", "_recv", "_bind", "_listen",
       "_accept", "_shutdown", "_setsockopt", "_getsockopt",
       "_getsockname", "_getpeername", "_sendto", "_recvfrom",
       "_res_9_init", "_res_9_ninit", "_res_9_query")
def _sock_stub(l, a=0, b=0, c=0, d=0):
    return -1


@cfunc("_getaddrinfo")
def _getaddrinfo_fn(l, node, service, hints, res):
    return -1  # EAI_FAIL-ish


@cfunc("_freeaddrinfo")
def _freeaddrinfo_fn(l, res):
    return 0


@cfunc("_getifaddrs")
def _getifaddrs_fn(l, out):
    return -1


@cfunc("_freeifaddrs")
def _freeifaddrs_fn(l, addrs):
    return 0


# ====================================================================
# main
# ====================================================================

def main():
    base = "/home/z/my-project"
    macho_path = os.path.join(
        base, "fn35/extracted/Payload/FortniteClient.app/FortniteClient")
    sandbox = os.path.join(base, "fn35/sandbox")
    budget = float(os.environ.get("FN35_BUDGET", "90"))
    trace_n = int(os.environ.get("FN35_TRACE", "0"))
    live = os.environ.get("FN35_QUIET", "") == ""
    snapdir = os.environ.get("FN35_SNAPSHOT", "")
    resume = False

    if not os.path.isfile(macho_path):
        print("missing executable: %s" % macho_path)
        return 1

    # sandbox filesystem: expose the app bundle (paks included)
    app_src = os.path.join(
        base, "fn35/extracted/Payload/FortniteClient.app")
    for d in ("Bundle", "Data", "tmp", "System"):
        os.makedirs(os.path.join(sandbox, d), exist_ok=True)
    bl = os.path.join(sandbox, "Bundle", "FortniteClient.app")
    if not os.path.exists(bl):
        os.symlink(app_src, bl)

    # force the OpenGL ES RHI: the engine reads ue4commandline.txt from
    # the bundle on iOS; RHIInit honours -es2 (verified in disassembly)
    cl_path = os.path.join(app_src, "ue4commandline.txt")
    try:
        cur = ""
        if os.path.isfile(cl_path):
            with open(cl_path, "r") as f:
                cur = f.read().strip()
        if "-es2" not in cur:
            with open(cl_path, "w") as f:
                f.write(cur + " -es2")
            print("[fn35] ue4commandline.txt += -es2 (OpenGL ES RHI)")
    except Exception as e:
        print("[fn35] commandline patch failed: %r" % (e,))

    if snapdir and os.path.isfile(os.path.join(snapdir, "index.json")):
        # ---- resume from snapshot (chained segment) ----
        import fn35_snap
        try:
            l = fn35_snap.load_snapshot(
                snapdir, macho_path, sandbox, budget=budget,
                trace_n=trace_n, live_log=live)
            resume = True
            print("[fn35] RESUMED from snapshot: %s" % snapdir)
            if os.environ.get("FN35_LM_ON_RESUME"):
                # arm the lastmile immediately: the resumed window can
                # crash before any console milestone re-arms it
                try:
                    l.arm_lastmile_trace(2_000_000)
                except Exception as e:
                    print("[fn35] lm arm failed: %r" % (e,))
        except Exception as e:
            import traceback
            traceback.print_exc()
            print("[fn35] resume failed (%r); cold start" % (e,))
            l = None
    else:
        l = None

    if l is None:
        l = FNLoader(macho_path, sandbox, budget=budget, trace_n=trace_n,
                     live_log=live)
        print("[fn35] integrated loader starting")
        print("[fn35] mach-o: %s" % macho_path)
        print("[fn35] cryptid=%d (0 = decrypted, good)"
              % l.macho.cryptid)
        try:
            l.prepare()
        except Exception as e:
            import traceback
            traceback.print_exc()
            print("[fn35] prepare failed: %r" % e)
            return 1
    l.run()

    # save state for the next chained segment
    if snapdir and l.stop_reason == "budget" and not l.fatal_msg:
        try:
            import fn35_snap
            fn35_snap.save_snapshot(
                l, snapdir, note="seg after %.0fs" % budget)
        except Exception as e:
            import traceback
            traceback.print_exc()
            print("[fn35] snapshot save failed: %r" % (e,))
    elif snapdir and l.fatal_msg:
        # crash snapshot for offline analysis (registers/stack intact)
        try:
            import fn35_snap
            fn35_snap.save_snapshot(
                l, snapdir + "_crash",
                note="crash: %s" % str(l.fatal_msg)[:160])
        except Exception:
            pass

    out = os.path.join(base, "download/fn35/fn35_boot_report.txt")
    os.makedirs(os.path.dirname(out), exist_ok=True)
    l.write_report(out)
    print("[fn35] report -> %s" % out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
