#!/usr/bin/env python3
"""fn35_snap.py — snapshot / restore for the FN35 integrated loader.

Purpose: this sandbox kills every process when the Bash tool call ends
(verified: even setsid+nohup orphans die). Continuous emulation is capped
at ~10 minutes per call. This module lets us chain segments: each segment
saves the complete emulator state to disk, the next call restores it and
keeps going — until the login screen.

Snapshot layout (directory):
  index.json   region map + meta
  state.pkl    pickled loader python state (uc/macho/fds replaced)
  rNNN.bin     concatenated non-zero 64KB chunks of each region
"""
import json
import os
import pickle
import shutil
import sys
import time

CHUNK = 1 << 16                      # 64 KB granularity for zero-skip
VERSION = 1

# fields that must NOT be pickled (recreated on restore)
_DROP = ("uc", "macho", "_code_hook", "_block_hook", "_trace_hook")


class _LoaderRef(object):
    """marker standing in for the back-ref objc.l"""


class _SnapUnpickler(pickle.Unpickler):
    """Classes defined in fn35_loader.py get pickled as __main__.X when
    the loader runs as a script; remap them back to the module."""
    def find_class(self, module, name):
        if module == "__main__":
            try:
                import fn35_loader as FL
                return getattr(FL, name)
            except (ImportError, AttributeError):
                pass
        return super().find_class(module, name)


def _load_state(path):
    with open(path, "rb") as f:
        return _SnapUnpickler(f).load()


def _tell(f):
    try:
        return f.tell()
    except Exception:
        return 0


def _ser_fds(l):
    out = {}
    for fd, ent in (l.fds or {}).items():
        try:
            if ent is None:
                out[fd] = None
            elif ent[0] == "file":
                _, f, host = ent
                out[fd] = {"k": "file", "host": host,
                           "mode": getattr(f, "mode", "rb"),
                           "pos": _tell(f)}
            elif ent[0] == "dir":
                if len(ent) >= 4:
                    _, host, lst, idx = ent[0], ent[1], ent[2], ent[3]
                    out[fd] = {"k": "dir", "host": host,
                               "names": list(lst), "idx": idx}
                else:
                    out[fd] = {"k": "dir", "host": ent[1],
                               "names": None, "idx": 0}
            elif ent[0] == "console":
                out[fd] = {"k": "console", "dir": ent[1]}
            elif ent[0] == "kqueue":
                out[fd] = {"k": "kqueue"}
            else:
                out[fd] = {"k": "unknown", "repr": repr(ent)[:200]}
        except Exception as e:
            out[fd] = {"k": "error", "repr": repr(ent)[:200], "e": str(e)}
    return out


def _deser_fds(l, ser):
    fds = {}
    for fd, d in (ser or {}).items():
        try:
            if d is None:
                fds[fd] = None
            elif d["k"] == "file":
                f = open(d["host"], d["mode"])
                f.seek(d["pos"])
                fds[fd] = ("file", f, d["host"])
            elif d["k"] == "dir" and d.get("names") is not None:
                fds[fd] = ("dir", d["host"], d["names"], d["idx"])
            elif d["k"] == "dir":
                fds[fd] = ("dir", d["host"])
            elif d["k"] == "console":
                fds[fd] = ("console", d["dir"])
            elif d["k"] == "kqueue":
                fds[fd] = ("kqueue",)
            else:
                fds[fd] = ("console", "r")
        except Exception:
            fds[fd] = ("console", "r")
    return fds


def save_snapshot(l, snapdir, note=""):
    """Save complete emulator state. Requires py_stack drained."""
    if l.py_stack or l.pending_py is not None:
        raise RuntimeError("py_stack not drained (%d pending)"
                           % len(l.py_stack))
    tmp = snapdir + ".tmp"
    if os.path.isdir(tmp):
        shutil.rmtree(tmp)
    os.makedirs(tmp)

    t0 = time.time()
    regions = []
    total_kept = 0
    for i, reg in enumerate(l.uc.mem_regions()):
        b, e, perms = reg[0], reg[1], reg[2]
        size = e - b + 1
        present = []
        fname = "r%03d.bin" % i
        with open(os.path.join(tmp, fname), "wb") as f:
            for cs in range(0, size, CHUNK):
                n = min(CHUNK, size - cs)
                data = bytes(l.uc.mem_read(b + cs, n))
                if data.count(0) == len(data):   # all-zero chunk: skip
                    continue
                f.write(data)
                present.append(cs // CHUNK)
                total_kept += n
        if not present:
            os.remove(os.path.join(tmp, fname))
            fname = None
        regions.append({"begin": b, "end": e, "perms": perms,
                        "chunksz": CHUNK, "file": fname, "present": present})

    # --- python-side state ---
    state = dict(l.__dict__)
    # NEVER persist the impl-arity cache: it is derived from IMPL's
    # current signatures. A stale entry (e.g. "_sched_yield" recorded
    # as variadic back when it was an unimplemented import) resurrects
    # on restore and mis-calls NEW implementations with 9 args.
    state.pop("_arity", None)
    for k in _DROP:
        state[k] = None
    state["fds"] = _ser_fds(l)
    state["pakfs"] = None              # rebuilt deterministically
    state["py_stack"] = []
    state["pending_py"] = None
    # break the objc->loader backref cycle with a marker
    objc_real = state.get("objc")
    state["_objc_real"] = objc_real
    state["objc"] = None
    if objc_real is not None:
        objc_real.l = None             # break backref for pickling
    try:
        with open(os.path.join(tmp, "state.pkl"), "wb") as f:
            pickle.dump(state, f, protocol=5)
    finally:
        if objc_real is not None:
            objc_real.l = l            # reattach for continued use

    meta = {
        "version": VERSION,
        "note": note,
        "wall": time.time(),
        "vclock": getattr(l, "vclock", 0),
        "phase": getattr(l, "phase", "?"),
        "init_index": getattr(l, "init_index", 0),
        "stop_reason": getattr(l, "stop_reason", None),
        "fatal": getattr(l, "fatal_msg", None),
        "thread_count": len(getattr(l, "threads", {})),
        "regions": regions,
        "saved_mb": round(total_kept / 1e6, 1),
    }
    with open(os.path.join(tmp, "index.json"), "w") as f:
        json.dump(meta, f)

    # atomic publish
    if os.path.isdir(snapdir):
        shutil.rmtree(snapdir)
    os.rename(tmp, snapdir)
    dt = time.time() - t0
    l.console("[snap] saved %d regions, %.1f MB in %.1fs -> %s"
              % (len(regions), total_kept / 1e6, dt, snapdir))
    return meta


def _is_mapped(uc, addr):
    try:
        uc.mem_read(addr, 1)
        return True
    except Exception:
        return False


def _mapped_intervals(uc):
    out = []
    for reg in uc.mem_regions():
        out.append((reg[0], reg[1]))
    return out


def _unmap_intersecting(uc, b, e):
    for rb, re_ in _mapped_intervals(uc):
        if rb <= e and re_ >= b:                # intersects
            try:
                uc.mem_unmap(rb, re_ - rb + 1)
            except Exception:
                pass


def load_snapshot(snapdir, macho_path, sandbox, budget=600.0, trace_n=0,
                  live_log=True, slice_instr=None):
    """Rebuild a loader from a snapshot and return it ready to run()."""
    import fn35_loader as FL
    with open(os.path.join(snapdir, "index.json")) as f:
        meta = json.load(f)
    state = _load_state(os.path.join(snapdir, "state.pkl"))

    kwargs = {}
    if slice_instr is not None:
        kwargs["slice_instr"] = slice_instr
    l = FL.FNLoader(macho_path, sandbox, budget=budget, trace_n=trace_n,
                    live_log=live_log, **kwargs)

    # deterministic rebuild of structure (host-side, ~0.4s): image map,
    # link, stubs, native stubs, objc boot, hooks, main-thread dummy
    l.prepare()

    # --- overlay memory: reproduce exactly the saved region map ---
    restored = 0
    for r in meta["regions"]:
        b, e, perms = r["begin"], r["end"], r["perms"]
        size = e - b + 1
        _unmap_intersecting(l.uc, b, e)
        try:
            l.uc.mem_map(b, size, perms)
        except Exception as ex:
            l.console("[snap] mem_map(0x%x, 0x%x) failed: %r" % (b, size, ex))
            continue
        if r["file"]:
            path = os.path.join(snapdir, r["file"])
            csz = r["chunksz"]
            with open(path, "rb") as f:
                for ci in r["present"]:
                    data = f.read(csz)
                    addr = b + ci * csz
                    # clamp the write to the region end: the last chunk
                    # of a non-aligned region is partial
                    wlen = min(len(data), e + 1 - addr)
                    if wlen <= 0:
                        continue
                    l.uc.mem_write(addr, data[:wlen])
                    restored += wlen

    # --- overlay python state ---
    keep = {"uc", "macho", "_code_hook", "_block_hook", "_trace_hook",
            "macho_path", "sandbox", "budget", "live_log", "slice_instr",
            "trace_remaining"}
    for k, v in state.items():
        if k in keep:
            continue
        if k in ("fds",):
            l.fds = _deser_fds(l, v)
        elif k == "objc":
            continue                     # handled below via _objc_real
        elif k == "_objc_real":
            continue
        else:
            try:
                setattr(l, k, v)
            except Exception:
                pass
    # restore the ObjC runtime graph and re-point its backref
    objc = state.get("_objc_real")
    if objc is not None:
        objc.l = l
        l.objc = objc
    # module-level reader hooks pointing at the *new* loader instance
    FL.set_cstr_reader(l.gcstr)
    if hasattr(FL, "fn35_clib"):
        try:
            FL.fn35_clib._CSTR_CACHE.clear()
        except Exception:
            pass

    # pakfs: deterministic rebuild (entries/parse), then runtime overlay
    if state.get("pakfs") is None:
        pak_path = os.path.join(os.path.dirname(macho_path),
                                "cookeddata", "fortnitegame", "content",
                                "paks", "pakchunkearly-iosclient.pak")
        cache = os.path.join(os.path.dirname(sandbox), "pakcache")
        try:
            from fn35_pakfs import PakFS
            l.pakfs = PakFS(pak_path, cache, loader_console=l.console)
        except Exception as ex:
            l.console("[snap] pakfs rebuild failed: %r" % (ex,))
            l.pakfs = None

    # ---- farm integrity heal -------------------------------------------
    # The saved farm is often many separate 4KB regions; restore + a
    # partial-page farm_off can leave pages unmapped while the restored
    # bookkeeping (farm_mapped_end) claims coverage. That hole was the
    # segAJ killer (glGetString(GL_EXTENSIONS) -> UcError WRITE_UNMAPPED
    # -> poisoned cstring cell -> MainAppThread PC=0). Walk the whole
    # farm span and map any missing page explicitly.
    try:
        import fn35_loader as _FL
        _farm_lo = _FL.DATA_FARM
        _farm_hi = max(l.farm_off, l.farm_mapped_end)
        _page = _FL.PAGE
        _holes = 0
        _p = _farm_lo
        while _p < _farm_hi:
            try:
                l.uc.mem_read(_p, 1)
            except Exception:
                try:
                    l.uc.mem_map(_p, _page)
                    _holes += 1
                except Exception:
                    pass
            _p += _page
        if _holes:
            l.console("[snap] farm heal: mapped %d missing page(s) in "
                      "[0x%x .. 0x%x)" % (_holes, _farm_lo, _farm_hi))
    except Exception as _e:
        l.console("[snap] farm heal skipped: %r" % (_e,))

    # resume bookkeeping
    l.phase = getattr(l, "phase", "main") or "main"
    l.stop_reason = None
    l.fatal_msg = None
    l.exit_code = None
    l.py_stack = []
    l.pending_py = None
    l.t_start = None
    # re-apply code patches: the region overlay above restored the
    # ORIGINAL __TEXT bytes over them
    try:
        l.apply_code_patches()
    except Exception as _e:
        l.console("[snap] code patch re-apply failed: %r" % (_e,))
    # derived cache: stale entries from older snapshots can mis-call
    # implementations that gained real signatures since (see the
    # _sched_yield TypeError storm in segAR)
    l._arity = {}
    # clock anchors: allow vclock to catch up with the pause gap
    l._clk_anchor_wall = None
    l.vclock = max(int(time.time() * 1e9) - 50_000_000,
                   getattr(l, "vclock", 0)) & 0x7FFFFFFFFFFFFFFF
    l.console("[snap] restored: %d regions, %.1f MB, phase=%s, "
              "vclock advanced %.1fs past save"
              % (len(meta["regions"]), restored / 1e6, l.phase,
                 (l.vclock - meta.get("vclock", l.vclock)) / 1e9))
    return l


if __name__ == "__main__":
    # standalone verification tool: restore + short run
    snap = sys.argv[1] if len(sys.argv) > 1 else "/home/z/my-project/fn35/snap"
    secs = float(sys.argv[2]) if len(sys.argv) > 2 else 10.0
    base = "/home/z/my-project"
    l = load_snapshot(snap,
                      os.path.join(base, "fn35/extracted/Payload/"
                                   "FortniteClient.app/FortniteClient"),
                      os.path.join(base, "fn35/sandbox"), budget=secs)
    l.run()
    l.write_report(os.path.join(base, "download/fn35/fn35_boot_report.txt"))
