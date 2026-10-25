#!/usr/bin/env python3
"""diag_farm.py — diagnose the farm mapping state after snapshot restore.

The segAJ failure was: glGetString(GL_EXTENSIONS) -> cstring_cell ->
data_cell -> wrb(0x510000013500, 4146 bytes) -> UcError WRITE_UNMAPPED.

This script restores the current snapshot, prints the ACTUAL unicorn
mappings around the data farm, compares them with the Python-side
bookkeeping (farm_off / farm_mapped_end), and then tries the failing
allocation directly. Evidence, not theory.
"""
import os
import sys

BASE = "/home/z/my-project"
sys.path.insert(0, os.path.join(BASE, "scripts"))

import fn35_snap


def dump_farm(l, tag):
    lo, hi = 0x510000000000, 0x5100000100000
    print("--- unicorn mappings in farm window [%s] ---" % tag)
    n = 0
    for reg in l.uc.mem_regions():
        b, e, p = reg[0], reg[1], reg[2]
        if b >= hi or e < lo:
            continue
        print("  [0x%x .. 0x%x) perms=%d size=0x%x" % (b, e + 1, p, e + 1 - b))
        n += 1
    if n == 0:
        print("  (none)")
    print("  farm_off        = 0x%x" % l.farm_off)
    print("  farm_mapped_end = 0x%x" % l.farm_mapped_end)
    print("  data_cells: %d, cstr_cells: %d" % (len(l.data_cells),
                                                 len(l.cstr_cells)))
    # is the exact failing page there?
    for probe in (0x510000013000, 0x510000014000, 0x510000013500):
        try:
            l.uc.mem_read(probe, 1)
            ok = "MAPPED"
        except Exception as ex:
            ok = "unmapped (%s)" % type(ex).__name__
        print("  probe 0x%x: %s" % (probe, ok))


def main():
    snapdir = os.path.join(BASE, "fn35/snap")
    if not os.path.isfile(os.path.join(snapdir, "index.json")):
        print("no snapshot at %s" % snapdir)
        return 1
    l = fn35_snap.load_snapshot(
        snapdir,
        os.path.join(BASE, "fn35/extracted/Payload/FortniteClient.app/"
                     "FortniteClient"),
        os.path.join(BASE, "fn35/sandbox"), budget=1.0, live_log=False)

    dump_farm(l, "after restore")

    # now reproduce the failing allocation (a ~4.1KB GL_EXTENSIONS string)
    print("--- reproducing cstring_cell('glstr.1f03', ~4145 chars) ---")
    try:
        a = l.cstring_cell("glstr.1f03", "E" * 4145)
        print("  OK: cell at 0x%x" % a)
        back = l.gcstr(a, 64)
        print("  readback: %r..." % back[:32])
    except Exception as ex:
        print("  FAILED: %r" % (ex,))

    dump_farm(l, "after attempt")
    return 0


if __name__ == "__main__":
    sys.exit(main())
