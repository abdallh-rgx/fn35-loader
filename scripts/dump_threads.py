#!/usr/bin/env python3
"""Dump all thread states + wait targets from the current snapshot."""
import os, sys
sys.path.insert(0, "/home/z/my-project/scripts")
os.environ["FN35_QUIET"] = "1"
os.environ["FN35_SYNC_HOOK"] = "block"

import fn35_snap

BASE = "/home/z/my-project"
MACHO = BASE + "/fn35/extracted/Payload/FortniteClient.app/FortniteClient"
SNAP = os.environ.get("FN35_SNAPSHOT", BASE + "/fn35/snap")

l = fn35_snap.load_snapshot(SNAP, MACHO, BASE + "/fn35/sandbox",
                            budget=1.0, live_log=False)
print("[threads] dump after restore:")
for tid, t in sorted(l.threads.items()):
    pc = t.pc
    nm, sa = l.nearest_symbol(pc) if pc else ("?", 0)
    w = getattr(t, "wait", None)
    wk = getattr(t, "wake_ns", None)
    extra = getattr(t, "extra", None)
    print("  tid=0x%-6x %-8s pc=0x%-10x %s+0x%x wait=%r wake=%r extra=%r"
          % (tid, t.state, pc, (nm or "?")[:40], (pc or 0) - (sa or 0),
             w, (wk / 1e9) if wk else None, extra))
