#!/usr/bin/env python3
"""probe_got.py — boot to link completion, dump GOT slots the loader
should have filled (esp. ___toupper @0x1037c2700)."""
import os, sys
os.environ["FN35_BUDGET"] = "1"          # link + immediately stop
os.environ["FN35_SYNC_HOOK"] = "code"
os.environ["FN35_SNAPSHOT"] = "/home/z/my-project/fn35/probe_snap"
import fn35_loader as L

orig_link = L.FNLoader.link

def patched_link(self):
    orig_link(self)
    for slot, name in ((0x1037c2700, "___toupper"),
                       (0x1037c2708, "next"),
                       (0x1037c26f8, "prev")):
        try:
            v = self.rdb(slot, 8)
            print("[probe] slot 0x%x (%s) = %s" %
                  (slot, name, v.hex()))
        except Exception as e:
            print("[probe] slot 0x%x unreadable: %r" % (slot, e))
    # dump 3 slots around
    try:
        blob = self.rdb(0x1037c26e0, 0x40)
        for i in range(0, 0x40, 8):
            print("[probe] 0x%x: %s" % (0x1037c26e0 + i,
                  blob[i:i+8].hex()))
    except Exception as e:
        print("[probe] region unreadable %r" % e)

L.FNLoader.link = patched_link
sys.argv = [sys.argv[0]]
L.main()
