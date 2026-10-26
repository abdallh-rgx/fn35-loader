#!/usr/bin/env python3
"""Validate pakfs serves the exact guest paths the engine asked for at LogInit.

From ch_1025_235704.log:
  /private/var/containers/Bundle/Application/<UUID>/FortniteClient.app/cookeddata/fortnitegame/fortnitegame.uproject
  /FortniteGame/FortniteGame.uproject
plus the follow-on config paths (BaseEngine.ini etc) the loader will ask
for once the descriptor opens successfully.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from fn35_pakfs import PakFS, find_pak  # noqa: E402

APP = ("/home/z/my-project/fn35/extracted/Payload/FortniteClient.app")
pak = find_pak(APP)
assert pak and os.path.isfile(pak), "find_pak failed: %r" % (pak,)
print("pak found:", pak.replace(APP + "/", ""))

cache = "/home/z/my-project/fn35/pakcache-test"
p = PakFS(pak, cache)

GUEST_PATHS = [
    # the two exact failing opens from the runner trace
    "/private/var/containers/Bundle/Application/6B3F2A11-4C4E-4E22-9A04-7D9E1A55C0FF/FortniteClient.app/cookeddata/fortnitegame/fortnitegame.uproject",
    "/FortniteGame/FortniteGame.uproject",
    # follow-on config chain
    "../../../FortniteGame/Config/DefaultEngine.ini",
    "../../../FortniteGame/Config/DefaultGame.ini",
    "../../../FortniteGame/Config/DefaultInput.ini",
    "../../../Engine/Config/BaseEngine.ini",
    "../../../Engine/Config/BaseDeviceProfiles.ini",
    # engine stat probes that will follow
    "../../../FortniteGame/Config",
    "../../../FortniteGame/Content",
]
fails = 0
for g in GUEST_PATHS:
    e = p.resolve(g)
    d = p.resolve_dir(g)
    if e is None and d is None:
        fails += 1
        print("FAIL  %-25s -> no pak entry" % g.split("/")[-1])
        continue
    mk = p.materialize(g)
    ok = mk and os.path.exists(mk)
    tag = "DIR " if d and not e else "FILE"
    print("%s %-4s %-25s -> %s" % ("OK  " if ok else "FAIL",
                                   tag, g.split("/")[-1],
                                   os.path.basename(mk) if mk else None))
    if not ok:
        fails += 1

# read the uproject head to prove content integrity
up = p.materialize(GUEST_PATHS[0])
if up:
    with open(up, "rb") as f:
        head = f.read(120)
    print("\nuproject head:", head[:100])
    assert b"FileVersion" in head or b"{" in head, "uproject content bad"

print("\nRESULT:", "ALL GREEN" if fails == 0 else "%d FAILURES" % fails)
sys.exit(1 if fails else 0)
