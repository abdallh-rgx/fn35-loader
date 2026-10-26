#!/usr/bin/env python3
"""fn35_pakfs_oracle.py - dump pakfs facts for the Rust differential test.

Produces JSON on stdout:
  { mount, count, dir_count, names: [.. up to 40 sorted ..],
    entries: { name: {size, usize, comp, sha256} } }

Covers: the uproject, every game config ini, engine configs, and a
spread of content entries (uassets/umbra/png) so the Rust side proves
byte-identical index parsing AND block decryption/inflation.
"""
import hashlib
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from fn35_pakfs import PakFS  # noqa: E402

PAK = ("/home/z/my-project/fn35/extracted/Payload/FortniteClient.app/"
       "cookeddata/fortnitegame/Content/Paks/pakchunkearly-iosclient.pak")

p = PakFS(PAK, "/tmp/oracle-pakcache")

# deterministic selection: everything in FortniteGame/Config + Engine/Config
# (all small, all on the critical boot path) + the uproject + a spread of
# content files with varied sizes/compression.
picked = []
for name in p.entries:
    if name.lower().endswith(".uproject"):
        picked.append(name)
    elif "/Config/" in name and name.lower().endswith(".ini"):
        picked.append(name)
picked.sort()

# size-spread content sample: 12 entries across the size spectrum
content = [n for n in p.entries if n not in picked]
content.sort(key=lambda n: (p.entries[n]["usize"], n))
if content:
    step = max(1, len(content) // 12)
    for i in range(0, len(content), step):
        if len(picked) >= 60:
            break
        if content[i] not in picked:
            picked.append(content[i])

out = {
    "mount": p.mount,
    "count": len(p.entries),
    "dir_count": len(p.dirs),
    "names": sorted(p.entries.keys())[:40],
    "entries": {},
}
for name in picked:
    e = p.entries[name]
    data = p.read_entry(e)
    out["entries"][name] = {
        "size": e["size"],
        "usize": e["usize"],
        "comp": e["comp"],
        "sha256": hashlib.sha256(data).hexdigest(),
        "len": len(data),
    }

json.dump(out, sys.stdout, indent=1, sort_keys=True)
print()
