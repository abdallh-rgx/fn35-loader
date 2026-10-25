#!/usr/bin/env python3
"""find_aes_key.py — brute-force scan GUEST MEMORY for the pak AES-256 key.

Method:
 1. Load a snapshot (default snapC = post-crypto-grind state).
 2. Take a known encrypted pak entry (Engine/Config/Base.ini, 32 bytes,
    comp=0 enc=1 -> AES-256-ECB over 2 blocks, no compression).
 3. For every 32-byte window in guest data/bss/heap/VM regions, try
    AES-256-ECB decrypt of the entry; check if result looks like INI
    text (printable, starts with '[' or contains '=').
 4. Report the key + its guest address.
"""
import os, json, sys
from Crypto.Cipher import AES

SNAP = sys.argv[1] if len(sys.argv) > 1 else "/home/z/my-project/fn35/snapC"
PAK = ("/home/z/my-project/fn35/extracted/Payload/FortniteClient.app/"
       "cookeddata/fortnitegame/content/paks/pakchunkearly-iosclient.pak")

# entry: Engine/Config/Base.ini  off=?(see pak_index) size=32 enc=1 comp=0
idx = json.load(open("/home/z/my-project/fn35/pak_index.json"))
entries = idx if isinstance(idx, list) else idx.get("entries", [])
ent = next(e for e in entries if e["name"] == "Engine/Config/Base.ini")
print("entry:", ent)

# the data starts after the entry header. UE4 pak entry layout (v3-v8):
# at entry offset: [FPakEntry header (variable)] then data. Our pakfs
# parser knows: blocks list already points at DATA offsets!
blk_start, blk_end = ent["blocks"][0]
with open(PAK, "rb") as f:
    f.seek(blk_start)
    cipher = f.read(blk_end - blk_start)
print("ciphertext (%d bytes): %s" % (len(cipher), cipher.hex()))

# scan guest memory
idx2 = json.load(open(os.path.join(SNAP, "index.json")))
regions = idx2["regions"]
print("scanning %d regions..." % len(regions))


def looks_ini(data):
    if not data:
        return False
    txt = data.decode("latin1")
    printable = sum(1 for c in txt if 32 <= ord(c) < 127 or c in "\r\n\t")
    return printable / max(1, len(txt)) > 0.85


hits = 0
for r in regions:
    b, e = r["begin"], r["end"]
    # skip the giant image region? no - keep everything; skip empty
    if not r.get("present"):
        continue
    csz = r["chunksz"]
    path = os.path.join(SNAP, r["file"])
    if not os.path.isfile(path):
        continue
    with open(path, "rb") as fh:
        for ci in r["present"]:
            fh.seek(r["present"].index(ci) * csz)
            chunk = fh.read(csz)
            # slide 32-byte windows (8-byte aligned candidates)
            for off in range(0, len(chunk) - 32, 8):
                cand = chunk[off:off + 32]
                if cand == b"\x00" * 32:
                    continue
                try:
                    plain = AES.new(cand, AES.MODE_ECB).decrypt(cipher[:32])
                except Exception:
                    continue
                if looks_ini(plain):
                    addr = b + ci * csz + off
                    print("KEY FOUND @ guest 0x%x: %s" %
                          (addr, cand.hex()))
                    print("  plaintext preview: %r" % plain[:48])
                    hits += 1
                    if hits > 8:
                        sys.exit(0)
print("done. hits:", hits)
