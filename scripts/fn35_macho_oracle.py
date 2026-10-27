#!/usr/bin/env python3
"""fn35_macho_oracle.py — dump the Python parser's view of the binary as
JSON for the Rust differential test (tests/oracle.json)."""
import json
import sys

sys.path.insert(0, "/home/z/my-project/scripts")
from fn35_macho import MachO

BIN = ("/home/z/my-project/fn35/extracted/Payload/"
       "FortniteClient.app/FortniteClient")

mo = MachO(BIN)
n = mo.load_symbols()
stats = mo.link_stats()
slots = list(mo.iter_pointer_slots())
binds = mo.parse_binds()

out = {
    "segments": stats["segments"],
    "sections": stats["sections"],
    "dylibs": stats["dylibs"],
    "symbols": stats["symbols"],
    "pointer_slots": stats["pointer_slots"],
    "indirect_entries": stats["indirect_entries"],
    "bind_records": stats["bind_records"],
    "cryptid": stats["cryptid"],
    "entryoff": stats["entryoff"],
    "slots": [[a, idx] for (a, idx) in slots],
    "mod_inits": mo.mod_init_funcs(),
    "tlv": list(mo.tlv_template()),
    "binds_head": [[r.seg_index, r.seg_offset, r.symbol]
                   for r in binds[:2000]],
    "slot_names_head": [mo.sym_name(idx) if idx is not None else None
                        for (_, idx) in slots[:2000]],
    "n_syms_loaded": n,
}
with open("/home/z/my-project/rust/fn35-macho/tests/oracle.json",
          "w") as f:
    json.dump(out, f)
print("oracle written: %d slots, %d binds, %d symbols"
      % (len(slots), len(binds), n))
