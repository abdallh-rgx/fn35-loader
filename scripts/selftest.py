#!/usr/bin/env python3
"""Self-test: validates the loader stack without any game binary.

Builds a synthetic minimal ARM64 Mach-O in memory, writes it to a temp
file, and parses it with fn35_macho.MachO. Then checks that every
module of the stack imports cleanly (unicor + capstone + all fn35_*
modules). Exits non-zero on any failure. Used by CI (.github/workflows).
"""
import os
import struct
import sys
import tempfile
import traceback

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

FAILURES = []


def check(name, fn):
    try:
        fn()
        print("[ok] %s" % name)
    except Exception:
        print("[FAIL] %s" % name)
        traceback.print_exc()
        FAILURES.append(name)


def build_synth_macho():
    """Minimal 64-bit ARM64 Mach-O with one __TEXT segment."""
    MH_MAGIC_64 = 0xFEEDFACF
    CPU_TYPE_ARM64 = 0x0100000C
    LC_SEGMENT_64 = 0x19
    LC_UUID = 0x1B
    segname = b"__TEXT\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    sect = b"__text\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" + \
           b"__TEXT\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    # mach_header_64: magic, cputype, cpusub, filetype, ncmds,
    # sizeofcmds, flags, reserved  (32 bytes)
    ncmds = 2
    sizeofcmds = 152 + 24
    hdr = struct.pack("<IIIIIIII", MH_MAGIC_64, CPU_TYPE_ARM64, 0, 2,
                      ncmds, sizeofcmds, 0, 0)
    # segment_command_64 (72) + one section_64 (80) = 152
    sect = struct.pack("<16s16sQQIIIIIIII",
                       b"__text" + b"\x00" * 10,
                       b"__TEXT" + b"\x00" * 10,
                       0x1000000D0, 4, 0xD0, 2, 0, 0, 0x80000400, 0, 0, 0)
    seg = struct.pack("<II16sQQQQIIII", LC_SEGMENT_64, 152, segname,
                      0x100000000, 0x1000, 0, 0x1000, 7, 5, 1, 0) + sect
    assert len(seg) == 152, len(seg)
    # uuid_command (24)
    uuid = struct.pack("<II", LC_UUID, 24) + b"\x11" * 16
    # a couple of ARM64 instructions (ret)
    text = b"\xc0\x03\x5f\xd6"
    blob = hdr + seg + uuid + text
    assert len(blob) == 32 + 152 + 24 + 4
    fd, path = tempfile.mkstemp(suffix=".macho")
    with os.fdopen(fd, "wb") as f:
        f.write(blob)
    return path


def test_macho_parse():
    from fn35_macho import MachO
    path = build_synth_macho()
    try:
        m = MachO(path)
        names = [s.name for s in m.segments]
        assert "__TEXT" in names, names
        sects = [s.name for s in m.sections]
        assert "__text" in sects, sects
        txt = [s for s in m.sections if s.name == "__text"][0]
        assert txt.addr == 0x1000000D0, hex(txt.addr)
        assert txt.seg == "__TEXT", txt.seg
    finally:
        os.unlink(path)


def test_unicorn():
    import unicorn
    import unicorn.arm64_const as a64
    uc = unicorn.Uc(unicorn.UC_ARCH_ARM64, unicorn.UC_MODE_ARM)
    uc.mem_map(0x1000, 0x1000)
    uc.mem_write(0x1000, b"\xc0\x03\x5f\xd6")  # ret
    uc.reg_write(a64.UC_ARM64_REG_LR, 0x1004)  # ret lands on 'until'
    uc.emu_start(0x1000, 0x1004, timeout=1000000)
    assert uc.reg_read(a64.UC_ARM64_REG_PC) == 0x1004


def test_capstone():
    import capstone
    md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
    ins = list(md.disasm(b"\xc0\x03\x5f\xd6", 0))
    assert ins and ins[0].mnemonic == "ret"


def test_imports():
    # clib/ioslib/objc/gles register themselves on import; loader pulls
    # them in. They import cleanly without the game binary present.
    import fn35_clib       # noqa: F401
    import fn35_ioslib     # noqa: F401
    import fn35_gles       # noqa: F401
    import fn35_pakfs      # noqa: F401


def main():
    check("unicorn emulates a ret", test_unicorn)
    check("capstone disassembles", test_capstone)
    check("fn35_macho parses synthetic Mach-O", test_macho_parse)
    check("fn35 modules import", test_imports)
    print()
    if FAILURES:
        print("SELFTEST FAILED: %d" % len(FAILURES))
        return 1
    print("SELFTEST OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
