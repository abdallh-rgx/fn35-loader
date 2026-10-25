#!/usr/bin/env python3
"""repro_reg_corrupt.py — minimal reproduction of the register-corruption
crash pattern: emulate the exact CRC sequence, stop mid-sequence via a code
hook + emu_stop (like our thread switching), save/restore registers, resume,
and verify the lsr/add/ldr math stays consistent.

Observed in-game: `lsr w8,w8,#24; add x8,x9,w8,uxtw#2; ldr w8,[x8,#0x1000]`
faults at an address that is arithmetically impossible from the dumped
registers (x9 valid table base, w8<=0xFF by construction). Suspect: unicorn
2.1.4 mis-commits register state when emulation stops mid-TB (slice count or
hook emu_stop), so a RESTORED thread runs the add with a stale w8.
"""
import struct
import unicorn
from unicorn import Uc, UC_ARCH_ARM64, UC_MODE_ARM, UC_HOOK_CODE
import unicorn.arm64_const as a64

print("unicorn", unicorn.__version__)

CODE = 0x10000
TABLE = 0x20000            # x9 -> table base (mapped far below +0x1000...)
GAP = 0x30000              # fault playground

# 0x101f9f31c: lsr w8, w8, #24      087d1853
# 0x101f9f320: add x8, x9, w8,uxtw#2 2849288b
# 0x101f9f324: ldr w8, [x8,#0x1000] 080150b9
# 0x101f9f328: eor w8, w13, w8     a801084a
# 0x101f9f32c: b .-0x18 (loop back) -> use ret instead
CODE_BYTES = struct.pack("<IIIII",
                         0x53187d08, 0x8b284928, 0xb9500108,
                         0x4a08014a, 0xd65f03c0)

uc = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
for base in (CODE, TABLE, GAP):
    uc.mem_map(base, 0x10000, 7)
uc.mem_write(CODE, CODE_BYTES)
uc.mem_write(TABLE, b"\xAA" * 0x8000)   # tables live at +0..+0x2000

X8 = a64.UC_ARM64_REG_X8
X9 = a64.UC_ARM64_REG_X9
X13 = a64.UC_ARM64_REG_X13
PC = a64.UC_ARM64_REG_PC

faults = []


def hook_inv(uc2, access, address, size, value, user):
    faults.append((address, uc2.reg_read(PC),
                   uc2.reg_read(X8), uc2.reg_read(X9)))
    return False


from unicorn import UC_HOOK_MEM_INVALID
uc.hook_add(UC_HOOK_MEM_INVALID, hook_inv)

stop_at = [0x101f9f31c, 0x101f9f320]  # try stopping at each point


def run_with_stop(stop_pc, bad_w8):
    """Run the 5-instruction snippet, stopping exactly at stop_pc (once),
    then saving ALL regs, restoring them, and continuing."""
    # fresh state each time
    uc2 = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
    for base in (CODE, TABLE, GAP):
        uc2.mem_map(base, 0x10000, 7)
    uc2.mem_write(CODE, CODE_BYTES)
    uc2.mem_write(TABLE, b"\xAA" * 0x8000)
    f2 = []
    uc2.hook_add(UC_HOOK_MEM_INVALID,
                 lambda u, a, ad, s, v, _u: (f2.append(
                     (ad, u.reg_read(PC), u.reg_read(X8), u.reg_read(X9)))
                     or False))
    stopped = [False]
    saved = {}

    def hook_code(u, addr, size, user):
        if addr == stop_pc and not stopped[0]:
            stopped[0] = True
            u.emu_stop()

    uc2.hook_add(UC_HOOK_CODE, hook_code)
    uc2.reg_write(X8, bad_w8)
    uc2.reg_write(X9, TABLE)
    uc2.reg_write(X13, 0x11223344)
    # first leg: stops at stop_pc (or runs to fault/ret)
    try:
        uc2.emu_start(CODE + 0, CODE + 0x14)
    except Exception as e:
        return ("phase1-exc", str(e), f2)
    pc = uc2.reg_read(PC)
    if not stopped[0]:
        return ("no-stop", hex(pc), f2)
    # SAVE all regs
    for r in (a64.UC_ARM64_REG_X0 + i for i in range(29)):
        try:
            saved[r] = uc2.reg_read(r)
        except Exception:
            pass
    saved[PC] = uc2.reg_read(PC)
    # RESTORE (write them all back)
    for r, v in saved.items():
        uc2.reg_write(r, v)
    # resume
    try:
        uc2.emu_start(pc, CODE + 0x10)
    except Exception as e:
        return ("phase2-exc pc=%x" % pc, str(e), f2)
    x8 = uc2.reg_read(X8)
    ok = (TABLE + 0x1000 + (bad_w8 >> 24) * 4 == (x8 & 0xFFFFFFFF) + TABLE - TABLE)
    return ("done pc=%x x8=%x" % (uc2.reg_read(PC), x8),
            "w8-before=%x expect-index=%x" % (bad_w8, (bad_w8 >> 24) * 4),
            f2)


print("\n--- stop at lsr (0x00): ---")
print(run_with_stop(0x101f9f31c - 0x101f9f31c + CODE, 0xdeadbeef))
print("\n--- stop at add (0x04): ---")
print(run_with_stop(0x101f9f320 - 0x101f9f31c + CODE, 0xcafebabe))
print("\n--- stop at ldr (0x08): ---")
print(run_with_stop(0x101f9f324 - 0x101f9f31c + CODE, 0x12345678))
