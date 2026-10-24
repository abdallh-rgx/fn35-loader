# FN3.5 Loader — Fortnite 3.5 iOS on Unicorn (Linux x64, no KVM)

User-space loader that boots the **Fortnite 3.5 iOS client** (Mach-O ARM64,
decrypted `cryptid=0`, 91.2 MB) on plain Linux x64 with **Unicorn Engine**
CPU emulation — no KVM, no Apple hardware, no game files modified.

The approach is the **Wine / touchHLE** approach: the executable runs
untouched; we substitute everything around it.

| Layer | Substitute |
|---|---|
| **dyld** | custom linker: applies bind/rebase opcodes, fills all 2,581 GOT slots with a Python "stub farm" (trampolines) |
| **XNU kernel** | BSD syscalls (`svc #0x80`, x16 = nr) + Mach VM (`vm_allocate`, `vm_deallocate`, `mach_msg`) |
| **libSystem** | libc, pthreads, GCD, TLS, `objc_msgSend` + 595 ObjC classes |
| **Frameworks** | UIKit / Foundation / CoreAnimation / IOSurface / Metal-naming stubs |
| **GPU** | OpenGL ES calls forwarded to **Mesa llvmpipe** (GL 3.20 ES) |
| **FS** | sandbox exposing the app bundle (pak index: 3,260 entries) |

## Progress (as of run53 / segAJ)

```
✓ 773/773 __mod_init_func initializers
✓ main() (0x102DAE84C) → FEngineLoop pre-init
✓ UE LogInit: full device profile [IPhone8] + CVars
✓ Slate users created
✓ LogRHI: Initializing OpenGL RHI (llvmpipe GLSL ES 3.20 online)
→ next: RHI shaders → Slate UI → login screen
```

Runs are **resumable**: `fn35_snap.py` snapshots the whole VM
(220 regions / 140 MB in 0.9 s) so a stopped run continues where it left off.

## Files

| File | Lines | Purpose |
|---|---|---|
| `scripts/fn35_macho.py` | 470 | Mach-O parser (segments, symtab, indirect tables, dyld bind opcodes) |
| `scripts/fn35_loader.py` | 2,872 | Integrated loader + cooperative scheduler + syscall dispatch |
| `scripts/fn35_objc.py` | 2,520 | ObjC runtime with class registration + msgSend dispatch |
| `scripts/fn35_gles.py` | 907 | GLES → Mesa bridge (llvmpipe) |
| `scripts/fn35_ioslib.py` | 1,167 | iOS framework stubs |
| `scripts/fn35_clib.py` | 1,172 | libc / libSystem emulation |
| `scripts/fn35_pakfs.py` | 350 | pak filesystem index |
| `scripts/fn35_snap.py` | 334 | VM snapshot / resume |
| `scripts/fn35_native.py` | 190 | native call-ins (trampoline helpers) |

Debug utilities: `disas_*.py`, `stack_walk*.py`, `xref*.py`, `debug_restore*.py`.

## Usage

```bash
python3 -m pip install unicorn capstone
# place the decrypted FortniteClient binary under fn35/extracted/... (not in git)
python3 scripts/fn35_loader.py          # budget-limited boot
FN35_BUDGET=3600 python3 scripts/fn35_loader.py   # 1h run
```

Key env vars: `FN35_BUDGET` (seconds, default 300), `FN35_SNAP=1` (snapshot at exit).

## Legal

This repository contains **only the loader code we wrote**. No Epic Games
binaries, assets, or keys are committed (see `.gitignore`). Fortnite is a
trademark of Epic Games, Inc. Research/educational use.

## Roadmap

1. RHI init completion → shader compile via llvmpipe
2. Slate main loop → login screen render
3. Rust port (safe) with GUI + CLI, shared object for Android (ARM64 native — no Unicorn needed on-device)
