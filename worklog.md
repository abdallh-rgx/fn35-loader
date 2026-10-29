# FN35 Loader Worklog

## 2026-10-30 (UTC)

### 10:50Z — ROOT CAUSE FOUND + FIXED: uikit-runloop deadlock (24h spin stall)
- **Symptom**: every 530s segment for 24h+ ended `stopped: reason=budget`
  with zero progress. Snapshot vclock advanced but game state frozen.
- **Forensics added** (fn35_loader.py `dispatch_stub` stub-hb):
  live stub name, LR + nearest symbol, thread start pc, all thread
  states, blocked-waiter dump (kind+key), x29 FP-chain walk (5 frames).
- **Diagnosis chain**:
  1. stub-hb: one pthread (tid=0x8330) spinning ~200k stubs/20s in
     `_mach_absolute_time`/`_pthread_mutex_lock`/`_pthread_getspecific`
     (2:1:1:1) at farm stubs 0x4b00/0x5170/0x51e0.
  2. LR -> guest loop fn 0x102c5256c (FEvent-like Wait: state@+0x14,
     mutex@+0x20, cond@+0x60, waiter count@+0x18).
  3. FP-walk: spin chain 0x102b16638 <- 0x102a90c44 <- 0x101bc5dcc
     <- engine loop 0x101bc5da0:
     `while(!ldar(this+0x168)){ rc=event->Wait(-1,0); if(rc) retry(); }`
  4. Frames pass 0x102bf9498 = Wait() state==2 FAST PATH (event already
     valve-timed-out) -> Wait returns 1 instantly -> engine retries a
     DEAD event at ~40k/s forever.
  5. Scheduler bug: `objc.tick()` (fires NSTimers/CADisplayLink - the
     frame driver) ran ONLY on the idle path (pick_ready()==None);
     with 8 ready spinning threads it NEVER ran -> main thread parked
     'forever' in uikit_runloop -> no ticks -> the task that should
     complete the waited event never runs.
- **Fixes**:
  a. FIRE-THROUGH: scheduler loop now calls `objc.tick()` every 2ms
     wall regardless of ready threads (timers fire again; splash
     timer + RecordPeakMemory confirmed firing via FN35_TRACE_TICK).
  b. SPIN-BREAKER cave (0x106001000, armed at 0x101bc5dcc): counts
     consecutive timed-out Wait returns; after FN35_SPIN_GRACE_SECS
     (default 1800) force-stores 1 to this+0x168 so the engine loop
     exits and boot continues. Success resets scratch (legit waits
     untouched). Re-armed on snapshot restore via apply_code_patches.
  c. stub-hb forensics (see above) - kept, cheap.
- **Result**: stub storm GONE (0 stub-hb in 240s run); of.MainAppThread
  executing (+45..75M instr/30s); of.RecordPeakMemory threads spawn/exit.
- Commit: 7d1797a (pushed).

### 2026-10-30 ~13:30Z — KEYSTONE >4GB FAR-BRANCH BUG FOUND + FIXED (the real spinner)
- `place()` in fn35_native.py assembles with `ks.asm(src)` WITHOUT addr=
  (PC=0) -> absolute branch `Lpy: b 0x500000000000` (15MB beyond PC,
  >4GB absolute) truncated by keystone into `b block_start`
  (0x17fffff8) -> **every non-ASCII UTF-16 char spun the native
  toupper block forever**. The engine's MainAppThread (game loop, fired
  via [IOSAppDelegate MainAppThread:]) was CRC-16-ing a UTF-16 string
  and froze on the first non-ASCII char (x19 static at 0x700000bff8f2).
- Forensics that cracked it: Lpy branch decode from live snapshot
  memory (`[tramp]` diag) + one-shot `___toupper_py` SVC probe.
- Fixes (commit 373a92c):
  1. fn35_native.py: hybrid trampolines assembled as body + MANUALLY
     encoded imm26 far branch (3.9M instr offsets, in ±33.5M range).
  2. fn35_snap.py: restore path now RE-PLACES native stubs after the
     region overlay (the overlay had been resurrecting the old broken
     bytes on every resume) + TB cache invalidate.
  3. fn35_clib.py: real unicode case fallbacks ___toupper_py/___tolower_py.
  4. spin-breaker cave rewritten count-based (no unencodable 343GB bl);
     snapshot pickle no longer persists probe handles (_crc_probe_h etc.).
- RESULT: pycase fires, CRC pointer ADVANCES (0x…f8f2 -> f8f4 -> f8f6),
  MainAppThread EXITED the CRC loop into new code
  (frames 0x1029b30f0 <- 0x10256aa68 <- 0x102e814f0), snapshot +0.3MB.

### 2026-10-30 ~14:40Z — VM-grind throughput: 28x (75k -> 2.1M instr/s)
- Slice pacing probe (`FN35_SLICE_PROBE=1`): MainApp/pthread slices end
  at the 5M-instruction count (~2.2s at VM speed), NOT the 2s timeout;
  the pthread 0x8330 burned half the wall time on 2s no-progress turns.
- Fixes (commit series):
  1. `FN35_FREEZE_TIDS=8330` (one_seg.sh default): the proven
     dead-event waiter is skipped by pick_ready; the obfuscated-VM
     interpreter thread (of.MainAppThread) now gets the whole CPU.
  2. `FN35_SLICE_TIMEOUT_SECS` env (default 8s) for the emu_start cap.
- RESULT (530s segment): of.MainAppThread +1,120M instr = 2.1M/s
  sustained, up from ~75k/s. VM interpreter frames stable, engine not
  logging yet — the 13MB VM bytecode grind continues at 28x speed.

### 2026-10-30 15:30-16:40Z — VM grind status (segments seg_fix7..11)
- Steady +1.1-1.2B instructions per 530s segment at 2.1-2.3M instr/s.
- VM interpreter frames stable (0x1029b30f0 <- 0x10256aa68 <- 0x102e814f0):
  the obfuscated-VM dispatch loop is healthy and grinding.
- Snapshot ~117MB, verified, uploaded each segment; git mirror synced.
- Cron Job 478173 now carries FN35_FREEZE_TIDS=8330 via one_seg.sh, so
  every future segment runs at full VM throughput automatically.
- Next milestones to watch: engine console output (first LogInit/NSLog
  lines), new thread creations (render/RHI threads), screenshots in
  download/fn35/screenshots/.
