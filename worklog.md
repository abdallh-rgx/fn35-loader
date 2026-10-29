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
