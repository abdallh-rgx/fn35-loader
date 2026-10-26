#!/bin/bash
# one_seg.sh — run exactly ONE loader segment locally with crash-recovery.
# Improvements over chainlong:
#  * crash counter resets when the crash PC CHANGES (progress, not a loop)
#  * BLOCK sync once past the init table (didFinishLaunching seen) - the
#    6.5x VM-grind speedup; CODE only needed for inits 0-253
cd /home/z/my-project/scripts
export LD_LIBRARY_PATH=/home/z/mesa-debs/root/usr/lib/x86_64-linux-gnu${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}
export FN35_SYNC_HOOK=auto
export FN35_BUDGET=${FN35_BUDGET:-530}
export FN35_SNAPSHOT=/home/z/my-project/fn35/snap
F35=/home/z/my-project/fn35
CONSOLE=$F35/chain_console.log
CRASHES_FILE=$F35/.chain_crashes
CRASHPC_FILE=$F35/.chain_crashpc

# past the init table? (any recent log saw didFinishLaunching) -> BLOCK
# past the init table (init 773/773 + didFinishLaunching done 2026-10-25):
# BLOCK sync from here on; swap logic lives in the loader (auto) only
# for fresh boots.
export FN35_SYNC_HOOK=block

LOG=$F35/loc_$(date +%m%d_%H%M%S).log
timeout 575 python3 -u fn35_loader.py > "$LOG" 2>&1
RC=$?
LAST=$(grep -E "stopped:" "$LOG" | tail -1)
MILES=$(grep -aoE "didFinishLaunching|LogInit:|LogPakFile|LogRHI|LogSlate|LogStreaming|LogHAL|Device Profile|LogUObject|LogCore|LogEOS|portrait mode|first frame|abort\(\) called" "$LOG" | sort -u | tr '\n' ',')
INITS=$(grep -aoE "init [0-9]+/773" "$LOG" | tail -1)
echo "[local] rc=$RC ${LAST:0:110} | ${INITS} | $MILES" | tee -a "$CONSOLE"
if ls /home/z/my-project/download/fn35/screenshots/*.png >/dev/null 2>&1; then
  echo "[local] *** FRAMES RENDERED — screenshots in download/fn35/screenshots"
fi
if grep -q "FATAL" "$LOG"; then
  # crash PC fingerprint: different PC = progress, reset the counter
  NEWPC=$(grep -aoE "fault at 0x[0-9a-f]+ .*pc=0x[0-9a-f]+" "$LOG" | head -1 | grep -oE "pc=0x[0-9a-f]+")
  OLDCPC=$(cat "$CRASHPC_FILE" 2>/dev/null)
  C=$(cat "$CRASHES_FILE" 2>/dev/null || echo 0)
  if [ "$NEWPC" != "$OLDCPC" ] && [ -n "$NEWPC" ]; then
    echo "$NEWPC" > "$CRASHPC_FILE"
    C=1
    echo "[local] new crash pc $NEWPC (progress) - counter reset" | tee -a "$CONSOLE"
  else
    C=$((C+1))
  fi
  echo $C > "$CRASHES_FILE"
  if [ -f "$F35/snap_crash/index.json" ]; then
    if [ "$C" -ge 5 ]; then
      echo "[local] stuck at same pc x$C -> ROLLBACK to last good" | tee -a "$CONSOLE"
      rm -rf "$F35/snap" "$F35/snap_crash"
      [ -f "$F35/snap_good/index.json" ] && cp -r "$F35/snap_good" "$F35/snap"
      echo 0 > "$CRASHES_FILE"
    else
      rm -rf "$F35/snap"; mv "$F35/snap_crash" "$F35/snap"
      echo "[local] crash #$C -> resumed from crash snapshot" | tee -a "$CONSOLE"
    fi
  elif [ "$C" -ge 5 ]; then
    # POISON crashes (exec fetch faults) save NO crash snapshot; the
    # same-pc loop means the current snap itself is doomed - roll back
    echo "[local] poison crash-loop x$C (no snapshot) -> ROLLBACK to last good" | tee -a "$CONSOLE"
    rm -rf "$F35/snap"
    if [ -f "$F35/snap_good/index.json" ]; then
      cp -r "$F35/snap_good" "$F35/snap"
    fi
    echo 0 > "$CRASHES_FILE"
  fi
else
  echo 0 > "$CRASHES_FILE"
  if [ -f "$F35/snap/index.json" ]; then
    rm -rf "$F35/snap_good"; cp -r "$F35/snap" "$F35/snap_good"
  fi
fi
ls -t "$F35"/loc_*.log 2>/dev/null | tail -n +21 | xargs -r rm -f
