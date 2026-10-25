#!/bin/bash
# one_seg.sh — run exactly ONE loader segment locally with the same
# crash-recovery logic as the chain, then print the summary line.
# (The sandbox reaps background processes between tool calls, so the
# long chain runs on GitHub Actions; this keeps a local segment going
# in parallel, one 10-min tool call at a time.)
cd /home/z/my-project/scripts
export LD_LIBRARY_PATH=/home/z/mesa-debs/root/usr/lib/x86_64-linux-gnu${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}
export FN35_SYNC_HOOK=auto
export FN35_BUDGET=${FN35_BUDGET:-530}
export FN35_SNAPSHOT=/home/z/my-project/fn35/snap
F35=/home/z/my-project/fn35
CONSOLE=$F35/chain_console.log
CRASHES_FILE=$F35/.chain_crashes
[ -f "$F35/snap/index.json" ] && export FN35_SYNC_HOOK=block
LOG=$F35/loc_$(date +%m%d_%H%M%S).log
timeout 575 python3 -u fn35_loader.py > "$LOG" 2>&1
RC=$?
LAST=$(grep -E "stopped:" "$LOG" | tail -1)
MILES=$(grep -aoE "didFinishLaunching|LogInit:|LogPakFile|LogRHI|LogSlate|portrait mode|LogEOS" "$LOG" | sort -u | tr '\n' ',')
INITS=$(grep -aoE "init [0-9]+/773" "$LOG" | tail -1)
echo "[local] rc=$RC ${LAST:0:110} | ${INITS} | $MILES" | tee -a "$CONSOLE"
if ls /home/z/my-project/download/fn35/screenshots/*.png >/dev/null 2>&1; then
  echo "[local] *** FRAMES RENDERED — screenshots in download/fn35/screenshots"
fi
if grep -q "FATAL" "$LOG"; then
  C=$(cat "$CRASHES_FILE" 2>/dev/null || echo 0); C=$((C+1)); echo $C > "$CRASHES_FILE"
  if [ -f "$F35/snap_crash/index.json" ]; then
    if [ "$C" -ge 3 ]; then
      echo "[local] crash-loop x$C -> ROLLBACK to last good" | tee -a "$CONSOLE"
      rm -rf "$F35/snap" "$F35/snap_crash"
      [ -f "$F35/snap_good/index.json" ] && cp -r "$F35/snap_good" "$F35/snap"
      echo 0 > "$CRASHES_FILE"
    else
      rm -rf "$F35/snap"; mv "$F35/snap_crash" "$F35/snap"
      echo "[local] crash #$C -> resumed from crash snapshot" | tee -a "$CONSOLE"
    fi
  fi
else
  echo 0 > "$CRASHES_FILE"
  if [ -f "$F35/snap/index.json" ]; then
    rm -rf "$F35/snap_good"; cp -r "$F35/snap" "$F35/snap_good"
  fi
fi
ls -t "$F35"/loc_*.log 2>/dev/null | tail -n +21 | xargs -r rm -f
