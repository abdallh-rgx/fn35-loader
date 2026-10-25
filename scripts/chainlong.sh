#!/bin/bash
# chainlong.sh — unattended long-run chain wrapper.
# Usage: nohup bash chainlong.sh [segments] > /dev/null 2>&1 &
# Fresh boot: AUTO sync (CODE through inits -> BLOCK at portrait).
# Restart-safe: if fn35/snap exists, resumes from it.
cd /home/z/my-project/scripts
export LD_LIBRARY_PATH=/home/z/mesa-debs/root/usr/lib/x86_64-linux-gnu${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}
export FN35_SYNC_HOOK=auto
export FN35_BUDGET=${FN35_BUDGET:-500}
export FN35_SNAPSHOT=/home/z/my-project/fn35/snap
N=${1:-200}
CONSOLE=/home/z/my-project/fn35/chain_console.log
echo "[chainlong] start $(date) segments=$N budget=$FN35_BUDGET" >> $CONSOLE
for ((i=1; i<=N; i++)); do
  LOG=/home/z/my-project/fn35/ch_$(date +%m%d_%H%M%S).log
  timeout 560 python3 -u fn35_loader.py > "$LOG" 2>&1
  RC=$?
  LAST=$(grep -E "stopped:" "$LOG" | tail -1)
  MILES=$(grep -aoE "didFinishLaunching|LogInit:|LogPakFile|LogRHI|LogSlate|LogInit: Display|portrait mode" "$LOG" | sort -u | tr '\n' ',' )
  INITS=$(grep -aoE "init [0-9]+/773" "$LOG" | tail -1)
  echo "[chainlong] $i rc=$RC ${LAST:0:110} | ${INITS} | $MILES" >> $CONSOLE
  # crash-recovery: reuse chain.sh logic
  if grep -q "FATAL" "$LOG"; then
    C=$(cat /home/z/my-project/fn35/.chain_crashes 2>/dev/null || echo 0)
    C=$((C+1)); echo $C > /home/z/my-project/fn35/.chain_crashes
    if [ -f /home/z/my-project/fn35/snap_crash/index.json ]; then
      if [ $C -ge 3 ]; then
        echo "[chainlong] crash-loop x$C -> ROLLBACK to last good" >> $CONSOLE
        rm -rf /home/z/my-project/fn35/snap /home/z/my-project/fn35/snap_crash
        [ -f /home/z/my-project/fn35/snap_good/index.json ] && cp -r /home/z/my-project/fn35/snap_good /home/z/my-project/fn35/snap
        echo 0 > /home/z/my-project/fn35/.chain_crashes
      else
        rm -rf /home/z/my-project/fn35/snap
        mv /home/z/my-project/fn35/snap_crash /home/z/my-project/fn35/snap
        echo "[chainlong] crash #$C -> resumed from crash snapshot" >> $CONSOLE
      fi
    fi
  else
    echo 0 > /home/z/my-project/fn35/.chain_crashes
    if [ -f /home/z/my-project/fn35/snap/index.json ]; then
      rm -rf /home/z/my-project/fn35/snap_good
      cp -r /home/z/my-project/fn35/snap /home/z/my-project/fn35/snap_good
    fi
  fi
  # milestone beacon -> easy to spot in console
  if [ -n "$MILES" ]; then
    echo "[chainlong] *** MILESTONES: $MILES" >> $CONSOLE
  fi
  # rotate logs: keep the 40 most recent ch_*.log
  ls -t /home/z/my-project/fn35/ch_*.log 2>/dev/null | tail -n +41 | xargs -r rm -f
done
echo "[chainlong] finished $(date)" >> $CONSOLE
