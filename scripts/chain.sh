#!/bin/bash
# chain.sh [n_segments] — auto-advancing loader chain with desync-crash
# recovery AND rollback to the last good snapshot when a crash state is
# unrecoverable garbage.
cd /home/z/my-project/scripts
export LD_LIBRARY_PATH=/home/z/mesa-debs/root/usr/lib/x86_64-linux-gnu
# snap is mid-VM-grind (past portrait + init table loops) -> BLOCK sync
# hook directly (6.5x grind speedup; CODE only needed for init 0-253)
export FN35_SYNC_HOOK=${FN35_SYNC_HOOK:-block}
export FN35_BUDGET=${FN35_BUDGET:-430}
export FN35_SNAPSHOT=${FN35_SNAPSHOT:-/home/z/my-project/fn35/snap}
N=${1:-5}
CRASHES=${CRASHES:-0}
CRASHES_FILE=../fn35/.chain_crashes
[ -f $CRASHES_FILE ] && CRASHES=$(cat $CRASHES_FILE)
for i in $(seq 1 $N); do
  LOG=../fn35/ch_$(date +%H%M%S).log
  timeout 540 python -u fn35_loader.py > $LOG 2>&1
  LAST=$(grep -E "stopped:" $LOG | tail -1)
  echo "[chain] seg $i: ${LAST:0:130}"
  if grep -q "FATAL" $LOG; then
    CRASHES=$((CRASHES+1))
    if grep -q "stopped: reason=budget" $LOG; then
      # ended at budget AFTER a fatal? treat as crash only
      :
    fi
    if [ -f ../fn35/snap_crash/index.json ]; then
      if [ $CRASHES -ge 3 ]; then
        echo "[chain] stuck in crash loop -> ROLLBACK to last good"
        rm -rf ../fn35/snap ../fn35/snap_crash
        if [ -f ../fn35/snap_good/index.json ]; then
          cp -r ../fn35/snap_good ../fn35/snap
        fi
        CRASHES=0
      else
        rm -rf ../fn35/snap
        mv ../fn35/snap_crash ../fn35/snap
        echo "[chain] crash #$CRASHES -> recovered from crash snapshot"
      fi
    fi
  else
    echo 0 > $CRASHES_FILE; CRASHES=0
    if [ -f ../fn35/snap/index.json ]; then
      rm -rf ../fn35/snap_good
      cp -r ../fn35/snap ../fn35/snap_good
      MILES=$(grep -cE "didFinishLaunching|LogInit:|LogPakFile|LogRHI|portrait mode" $LOG 2>/dev/null)
      echo "[chain]   budget end; good snapshot saved (milestones this seg: $MILES)"
    fi
  fi
done
echo "[chain] done"
