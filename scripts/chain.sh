#!/bin/bash
# chain.sh [n_segments] — run the loader repeatedly:
#   - budget end -> snapshot advances (normal chain)
#   - random desync crash -> recover from the crash snapshot (the
#     committed state is usually valid; the resume re-translates
#     fresh TBs so the fault class typically does not re-fire)
# Stops after 3 consecutive crashes with no progress.
cd /home/z/my-project/scripts
export LD_LIBRARY_PATH=/home/z/mesa-debs/root/usr/lib/x86_64-linux-gnu
export FN35_SYNC_HOOK=auto
export FN35_BUDGET=440
export FN35_SNAPSHOT=/home/z/my-project/fn35/snap3
N=${1:-5}
CRASHES=0
PREV_INITS=0
for i in $(seq 1 $N); do
  LOG=../fn35/ch_$(date +%H%M%S).log
  timeout 545 python fn35_loader.py > $LOG 2>&1
  LAST=$(grep -E "stopped:" $LOG | tail -1)
  echo "[chain] seg $i: $LAST"
  if grep -q "FATAL" $LOG; then
    CRASHES=$((CRASHES+1))
    if [ -f ../fn35/snap3_crash/index.json ]; then
      rm -rf ../fn35/snap3
      mv ../fn35/snap3_crash ../fn35/snap3
      echo "[chain] crash #$CRASHES -> recovered from crash snapshot"
    fi
    if [ $CRASHES -ge 3 ]; then
      echo "[chain] 3 consecutive crashes -- stopping for analysis"
      tail -5 $LOG | cut -c1-200
      break
    fi
  else
    CRASHES=0
  fi
  # progress check: init count or milestone lines
  INITS=$(grep -c "dyld\] init" $LOG 2>/dev/null || echo 0)
  MILES=$(grep -cE "LogInit|didFinishLaunching|LogPakFile|portrait" $LOG 2>/dev/null || echo 0)
  echo "[chain]   inits=+$INITS milestones=$MILES"
done
echo "[chain] done"
