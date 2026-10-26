#!/bin/bash
# gha_chain.sh — boot-chain driver for GitHub Actions runners.
# Runs as many 500s loader segments as fit before the hard deadline,
# with the same crash-recovery/rollback logic as chainlong.sh.
#
# Env:
#   CHAIN_DEADLINE_EPOCH  — stop starting new segments after this time
#   FN35_SYNC_HOOK        — auto (fresh) / block (resumed deep state)
#   FN35_BUDGET           — per-segment seconds (default 500)
set -u
cd /home/z/my-project/scripts

export FN35_SYNC_HOOK=${FN35_SYNC_HOOK:-auto}
export FN35_BUDGET=${FN35_BUDGET:-500}
export FN35_SNAPSHOT=/home/z/my-project/fn35/snap
# forensics: every guest _open (with host-exists check) + every >=4KB
# read (fd/offset/result) — would have cracked the w2 uproject
# read-failure mystery on the spot
export FN35_LOG_OPEN=${FN35_LOG_OPEN:-1}
export FN35_TRACE_READ=${FN35_TRACE_READ:-1}
export EGL_PLATFORM=surfaceless
export LIBGL_ALWAYS_SOFTWARE=1
export GALLIUM_DRIVER=llvmpipe
export MESA_DEBUG=silent

F35=/home/z/my-project/fn35
CONSOLE=$F35/chain_console.log
CRASHES_FILE=$F35/.chain_crashes
CRASHPC_FILE=$F35/.chain_crashpc
DEADLINE=${CHAIN_DEADLINE_EPOCH:-0}
SEGMAX=${CHAIN_SEGMAX:-1000}
mkdir -p "$F35"

# phys-pak model persistence across windows: the mode survives in the
# state artifact as a marker file (.phys_mode uploaded alongside snap)
if [ -f "$F35/.phys_mode" ]; then
  export FN35_NO_ENGINE_PAK=1
fi
if [ "${FN35_NO_ENGINE_PAK:-}" = "1" ]; then
  touch "$F35/.phys_mode"
  echo "[gha-chain] phys-pak model ON (engine pak layer bypassed)" >> "$CONSOLE"
fi

# pick sync mode smartly: if a deep snapshot exists, BLOCK is 6.5x faster
if [ -f "$F35/snap/index.json" ]; then
  export FN35_SYNC_HOOK=block
fi

echo "[gha-chain] start $(date -u) deadline=$(date -u -d @$DEADLINE)" >> "$CONSOLE"
STOP_REASON=""
for ((i=1; i<=SEGMAX; i++)); do
  NOW=$(date +%s)
  if [ "$DEADLINE" -gt 0 ] && [ $((NOW + 570)) -gt "$DEADLINE" ]; then
    STOP_REASON="deadline"
    break
  fi
  LOG=$F35/ch_$(date +%m%d_%H%M%S).log
  timeout 560 python3 -u fn35_loader.py > "$LOG" 2>&1
  RC=$?
  LAST=$(grep -E "stopped:" "$LOG" | tail -1)
  MILES=$(grep -aoE "didFinishLaunching|LogInit:|LogPakFile|LogRHI|LogSlate|LogStreaming|LogHAL|Device Profile|LogUObject|LogCore|LogEOS|portrait mode|first frame|abort\(\) called" "$LOG" | sort -u | tr '\n' ',')
  echo "[gha-chain] $i rc=$RC ${LAST:0:110} | $MILES" >> "$CONSOLE"
  # rendered frames = mission accomplished
  if ls /home/z/my-project/download/fn35/screenshots/*.png >/dev/null 2>&1; then
    STOP_REASON="first-frame-rendered"
    break
  fi
  if grep -q "FATAL" "$LOG"; then
    # same-pc fingerprint: different pc = progress (reset), same pc = loop
    NEWPC=$(grep -aoE "pc=0x[0-9a-f]+" "$LOG" | head -1)
    OLDCPC=$(cat "$CRASHPC_FILE" 2>/dev/null)
    if [ "$NEWPC" != "$OLDCPC" ] && [ -n "$NEWPC" ]; then
      echo "$NEWPC" > "$CRASHPC_FILE"
      C=1
    else
      C=$(cat "$CRASHES_FILE" 2>/dev/null || echo 0)
      C=$((C+1))
    fi
    echo $C > "$CRASHES_FILE"
    if [ -f "$F35/snap_crash/index.json" ]; then
      if [ "$C" -ge 3 ]; then
        echo "[gha-chain] crash-loop x$C -> ROLLBACK to last good" >> "$CONSOLE"
        rm -rf "$F35/snap" "$F35/snap_crash"
        [ -f "$F35/snap_good/index.json" ] && cp -r "$F35/snap_good" "$F35/snap"
        echo 0 > "$CRASHES_FILE"
      else
        rm -rf "$F35/snap"
        mv "$F35/snap_crash" "$F35/snap"
        echo "[gha-chain] crash #$C -> resumed from crash snapshot" >> "$CONSOLE"
      fi
    elif [ "$C" -ge 3 ]; then
      # POISON crashes (exec fetch faults) save NO crash snapshot; the
      # same-pc loop means the current snap itself is doomed - roll back
      echo "[gha-chain] poison crash-loop x$C (no snapshot) -> ROLLBACK to last good" >> "$CONSOLE"
      rm -rf "$F35/snap"
      if [ -f "$F35/snap_good/index.json" ]; then
        cp -r "$F35/snap_good" "$F35/snap"
      fi
      echo 0 > "$CRASHES_FILE"
    fi
  else
    echo 0 > "$CRASHES_FILE"
    if [ -f "$F35/snap/index.json" ]; then
      rm -rf "$F35/snap_good"
      cp -r "$F35/snap" "$F35/snap_good"
    fi
  fi
  # rotate logs (keep 40)
  ls -t "$F35"/ch_*.log 2>/dev/null | tail -n +41 | xargs -r rm -f
done
echo "STOP_REASON=$STOP_REASON"
echo "[gha-chain] end $(date -u) reason=${STOP_REASON:-chain-end}" >> "$CONSOLE"
