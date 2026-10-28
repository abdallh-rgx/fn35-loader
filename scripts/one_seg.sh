#!/bin/bash
# one_seg.sh — run exactly ONE loader segment locally with crash-recovery.
# Improvements over chainlong:
#  * crash counter resets when the crash PC CHANGES (progress, not a loop)
#  * BLOCK sync once past the init table (didFinishLaunching seen) - the
#    6.5x VM-grind speedup; CODE only needed for inits 0-253
#  * sandbox-proof: flock (concurrent invocations skip), and every segment
#    ends with git add+commit+push (the 1:1 GitHub mirror) — background
#    daemons do NOT survive this sandbox, so persistence is per-segment
cd /home/z/my-project/scripts
export LD_LIBRARY_PATH=/home/z/mesa-debs/root/usr/lib/x86_64-linux-gnu${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}
export FN35_SYNC_HOOK=auto
export FN35_BUDGET=${FN35_BUDGET:-530}
export FN35_SNAPSHOT=/home/z/my-project/fn35/snap
F35=/home/z/my-project/fn35
CONSOLE=$F35/chain_console.log
CRASHES_FILE=$F35/.chain_crashes
CRASHPC_FILE=$F35/.chain_crashpc

# ---- flock: if another one_seg is already running, SKIP this tick ----
LOCK=/tmp/fn35_one_seg.lock
if ! mkdir "$LOCK" 2>/dev/null; then
  # stale lock? (holder crashed) — locks older than 15 min are stolen
  if [ -n "$(find "$LOCK" -maxdepth 0 -mmin +15 2>/dev/null)" ]; then
    rm -rf "$LOCK"; mkdir "$LOCK" 2>/dev/null || exit 0
  else
    echo "[local] one_seg already running — skip"
    exit 0
  fi
fi
trap 'rm -rf "$LOCK"' EXIT

# ---- SELF-HEAL: sandbox wipes pip modules between sessions; a missing
# dep silently burns every 10-min segment (15h lost 2026-10-28). Verify
# and reinstall BEFORE running the segment.
if ! python3 -c "import unicorn, capstone" 2>/dev/null; then
  echo "[local] deps wiped -> reinstalling unicorn+capstone" | tee -a "$CONSOLE"
  pip install -q unicorn capstone 2>&1 | tail -1 | tee -a "$CONSOLE"
fi
if ! python3 -c "from keystone import Ks" 2>/dev/null; then
  pip uninstall -y -q keystone 2>/dev/null
  pip install -q keystone-engine 2>&1 | tail -1 | tee -a "$CONSOLE"
fi

# ---- ASSET-HEAL: the 91MB binary + extracted tree are gitignored (too
# big for git) but live as a GitHub release asset 'game-assets'. If the
# sandbox wiped fn35/extracted, restore from the local ipa / release.
EXE=$F35/extracted/Payload/FortniteClient.app/FortniteClient
if [ ! -f "$EXE" ]; then
  echo "[local] binary wiped -> restoring" | tee -a "$CONSOLE"
  if [ ! -f "$F35/Fortnite35.ipa" ]; then
    TOKEN=$(cat /home/z/my-project/.gittoken 2>/dev/null)
    AID=$(curl -sL -H "Authorization: token $TOKEN" \
      https://api.github.com/repos/abdallh-rgx/fn35-loader/releases | \
      python3 -c "import json,sys;print([a['id'] for r in json.load(sys.stdin) if r['tag_name']=='game-assets' for a in r['assets']][0])" 2>/dev/null)
    [ -n "$AID" ] && curl -sL -H "Authorization: token $TOKEN" \
      -H "Accept: application/octet-stream" \
      "https://api.github.com/repos/abdallh-rgx/fn35-loader/releases/assets/$AID" \
      -o "$F35/Fortnite35.ipa"
  fi
  if [ -f "$F35/Fortnite35.ipa" ]; then
    mkdir -p "$F35/extracted"
    (cd "$F35/extracted" && unzip -q -o ../Fortnite35.ipa)
    echo "[local] binary restored: $(stat -c%s "$EXE" 2>/dev/null) bytes" | tee -a "$CONSOLE"
  else
    echo "[local] FATAL: no IPA available for restore" | tee -a "$CONSOLE"
  fi
fi


# sync mode is STATE-AWARE: fresh boot (no snapshot) or mid-init-table
# resume needs AUTO (code mode through init 0-253; loader auto-swaps to
# block at the portrait milestone). Snapshot past the init table
# (init_index>=773) -> BLOCK from segment 1 (6.5x VM-grind speedup).
if [ -f "$F35/snap/index.json" ]; then
  INITIDX=$(python3 -c "import json;print(json.load(open('$F35/snap/index.json')).get('init_index',0))" 2>/dev/null || echo 0)
else
  INITIDX=0
fi
if [ "${INITIDX:-0}" -ge 773 ]; then
  export FN35_SYNC_HOOK=block
else
  export FN35_SYNC_HOOK=auto
fi

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

# ---- 1:1 GitHub mirror: every segment ends with add+commit+push ----
cd /home/z/my-project
if [ -n "$(git ls-files --others --exclude-standard)" ] || ! git diff --quiet HEAD 2>/dev/null; then
  git add -A 2>/dev/null
  git diff --cached --quiet 2>/dev/null || git commit -q -m "autosync: seg $(date -u +%FT%TZ)" 2>/dev/null
fi
git push -q origin main 2>/dev/null \
  || { git pull --rebase -q -X ours origin main >/dev/null 2>&1; git push -q origin main 2>/dev/null; }
echo "[local] git mirror synced $(date -u +%H:%M:%SZ)"
