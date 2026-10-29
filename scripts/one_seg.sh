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
# 2026-10-30: tid 0x8330 is a proven dead-event waiter (30h+ of
# zero-progress slices on the same wait chain, see worklog) -- keep it
# out of the scheduler rotation so the VM grind gets the whole CPU.
export FN35_FREEZE_TIDS=${FN35_FREEZE_TIDS:-8330}
# 2026-10-30: the spin-breaker force-completes long retry waits after
# FN35_SPIN_MAX_RETRIES -- it falsely "completed" the async pak-mount
# wait on the fresh boot (project-file check then failed). The
# fire-through tick fix already resolves the original deadlock; the
# breaker stays OFF unless debugging.
export FN35_SPIN_BREAK=${FN35_SPIN_BREAK:-0}
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


# ---- SNAPSHOT PERSIST (1:1 progress rule, extended to snapshots):
# git ignores fn35/snap (too big) but the snapshot IS the progress.
# Backup: after every clean segment, tar the snap dir and upload as the
# 'snapshot-latest' asset of GitHub release tag 'snapshots' (background,
# non-fatal). Restore: if a fresh-boot was intended but a backup exists
# (flag file .snaprestore), pull it back instead of rebooting from zero.
SNAPREL_TAG=snapshots
SNAP_ASSET=snapshot-latest.tgz
snap_backup() {
  ( # background so the segment cadence never waits on the upload
    SBLOCK=/tmp/fn35_snapup.lock
    mkdir "$SBLOCK" 2>/dev/null || exit 0
    trap 'rm -rf "$SBLOCK"' EXIT
    TOKEN=$(cat /home/z/my-project/.gittoken 2>/dev/null) || exit 0
    API=https://api.github.com/repos/abdallh-rgx/fn35-loader
    TGZ=$F35/snapshot-latest.tgz
    tar czf "$TGZ" -C "$F35" snap 2>/dev/null || exit 0
    REL=$(curl -sL -H "Authorization: token $TOKEN" "$API/releases/tags/$SNAPREL_TAG")
    RID=$(echo "$REL" | python3 -c "import json,sys;d=json.load(sys.stdin);print(d.get('id','') if isinstance(d,dict) else '')" 2>/dev/null)
    if [ -z "$RID" ]; then
      RID=$(curl -sL -H "Authorization: token $TOKEN" -X POST \
        -d "{\"tag_name\":\"$SNAPREL_TAG\",\"name\":\"snapshot backups\"}" \
        "$API/releases" | python3 -c "import json,sys;print(json.load(sys.stdin).get('id',''))" 2>/dev/null)
    fi
    [ -z "$RID" ] && exit 0
    AID=$(echo "$REL" | python3 -c "import json,sys;d=json.load(sys.stdin);print([a['id'] for a in d.get('assets',[]) if a['name']=='$SNAP_ASSET'][0] if d.get('assets') else '')" 2>/dev/null)
    [ -n "$AID" ] && curl -sL -X DELETE -H "Authorization: token $TOKEN" "$API/releases/assets/$AID" >/dev/null
    SZ=$(stat -c%s "$TGZ")
    # NB: asset UPLOADS go to uploads.github.com (api.github.com rejects
    # the body with 410/404 silently - the reason the first backup
    # vanished)
    curl -sL -H "Authorization: token $TOKEN" \
      -H "Content-Type: application/octet-stream" \
      --data-binary @"$TGZ" \
      "https://uploads.github.com/repos/abdallh-rgx/fn35-loader/releases/$RID/assets?name=$SNAP_ASSET" >/dev/null
    # verify the asset actually landed (background uploads die silently)
    VOK=$(curl -sL -H "Authorization: token $TOKEN" \
      "$API/releases/tags/$SNAPREL_TAG" | \
      python3 -c "import json,sys;d=json.load(sys.stdin);print(len([a for a in d.get('assets',[]) if a['name']=='$SNAP_ASSET']))" 2>/dev/null)
    echo "[local] snapshot backed up to release '$SNAPREL_TAG' ($SZ bytes, verified=$VOK) $(date -u +%FT%TZ)" >> "$CONSOLE"
    rm -f "$TGZ"
  ) &
}
snap_restore() {
  TOKEN=$(cat /home/z/my-project/.gittoken 2>/dev/null) || return 0
  API=https://api.github.com/repos/abdallh-rgx/fn35-loader
  REL=$(curl -sL -H "Authorization: token $TOKEN" "$API/releases/tags/$SNAPREL_TAG")
  AID=$(echo "$REL" | python3 -c "import json,sys;d=json.load(sys.stdin);print([a['id'] for a in d.get('assets',[]) if a['name']=='$SNAP_ASSET'][0] if d.get('assets') else '')" 2>/dev/null)
  [ -z "$AID" ] && return 0
  echo "[local] restoring snapshot from release backup..." | tee -a "$CONSOLE"
  curl -sL -H "Authorization: token $TOKEN" -H "Accept: application/octet-stream" \
    "$API/releases/assets/$AID" -o "$F35/snapshot-latest.tgz"
  if [ -s "$F35/snapshot-latest.tgz" ]; then
    tar xzf "$F35/snapshot-latest.tgz" -C "$F35" && \
      echo "[local] snapshot restored: $(python3 -c "import json;d=json.load(open('$F35/snap/index.json'));print(d.get('phase'),d.get('init_index'))" 2>/dev/null)" | tee -a "$CONSOLE"
    rm -f "$F35/snapshot-latest.tgz"
  fi
  rm -f "$F35/.snaprestore"
}
if [ -f "$F35/.snaprestore" ] && [ ! -f "$F35/snap/index.json" ]; then
  snap_restore
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
    # 1:1 snapshot persistence: clean segment -> upload backup to the
    # GitHub 'snapshots' release (background, non-fatal)
    snap_backup
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
