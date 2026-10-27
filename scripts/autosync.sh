#!/bin/bash
# autosync.sh — 1:1 GitHub mirror daemon (runs forever in background)
# Every interval: commit + push ALL tracked-eligible changes.
# Launched via: nohup scripts/autosync.sh >/home/z/my-project/fn35/autosync.log 2>&1 &
cd /home/z/my-project || exit 1
INTERVAL="${1:-90}"
echo "[autosync] daemon up — interval ${INTERVAL}s — $(date -u +%FT%TZ)"
while true; do
  # any staged-able diff? (tracked modified or untracked-but-not-ignored)
  if ! git diff --quiet HEAD 2>/dev/null || [ -n "$(git ls-files --others --exclude-standard)" ]; then
    git add -A
    if ! git diff --cached --quiet 2>/dev/null; then
      TS=$(date -u +%FT%TZ)
      COUNT=$(git diff --cached --name-only | wc -l)
      if git commit -q -m "autosync ${TS}: ${COUNT} files"; then
        echo "[autosync] ${TS} committed ${COUNT} files"
      fi
    fi
  fi
  # push regardless (covers manual commits made between ticks)
  if ! git push -q origin main 2>/dev/null; then
    git pull --rebase -q -X ours origin main >/dev/null 2>&1
    git push -q origin main 2>/dev/null || echo "[autosync] push retry failed $(date -u +%H:%M:%SZ)"
  fi
  sleep "$INTERVAL"
done
